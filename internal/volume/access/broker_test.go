// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package access_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/agent-substrate/substrate/internal/volume/access"
)

type fixture struct {
	now      time.Time
	state    access.Snapshot
	executor access.Executor
	request  access.Request
	resolves int
	acquires int
	resolve  func() error
	acquire  func(access.ApprovedAccess) (access.Credential, error)
	broker   *access.Broker
}

func newFixture() *fixture {
	f := &fixture{now: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)}
	f.executor = access.Executor{Component: "atelet", ClusterUID: "cluster", NodeUID: "node"}
	f.request = access.Request{BindingUID: "binding", Revision: 2, ActivationUID: "activation", Mode: access.ReadOnly, MaxCredentialLifetime: 30 * time.Minute}
	f.state = access.Snapshot{
		ActorUID: "actor", Atespace: "space", PolicyRevision: 3,
		Binding: access.Binding{UID: "binding", Revision: 2, ActorUID: "actor", VolumeUID: "volume", GrantUID: "grant", ResourceGeneration: 4,
			ClusterUID: "cluster", NodeUID: "node", WorkerUID: "worker", ActivationUID: "activation", Mode: access.ReadOnly, ExpiresAt: f.now.Add(time.Hour)},
		Grant:      access.Grant{UID: "grant", Revision: 5, ActorUID: "actor", VolumeUID: "volume", Atespace: "space", Operations: access.Read | access.List, ExpiresAt: f.now.Add(time.Hour)},
		Assignment: access.Assignment{ActorUID: "actor", ClusterUID: "cluster", NodeUID: "node", WorkerUID: "worker", ActivationUID: "activation"},
		Volume: access.Volume{UID: "volume", Generation: 4, Atespace: "space", OwnerActorUID: "actor", Driver: "fake", Handle: "dataset", Exclusive: true,
			Scope: access.Scope{Endpoint: "https://storage.example.invalid", Resource: "bucket", Prefix: "actors/actor/dataset/", ListPrefix: "actors/actor/dataset/", Operations: access.Read | access.List}},
		Profile: access.Profile{Name: access.StagePublishSecrets, Version: 1, Driver: "fake", CredentialKind: access.SessionCredential, Delivery: access.StagePublishSecrets,
			MinLifetime: 15 * time.Minute, MaxLifetime: time.Hour, ReadOperations: access.Read | access.List, WriteOperations: access.Read | access.Write | access.List},
	}
	f.acquire = func(a access.ApprovedAccess) (access.Credential, error) {
		return access.Credential{Scope: a.Scope, Kind: access.SessionCredential, ProfileName: access.StagePublishSecrets, ProfileVersion: 1,
			ExpiresAt: a.Deadline, Secrets: map[string]string{"accessKey": "synthetic-access", "secretKey": "synthetic-secret", "sessionToken": "synthetic-session"}}, nil
	}
	f.broker = access.NewBroker(f, f, func() time.Time { return f.now })
	return f
}

func (f *fixture) Resolve(_ context.Context, uid string) (access.Snapshot, error) {
	f.resolves++
	if f.resolve != nil {
		if err := f.resolve(); err != nil {
			return access.Snapshot{}, err
		}
	}
	if uid != f.state.Binding.UID {
		return access.Snapshot{}, access.ErrDenied
	}
	return f.state, nil
}

func (f *fixture) Acquire(_ context.Context, a access.ApprovedAccess) (access.Credential, error) {
	f.acquires++
	return f.acquire(a)
}

func TestExchange(t *testing.T) {
	f := newFixture()
	lease, err := f.broker.Exchange(t.Context(), f.executor, f.request)
	if err != nil || lease == nil {
		t.Fatalf("Exchange: lease=%v err=%v", lease, err)
	}
	a := lease.Approved()
	if a.BindingUID != "binding" || a.Revision != 2 || a.ActorUID != "actor" || a.ActivationUID != "activation" || a.VolumeUID != "volume" || a.Driver != "fake" || a.Handle != "dataset" || a.Mode != access.ReadOnly || a.Scope != f.state.Volume.Scope || a.Profile != f.state.Profile {
		t.Fatalf("incorrect approval: %+v", a)
	}
	if !a.Deadline.Equal(f.now.Add(30*time.Minute)) || len(lease.Secrets()) != 3 {
		t.Fatal("incorrect deadline or secret delivery")
	}
	if f.acquires != 1 || f.resolves != 2 {
		t.Fatalf("acquires/resolves = %d/%d, want 1/2", f.acquires, f.resolves)
	}
}

func (f *fixture) exchange(t *testing.T) *access.Lease {
	t.Helper()
	l, err := f.broker.Exchange(t.Context(), f.executor, f.request)
	if err != nil || l == nil {
		t.Fatalf("Exchange: lease=%v err=%v", l, err)
	}
	return l
}

func (f *fixture) target() access.Target {
	return access.Target{ActorUID: f.state.ActorUID, ActivationUID: f.state.Binding.ActivationUID, Driver: f.state.Volume.Driver, Handle: f.state.Volume.Handle}
}

func TestValidateReauthorizes(t *testing.T) {
	f := newFixture()
	l := f.exchange(t)
	for range 2 {
		if err := f.broker.Validate(t.Context(), f.executor, l, f.target()); err != nil {
			t.Fatalf("Validate: %v", err)
		}
	}
	if f.resolves != 4 || f.acquires != 1 {
		t.Fatalf("acquires/resolves = %d/%d, want 1/4", f.acquires, f.resolves)
	}
	if next := f.exchange(t); next == l || f.acquires != 2 {
		t.Fatal("repeated exchange reused an earlier result")
	}
	f.state.Grant.Revoked = true
	if err := f.broker.Validate(t.Context(), f.executor, l, f.target()); !errors.Is(err, access.ErrDenied) {
		t.Fatalf("revoked Validate: %v", err)
	}
	if lease, err := f.broker.Exchange(t.Context(), f.executor, f.request); lease != nil || !errors.Is(err, access.ErrDenied) {
		t.Fatalf("revoked Exchange: lease=%v err=%v", lease, err)
	}
	if f.acquires != 2 {
		t.Fatal("revoked repeated request reached provider")
	}
}

func TestSecretOwnership(t *testing.T) {
	f := newFixture()
	original := f.acquire
	var retained map[string]string
	f.acquire = func(a access.ApprovedAccess) (access.Credential, error) {
		c, err := original(a)
		retained = c.Secrets
		a.BindingUID, a.Scope.Resource, a.Profile.Driver = "changed", "changed", "changed"
		return c, err
	}
	f.resolve = func() error {
		if f.resolves == 2 {
			retained["secretKey"] = "dependency-change"
		}
		return nil
	}
	l := f.exchange(t)
	delete(retained, "accessKey")
	secrets := l.Secrets()
	if len(secrets) != 3 || secrets["secretKey"] != "synthetic-secret" || secrets["accessKey"] != "synthetic-access" {
		t.Fatal("provider retained map changed issued secrets")
	}
	secrets["secretKey"] = "caller-change"
	delete(secrets, "sessionToken")
	if next := l.Secrets(); len(next) != 3 || next["secretKey"] != "synthetic-secret" {
		t.Fatal("Secrets did not return a fresh copy")
	}
	a := l.Approved()
	a.Scope.Prefix, a.Profile.Driver, a.Handle = "changed/", "changed", "changed"
	if l.Approved().Scope.Prefix != "actors/actor/dataset/" || l.Approved().Profile.Driver != "fake" || l.Approved().Handle != "dataset" {
		t.Fatal("approval shares mutable state")
	}
	if err := f.broker.Validate(t.Context(), f.executor, l, f.target()); err != nil {
		t.Fatalf("mutation changed valid lease: %v", err)
	}
}

func TestRedaction(t *testing.T) {
	const marker = "SYNTHETIC-SECRET-MARKER"
	f := newFixture()
	original := f.acquire
	var credential access.Credential
	f.acquire = func(a access.ApprovedAccess) (access.Credential, error) {
		credential, _ = original(a)
		credential.Secrets["secretKey"] = marker
		return credential, nil
	}
	l := f.exchange(t)
	for _, value := range []any{credential, &credential, l, *l, f.broker, struct{ Value any }{l}} {
		var output bytes.Buffer
		for _, format := range []string{"%v", "%+v", "%#v"} {
			fmt.Fprintf(&output, format, value)
			log.New(&output, "", 0).Printf(format, value)
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("JSON: %v", err)
		}
		output.Write(encoded)
		slog.New(slog.NewTextHandler(&output, nil)).Info("material", "value", value)
		slog.New(slog.NewJSONHandler(&output, nil)).Info("material", "value", value)
		if strings.Contains(output.String(), marker) {
			t.Fatalf("secret leaked through formatting %T", value)
		}
	}
}

func TestInitialDenials(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*fixture)
		want   error
	}{
		{"missing binding", func(f *fixture) { f.request.BindingUID = "missing" }, access.ErrDenied},
		{"empty binding", func(f *fixture) { f.request.BindingUID = "" }, access.ErrInvalidRequest},
		{"empty revision", func(f *fixture) { f.request.Revision = 0 }, access.ErrInvalidRequest},
		{"stale revision", func(f *fixture) { f.request.Revision++ }, access.ErrDenied},
		{"empty activation", func(f *fixture) { f.request.ActivationUID = "" }, access.ErrInvalidRequest},
		{"foreign activation", func(f *fixture) { f.request.ActivationUID = "other" }, access.ErrDenied},
		{"empty mode", func(f *fixture) { f.request.Mode = "" }, access.ErrInvalidRequest},
		{"unknown mode", func(f *fixture) { f.request.Mode = "other" }, access.ErrUnsupported},
		{"mode escalation", func(f *fixture) { f.request.Mode = access.ReadWrite }, access.ErrDenied},
		{"empty lifetime", func(f *fixture) { f.request.MaxCredentialLifetime = 0 }, access.ErrInvalidRequest},
		{"negative lifetime", func(f *fixture) { f.request.MaxCredentialLifetime = -1 }, access.ErrInvalidRequest},
		{"component", func(f *fixture) { f.executor.Component = "controller" }, access.ErrDenied},
		{"cluster", func(f *fixture) { f.executor.ClusterUID = "other" }, access.ErrDenied},
		{"node incarnation", func(f *fixture) { f.executor.NodeUID = "other" }, access.ErrDenied},
		{"absent executor", func(f *fixture) { f.executor = access.Executor{} }, access.ErrDenied},
		{"absent state", func(f *fixture) { f.state = access.Snapshot{} }, access.ErrDenied},
		{"policy revision", func(f *fixture) { f.state.PolicyRevision = 0 }, access.ErrDenied},
		{"grant revision", func(f *fixture) { f.state.Grant.Revision = 0 }, access.ErrDenied},
		{"resource generations", func(f *fixture) { f.state.Binding.ResourceGeneration = 0; f.state.Volume.Generation = 0 }, access.ErrDenied},
		{"revoked", func(f *fixture) { f.state.Grant.Revoked = true }, access.ErrDenied},
		{"binding expired equality", func(f *fixture) { f.state.Binding.ExpiresAt = f.now }, access.ErrDenied},
		{"grant expired equality", func(f *fixture) { f.state.Grant.ExpiresAt = f.now }, access.ErrDenied},
		{"missing binding expiry", func(f *fixture) { f.state.Binding.ExpiresAt = time.Time{} }, access.ErrDenied},
		{"missing grant expiry", func(f *fixture) { f.state.Grant.ExpiresAt = time.Time{} }, access.ErrDenied},
		{"shared volume", func(f *fixture) { f.state.Volume.Exclusive = false }, access.ErrUnsupported},
		{"empty driver", func(f *fixture) { f.state.Volume.Driver = ""; f.state.Profile.Driver = "" }, access.ErrDenied},
		{"empty handle", func(f *fixture) { f.state.Volume.Handle = "" }, access.ErrDenied},
		{"profile name", func(f *fixture) { f.state.Profile.Name = "unknown" }, access.ErrUnsupported},
		{"profile version", func(f *fixture) { f.state.Profile.Version = 0 }, access.ErrUnsupported},
		{"profile driver", func(f *fixture) { f.state.Profile.Driver = "other" }, access.ErrUnsupported},
		{"profile delivery", func(f *fixture) { f.state.Profile.Delivery = "publish-only" }, access.ErrUnsupported},
		{"profile credential", func(f *fixture) { f.state.Profile.CredentialKind = "static" }, access.ErrUnsupported},
		{"profile minimum", func(f *fixture) { f.state.Profile.MinLifetime = 0 }, access.ErrUnsupported},
		{"profile maximum", func(f *fixture) { f.state.Profile.MaxLifetime = 0 }, access.ErrUnsupported},
		{"profile range", func(f *fixture) { f.state.Profile.MaxLifetime = time.Minute }, access.ErrUnsupported},
		{"profile read empty", func(f *fixture) { f.state.Profile.ReadOperations = 0 }, access.ErrUnsupported},
		{"profile read missing list", func(f *fixture) { f.state.Profile.ReadOperations = access.Read }, access.ErrUnsupported},
		{"profile read missing read", func(f *fixture) { f.state.Profile.ReadOperations = access.List }, access.ErrUnsupported},
		{"profile read write", func(f *fixture) { f.state.Profile.ReadOperations |= access.Write }, access.ErrUnsupported},
		{"profile read unknown", func(f *fixture) { f.state.Profile.ReadOperations |= 128 }, access.ErrUnsupported},
		{"profile write missing write", func(f *fixture) { f.state.Profile.WriteOperations = access.Read | access.List }, access.ErrUnsupported},
		{"profile write unknown", func(f *fixture) { f.state.Profile.WriteOperations |= 128 }, access.ErrUnsupported},
		{"volume missing read", func(f *fixture) { f.state.Volume.Scope.Operations = access.List }, access.ErrDenied},
		{"volume missing list", func(f *fixture) { f.state.Volume.Scope.Operations = access.Read }, access.ErrDenied},
		{"volume unknown ops", func(f *fixture) { f.state.Volume.Scope.Operations |= 128 }, access.ErrDenied},
		{"grant missing read", func(f *fixture) { f.state.Grant.Operations = access.List }, access.ErrDenied},
		{"grant missing list", func(f *fixture) { f.state.Grant.Operations = access.Read }, access.ErrDenied},
		{"grant unknown ops", func(f *fixture) { f.state.Grant.Operations |= 128 }, access.ErrDenied},
		{"empty resource", func(f *fixture) { f.state.Volume.Scope.Resource = "" }, access.ErrDenied},
		{"blank resource", func(f *fixture) { f.state.Volume.Scope.Resource = " " }, access.ErrDenied},
		{"empty prefix", func(f *fixture) { f.state.Volume.Scope.Prefix = "" }, access.ErrDenied},
		{"undelimited prefix", func(f *fixture) { f.state.Volume.Scope.Prefix = "actors/actor/dataset" }, access.ErrDenied},
		{"empty LIST", func(f *fixture) { f.state.Volume.Scope.ListPrefix = "" }, access.ErrDenied},
		{"broad LIST", func(f *fixture) { f.state.Volume.Scope.ListPrefix = "actors/" }, access.ErrDenied},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture()
			tc.change(f)
			l, err := f.broker.Exchange(t.Context(), f.executor, f.request)
			if l != nil || !errors.Is(err, tc.want) || f.acquires != 0 {
				t.Fatalf("lease=%v err=%v acquires=%d, want %v without acquisition", l, err, f.acquires, tc.want)
			}
		})
	}
	for _, endpoint := range []string{"", "http://storage.invalid", "https:", "https:///path", "https://user@storage.invalid", "https://storage.invalid?x=1", "https://storage.invalid?", "https://storage.invalid#x", "https://storage.invalid#", "https://%invalid"} {
		t.Run("endpoint="+endpoint, func(t *testing.T) {
			f := newFixture()
			f.state.Volume.Scope.Endpoint = endpoint
			if l, err := f.broker.Exchange(t.Context(), f.executor, f.request); l != nil || !errors.Is(err, access.ErrDenied) || f.acquires != 0 {
				t.Fatalf("lease=%v err=%v acquires=%d", l, err, f.acquires)
			}
		})
	}
}

func TestReadWriteIsolation(t *testing.T) {
	for _, tc := range []struct {
		name          string
		grant, volume access.Operations
		want          error
	}{
		{"workspace", access.Read | access.Write | access.List, access.Read | access.Write | access.List, nil},
		{"grant read only", access.Read | access.List, access.Read | access.Write | access.List, access.ErrDenied},
		{"volume read only", access.Read | access.Write | access.List, access.Read | access.List, access.ErrDenied},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture()
			f.request.Mode, f.state.Binding.Mode = access.ReadWrite, access.ReadWrite
			f.state.Volume.Handle = "workspace"
			f.state.Volume.Scope.Prefix, f.state.Volume.Scope.ListPrefix = "actors/actor/workspace/", "actors/actor/workspace/"
			f.state.Grant.Operations, f.state.Volume.Scope.Operations = tc.grant, tc.volume
			l, err := f.broker.Exchange(t.Context(), f.executor, f.request)
			if !errors.Is(err, tc.want) {
				t.Fatalf("Exchange: %v, want %v", err, tc.want)
			}
			if tc.want == nil {
				if l == nil || l.Approved().Scope.Operations != access.Read|access.Write|access.List || l.Approved().Handle != "workspace" || f.acquires != 1 {
					t.Fatal("incorrect workspace approval")
				}
			} else if l != nil || f.acquires != 0 {
				t.Fatal("read-only authority acquired writable material")
			}
		})
	}
}

func TestAuthorityChanges(t *testing.T) {
	for _, tc := range []struct {
		name    string
		change  func(*access.Snapshot)
		initial error
	}{
		{"actor", func(s *access.Snapshot) { s.ActorUID = "other" }, access.ErrDenied},
		{"atespace", func(s *access.Snapshot) { s.Atespace = "other" }, access.ErrDenied},
		{"policy", func(s *access.Snapshot) { s.PolicyRevision++ }, nil},
		{"binding UID", func(s *access.Snapshot) { s.Binding.UID = "other" }, access.ErrDenied},
		{"binding revision", func(s *access.Snapshot) { s.Binding.Revision++ }, access.ErrDenied},
		{"binding actor", func(s *access.Snapshot) { s.Binding.ActorUID = "other" }, access.ErrDenied},
		{"binding volume", func(s *access.Snapshot) { s.Binding.VolumeUID = "other" }, access.ErrDenied},
		{"binding grant", func(s *access.Snapshot) { s.Binding.GrantUID = "other" }, access.ErrDenied},
		{"binding generation", func(s *access.Snapshot) { s.Binding.ResourceGeneration++ }, access.ErrDenied},
		{"binding cluster", func(s *access.Snapshot) { s.Binding.ClusterUID = "other" }, access.ErrDenied},
		{"binding node", func(s *access.Snapshot) { s.Binding.NodeUID = "other" }, access.ErrDenied},
		{"binding worker", func(s *access.Snapshot) { s.Binding.WorkerUID = "other" }, access.ErrDenied},
		{"binding activation", func(s *access.Snapshot) { s.Binding.ActivationUID = "other" }, access.ErrDenied},
		{"binding mode", func(s *access.Snapshot) { s.Binding.Mode = access.ReadWrite }, access.ErrDenied},
		{"binding expiry", func(s *access.Snapshot) { s.Binding.ExpiresAt = s.Binding.ExpiresAt.Add(time.Minute) }, nil},
		{"grant UID", func(s *access.Snapshot) { s.Grant.UID = "other" }, access.ErrDenied},
		{"grant revision", func(s *access.Snapshot) { s.Grant.Revision++ }, nil},
		{"grant actor", func(s *access.Snapshot) { s.Grant.ActorUID = "other" }, access.ErrDenied},
		{"grant volume", func(s *access.Snapshot) { s.Grant.VolumeUID = "other" }, access.ErrDenied},
		{"grant atespace", func(s *access.Snapshot) { s.Grant.Atespace = "other" }, access.ErrDenied},
		{"grant ops", func(s *access.Snapshot) { s.Grant.Operations |= access.Write }, nil},
		{"grant expiry", func(s *access.Snapshot) { s.Grant.ExpiresAt = s.Grant.ExpiresAt.Add(time.Minute) }, nil},
		{"grant revoked", func(s *access.Snapshot) { s.Grant.Revoked = true }, access.ErrDenied},
		{"assignment actor", func(s *access.Snapshot) { s.Assignment.ActorUID = "other" }, access.ErrDenied},
		{"assignment cluster", func(s *access.Snapshot) { s.Assignment.ClusterUID = "other" }, access.ErrDenied},
		{"assignment node", func(s *access.Snapshot) { s.Assignment.NodeUID = "other" }, access.ErrDenied},
		{"assignment worker", func(s *access.Snapshot) { s.Assignment.WorkerUID = "other" }, access.ErrDenied},
		{"assignment activation", func(s *access.Snapshot) { s.Assignment.ActivationUID = "other" }, access.ErrDenied},
		{"volume UID", func(s *access.Snapshot) { s.Volume.UID = "other" }, access.ErrDenied},
		{"volume generation", func(s *access.Snapshot) { s.Volume.Generation++ }, access.ErrDenied},
		{"volume atespace", func(s *access.Snapshot) { s.Volume.Atespace = "other" }, access.ErrDenied},
		{"volume owner", func(s *access.Snapshot) { s.Volume.OwnerActorUID = "other" }, access.ErrDenied},
		{"volume driver", func(s *access.Snapshot) { s.Volume.Driver = "other" }, access.ErrUnsupported},
		{"volume handle", func(s *access.Snapshot) { s.Volume.Handle = "other" }, nil},
		{"scope endpoint", func(s *access.Snapshot) { s.Volume.Scope.Endpoint = "https://other.invalid" }, nil},
		{"scope resource", func(s *access.Snapshot) { s.Volume.Scope.Resource = "other" }, nil},
		{"scope prefix", func(s *access.Snapshot) { s.Volume.Scope.Prefix = "other/" }, access.ErrDenied},
		{"scope list", func(s *access.Snapshot) { s.Volume.Scope.ListPrefix = "other/" }, access.ErrDenied},
		{"scope ops", func(s *access.Snapshot) { s.Volume.Scope.Operations |= access.Write }, nil},
		{"exclusive", func(s *access.Snapshot) { s.Volume.Exclusive = false }, access.ErrUnsupported},
		{"profile name", func(s *access.Snapshot) { s.Profile.Name = "other" }, access.ErrUnsupported},
		{"profile version", func(s *access.Snapshot) { s.Profile.Version++ }, nil},
		{"profile driver", func(s *access.Snapshot) { s.Profile.Driver = "other" }, access.ErrUnsupported},
		{"profile kind", func(s *access.Snapshot) { s.Profile.CredentialKind = "other" }, access.ErrUnsupported},
		{"profile delivery", func(s *access.Snapshot) { s.Profile.Delivery = "other" }, access.ErrUnsupported},
		{"profile minimum", func(s *access.Snapshot) { s.Profile.MinLifetime += time.Minute }, nil},
		{"profile maximum", func(s *access.Snapshot) { s.Profile.MaxLifetime += time.Minute }, nil},
		{"profile read", func(s *access.Snapshot) { s.Profile.ReadOperations |= access.Write }, access.ErrUnsupported},
		{"profile write", func(s *access.Snapshot) { s.Profile.WriteOperations = access.Read }, access.ErrUnsupported},
	} {
		for _, phase := range []string{"initial", "acquire", "validate"} {
			t.Run(tc.name+"/"+phase, func(t *testing.T) {
				f := newFixture()
				// The provider follows the current approved profile, not fixture constants.
				original := f.acquire
				f.acquire = func(a access.ApprovedAccess) (access.Credential, error) {
					c, err := original(a)
					c.ProfileVersion = a.Profile.Version
					if phase == "acquire" {
						tc.change(&f.state)
					}
					return c, err
				}
				var err error
				if phase == "validate" {
					l := f.exchange(t)
					target := f.target()
					tc.change(&f.state)
					err = f.broker.Validate(t.Context(), f.executor, l, target)
				} else {
					if phase == "initial" {
						tc.change(&f.state)
					}
					var l *access.Lease
					l, err = f.broker.Exchange(t.Context(), f.executor, f.request)
					if err != nil && l != nil {
						t.Fatal("denial delivered a lease")
					}
				}
				if phase == "initial" {
					if !errors.Is(err, tc.initial) {
						t.Fatalf("initial error=%v, want %v", err, tc.initial)
					}
					if tc.initial != nil && f.acquires != 0 {
						t.Fatal("initial denial acquired material")
					}
				} else {
					want := tc.initial
					if want == nil {
						want = access.ErrDenied
					}
					if !errors.Is(err, want) || f.acquires != 1 {
						t.Fatalf("authority change: err=%v acquires=%d, want %v", err, f.acquires, want)
					}
				}
			})
		}
	}
}

func TestNoInferredIdentity(t *testing.T) {
	for name, change := range map[string]func(*fixture, string){
		"actors": func(f *fixture, identity string) {
			f.state.ActorUID = identity
			f.state.Binding.ActorUID = identity
			f.state.Grant.ActorUID = identity
			f.state.Assignment.ActorUID = identity
			f.state.Volume.OwnerActorUID = identity
		},
		"atespaces": func(f *fixture, identity string) {
			f.state.Atespace, f.state.Grant.Atespace, f.state.Volume.Atespace = identity, identity, identity
		},
		"clusters": func(f *fixture, identity string) {
			f.executor.ClusterUID, f.state.Binding.ClusterUID, f.state.Assignment.ClusterUID = identity, identity, identity
		},
		"nodes": func(f *fixture, identity string) {
			f.executor.NodeUID, f.state.Binding.NodeUID, f.state.Assignment.NodeUID = identity, identity, identity
		},
		"workers": func(f *fixture, identity string) {
			f.state.Binding.WorkerUID, f.state.Assignment.WorkerUID = identity, identity
		},
		"volumes": func(f *fixture, identity string) {
			f.state.Binding.VolumeUID, f.state.Grant.VolumeUID, f.state.Volume.UID = identity, identity, identity
		},
		"grants": func(f *fixture, identity string) { f.state.Binding.GrantUID, f.state.Grant.UID = identity, identity },
	} {
		for kind, identity := range map[string]string{"empty": "", "whitespace": " \t\n"} {
			t.Run(name+"/"+kind, func(t *testing.T) {
				f := newFixture()
				change(f, identity)
				if l, err := f.broker.Exchange(t.Context(), f.executor, f.request); l != nil || !errors.Is(err, access.ErrDenied) || f.acquires != 0 {
					t.Fatalf("lease=%v err=%v acquires=%d", l, err, f.acquires)
				}
			})
		}
	}
}

func TestIdentityReferencesAreExact(t *testing.T) {
	for name, change := range map[string]func(*fixture){
		"actor":    func(f *fixture) { f.state.ActorUID += " " },
		"atespace": func(f *fixture) { f.state.Volume.Atespace += " " },
		"grant":    func(f *fixture) { f.state.Binding.GrantUID += " " },
		"volume":   func(f *fixture) { f.state.Binding.VolumeUID += " " },
		"cluster":  func(f *fixture) { f.executor.ClusterUID += " " },
		"node":     func(f *fixture) { f.state.Assignment.NodeUID += " " },
		"worker":   func(f *fixture) { f.state.Assignment.WorkerUID += " " },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture()
			change(f)
			if lease, err := f.broker.Exchange(t.Context(), f.executor, f.request); lease != nil || err != access.ErrDenied || f.acquires != 0 {
				t.Fatal("identity references were normalized instead of compared exactly")
			}
		})
	}
}

func TestRequiredFieldsPrecedeProfileRejection(t *testing.T) {
	for _, field := range []string{"driver", "handle", "endpoint", "resource", "prefix", "list"} {
		for _, phase := range []string{"exchange", "validate"} {
			t.Run(field+"/"+phase, func(t *testing.T) {
				f := newFixture()
				target := f.target()
				var lease *access.Lease
				if phase == "validate" {
					lease = f.exchange(t)
				}
				f.state.Profile.Name = "unsupported"
				switch field {
				case "driver":
					f.state.Volume.Driver = " "
				case "handle":
					f.state.Volume.Handle = " "
				case "endpoint":
					f.state.Volume.Scope.Endpoint = " "
				case "resource":
					f.state.Volume.Scope.Resource = " "
				case "prefix":
					f.state.Volume.Scope.Prefix = " "
				case "list":
					f.state.Volume.Scope.ListPrefix = " "
				}
				var err error
				if phase == "validate" {
					err = f.broker.Validate(t.Context(), f.executor, lease, target)
				} else {
					lease, err = f.broker.Exchange(t.Context(), f.executor, f.request)
					if lease != nil || f.acquires != 0 {
						t.Fatal("incomplete authority acquired credentials")
					}
				}
				if err != access.ErrDenied {
					t.Fatalf("missing field and unsupported profile: %v, want Denied", err)
				}
			})
		}
	}
	t.Run("profile before nonempty invalid scope", func(t *testing.T) {
		f := newFixture()
		f.state.Profile.Name = "unsupported"
		f.state.Volume.Scope.Endpoint = "http://storage.example.invalid"
		if lease, err := f.broker.Exchange(t.Context(), f.executor, f.request); lease != nil || err != access.ErrUnsupported || f.acquires != 0 {
			t.Fatalf("unsupported profile and invalid scope: %v, want Unsupported", err)
		}
	})
}

func TestInvalidCredentials(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*access.Credential, *fixture)
		want   error
	}{
		{"resource", func(c *access.Credential, _ *fixture) { c.Scope.Resource = "other" }, access.ErrDenied},
		{"endpoint", func(c *access.Credential, _ *fixture) { c.Scope.Endpoint += "/" }, access.ErrDenied},
		{"prefix", func(c *access.Credential, _ *fixture) { c.Scope.Prefix = "actors/" }, access.ErrDenied},
		{"list", func(c *access.Credential, _ *fixture) { c.Scope.ListPrefix = "actors/" }, access.ErrDenied},
		{"write", func(c *access.Credential, _ *fixture) { c.Scope.Operations |= access.Write }, access.ErrDenied},
		{"unknown operation", func(c *access.Credential, _ *fixture) { c.Scope.Operations |= 128 }, access.ErrDenied},
		{"missing operation", func(c *access.Credential, _ *fixture) { c.Scope.Operations = access.Read }, access.ErrDenied},
		{"kind", func(c *access.Credential, _ *fixture) { c.Kind = "static" }, access.ErrDenied},
		{"profile", func(c *access.Credential, _ *fixture) { c.ProfileName = "other" }, access.ErrDenied},
		{"version", func(c *access.Credential, _ *fixture) { c.ProfileVersion++ }, access.ErrDenied},
		{"missing expiry", func(c *access.Credential, _ *fixture) { c.ExpiresAt = time.Time{} }, access.ErrDenied},
		{"expired", func(c *access.Credential, f *fixture) { c.ExpiresAt = f.now.Add(-time.Nanosecond) }, access.ErrDenied},
		{"expiry equality", func(c *access.Credential, f *fixture) { c.ExpiresAt = f.now }, access.ErrDenied},
		{"too short", func(c *access.Credential, f *fixture) { c.ExpiresAt = f.now.Add(15*time.Minute - time.Nanosecond) }, access.ErrUnsupported},
		{"overlong", func(c *access.Credential, _ *fixture) { c.ExpiresAt = c.ExpiresAt.Add(time.Nanosecond) }, access.ErrDenied},
		{"slow extension", func(c *access.Credential, f *fixture) {
			f.now = f.now.Add(time.Minute)
			c.ExpiresAt = c.ExpiresAt.Add(time.Minute)
		}, access.ErrDenied},
		{"expiry during acquire", func(_ *access.Credential, f *fixture) { f.now = f.now.Add(30 * time.Minute) }, access.ErrDenied},
		{"minimum lost during acquire", func(_ *access.Credential, f *fixture) { f.now = f.now.Add(16 * time.Minute) }, access.ErrUnsupported},
		{"nil secrets", func(c *access.Credential, _ *fixture) { c.Secrets = nil }, access.ErrDenied},
		{"extra secret", func(c *access.Credential, _ *fixture) { c.Secrets["extra"] = "synthetic" }, access.ErrDenied},
		{"empty accessKey", func(c *access.Credential, _ *fixture) { c.Secrets["accessKey"] = "" }, access.ErrDenied},
		{"empty secretKey", func(c *access.Credential, _ *fixture) { c.Secrets["secretKey"] = "" }, access.ErrDenied},
		{"empty sessionToken", func(c *access.Credential, _ *fixture) { c.Secrets["sessionToken"] = "" }, access.ErrDenied},
		{"missing accessKey", func(c *access.Credential, _ *fixture) { delete(c.Secrets, "accessKey") }, access.ErrDenied},
		{"missing secretKey", func(c *access.Credential, _ *fixture) { delete(c.Secrets, "secretKey") }, access.ErrDenied},
		{"missing sessionToken", func(c *access.Credential, _ *fixture) { delete(c.Secrets, "sessionToken") }, access.ErrDenied},
		{"substituted key", func(c *access.Credential, _ *fixture) {
			delete(c.Secrets, "sessionToken")
			c.Secrets["other"] = "synthetic"
		}, access.ErrDenied},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture()
			original := f.acquire
			f.acquire = func(a access.ApprovedAccess) (access.Credential, error) {
				c, err := original(a)
				tc.change(&c, f)
				return c, err
			}
			if l, err := f.broker.Exchange(t.Context(), f.executor, f.request); l != nil || !errors.Is(err, tc.want) || f.acquires != 1 {
				t.Fatalf("lease=%v err=%v acquires=%d, want %v after acquisition", l, err, f.acquires, tc.want)
			}
		})
	}
}

func TestDeadlineLimits(t *testing.T) {
	for _, field := range []string{"binding", "grant"} {
		t.Run("absent "+field+" deadline independent of clock", func(t *testing.T) {
			f := newFixture()
			f.now = time.Time{}.Add(-time.Hour)
			if field == "binding" {
				f.state.Binding.ExpiresAt = time.Time{}
			} else {
				f.state.Grant.ExpiresAt = time.Time{}
			}
			if l, err := f.broker.Exchange(t.Context(), f.executor, f.request); l != nil || !errors.Is(err, access.ErrDenied) || f.acquires != 0 {
				t.Fatalf("missing deadline: lease=%v err=%v acquires=%d", l, err, f.acquires)
			}
		})
	}
	for _, limit := range []string{"request", "profile", "binding", "grant"} {
		for _, ttl := range []time.Duration{15*time.Minute - time.Nanosecond, 15 * time.Minute, 20 * time.Minute} {
			t.Run(limit+"/"+ttl.String(), func(t *testing.T) {
				f := newFixture()
				switch limit {
				case "request":
					f.request.MaxCredentialLifetime = ttl
				case "profile":
					f.state.Profile.MaxLifetime = ttl
				case "binding":
					f.state.Binding.ExpiresAt = f.now.Add(ttl)
				case "grant":
					f.state.Grant.ExpiresAt = f.now.Add(ttl)
				}
				l, err := f.broker.Exchange(t.Context(), f.executor, f.request)
				if ttl < 15*time.Minute {
					if l != nil || !errors.Is(err, access.ErrUnsupported) || f.acquires != 0 {
						t.Fatalf("lease=%v err=%v acquires=%d", l, err, f.acquires)
					}
					return
				}
				if err != nil || l == nil || !l.Approved().Deadline.Equal(f.now.Add(ttl)) {
					t.Fatalf("deadline limit: lease=%v err=%v", l, err)
				}
				f.now = l.Approved().Deadline.Add(-time.Nanosecond)
				if err := f.broker.Validate(t.Context(), f.executor, l, f.target()); err != nil {
					t.Fatalf("before deadline: %v", err)
				}
				f.now = f.now.Add(time.Nanosecond)
				if err := f.broker.Validate(t.Context(), f.executor, l, f.target()); !errors.Is(err, access.ErrDenied) {
					t.Fatalf("at deadline: %v", err)
				}
			})
		}
	}
	t.Run("actual expiry earlier than deadline", func(t *testing.T) {
		f := newFixture()
		original := f.acquire
		f.acquire = func(a access.ApprovedAccess) (access.Credential, error) {
			c, err := original(a)
			c.ExpiresAt = f.now.Add(15 * time.Minute)
			return c, err
		}
		l := f.exchange(t)
		f.now = f.now.Add(15 * time.Minute)
		if err := f.broker.Validate(t.Context(), f.executor, l, f.target()); !errors.Is(err, access.ErrDenied) {
			t.Fatalf("actual expiry: %v", err)
		}
	})
}

func TestValidateMaterialBinding(t *testing.T) {
	for _, name := range []string{"actor", "activation", "driver", "handle", "empty target", "component", "cluster", "node", "nil lease", "empty lease", "other broker", "other binding"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture()
			l := f.exchange(t)
			target, executor, broker := f.target(), f.executor, f.broker
			switch name {
			case "actor":
				target.ActorUID = "other"
			case "activation":
				target.ActivationUID = "other"
			case "driver":
				target.Driver = "other"
			case "handle":
				target.Handle = "other"
			case "empty target":
				target = access.Target{}
			case "component":
				executor.Component = "other"
			case "cluster":
				executor.ClusterUID = "other"
			case "node":
				executor.NodeUID = "other"
			case "nil lease":
				l = nil
			case "empty lease":
				l = &access.Lease{}
			case "other broker":
				broker = newFixture().broker
			case "other binding":
				f.state.Binding.UID, f.request.BindingUID = "other-binding", "other-binding"
				f.state.Binding.VolumeUID, f.state.Grant.VolumeUID, f.state.Volume.UID, f.state.Volume.Handle = "other-volume", "other-volume", "other-volume", "other-handle"
				f.exchange(t)
				target = f.target()
			}
			before := f.acquires
			if err := broker.Validate(t.Context(), executor, l, target); !errors.Is(err, access.ErrDenied) || f.acquires != before {
				t.Fatalf("substitution: err=%v acquires=%d", err, f.acquires)
			}
		})
	}
}

func TestDependencyErrors(t *testing.T) {
	const marker = "SYNTHETIC-ERROR-SECRET"
	for _, phase := range []string{"initial", "provider", "after acquire", "validate"} {
		for _, missing := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/missing=%t", phase, missing), func(t *testing.T) {
				f := newFixture()
				dependencyError := errors.New(marker)
				want := access.ErrUnavailable
				if missing {
					dependencyError = fmt.Errorf("%s: %w", marker, access.ErrDenied)
					if phase != "provider" {
						want = access.ErrDenied
					}
				}
				var lease *access.Lease
				if phase == "validate" {
					lease = f.exchange(t)
				}
				f.resolve = func() error {
					if phase == "initial" || phase == "validate" || phase == "after acquire" && f.resolves == 2 {
						return dependencyError
					}
					return nil
				}
				if phase == "provider" {
					f.acquire = func(access.ApprovedAccess) (access.Credential, error) { return access.Credential{}, dependencyError }
				}
				var err error
				if phase == "validate" {
					err = f.broker.Validate(t.Context(), f.executor, lease, f.target())
				} else {
					lease, err = f.broker.Exchange(t.Context(), f.executor, f.request)
					if lease != nil {
						t.Fatal("dependency failure delivered material")
					}
				}
				if !errors.Is(err, want) {
					t.Fatalf("error=%v, want %v", err, want)
				}
				calls := 1
				if phase == "initial" {
					calls = 0
				}
				if f.acquires != calls {
					t.Fatalf("acquires=%d, want %d", f.acquires, calls)
				}
				var output bytes.Buffer
				for _, format := range []string{"%v", "%+v", "%#v"} {
					fmt.Fprintf(&output, format, err)
					log.New(&output, "", 0).Printf(format, err)
				}
				encoded, marshalErr := json.Marshal(err)
				if marshalErr != nil {
					t.Fatal(marshalErr)
				}
				output.Write(encoded)
				if strings.Contains(output.String(), marker) {
					t.Fatal("dependency error leaked secret")
				}
			})
		}
	}
	f := newFixture()
	f.request.BindingUID = "missing"
	_, missingErr := f.broker.Exchange(t.Context(), f.executor, f.request)
	f.request.BindingUID, f.executor.NodeUID = "binding", "foreign"
	_, foreignErr := f.broker.Exchange(t.Context(), f.executor, f.request)
	if missingErr != foreignErr || missingErr.Error() != foreignErr.Error() {
		t.Fatal("missing and foreign denials differ")
	}
}

func TestFinalDecisionClockAndCancellation(t *testing.T) {
	for _, phase := range []string{"exchange", "validate"} {
		for _, cancel := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/cancel=%t", phase, cancel), func(t *testing.T) {
				f := newFixture()
				ctx, stop := context.WithCancel(t.Context())
				defer stop()
				var l *access.Lease
				if phase == "validate" {
					l = f.exchange(t)
				}
				f.resolve = func() error {
					if f.resolves >= 2 {
						if cancel {
							stop()
						} else {
							f.now = f.now.Add(time.Hour)
						}
					}
					return nil
				}
				var err error
				if phase == "validate" {
					err = f.broker.Validate(ctx, f.executor, l, f.target())
				} else {
					l, err = f.broker.Exchange(ctx, f.executor, f.request)
					if l != nil {
						t.Fatal("late failure issued a lease")
					}
				}
				want := access.ErrDenied
				if cancel {
					want = access.ErrUnavailable
				}
				if !errors.Is(err, want) {
					t.Fatalf("late decision: %v, want %v", err, want)
				}
			})
		}
	}
}

func TestCheckLeaseIsLocalNotAuthorization(t *testing.T) {
	f := newFixture()
	lease := f.exchange(t)
	target := f.target()
	f.state.Grant.Revoked = true
	if err := f.broker.CheckLease(t.Context(), f.executor, lease, target); err != nil {
		t.Fatalf("local check read changed authority: %v", err)
	}
	if f.resolves != 2 || f.acquires != 1 {
		t.Fatal("local preflight accessed resolver or provider")
	}
	if err := f.broker.Validate(t.Context(), f.executor, lease, target); err != access.ErrDenied || f.resolves != 3 {
		t.Fatal("delivery validation failed to observe revocation")
	}
}

func TestCheckLeaseRejectsLocalMisuse(t *testing.T) {
	for _, field := range []string{"nil_broker", "nil_lease", "empty_lease", "issuer", "executor", "actor", "activation", "driver", "handle", "expired", "actual_expiry", "cancelled", "before_expiry"} {
		t.Run(field, func(t *testing.T) {
			f := newFixture()
			if field == "actual_expiry" {
				original := f.acquire
				f.acquire = func(a access.ApprovedAccess) (access.Credential, error) {
					credential, err := original(a)
					credential.ExpiresAt = f.now.Add(15 * time.Minute)
					return credential, err
				}
			}
			lease := f.exchange(t)
			broker, target, executor := f.broker, f.target(), f.executor
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			want := access.ErrDenied
			switch field {
			case "nil_broker":
				broker = nil
			case "nil_lease":
				lease = nil
			case "empty_lease":
				lease = &access.Lease{}
			case "issuer":
				broker = newFixture().broker
			case "executor":
				executor.NodeUID = "other"
			case "actor":
				target.ActorUID = "other"
			case "activation":
				target.ActivationUID = "other"
			case "driver":
				target.Driver = "other"
			case "handle":
				target.Handle = "other"
			case "expired":
				f.now = lease.Approved().Deadline
			case "actual_expiry":
				f.now = f.now.Add(15 * time.Minute)
			case "cancelled":
				cancel()
				want = access.ErrUnavailable
			case "before_expiry":
				f.now = lease.Approved().Deadline.Add(-time.Nanosecond)
				want = nil
			}
			if err := broker.CheckLease(ctx, executor, lease, target); err != want {
				t.Fatalf("CheckLease=%v, want %v", err, want)
			}
			if f.resolves != 2 || f.acquires != 1 {
				t.Fatal("local rejection accessed authority or provider")
			}
		})
	}
}

func TestValidateKeepsCurrentReadErrorPrecedence(t *testing.T) {
	f := newFixture()
	lease := f.exchange(t)
	f.now = lease.Approved().Deadline
	f.resolve = func() error { return errors.New("authority unavailable") }
	if err := f.broker.Validate(t.Context(), f.executor, lease, f.target()); err != access.ErrUnavailable || f.resolves != 3 {
		t.Fatalf("Validate=%v, resolves=%d", err, f.resolves)
	}
}

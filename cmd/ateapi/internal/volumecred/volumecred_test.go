// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package volumecred

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"github.com/google/go-cmp/cmp"
)

const driver = "ossplugin.csi.alibabacloud.com"

type fakeProvider struct {
	err  error
	cred Credential
	reqs []Request
}

func (f *fakeProvider) Issue(_ context.Context, req Request) (Credential, error) {
	f.reqs = append(f.reqs, req)
	return f.cred, f.err
}

var now = time.Date(2026, 10, 12, 10, 0, 0, 0, time.UTC)

func newTestBroker(t *testing.T, p *fakeProvider, mutate ...func(*Profile)) *Broker {
	t.Helper()
	profile := Profile{
		Driver:        driver,
		Provider:      p,
		BucketKey:     "bucket",
		PrefixKey:     "path",
		Duration:      time.Hour,
		RefreshBefore: 15 * time.Minute,
	}
	for _, m := range mutate {
		m(&profile)
	}
	b, err := NewBroker(profile)
	if err != nil {
		t.Fatalf("NewBroker: %v", err)
	}
	b.now = func() time.Time { return now }
	return b
}

func actorWith(vols ...*ateapipb.ExternalVolume) *ateapipb.Actor {
	return &ateapipb.Actor{
		Metadata: &ateapipb.ResourceMetadata{Atespace: "team-a", Name: "runner", Uid: "3c9a1f2e-4b5d-4e6f-8a7b-9c0d1e2f3a4b"},
		Status:   &ateapipb.ActorStatus{ExternalVolumes: vols},
	}
}

func ossVolume(ctx map[string]string) *ateapipb.ExternalVolume {
	return &ateapipb.ExternalVolume{Name: "data", StorageVolumeId: "vol-1", VolumeType: driver, VolumeContext: ctx}
}

func TestBrokerIssue(t *testing.T) {
	expire := now.Add(time.Hour)
	p := &fakeProvider{cred: Credential{Secrets: map[string]string{"akId": "id"}, Expiration: expire}}
	b := newTestBroker(t, p)

	issued, err := b.Issue(context.Background(), actorWith(ossVolume(map[string]string{"bucket": "team-a-data", "path": "/substrate-uid-data"})), "data")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	want := Issued{Secrets: map[string]string{"akId": "id"}, ExpireTime: expire, RefreshTime: expire.Add(-15 * time.Minute)}
	if diff := cmp.Diff(want, issued); diff != "" {
		t.Errorf("issued mismatch (-want +got):\n%s", diff)
	}
	wantReq := Request{
		Scope:       Scope{Bucket: "team-a-data", Prefix: "substrate-uid-data/"},
		Duration:    time.Hour,
		SessionName: "ate-3c9a1f2e-4b5d-4e6f-8a7b-9c0d1e2f3a4b",
	}
	if diff := cmp.Diff([]Request{wantReq}, p.reqs); diff != "" {
		t.Errorf("provider requests mismatch (-want +got):\n%s", diff)
	}
}

func TestBrokerIssueRefresh(t *testing.T) {
	t.Run("no refresh", func(t *testing.T) {
		p := &fakeProvider{cred: Credential{Secrets: map[string]string{"k": "v"}, Expiration: now.Add(time.Hour)}}
		b := newTestBroker(t, p, func(p *Profile) { p.RefreshBefore = 0 })
		issued, err := b.Issue(context.Background(), actorWith(ossVolume(map[string]string{"bucket": "b-1", "path": "p"})), "data")
		if err != nil || !issued.RefreshTime.IsZero() {
			t.Fatalf("Issue = %+v, %v; want no refresh time", issued, err)
		}
	})
	t.Run("short credential refreshes halfway", func(t *testing.T) {
		p := &fakeProvider{cred: Credential{Secrets: map[string]string{"k": "v"}, Expiration: now.Add(10 * time.Minute)}}
		b := newTestBroker(t, p)
		issued, err := b.Issue(context.Background(), actorWith(ossVolume(map[string]string{"bucket": "b-1", "path": "p"})), "data")
		if err != nil || !issued.RefreshTime.Equal(now.Add(5*time.Minute)) {
			t.Fatalf("Issue = %+v, %v; want refresh at %v", issued, err, now.Add(5*time.Minute))
		}
	})
}

func TestBrokerIssueErrors(t *testing.T) {
	good := map[string]string{"bucket": "b-1", "path": "p/q"}
	tests := []struct {
		name    string
		actor   *ateapipb.Actor
		volume  string
		cred    Credential
		provErr error
		wantErr error
	}{
		{name: "unknown volume", actor: actorWith(ossVolume(good)), volume: "other", wantErr: ErrInvalidScope},
		{name: "unprovisioned volume", actor: actorWith(&ateapipb.ExternalVolume{Name: "data", VolumeType: driver}), volume: "data", wantErr: ErrInvalidScope},
		{name: "driver without profile", actor: actorWith(&ateapipb.ExternalVolume{Name: "data", StorageVolumeId: "v", VolumeType: "other.csi"}), volume: "data", wantErr: ErrNoProfile},
		{name: "missing bucket", actor: actorWith(ossVolume(map[string]string{"path": "p"})), volume: "data", wantErr: ErrInvalidScope},
		{name: "missing prefix", actor: actorWith(ossVolume(map[string]string{"bucket": "b-1", "path": "/"})), volume: "data", wantErr: ErrInvalidScope},
		{name: "relative prefix", actor: actorWith(ossVolume(map[string]string{"bucket": "b-1", "path": "a/../b"})), volume: "data", wantErr: ErrInvalidScope},
		{name: "wildcard prefix", actor: actorWith(ossVolume(map[string]string{"bucket": "b-1", "path": "a*"})), volume: "data", wantErr: ErrInvalidScope},
		{name: "empty path segment", actor: actorWith(ossVolume(map[string]string{"bucket": "b-1", "path": "a//b"})), volume: "data", wantErr: ErrInvalidScope},
		{name: "provider failure", actor: actorWith(ossVolume(good)), volume: "data", provErr: errors.New("boom"), wantErr: ErrUnavailable},
		{name: "expired credential", actor: actorWith(ossVolume(good)), volume: "data", cred: Credential{Secrets: map[string]string{"k": "v"}, Expiration: now}, wantErr: ErrUnavailable},
		{name: "empty credential", actor: actorWith(ossVolume(good)), volume: "data", cred: Credential{Expiration: now.Add(time.Hour)}, wantErr: ErrUnavailable},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := &fakeProvider{cred: tc.cred, err: tc.provErr}
			b := newTestBroker(t, p)
			if _, err := b.Issue(context.Background(), tc.actor, tc.volume); !errors.Is(err, tc.wantErr) {
				t.Fatalf("Issue error = %v, want %v", err, tc.wantErr)
			}
			if errors.Is(tc.wantErr, ErrInvalidScope) || errors.Is(tc.wantErr, ErrNoProfile) {
				if len(p.reqs) != 0 {
					t.Errorf("provider called %d times for a rejected scope", len(p.reqs))
				}
			}
		})
	}
}

func TestBrokered(t *testing.T) {
	var nilBroker *Broker
	if nilBroker.Brokered(driver) {
		t.Error("nil Broker brokers a driver")
	}
	b := newTestBroker(t, &fakeProvider{})
	if !b.Brokered(driver) || b.Brokered("other.csi") {
		t.Error("Brokered does not match the configured profiles")
	}
	if _, err := nilBroker.Issue(context.Background(), actorWith(ossVolume(map[string]string{"bucket": "b-1", "path": "p"})), "data"); !errors.Is(err, ErrNoProfile) {
		t.Errorf("nil Broker Issue = %v, want ErrNoProfile", err)
	}
}

func TestNewBrokerValidation(t *testing.T) {
	base := Profile{Driver: driver, Provider: &fakeProvider{}, BucketKey: "bucket", PrefixKey: "path", Duration: time.Hour, RefreshBefore: time.Minute}
	for name, mutate := range map[string]func(*Profile){
		"no driver":        func(p *Profile) { p.Driver = "" },
		"no provider":      func(p *Profile) { p.Provider = nil },
		"no bucket key":    func(p *Profile) { p.BucketKey = "" },
		"no prefix key":    func(p *Profile) { p.PrefixKey = "" },
		"no duration":      func(p *Profile) { p.Duration = 0 },
		"refresh too late": func(p *Profile) { p.RefreshBefore = time.Hour },
		"negative refresh": func(p *Profile) { p.RefreshBefore = -time.Second },
	} {
		t.Run(name, func(t *testing.T) {
			p := base
			mutate(&p)
			if _, err := NewBroker(p); err == nil {
				t.Error("NewBroker accepted an invalid profile")
			}
		})
	}
	if _, err := NewBroker(base, base); err == nil {
		t.Error("NewBroker accepted two profiles for one driver")
	}
}

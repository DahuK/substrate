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

package csi

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agent-substrate/substrate/internal/volume/access"
	"github.com/container-storage-interface/spec/lib/go/csi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const syntheticSecret = "SYNTHETIC-CSI-SECRET-NOT-A-CLOUD-CREDENTIAL"

type accessFixture struct {
	mu           sync.Mutex
	now          time.Time
	states       map[string]access.Snapshot
	broker       *access.Broker
	plugin       *Plugin
	executor     access.Executor
	request      access.Request
	target       access.Target
	targetPath   string
	resolves     atomic.Int64
	acquires     atomic.Int64
	stages       atomic.Int64
	publishes    atomic.Int64
	unstages     atomic.Int64
	unpublishes  atomic.Int64
	controllers  atomic.Int64
	stage        chan *csi.NodeStageVolumeRequest
	publish      chan *csi.NodePublishVolumeRequest
	unstage      chan *csi.NodeUnstageVolumeRequest
	unpublish    chan *csi.NodeUnpublishVolumeRequest
	afterAcquire func(access.ApprovedAccess, *access.Credential)
	afterStage   func() error
	onPublish    func() error
	onUnpublish  func() error
	onUnstage    func() error
	onRPC        func(context.Context, string, string) error
	onResolve    func(context.Context, string) error
}

func newAccessFixture(t *testing.T) *accessFixture {
	t.Helper()
	f := &accessFixture{
		now:      time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC),
		states:   make(map[string]access.Snapshot),
		executor: access.Executor{Component: "atelet", ClusterUID: "cluster-1", NodeUID: "node-1"},
		request:  access.Request{BindingUID: "dataset", Revision: 1, ActivationUID: "run-1", Mode: access.ReadOnly, MaxCredentialLifetime: 30 * time.Minute},
		target:   access.Target{ActorUID: "A", ActivationUID: "run-1", Driver: "mock-driver", Handle: "dataset-handle"},
		stage:    make(chan *csi.NodeStageVolumeRequest, 16), publish: make(chan *csi.NodePublishVolumeRequest, 16),
		unstage: make(chan *csi.NodeUnstageVolumeRequest, 16), unpublish: make(chan *csi.NodeUnpublishVolumeRequest, 16),
	}
	for _, name := range []string{"dataset", "workspace"} {
		mode, ops := access.ReadOnly, access.Read|access.List
		if name == "workspace" {
			mode, ops = access.ReadWrite, access.Read|access.Write|access.List
		}
		f.states[name] = access.Snapshot{
			ActorUID: "A", Atespace: "team-a", PolicyRevision: 1,
			Binding: access.Binding{UID: name, Revision: 1, ActorUID: "A", VolumeUID: name, GrantUID: name + "-grant", ResourceGeneration: 1,
				ClusterUID: "cluster-1", NodeUID: "node-1", WorkerUID: "worker-1", ActivationUID: "run-1", Mode: mode, ExpiresAt: f.now.Add(time.Hour)},
			Grant:      access.Grant{UID: name + "-grant", Revision: 1, ActorUID: "A", VolumeUID: name, Atespace: "team-a", Operations: ops, ExpiresAt: f.now.Add(time.Hour)},
			Assignment: access.Assignment{ActorUID: "A", ClusterUID: "cluster-1", NodeUID: "node-1", WorkerUID: "worker-1", ActivationUID: "run-1"},
			Volume: access.Volume{UID: name, Generation: 1, Atespace: "team-a", OwnerActorUID: "A", Driver: "mock-driver", Handle: name + "-handle", Exclusive: true,
				Scope: access.Scope{Endpoint: "https://storage.example.invalid", Resource: name + "-bucket", Prefix: "actors/A/" + name + "/", ListPrefix: "actors/A/" + name + "/", Operations: ops}},
			Profile: access.Profile{Name: access.StagePublishSecrets, Version: 1, Driver: "mock-driver", CredentialKind: access.SessionCredential, Delivery: access.StagePublishSecrets,
				MinLifetime: 15 * time.Minute, MaxLifetime: time.Hour, ReadOperations: access.Read | access.List, WriteOperations: access.Read | access.Write | access.List},
		}
	}
	f.broker = access.NewBroker(f, f, func() time.Time {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.now
	})
	driver := &mockCSIDriver{
		nodeStageVolumeFunc: func(ctx context.Context, r *csi.NodeStageVolumeRequest) (*csi.NodeStageVolumeResponse, error) {
			f.stages.Add(1)
			f.stage <- r
			if f.onRPC != nil {
				if err := f.onRPC(ctx, "stage", r.VolumeId); err != nil {
					return nil, err
				}
			}
			if f.afterStage != nil {
				if err := f.afterStage(); err != nil {
					return nil, err
				}
			}
			return &csi.NodeStageVolumeResponse{}, nil
		},
		nodePublishVolumeFunc: func(ctx context.Context, r *csi.NodePublishVolumeRequest) (*csi.NodePublishVolumeResponse, error) {
			f.publishes.Add(1)
			f.publish <- r
			if f.onRPC != nil {
				if err := f.onRPC(ctx, "publish", r.VolumeId); err != nil {
					return nil, err
				}
			}
			if f.onPublish != nil {
				if err := f.onPublish(); err != nil {
					return nil, err
				}
			}
			return &csi.NodePublishVolumeResponse{}, nil
		},
		nodeUnpublishVolumeFunc: func(ctx context.Context, r *csi.NodeUnpublishVolumeRequest) (*csi.NodeUnpublishVolumeResponse, error) {
			f.unpublishes.Add(1)
			f.unpublish <- r
			if f.onRPC != nil {
				if err := f.onRPC(ctx, "unpublish", r.VolumeId); err != nil {
					return nil, err
				}
			}
			if f.onUnpublish != nil {
				if err := f.onUnpublish(); err != nil {
					return nil, err
				}
			}
			return &csi.NodeUnpublishVolumeResponse{}, nil
		},
		nodeUnstageVolumeFunc: func(ctx context.Context, r *csi.NodeUnstageVolumeRequest) (*csi.NodeUnstageVolumeResponse, error) {
			f.unstages.Add(1)
			f.unstage <- r
			if f.onRPC != nil {
				if err := f.onRPC(ctx, "unstage", r.VolumeId); err != nil {
					return nil, err
				}
			}
			if f.onUnstage != nil {
				if err := f.onUnstage(); err != nil {
					return nil, err
				}
			}
			return &csi.NodeUnstageVolumeResponse{}, nil
		},
		createVolumeFunc: func(context.Context, *csi.CreateVolumeRequest) (*csi.CreateVolumeResponse, error) {
			f.controllers.Add(1)
			return &csi.CreateVolumeResponse{}, nil
		},
		controllerPublishVolumeFunc: func(context.Context, *csi.ControllerPublishVolumeRequest) (*csi.ControllerPublishVolumeResponse, error) {
			f.controllers.Add(1)
			return &csi.ControllerPublishVolumeResponse{}, nil
		},
	}
	endpoint, cleanup := startMockCSIDriver(t, driver)
	t.Cleanup(cleanup)
	client, err := NewCSIClient(endpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	f.plugin = NewPlugin(client)
	root := t.TempDir()
	f.plugin.stagingDirPrefix = filepath.Join(root, "staging")
	f.targetPath = filepath.Join(root, "actors", "A", "run-1", "dataset")
	return f
}

func (f *accessFixture) Resolve(ctx context.Context, uid string) (access.Snapshot, error) {
	f.resolves.Add(1)
	if f.onResolve != nil {
		if err := f.onResolve(ctx, uid); err != nil {
			return access.Snapshot{}, err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.states[uid]
	if !ok {
		return access.Snapshot{}, access.ErrDenied
	}
	return s, nil
}

func (f *accessFixture) Acquire(_ context.Context, a access.ApprovedAccess) (access.Credential, error) {
	f.acquires.Add(1)
	c := access.Credential{Scope: a.Scope, Kind: access.SessionCredential, ProfileName: access.StagePublishSecrets, ProfileVersion: 1,
		ExpiresAt: a.Deadline, Secrets: map[string]string{"accessKey": "synthetic-" + a.BindingUID, "secretKey": syntheticSecret, "sessionToken": "synthetic-session"}}
	if f.afterAcquire != nil {
		f.afterAcquire(a, &c)
	}
	return c, nil
}

func (f *accessFixture) update(uid string, change func(*access.Snapshot)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.states[uid]
	change(&s)
	f.states[uid] = s
}

func (f *accessFixture) exchange(t *testing.T) *access.Lease {
	t.Helper()
	lease, err := f.broker.Exchange(t.Context(), f.executor, f.request)
	if err != nil {
		t.Fatal(err)
	}
	return lease
}

func (f *accessFixture) counts(t *testing.T, acquire, stage, publish int64) {
	t.Helper()
	if f.acquires.Load() != acquire || f.stages.Load() != stage || f.publishes.Load() != publish || f.controllers.Load() != 0 {
		t.Fatalf("acquire/stage/publish/controller = %d/%d/%d/%d, want %d/%d/%d/0", f.acquires.Load(), f.stages.Load(), f.publishes.Load(), f.controllers.Load(), acquire, stage, publish)
	}
}

func (f *accessFixture) mount(ctx context.Context) (*AuthorizedMount, error) {
	lease, err := f.broker.Exchange(ctx, f.executor, f.request)
	if err != nil {
		return nil, err
	}
	return f.plugin.MountAuthorizedVolume(ctx, f.broker, f.executor, lease, f.target, f.targetPath)
}

func TestVolumeAccessDemo(t *testing.T) {
	t.Run("allow_read_only_dataset", func(t *testing.T) {
		f := newAccessFixture(t)
		lease := f.exchange(t)
		mount, err := f.plugin.MountAuthorizedVolume(t.Context(), f.broker, f.executor, lease, f.target, f.targetPath)
		if err != nil || mount == nil {
			t.Fatalf("mount=%v err=%v", mount, err)
		}
		f.counts(t, 1, 1, 1)
		stage, publish := <-f.stage, <-f.publish
		for _, capability := range []*csi.VolumeCapability{stage.VolumeCapability, publish.VolumeCapability} {
			if capability.GetAccessMode().GetMode() != csi.VolumeCapability_AccessMode_SINGLE_NODE_READER_ONLY {
				t.Fatal("read-only capability not applied")
			}
		}
		if stage.VolumeId != "dataset-handle" || publish.VolumeId != "dataset-handle" || !publish.Readonly || publish.TargetPath != f.targetPath || stage.StagingTargetPath != publish.StagingTargetPath {
			t.Fatal("approved handle, target or read-only flag not preserved")
		}
		if !maps.Equal(stage.Secrets, lease.Secrets()) || !maps.Equal(publish.Secrets, lease.Secrets()) {
			t.Fatal("credential not delivered through both Secrets fields")
		}
		if err := f.plugin.UnmountAuthorizedVolume(t.Context(), mount); err != nil {
			t.Fatal(err)
		}
		if f.unpublishes.Load() != 1 || f.unstages.Load() != 1 {
			t.Fatal("owner cleanup did not unpublish and unstage")
		}
		t.Log("ALLOW dataset: provider=1 stage=1 publish=1 readonly=true; owner cleanup complete (fake driver, no real mount)")
	})
	t.Run("workspace_does_not_broaden_dataset", func(t *testing.T) {
		f := newAccessFixture(t)
		f.request.BindingUID, f.request.Mode = "workspace", access.ReadWrite
		lease := f.exchange(t)
		a := lease.Approved()
		if a.Scope.Resource != "workspace-bucket" || a.Scope.Prefix != "actors/A/workspace/" || a.Scope.ListPrefix != a.Scope.Prefix || a.Scope.Operations != access.Read|access.Write|access.List {
			t.Fatal("workspace scope was not independently approved")
		}
		if mount, err := f.plugin.MountAuthorizedVolume(t.Context(), f.broker, f.executor, lease, f.target, f.targetPath); mount != nil || !errors.Is(err, access.ErrDenied) {
			t.Fatalf("workspace material used for dataset: mount=%v err=%v", mount, err)
		}
		f.counts(t, 1, 0, 0)
		t.Log("ISOLATED workspace: read/write scope issued separately; substituting it into dataset mount is denied")
	})
	t.Run("foreign_actor_binding_denied", func(t *testing.T) {
		f := newAccessFixture(t)
		// A coherent binding for B is not authorized by A's activation reference.
		f.update("dataset", func(s *access.Snapshot) {
			s.ActorUID, s.Binding.ActorUID, s.Grant.ActorUID, s.Assignment.ActorUID, s.Volume.OwnerActorUID = "B", "B", "B", "B", "B"
			s.Binding.ActivationUID, s.Assignment.ActivationUID = "run-B", "run-B"
		})
		if mount, err := f.mount(t.Context()); mount != nil || !errors.Is(err, access.ErrDenied) {
			t.Fatalf("foreign mount=%v err=%v", mount, err)
		}
		f.counts(t, 0, 0, 0)
		t.Log("DENY foreign actor: provider=0 stage=0 publish=0")
	})
	t.Run("revoked_during_acquisition", func(t *testing.T) {
		f := newAccessFixture(t)
		f.afterAcquire = func(access.ApprovedAccess, *access.Credential) {
			f.update("dataset", func(s *access.Snapshot) { s.Grant.Revoked = true })
		}
		if mount, err := f.mount(t.Context()); mount != nil || !errors.Is(err, access.ErrDenied) {
			t.Fatalf("revoked mount=%v err=%v", mount, err)
		}
		f.counts(t, 1, 0, 0)
		t.Log("REVOKED during acquisition: provider=1 stage=0 publish=0; material withheld")
	})
	t.Run("revoked_between_stage_and_publish", func(t *testing.T) {
		f := newAccessFixture(t)
		f.afterStage = func() error {
			f.update("dataset", func(s *access.Snapshot) { s.Grant.Revoked = true })
			return nil
		}
		mount, err := f.mount(t.Context())
		if mount == nil || !errors.Is(err, access.ErrDenied) {
			t.Fatalf("revoked mount=%v err=%v", mount, err)
		}
		f.counts(t, 1, 1, 0)
		if next, err := f.mount(t.Context()); next != nil || !errors.Is(err, access.ErrDenied) {
			t.Fatalf("replay mount=%v err=%v", next, err)
		}
		f.counts(t, 1, 1, 0)
		if err := f.plugin.UnmountAuthorizedVolume(t.Context(), mount); err != nil {
			t.Fatal(err)
		}
		t.Log("REVOKED after Stage: provider=1 stage=1 publish=0; fresh exchange denied; cleanup allowed without new credentials")
		t.Log("Stage already received secrets: this is a delivery gate, not recall of a cloud credential")
	})
}

func TestAuthorizedMountInitialDenials(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(*accessFixture)
		want  error
	}{
		{"wrong_node", func(f *accessFixture) { f.executor.NodeUID = "node-2" }, access.ErrDenied},
		{"untrusted_component", func(f *accessFixture) { f.executor.Component = "actor" }, access.ErrDenied},
		{"stale_activation", func(f *accessFixture) { f.request.ActivationUID = "old-run" }, access.ErrDenied},
		{"expired_delegation", func(f *accessFixture) { f.update("dataset", func(s *access.Snapshot) { s.Binding.ExpiresAt = f.now }) }, access.ErrDenied},
		{"dataset_write", func(f *accessFixture) { f.request.Mode = access.ReadWrite }, access.ErrDenied},
		{"missing_list_permission", func(f *accessFixture) {
			f.update("dataset", func(s *access.Snapshot) { s.Grant.Operations = access.Read })
		}, access.ErrDenied},
		{"unknown_profile", func(f *accessFixture) { f.update("dataset", func(s *access.Snapshot) { s.Profile.Name = "unknown" }) }, access.ErrUnsupported},
		{"writable_read_profile", func(f *accessFixture) {
			f.update("dataset", func(s *access.Snapshot) { s.Profile.ReadOperations |= access.Write })
		}, access.ErrUnsupported},
		{"shared_volume", func(f *accessFixture) { f.update("dataset", func(s *access.Snapshot) { s.Volume.Exclusive = false }) }, access.ErrUnsupported},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAccessFixture(t)
			tc.setup(f)
			if mount, err := f.mount(t.Context()); mount != nil || !errors.Is(err, tc.want) {
				t.Fatalf("mount=%v err=%v, want %v", mount, err, tc.want)
			}
			f.counts(t, 0, 0, 0)
		})
	}
}

func TestAuthorizedMountRejectsProviderMaterial(t *testing.T) {
	for _, field := range []string{"accessKey", "secretKey", "sessionToken", "scope", "kind", "profile", "expiry"} {
		t.Run(field, func(t *testing.T) {
			f := newAccessFixture(t)
			f.afterAcquire = func(a access.ApprovedAccess, c *access.Credential) {
				switch field {
				case "scope":
					c.Scope.Prefix = "actors/"
				case "kind":
					c.Kind = "ambient"
				case "profile":
					c.ProfileVersion++
				case "expiry":
					c.ExpiresAt = a.Deadline.Add(time.Second)
				default:
					delete(c.Secrets, field)
				}
			}
			if mount, err := f.mount(t.Context()); mount != nil || !errors.Is(err, access.ErrDenied) {
				t.Fatalf("invalid material: mount=%v err=%v", mount, err)
			}
			f.counts(t, 1, 0, 0)
		})
	}
}

func TestAuthorizedMountTargetAndDeliveryGates(t *testing.T) {
	for _, field := range []string{"actor", "activation", "driver", "handle", "revoked", "expired", "relative_path", "unclean_path", "staging_target", "root_target", "actual_driver", "executor", "issuer", "nil_lease", "canceled"} {
		t.Run(field, func(t *testing.T) {
			f := newAccessFixture(t)
			if field == "actual_driver" {
				f.update("dataset", func(s *access.Snapshot) { s.Profile.Driver, s.Volume.Driver = "other-driver", "other-driver" })
				f.target.Driver = "other-driver"
			}
			lease := f.exchange(t)
			ctx := t.Context()
			want := access.ErrDenied
			switch field {
			case "actor":
				f.target.ActorUID = "B"
			case "activation":
				f.target.ActivationUID = "run-2"
			case "driver":
				f.target.Driver = "other-driver"
			case "handle":
				f.target.Handle = "workspace-handle"
			case "revoked":
				f.update("dataset", func(s *access.Snapshot) { s.Grant.Revoked = true })
			case "expired":
				f.now = f.now.Add(30 * time.Minute)
			case "relative_path":
				f.targetPath, want = "relative", access.ErrInvalidRequest
			case "unclean_path":
				f.targetPath, want = f.targetPath+"/../other", access.ErrInvalidRequest
			case "staging_target":
				f.targetPath, want = f.plugin.stagingDirPrefix, access.ErrInvalidRequest
			case "root_target":
				f.targetPath, want = string(filepath.Separator), access.ErrInvalidRequest
			case "executor":
				f.executor.NodeUID = "other-node"
			case "issuer":
				f.broker = access.NewBroker(f, f, func() time.Time { return f.now })
			case "nil_lease":
				lease = nil
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				want = access.ErrUnavailable
			}
			mount, err := f.plugin.MountAuthorizedVolume(ctx, f.broker, f.executor, lease, f.target, f.targetPath)
			if !errors.Is(err, want) {
				t.Fatalf("invalid target: mount=%v err=%v, want %v", mount, err, want)
			}
			f.counts(t, 1, 0, 0)
			if field == "revoked" {
				if mount == nil || f.resolves.Load() != 3 {
					t.Fatal("pre-Stage revocation must return the reserved owner after full validation")
				}
				f.plugin.protectedMu.Lock()
				record, retained := f.plugin.protectedMounts[mount]
				f.plugin.protectedMu.Unlock()
				if !retained || record.busy {
					t.Fatal("revocation lost the reservation or left its owner busy")
				}
				if _, err := os.Stat(record.stagingPath); err != nil {
					t.Fatalf("expected pre-Stage directory: %v", err)
				}
				if next, err := f.plugin.MountAuthorizedVolume(ctx, f.broker, f.executor, lease, f.target, f.targetPath); next != nil || !errors.Is(err, access.ErrUnsupported) {
					t.Fatalf("revoked attempt lost its reservation: owner=%v err=%v", next, err)
				}
				if err := f.plugin.UnmountAuthorizedVolume(ctx, mount); err != nil {
					t.Fatal(err)
				}
				if f.unpublishes.Load() != 1 || f.unstages.Load() != 1 || len(f.plugin.protectedMounts) != 0 || len(f.plugin.protectedPaths) != 0 || len(f.plugin.protectedHandles) != 0 {
					t.Fatal("revoked owner's complete cleanup did not release its reservation")
				}
				if _, err := os.Stat(record.stagingPath); !os.IsNotExist(err) {
					t.Fatalf("revoked staging directory survived cleanup: %v", err)
				}
			} else if mount != nil || len(f.plugin.protectedMounts) != 0 || f.resolves.Load() != 2 {
				t.Fatal("local denial must not resolve again, reserve or return an owner")
			}
		})
	}
}

func TestAuthorizedMountResolveSequence(t *testing.T) {
	f := newAccessFixture(t)
	events := make(chan string, 16)
	f.onResolve = func(context.Context, string) error { events <- "resolve"; return nil }
	f.afterAcquire = func(access.ApprovedAccess, *access.Credential) { events <- "acquire" }
	f.onRPC = func(_ context.Context, operation, _ string) error { events <- operation; return nil }
	owner, err := f.mount(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for len(events) > 0 {
		got = append(got, <-events)
	}
	want := []string{"resolve", "acquire", "resolve", "resolve", "stage", "resolve", "publish"}
	if !slices.Equal(got, want) || f.resolves.Load() != 4 {
		t.Fatalf("delivery sequence=%v resolves=%d, want %v and 4", got, f.resolves.Load(), want)
	}
	if err := f.plugin.UnmountAuthorizedVolume(t.Context(), owner); err != nil {
		t.Fatal(err)
	}
	if f.resolves.Load() != 4 {
		t.Fatal("cleanup must not reacquire authority")
	}
}

func TestAuthorizedMountAfterStage(t *testing.T) {
	for _, tc := range []struct {
		name string
		code codes.Code
		want error
	}{
		{"material_expired", codes.OK, access.ErrDenied},
		{"assignment_changed", codes.OK, access.ErrDenied},
		{"unsupported_stage", codes.Unimplemented, access.ErrUnsupported},
		{"uncertain_stage", codes.DeadlineExceeded, access.ErrUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAccessFixture(t)
			f.afterStage = func() error {
				switch tc.name {
				case "material_expired":
					f.mu.Lock()
					f.now = f.now.Add(30 * time.Minute)
					f.mu.Unlock()
				case "assignment_changed":
					f.update("dataset", func(s *access.Snapshot) { s.Assignment.ActivationUID = "run-2" })
				default:
					return status.Error(tc.code, syntheticSecret)
				}
				return nil
			}
			mount, err := f.mount(t.Context())
			if mount == nil || !errors.Is(err, tc.want) || strings.Contains(err.Error(), syntheticSecret) {
				t.Fatalf("after Stage: mount=%v safe error=%v", mount, err)
			}
			f.counts(t, 1, 1, 0)
			if err := f.plugin.UnmountAuthorizedVolume(t.Context(), mount); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAuthorizedMountReservations(t *testing.T) {
	f := newAccessFixture(t)
	lease := f.exchange(t)
	mount, err := f.plugin.MountAuthorizedVolume(t.Context(), f.broker, f.executor, lease, f.target, f.targetPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{f.targetPath, f.targetPath + "-other", filepath.Join(f.targetPath, "nested")} {
		if next, err := f.plugin.MountAuthorizedVolume(t.Context(), f.broker, f.executor, lease, f.target, path); next != nil || !errors.Is(err, access.ErrUnsupported) {
			t.Fatalf("handle reservation bypassed: mount=%v err=%v", next, err)
		}
	}
	f.request.BindingUID, f.request.Mode = "workspace", access.ReadWrite
	workspace := f.exchange(t)
	workspaceTarget := f.target
	workspaceTarget.Handle = "workspace-handle"
	for _, path := range []string{f.targetPath, filepath.Join(f.targetPath, "nested"), filepath.Dir(f.targetPath)} {
		if next, err := f.plugin.MountAuthorizedVolume(t.Context(), f.broker, f.executor, workspace, workspaceTarget, path); next != nil || !errors.Is(err, access.ErrUnsupported) {
			t.Fatalf("target reservation bypassed: mount=%v err=%v", next, err)
		}
	}
	copied := *mount
	for _, owner := range []*AuthorizedMount{nil, {}, &copied} {
		if err := f.plugin.UnmountAuthorizedVolume(t.Context(), owner); !errors.Is(err, access.ErrDenied) {
			t.Fatalf("non-owner cleanup: %v", err)
		}
	}
	otherPlugin := NewPlugin(f.plugin.client)
	if err := otherPlugin.UnmountAuthorizedVolume(t.Context(), mount); !errors.Is(err, access.ErrDenied) {
		t.Fatalf("wrong plugin cleanup: %v", err)
	}
	f.counts(t, 2, 1, 1)
	if err := f.plugin.UnmountAuthorizedVolume(t.Context(), mount); err != nil {
		t.Fatal(err)
	}
	next, err := f.plugin.MountAuthorizedVolume(t.Context(), f.broker, f.executor, lease, f.target, f.targetPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.plugin.UnmountAuthorizedVolume(t.Context(), mount); !errors.Is(err, access.ErrDenied) {
		t.Fatalf("stale cleanup: %v", err)
	}
	if f.unpublishes.Load() != 1 || f.unstages.Load() != 1 {
		t.Fatal("non-owner reached cleanup RPCs")
	}
	if err := f.plugin.UnmountAuthorizedVolume(t.Context(), next); err != nil {
		t.Fatal(err)
	}
}

func TestAuthorizedMountOwnerMutation(t *testing.T) {
	for _, mutation := range []string{"overwrite_with_other_mount", "zero_owner"} {
		t.Run(mutation, func(t *testing.T) {
			f := newAccessFixture(t)
			datasetLease := f.exchange(t)
			dataset, err := f.plugin.MountAuthorizedVolume(t.Context(), f.broker, f.executor, datasetLease, f.target, f.targetPath)
			if err != nil {
				t.Fatal(err)
			}
			datasetStage := <-f.stage
			f.request.BindingUID, f.request.Mode = "workspace", access.ReadWrite
			workspaceLease := f.exchange(t)
			workspaceTarget := f.target
			workspaceTarget.Handle = "workspace-handle"
			workspacePath := f.targetPath + "-workspace"
			workspace, err := f.plugin.MountAuthorizedVolume(t.Context(), f.broker, f.executor, workspaceLease, workspaceTarget, workspacePath)
			if err != nil {
				t.Fatal(err)
			}
			if mutation == "zero_owner" {
				*dataset = AuthorizedMount{}
			} else {
				*dataset = *workspace
			}
			if next, err := f.plugin.MountAuthorizedVolume(t.Context(), f.broker, f.executor, datasetLease, f.target, f.targetPath); next != nil || !errors.Is(err, access.ErrUnsupported) {
				t.Fatalf("overwriting owner released its reservation: mount=%v err=%v", next, err)
			}
			f.counts(t, 2, 2, 2)
			if err := f.plugin.UnmountAuthorizedVolume(t.Context(), dataset); err != nil {
				t.Fatal(err)
			}
			unpublish, unstage := <-f.unpublish, <-f.unstage
			if unpublish.VolumeId != "dataset-handle" || unpublish.TargetPath != f.targetPath || unstage.VolumeId != "dataset-handle" || unstage.StagingTargetPath != datasetStage.StagingTargetPath {
				t.Fatal("owner mutation redirected cleanup away from the original dataset")
			}
			if next, err := f.plugin.MountAuthorizedVolume(t.Context(), f.broker, f.executor, workspaceLease, workspaceTarget, workspacePath); next != nil || !errors.Is(err, access.ErrUnsupported) {
				t.Fatalf("dataset cleanup released workspace: mount=%v err=%v", next, err)
			}
			if err := f.plugin.UnmountAuthorizedVolume(t.Context(), workspace); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAuthorizedMountCleanupFailure(t *testing.T) {
	for _, phase := range []string{"stage", "publish", "unpublish", "unstage", "unsupported_unstage", "local_cleanup"} {
		t.Run(phase, func(t *testing.T) {
			f := newAccessFixture(t)
			failure := func() error { return status.Error(codes.DeadlineExceeded, syntheticSecret) }
			if phase == "stage" {
				f.afterStage = failure
			}
			if phase == "publish" {
				f.onPublish = failure
			}
			lease := f.exchange(t)
			mount, err := f.plugin.MountAuthorizedVolume(t.Context(), f.broker, f.executor, lease, f.target, f.targetPath)
			if mount == nil || ((phase == "stage" || phase == "publish") != (err != nil)) {
				t.Fatalf("mount=%v err=%v", mount, err)
			}
			if phase == "unpublish" {
				f.onUnpublish = failure
			}
			if phase == "unstage" {
				f.onUnstage = failure
			}
			if phase == "unsupported_unstage" {
				f.onUnstage = func() error { return status.Error(codes.Unimplemented, syntheticSecret) }
			}
			var leftover string
			if phase == "local_cleanup" {
				leftover = filepath.Join((<-f.stage).StagingTargetPath, "busy")
				if err := os.WriteFile(leftover, []byte("fixture"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if phase != "stage" && phase != "publish" {
				if err := f.plugin.UnmountAuthorizedVolume(t.Context(), mount); err == nil || strings.Contains(err.Error(), syntheticSecret) {
					t.Fatal("cleanup failure not safely returned")
				}
			}
			beforeStage, beforePublish := f.stages.Load(), f.publishes.Load()
			if next, err := f.plugin.MountAuthorizedVolume(t.Context(), f.broker, f.executor, lease, f.target, f.targetPath); next != nil || !errors.Is(err, access.ErrUnsupported) {
				t.Fatalf("failed attempt lost reservation: %v", err)
			}
			if f.stages.Load() != beforeStage || f.publishes.Load() != beforePublish {
				t.Fatal("reserved retry reached CSI")
			}
			f.afterStage, f.onPublish, f.onUnpublish, f.onUnstage = nil, nil, nil, nil
			if leftover != "" {
				if err := os.Remove(leftover); err != nil {
					t.Fatal(err)
				}
			}
			if err := f.plugin.UnmountAuthorizedVolume(t.Context(), mount); err != nil {
				t.Fatal(err)
			}
			next, err := f.plugin.MountAuthorizedVolume(t.Context(), f.broker, f.executor, lease, f.target, f.targetPath)
			if err != nil {
				t.Fatal(err)
			}
			if err := f.plugin.UnmountAuthorizedVolume(t.Context(), next); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAuthorizedMountConcurrentAttempts(t *testing.T) {
	f := newAccessFixture(t)
	lease := f.exchange(t)
	var wg sync.WaitGroup
	results := make(chan *AuthorizedMount, 8)
	for range 8 {
		wg.Go(func() {
			mount, err := f.plugin.MountAuthorizedVolume(t.Context(), f.broker, f.executor, lease, f.target, f.targetPath)
			if err != nil && !errors.Is(err, access.ErrUnsupported) {
				t.Errorf("unexpected concurrent result: %v", err)
			}
			results <- mount
		})
	}
	wg.Wait()
	close(results)
	var owner *AuthorizedMount
	for mount := range results {
		if mount != nil {
			if owner != nil {
				t.Fatal("multiple attempts own the same volume")
			}
			owner = mount
		}
	}
	f.counts(t, 1, 1, 1)
	if err := f.plugin.UnmountAuthorizedVolume(t.Context(), owner); err != nil {
		t.Fatal(err)
	}
}

// Barriers prove progress without relying on simulated RPC latency or a cloud SLO.
func TestAuthorizedMountIndependentProgress(t *testing.T) {
	for _, phase := range []string{"resolve", "stage", "publish", "unpublish", "unstage"} {
		t.Run(phase, func(t *testing.T) {
			f := newAccessFixture(t)
			f.update("workspace", func(s *access.Snapshot) { s.Volume.Scope.Endpoint = "https://workspace.example.invalid" })
			f.afterAcquire = func(a access.ApprovedAccess, c *access.Credential) {
				c.Secrets["secretKey"] = syntheticSecret + "-" + a.BindingUID
				c.Secrets["sessionToken"] = "synthetic-session-" + a.BindingUID
			}
			entered, release := make(chan struct{}), make(chan struct{})
			releaseRPC := sync.OnceFunc(func() { close(release) })
			defer releaseRPC()
			f.onRPC = func(ctx context.Context, operation, handle string) error {
				if operation == phase && handle == f.target.Handle {
					close(entered)
					select {
					case <-release:
					case <-ctx.Done():
						return ctx.Err()
					}
				}
				return nil
			}
			lease := f.exchange(t)
			requestB, targetB := f.request, f.target
			requestB.BindingUID, requestB.Mode, targetB.Handle = "workspace", access.ReadWrite, "workspace-handle"
			leaseB, err := f.broker.Exchange(t.Context(), f.executor, requestB)
			if err != nil {
				t.Fatal(err)
			}
			var resolveBlocked atomic.Bool
			f.onResolve = func(ctx context.Context, uid string) error {
				if phase == "resolve" && uid == "dataset" && !resolveBlocked.Swap(true) {
					close(entered)
					select {
					case <-release:
					case <-ctx.Done():
						return ctx.Err()
					}
				}
				return nil
			}
			pathB := f.targetPath + "-workspace"
			var owner *AuthorizedMount
			cleanup := phase == "unpublish" || phase == "unstage"
			if cleanup {
				owner, err = f.plugin.MountAuthorizedVolume(t.Context(), f.broker, f.executor, lease, f.target, f.targetPath)
				if err != nil {
					t.Fatal(err)
				}
			}
			type result struct {
				owner *AuthorizedMount
				err   error
			}
			doneA := make(chan result, 1)
			go func() {
				if cleanup {
					doneA <- result{owner, f.plugin.UnmountAuthorizedVolume(t.Context(), owner)}
				} else {
					mount, err := f.plugin.MountAuthorizedVolume(t.Context(), f.broker, f.executor, lease, f.target, f.targetPath)
					doneA <- result{mount, err}
				}
			}()
			awaitAuthorized(t, entered)
			doneB := make(chan result, 1)
			go func() {
				mount, err := f.plugin.MountAuthorizedVolume(t.Context(), f.broker, f.executor, leaseB, targetB, pathB)
				doneB <- result{mount, err}
			}()
			b := awaitAuthorized(t, doneB)
			if b.err != nil || b.owner == nil {
				t.Fatalf("independent mount while A %s blocked: owner=%v err=%v", phase, b.owner, b.err)
			}
			select {
			case <-doneA:
				t.Fatal("A completed before its barrier was released")
			default:
			}
			// Inspect the original pointer to exercise the mount-in-flight guard too.
			f.plugin.protectedMu.Lock()
			var busyOwner *AuthorizedMount
			for candidate, record := range f.plugin.protectedMounts {
				if record.handle == f.target.Handle && record.busy {
					busyOwner = candidate
				}
			}
			f.plugin.protectedMu.Unlock()
			if busyOwner == nil {
				t.Fatal("in-flight operation has no busy owner")
			}
			busy := make(chan error, 1)
			go func() { busy <- f.plugin.UnmountAuthorizedVolume(t.Context(), busyOwner) }()
			if err := awaitAuthorized(t, busy); !errors.Is(err, access.ErrUnavailable) {
				t.Fatalf("same-owner cleanup reentered: %v", err)
			}
			var wantUnpublishes, wantUnstages int64
			if cleanup {
				wantUnpublishes = 1
			}
			if phase == "unstage" {
				wantUnstages = 1
			}
			if f.unpublishes.Load() != wantUnpublishes || f.unstages.Load() != wantUnstages {
				t.Fatal("busy cleanup reached CSI")
			}
			// Release B so its handle cannot mask A's path reservation.
			finishedB := make(chan error, 1)
			go func() { finishedB <- f.plugin.UnmountAuthorizedVolume(t.Context(), b.owner) }()
			if err := awaitAuthorized(t, finishedB); err != nil {
				t.Fatal(err)
			}
			// Each conflicting request must return before A's RPC is released.
			for _, conflict := range []struct {
				lease  *access.Lease
				target access.Target
				path   string
			}{
				{lease, f.target, f.targetPath + "-other"},
				{leaseB, targetB, f.targetPath},
				{leaseB, targetB, filepath.Dir(f.targetPath)},
				{leaseB, targetB, filepath.Join(f.targetPath, "child")},
			} {
				conflicted := make(chan result, 1)
				go func() {
					mount, err := f.plugin.MountAuthorizedVolume(t.Context(), f.broker, f.executor, conflict.lease, conflict.target, conflict.path)
					conflicted <- result{mount, err}
				}()
				if r := awaitAuthorized(t, conflicted); r.owner != nil || !errors.Is(r.err, access.ErrUnsupported) {
					t.Fatalf("conflict was not rejected while %s blocked: owner=%v err=%v", phase, r.owner, r.err)
				}
			}
			releaseRPC()
			a := awaitAuthorized(t, doneA)
			if a.err != nil || a.owner == nil {
				t.Fatalf("A owner=%v err=%v", a.owner, a.err)
			}
			stages := map[string]*csi.NodeStageVolumeRequest{}
			publishes := map[string]*csi.NodePublishVolumeRequest{}
			for range 2 {
				s, p := awaitAuthorized(t, f.stage), awaitAuthorized(t, f.publish)
				stages[s.VolumeId], publishes[p.VolumeId] = s, p
			}
			for _, expected := range []struct {
				lease *access.Lease
				path  string
			}{{lease, f.targetPath}, {leaseB, pathB}} {
				approved := expected.lease.Approved()
				s, p := stages[approved.Handle], publishes[approved.Handle]
				wantContext := map[string]string{"endpoint": approved.Scope.Endpoint, "resource": approved.Scope.Resource, "prefix": approved.Scope.Prefix}
				if s == nil || p == nil || !maps.Equal(s.VolumeContext, wantContext) || !maps.Equal(p.VolumeContext, wantContext) ||
					!maps.Equal(s.Secrets, expected.lease.Secrets()) || !maps.Equal(p.Secrets, expected.lease.Secrets()) ||
					p.TargetPath != expected.path || s.StagingTargetPath != p.StagingTargetPath || p.Readonly != (approved.Mode == access.ReadOnly) {
					t.Fatal("concurrent mounts mixed scope, secrets, paths or read-only flags")
				}
				mode := csi.VolumeCapability_AccessMode_SINGLE_NODE_WRITER
				if approved.Mode == access.ReadOnly {
					mode = csi.VolumeCapability_AccessMode_SINGLE_NODE_READER_ONLY
				}
				if s.VolumeCapability.GetAccessMode().GetMode() != mode || p.VolumeCapability.GetAccessMode().GetMode() != mode {
					t.Fatal("concurrent mounts mixed capabilities")
				}
			}
			if stages[f.target.Handle].StagingTargetPath == stages[targetB.Handle].StagingTargetPath {
				t.Fatal("independent handles shared a staging path")
			}
			f.counts(t, 2, 2, 2)
			if f.resolves.Load() != 8 {
				t.Fatalf("two successful mounts resolved %d times, want 8", f.resolves.Load())
			}
			if !cleanup {
				if err := f.plugin.UnmountAuthorizedVolume(t.Context(), a.owner); err != nil {
					t.Fatal(err)
				}
			}
			t.Logf("B mount and cleanup completed while A %s remained blocked; conflicts failed fast", phase)
		})
	}
}

func awaitAuthorized[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(3 * time.Second):
		t.Fatal("operation did not complete while the independent RPC remained blocked")
		var zero T
		return zero
	}
}

func TestAuthorizedMountCanceledRPCReservation(t *testing.T) {
	for _, phase := range []string{"stage", "publish", "unpublish", "unstage"} {
		t.Run(phase, func(t *testing.T) {
			f := newAccessFixture(t)
			entered, canceled, release, exited := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
			releaseRPC := sync.OnceFunc(func() { close(release) })
			defer releaseRPC()
			var blocked atomic.Bool
			f.onRPC = func(ctx context.Context, operation, handle string) error {
				if operation == phase && handle == f.target.Handle && !blocked.Swap(true) {
					close(entered)
					<-ctx.Done()
					close(canceled)
					// A canceled client RPC does not prove the driver's work stopped.
					<-release
					close(exited)
				}
				return nil
			}
			lease := f.exchange(t)
			requestB, targetB := f.request, f.target
			requestB.BindingUID, requestB.Mode, targetB.Handle = "workspace", access.ReadWrite, "workspace-handle"
			leaseB, err := f.broker.Exchange(t.Context(), f.executor, requestB)
			if err != nil {
				t.Fatal(err)
			}
			cleanup := phase == "unpublish" || phase == "unstage"
			var owner *AuthorizedMount
			if cleanup {
				owner, err = f.plugin.MountAuthorizedVolume(t.Context(), f.broker, f.executor, lease, f.target, f.targetPath)
				if err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				if cleanup {
					done <- f.plugin.UnmountAuthorizedVolume(ctx, owner)
				} else {
					var err error
					owner, err = f.plugin.MountAuthorizedVolume(ctx, f.broker, f.executor, lease, f.target, f.targetPath)
					done <- err
				}
			}()
			awaitAuthorized(t, entered)
			cancel()
			if err := awaitAuthorized(t, done); !errors.Is(err, access.ErrUnavailable) {
				t.Fatalf("canceled %s returned %v", phase, err)
			}
			awaitAuthorized(t, canceled)
			f.plugin.protectedMu.Lock()
			record, retained := f.plugin.protectedMounts[owner]
			f.plugin.protectedMu.Unlock()
			if owner == nil || !retained || record.busy {
				t.Fatal("canceled RPC must retain an owner that can retry cleanup")
			}
			for _, conflict := range []struct {
				lease  *access.Lease
				target access.Target
				path   string
			}{
				{lease, f.target, f.targetPath + "-other"},
				{leaseB, targetB, f.targetPath},
				{leaseB, targetB, filepath.Dir(f.targetPath)},
				{leaseB, targetB, filepath.Join(f.targetPath, "child")},
			} {
				if next, err := f.plugin.MountAuthorizedVolume(t.Context(), f.broker, f.executor, conflict.lease, conflict.target, conflict.path); next != nil || !errors.Is(err, access.ErrUnsupported) {
					t.Fatalf("uncertain RPC released a reservation: owner=%v err=%v", next, err)
				}
			}
			releaseRPC()
			awaitAuthorized(t, exited)
			if err := f.plugin.UnmountAuthorizedVolume(t.Context(), owner); err != nil {
				t.Fatalf("owner cleanup retry: %v", err)
			}
			next, err := f.plugin.MountAuthorizedVolume(t.Context(), f.broker, f.executor, lease, f.target, f.targetPath)
			if err != nil || next == nil || next == owner {
				t.Fatalf("replacement owner=%v err=%v", next, err)
			}
			beforeUnpublish, beforeUnstage := f.unpublishes.Load(), f.unstages.Load()
			if err := f.plugin.UnmountAuthorizedVolume(t.Context(), owner); !errors.Is(err, access.ErrDenied) {
				t.Fatalf("delayed old owner reached replacement: %v", err)
			}
			if f.unpublishes.Load() != beforeUnpublish || f.unstages.Load() != beforeUnstage {
				t.Fatal("stale owner issued a cleanup RPC")
			}
			if err := f.plugin.UnmountAuthorizedVolume(t.Context(), next); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAuthorizedMountOpaqueHandleAndRedaction(t *testing.T) {
	for _, phase := range []string{"stage", "publish"} {
		t.Run(phase, func(t *testing.T) {
			f := newAccessFixture(t)
			f.target.Handle = "../../opaque/vendor/handle"
			f.update("dataset", func(s *access.Snapshot) { s.Volume.Handle = f.target.Handle })
			failure := func() error { return status.Error(codes.Internal, syntheticSecret) }
			if phase == "stage" {
				f.afterStage = failure
			} else {
				f.onPublish = failure
			}
			var output bytes.Buffer
			previous := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&output, nil)))
			defer slog.SetDefault(previous)
			mount, err := f.mount(t.Context())
			if !errors.Is(err, access.ErrUnavailable) {
				t.Fatalf("expected sanitized failure, got %v", err)
			}
			stage := <-f.stage
			if stage.VolumeId != f.target.Handle || !strings.HasPrefix(stage.StagingTargetPath, f.plugin.stagingDirPrefix+string(filepath.Separator)) || strings.Contains(stage.StagingTargetPath, "opaque") {
				t.Fatal("opaque handle used as a filesystem path or rewritten for CSI")
			}
			wantContext := map[string]string{"endpoint": "https://storage.example.invalid", "resource": "dataset-bucket", "prefix": "actors/A/dataset/"}
			if !maps.Equal(stage.VolumeContext, wantContext) {
				t.Fatal("unexpected Stage metadata")
			}
			if phase == "publish" {
				if !maps.Equal((<-f.publish).VolumeContext, wantContext) {
					t.Fatal("unexpected Publish metadata")
				}
			}
			for _, format := range []string{"%v", "%+v", "%#v"} {
				fmt.Fprintf(&output, format, mount)
				fmt.Fprintf(&output, format, err)
			}
			if strings.Contains(output.String(), syntheticSecret) {
				t.Fatal("secret leaked in errors, formatting or logs")
			}
			if err := f.plugin.UnmountAuthorizedVolume(t.Context(), mount); err != nil {
				t.Fatal(err)
			}
		})
	}
}

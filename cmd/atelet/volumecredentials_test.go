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

package main

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/agent-substrate/substrate/internal/apierror"
	"github.com/agent-substrate/substrate/internal/proto/ateletpb"
	"github.com/agent-substrate/substrate/internal/volume"
	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"github.com/google/go-cmp/cmp"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// fakeMinter answers MintVolumeCredential from a queue of results; the last
// result repeats.
type fakeMinter struct {
	mu      sync.Mutex
	reqs    []*ateapipb.MintVolumeCredentialRequest
	results []mintResult
}

type mintResult struct {
	resp *ateapipb.MintVolumeCredentialResponse
	err  error
}

func (f *fakeMinter) MintVolumeCredential(_ context.Context, req *ateapipb.MintVolumeCredentialRequest, _ ...grpc.CallOption) (*ateapipb.MintVolumeCredentialResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reqs = append(f.reqs, req)
	r := f.results[0]
	if len(f.results) > 1 {
		f.results = f.results[1:]
	}
	return r.resp, r.err
}

func (f *fakeMinter) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.reqs)
}

func credResponse(secret string, refresh bool) *ateapipb.MintVolumeCredentialResponse {
	resp := &ateapipb.MintVolumeCredentialResponse{
		Secrets:    map[string]string{"akId": secret},
		ExpireTime: timestamppb.New(time.Now().Add(time.Hour)),
	}
	if refresh {
		resp.RefreshTime = timestamppb.New(time.Now().Add(45 * time.Minute))
	}
	return resp
}

// immediately makes every refresh due at once.
func immediately(time.Duration) <-chan time.Time {
	ch := make(chan time.Time, 1)
	ch <- time.Now()
	return ch
}

func brokeredVolume(name string) *ateletpb.Volume {
	return &ateletpb.Volume{
		Name: name,
		Source: &ateletpb.Volume_External{External: &ateletpb.ExternalVolumeSource{
			StorageVolumeId:     "vol-" + name,
			VolumeType:          "mock-driver",
			BrokeredCredentials: true,
		}},
	}
}

var testOwner = volumeOwner{
	workerPodUID: "8f1c2d34-5e6a-4b7c-9d8e-0f1a2b3c4d5e",
	atespace:     "team-a",
	actorName:    "runner",
	actorUID:     "3c9a1f2e-4b5d-4e6f-8a7b-9c0d1e2f3a4b",
}

func TestMountExternalVolumesBrokered(t *testing.T) {
	ctx := context.Background()
	plain := &ateletpb.Volume{
		Name:   "plain",
		Source: &ateletpb.Volume_External{External: &ateletpb.ExternalVolumeSource{StorageVolumeId: "vol-plain", VolumeType: "mock-driver"}},
	}

	t.Run("mints before mounting", func(t *testing.T) {
		withTempActorsDir(t)
		fake := &fakeWorkerPlugin{}
		minter := &fakeMinter{results: []mintResult{{resp: credResponse("first", false)}}}
		s := &AteomHerder{
			volumePlugins:     map[string]volume.VolumePluginWorkerPlane{"mock-driver": fake},
			volumeCredentials: newVolumeCredentials(minter),
		}
		if err := s.mountExternalVolumes(ctx, testOwner, []*ateletpb.Volume{plain, brokeredVolume("data")}); err != nil {
			t.Fatalf("mountExternalVolumes: %v", err)
		}
		if diff := cmp.Diff([]map[string]string{nil, {"akId": "first"}}, fake.secrets); diff != "" {
			t.Errorf("mount secrets mismatch (-want +got):\n%s", diff)
		}
		want := []*ateapipb.MintVolumeCredentialRequest{{
			Worker:     &ateapipb.ObjectRef{Name: testOwner.workerPodUID},
			Actor:      &ateapipb.ObjectRef{Atespace: "team-a", Name: "runner"},
			ActorUid:   testOwner.actorUID,
			VolumeName: "data",
		}}
		if diff := cmp.Diff(want, minter.reqs, protocmp.Transform()); diff != "" {
			t.Errorf("mint requests mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("no minter refuses the volume", func(t *testing.T) {
		withTempActorsDir(t)
		fake := &fakeWorkerPlugin{}
		s := &AteomHerder{volumePlugins: map[string]volume.VolumePluginWorkerPlane{"mock-driver": fake}}
		if err := s.mountExternalVolumes(ctx, testOwner, []*ateletpb.Volume{brokeredVolume("data")}); err == nil {
			t.Fatal("mounted a brokered volume without credentials")
		}
		if len(fake.mountCalls) != 0 {
			t.Errorf("mount calls = %d, want 0", len(fake.mountCalls))
		}
	})

	t.Run("mint failure does not mount", func(t *testing.T) {
		withTempActorsDir(t)
		fake := &fakeWorkerPlugin{}
		minter := &fakeMinter{results: []mintResult{{err: apierror.Unavailable("down")}}}
		s := &AteomHerder{
			volumePlugins:     map[string]volume.VolumePluginWorkerPlane{"mock-driver": fake},
			volumeCredentials: newVolumeCredentials(minter),
		}
		if err := s.mountExternalVolumes(ctx, testOwner, []*ateletpb.Volume{brokeredVolume("data")}); err == nil {
			t.Fatal("mounted after a mint failure")
		}
		if len(fake.mountCalls) != 0 {
			t.Errorf("mount calls = %d, want 0", len(fake.mountCalls))
		}
	})
}

func TestVolumeCredentialRefresh(t *testing.T) {
	run := func(t *testing.T, results []mintResult) ([]string, *fakeMinter) {
		t.Helper()
		minter := &fakeMinter{results: results}
		m := newVolumeCredentials(minter)
		m.after = immediately
		var mu sync.Mutex
		var got []string
		done := make(chan struct{})
		m.startRefresh(testOwner, "data", credResponse("first", true), func(_ context.Context, secrets map[string]string) error {
			mu.Lock()
			defer mu.Unlock()
			got = append(got, secrets["akId"])
			return nil
		})
		go func() {
			// The refresher exits on its own; stopActor then returns at once.
			for minter.calls() < len(results) {
				time.Sleep(time.Millisecond)
			}
			m.stopActor(testOwner.actorUID)
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("refresher did not stop")
		}
		mu.Lock()
		defer mu.Unlock()
		return got, minter
	}

	t.Run("remounts each replacement until the profile stops refreshing", func(t *testing.T) {
		got, _ := run(t, []mintResult{
			{resp: credResponse("second", true)},
			{resp: credResponse("third", false)},
		})
		if diff := cmp.Diff([]string{"second", "third"}, got); diff != "" {
			t.Errorf("remounts mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("retries transient failures", func(t *testing.T) {
		got, _ := run(t, []mintResult{
			{err: apierror.Unavailable("down")},
			{resp: credResponse("second", false)},
		})
		if diff := cmp.Diff([]string{"second"}, got); diff != "" {
			t.Errorf("remounts mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("stops when the actor is no longer hosted", func(t *testing.T) {
		got, minter := run(t, []mintResult{{err: apierror.NotFound("gone")}})
		if len(got) != 0 || minter.calls() != 1 {
			t.Errorf("remounts = %v, mint calls = %d; want none and 1", got, minter.calls())
		}
	})

	t.Run("stopActor cancels a waiting refresher", func(t *testing.T) {
		minter := &fakeMinter{results: []mintResult{{resp: credResponse("never", true)}}}
		m := newVolumeCredentials(minter)
		m.after = func(time.Duration) <-chan time.Time { return nil } // never due
		m.startRefresh(testOwner, "data", credResponse("first", true), func(context.Context, map[string]string) error {
			return errors.New("must not remount")
		})
		stopped := make(chan struct{})
		go func() { m.stopActor(testOwner.actorUID); close(stopped) }()
		select {
		case <-stopped:
		case <-time.After(10 * time.Second):
			t.Fatal("stopActor did not return")
		}
		if minter.calls() != 0 {
			t.Errorf("mint calls = %d after stop, want 0", minter.calls())
		}
	})

	t.Run("no refresh time starts nothing", func(t *testing.T) {
		m := newVolumeCredentials(&fakeMinter{})
		m.startRefresh(testOwner, "data", credResponse("first", false), nil)
		if len(m.refreshers) != 0 {
			t.Errorf("refreshers = %d, want 0", len(m.refreshers))
		}
	})
}

func TestUnmountStopsRefresh(t *testing.T) {
	withTempActorsDir(t)
	fake := &fakeWorkerPlugin{}
	minter := &fakeMinter{results: []mintResult{{resp: credResponse("first", true)}}}
	m := newVolumeCredentials(minter)
	m.after = func(time.Duration) <-chan time.Time { return nil }
	s := &AteomHerder{
		volumePlugins:     map[string]volume.VolumePluginWorkerPlane{"mock-driver": fake},
		volumeCredentials: m,
	}
	vols := []*ateletpb.Volume{brokeredVolume("data")}
	if err := s.mountExternalVolumes(context.Background(), testOwner, vols); err != nil {
		t.Fatalf("mountExternalVolumes: %v", err)
	}
	if len(m.refreshers[testOwner.actorUID]) != 1 {
		t.Fatalf("refreshers = %d, want 1", len(m.refreshers[testOwner.actorUID]))
	}
	if err := s.unmountExternalVolumes(context.Background(), testOwner.actorUID, vols); err != nil {
		t.Fatalf("unmountExternalVolumes: %v", err)
	}
	if len(m.refreshers) != 0 {
		t.Errorf("refreshers left after unmount: %d", len(m.refreshers))
	}
}

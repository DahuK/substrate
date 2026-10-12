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

package workerservice

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/agent-substrate/substrate/cmd/ateapi/internal/ateletauth/ateletauthtest"
	"github.com/agent-substrate/substrate/cmd/ateapi/internal/store"
	"github.com/agent-substrate/substrate/cmd/ateapi/internal/volumecred"
	"github.com/agent-substrate/substrate/internal/apierror"
	"github.com/agent-substrate/substrate/internal/resources"
	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"github.com/google/go-cmp/cmp"
	"google.golang.org/grpc/codes"
)

const volumeActorUID = "3c9a1f2e-4b5d-4e6f-8a7b-9c0d1e2f3a4b"

// volumeCredentialStore serves one Worker and one Actor.
type volumeCredentialStore struct {
	store.Interface
	worker *ateapipb.Worker
	actor  *ateapipb.Actor
}

func (s *volumeCredentialStore) GetWorker(_ context.Context, name string) (*ateapipb.Worker, error) {
	if s.worker == nil || s.worker.GetMetadata().GetName() != name {
		return nil, store.ErrNotFound
	}
	return s.worker, nil
}

func (s *volumeCredentialStore) GetActor(_ context.Context, ref resources.ActorRef) (*ateapipb.Actor, error) {
	if s.actor == nil || resources.ActorRefFromActor(s.actor) != ref {
		return nil, store.ErrNotFound
	}
	return s.actor, nil
}

type fakeIssuer struct {
	err    error
	calls  []string
	issued volumecred.Issued
}

func (f *fakeIssuer) Issue(_ context.Context, actor *ateapipb.Actor, volumeName string) (volumecred.Issued, error) {
	f.calls = append(f.calls, actor.GetMetadata().GetUid()+"/"+volumeName)
	return f.issued, f.err
}

func TestMintVolumeCredential(t *testing.T) {
	expire := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	newStore := func() *volumeCredentialStore {
		return &volumeCredentialStore{
			worker: &ateapipb.Worker{Metadata: &ateapipb.ResourceMetadata{Name: testWorkerName}, NodeName: testNode},
			actor: &ateapipb.Actor{
				Metadata: &ateapipb.ResourceMetadata{Atespace: "team-a", Name: "runner", Uid: volumeActorUID},
				Status: &ateapipb.ActorStatus{
					State:            ateapipb.ActorState_ACTOR_STATE_RESUMING,
					WorkerAssignment: &ateapipb.WorkerAssignment{Worker: &ateapipb.ObjectRef{Name: testWorkerName}},
				},
			},
		}
	}
	request := func() *ateapipb.MintVolumeCredentialRequest {
		return &ateapipb.MintVolumeCredentialRequest{
			Worker:     &ateapipb.ObjectRef{Name: testWorkerName},
			Actor:      &ateapipb.ObjectRef{Atespace: "team-a", Name: "runner"},
			ActorUid:   volumeActorUID,
			VolumeName: "data",
		}
	}
	onNode := func(node string) context.Context {
		return ateletauthtest.ContextWith(ateletauthtest.CertOn(t, node))
	}

	tests := []struct {
		name      string
		ctx       context.Context
		mutate    func(*volumeCredentialStore, *ateapipb.MintVolumeCredentialRequest)
		issuer    *fakeIssuer
		noIssuer  bool
		wantCode  codes.Code
		wantIssue bool
	}{
		{
			name:      "hosted actor",
			ctx:       onNode(testNode),
			issuer:    &fakeIssuer{issued: volumecred.Issued{Secrets: map[string]string{"k": "v"}, ExpireTime: expire, RefreshTime: expire.Add(-15 * time.Minute)}},
			wantCode:  codes.OK,
			wantIssue: true,
		},
		{
			name:     "unauthenticated",
			ctx:      context.Background(),
			issuer:   &fakeIssuer{},
			wantCode: codes.Unauthenticated,
		},
		{
			name:     "not configured",
			ctx:      onNode(testNode),
			noIssuer: true,
			wantCode: codes.FailedPrecondition,
		},
		{
			name:     "worker on another node",
			ctx:      onNode("node-2"),
			issuer:   &fakeIssuer{},
			wantCode: codes.NotFound,
		},
		{
			name: "actor assigned elsewhere",
			ctx:  onNode(testNode),
			mutate: func(s *volumeCredentialStore, _ *ateapipb.MintVolumeCredentialRequest) {
				s.actor.Status.WorkerAssignment.Worker.Name = "1f2e3d4c-5b6a-4978-8a9b-0c1d2e3f4a5b"
			},
			issuer:   &fakeIssuer{},
			wantCode: codes.NotFound,
		},
		{
			name: "actor not assigned",
			ctx:  onNode(testNode),
			mutate: func(s *volumeCredentialStore, _ *ateapipb.MintVolumeCredentialRequest) {
				s.actor.Status = &ateapipb.ActorStatus{State: ateapipb.ActorState_ACTOR_STATE_SUSPENDED}
			},
			issuer:   &fakeIssuer{},
			wantCode: codes.NotFound,
		},
		{
			name: "stale actor incarnation",
			ctx:  onNode(testNode),
			mutate: func(_ *volumeCredentialStore, r *ateapipb.MintVolumeCredentialRequest) {
				r.ActorUid = "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d"
			},
			issuer:   &fakeIssuer{},
			wantCode: codes.NotFound,
		},
		{
			name: "invalid volume name",
			ctx:  onNode(testNode),
			mutate: func(_ *volumeCredentialStore, r *ateapipb.MintVolumeCredentialRequest) {
				r.VolumeName = "../data"
			},
			issuer:   &fakeIssuer{},
			wantCode: codes.InvalidArgument,
		},
		{
			name:      "no profile",
			ctx:       onNode(testNode),
			issuer:    &fakeIssuer{err: volumecred.ErrNoProfile},
			wantCode:  codes.FailedPrecondition,
			wantIssue: true,
		},
		{
			name:      "provider failure",
			ctx:       onNode(testNode),
			issuer:    &fakeIssuer{err: errors.Join(volumecred.ErrUnavailable, errors.New("role acs:ram::123:role/secret-role"))},
			wantCode:  codes.Unavailable,
			wantIssue: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st := newStore()
			req := request()
			if tc.mutate != nil {
				tc.mutate(st, req)
			}
			s := New(st, &fakeSuspender{}, testAteletSPIFFEID, nil)
			if !tc.noIssuer {
				s.SetVolumeCredentials(tc.issuer)
			}
			resp, err := s.MintVolumeCredential(tc.ctx, req)
			if got := apierror.Code(err); got != tc.wantCode {
				t.Fatalf("MintVolumeCredential = %v (%v), want %v", got, err, tc.wantCode)
			}
			if err != nil && strings.Contains(err.Error(), "acs:ram") {
				t.Errorf("error %q discloses provider details", err)
			}
			if tc.issuer != nil && (len(tc.issuer.calls) > 0) != tc.wantIssue {
				t.Errorf("issuer calls = %v, want issued=%v", tc.issuer.calls, tc.wantIssue)
			}
			if tc.wantCode != codes.OK {
				return
			}
			if diff := cmp.Diff([]string{volumeActorUID + "/data"}, tc.issuer.calls); diff != "" {
				t.Errorf("issuer calls mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(map[string]string{"k": "v"}, resp.GetSecrets()); diff != "" {
				t.Errorf("secrets mismatch (-want +got):\n%s", diff)
			}
			if !resp.GetExpireTime().AsTime().Equal(expire) || !resp.GetRefreshTime().AsTime().Equal(expire.Add(-15*time.Minute)) {
				t.Errorf("times = %v / %v", resp.GetExpireTime().AsTime(), resp.GetRefreshTime().AsTime())
			}
		})
	}
}

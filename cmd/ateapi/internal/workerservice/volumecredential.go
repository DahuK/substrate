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
	"fmt"
	"log/slog"

	"github.com/agent-substrate/substrate/cmd/ateapi/internal/apivalidation"
	"github.com/agent-substrate/substrate/cmd/ateapi/internal/ateletauth"
	"github.com/agent-substrate/substrate/cmd/ateapi/internal/store"
	"github.com/agent-substrate/substrate/cmd/ateapi/internal/volumecred"
	"github.com/agent-substrate/substrate/internal/apierror"
	"github.com/agent-substrate/substrate/internal/resources"
	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// VolumeCredentialIssuer issues credentials for an actor's external volume.
// *volumecred.Broker implements it.
type VolumeCredentialIssuer interface {
	Issue(ctx context.Context, actor *ateapipb.Actor, volumeName string) (volumecred.Issued, error)
}

// SetVolumeCredentials enables MintVolumeCredential. Call it before serving.
func (s *Server) SetVolumeCredentials(issuer VolumeCredentialIssuer) {
	s.volumeCredentials = issuer
}

// MintVolumeCredential issues credentials for an external volume of an Actor
// the calling Worker hosts. The caller must be an atelet running on the
// Worker's node; the scope comes from the stored Actor, not the request.
func (s *Server) MintVolumeCredential(ctx context.Context, req *ateapipb.MintVolumeCredentialRequest) (*ateapipb.MintVolumeCredentialResponse, error) {
	caller, err := ateletauth.Authenticate(ctx, s.ateletSPIFFEID)
	if err != nil {
		return nil, err
	}
	if errs := apivalidation.ValidateMintVolumeCredentialRequest(ctx, req); len(errs) > 0 {
		return nil, resources.ToAPIError(errs)
	}
	if s.volumeCredentials == nil {
		return nil, apierror.FailedPrecondition("volume credentials are not configured")
	}

	// As for RequestActorSuspend: authorize against stored state only. The
	// caller proves which node it is on, and nothing else.
	workerName := req.GetWorker().GetName()
	worker, err := s.store.GetWorker(ctx, workerName)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, apierror.NotFound("Worker %s not found", workerName)
		}
		return nil, fmt.Errorf("while fetching worker %s: %w", workerName, err)
	}
	if worker.GetNodeName() != caller.NodeName {
		slog.WarnContext(ctx, "Refusing a volume credential request for a worker on another node",
			slog.String("worker", workerName),
			slog.String("worker_node", worker.GetNodeName()),
			slog.String("caller_node", caller.NodeName))
		return nil, apierror.NotFound("Worker %s not found", workerName)
	}

	actorRef := resources.ActorRefFromObjectRef(req.GetActor())
	actor, err := s.store.GetActor(ctx, actorRef)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, apierror.NotFound("Actor %s not found", actorRef)
		}
		return nil, fmt.Errorf("while fetching actor %s: %w", actorRef, err)
	}
	// The assignment is recorded before atelet is asked to Run or Restore, so
	// it is in place for the first mount of a resume.
	if err := checkActorHostedBy(ctx, actor, workerName, req.GetActorUid()); err != nil {
		return nil, err
	}

	issued, err := s.volumeCredentials.Issue(ctx, actor, req.GetVolumeName())
	switch {
	case err == nil:
	case errors.Is(err, volumecred.ErrNoProfile), errors.Is(err, volumecred.ErrInvalidScope):
		return nil, apierror.FailedPrecondition("volume %q of Actor %s: %v", req.GetVolumeName(), actorRef, err)
	default:
		// The provider's error can name cloud accounts and roles: log it, and
		// tell the node only that issuance is unavailable.
		slog.ErrorContext(ctx, "Failed to issue volume credentials",
			slog.String("actor", actorRef.String()),
			slog.String("volume", req.GetVolumeName()),
			slog.Any("error", err))
		return nil, apierror.Unavailable("volume credentials are unavailable")
	}
	slog.InfoContext(ctx, "Issued volume credentials",
		slog.String("actor", actorRef.String()),
		slog.String("actor_uid", req.GetActorUid()),
		slog.String("volume", req.GetVolumeName()),
		slog.String("node", caller.NodeName),
		slog.Time("expire_time", issued.ExpireTime))

	resp := &ateapipb.MintVolumeCredentialResponse{
		Secrets:    issued.Secrets,
		ExpireTime: timestamppb.New(issued.ExpireTime),
	}
	if !issued.RefreshTime.IsZero() {
		resp.RefreshTime = timestamppb.New(issued.RefreshTime)
	}
	return resp, nil
}

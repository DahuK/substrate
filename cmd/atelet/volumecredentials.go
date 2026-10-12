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
	"log/slog"
	"sync"
	"time"

	"github.com/agent-substrate/substrate/internal/apierror"
	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

const (
	volumeCredentialRetryMin = time.Second
	volumeCredentialRetryMax = 30 * time.Second
)

// volumeCredentialMinter is the WorkerService slice atelet mints volume
// credentials through.
type volumeCredentialMinter interface {
	MintVolumeCredential(ctx context.Context, req *ateapipb.MintVolumeCredentialRequest, opts ...grpc.CallOption) (*ateapipb.MintVolumeCredentialResponse, error)
}

// volumeOwner names the actor a volume is mounted for, and the Worker hosting
// it, as the control plane checks them.
type volumeOwner struct {
	workerPodUID, atespace, actorName, actorUID string
}

// volumeCredentials mints brokered volume credentials and keeps them fresh
// while the volume stays mounted. Credentials live only in memory: an atelet
// restart stops refreshing them, and the mounted volume keeps its current
// credentials until they expire.
type volumeCredentials struct {
	minter volumeCredentialMinter
	now    func() time.Time
	// after is time.After, replaceable in tests.
	after func(time.Duration) <-chan time.Time

	mu         sync.Mutex
	refreshers map[string][]*volumeRefresher // by actor UID
}

type volumeRefresher struct {
	cancel context.CancelFunc
	done   chan struct{}
}

func newVolumeCredentials(minter volumeCredentialMinter) *volumeCredentials {
	return &volumeCredentials{
		minter:     minter,
		now:        time.Now,
		after:      time.After,
		refreshers: make(map[string][]*volumeRefresher),
	}
}

func (m *volumeCredentials) mint(ctx context.Context, owner volumeOwner, volumeName string) (*ateapipb.MintVolumeCredentialResponse, error) {
	return m.minter.MintVolumeCredential(ctx, &ateapipb.MintVolumeCredentialRequest{
		// Workers are global-scoped and named by their pod UID.
		Worker:     &ateapipb.ObjectRef{Name: owner.workerPodUID},
		Actor:      &ateapipb.ObjectRef{Atespace: owner.atespace, Name: owner.actorName},
		ActorUid:   owner.actorUID,
		VolumeName: volumeName,
	})
}

// startRefresh keeps a mounted volume's credentials fresh until stopActor.
// Before first.refresh_time it mints replacements and calls remount with
// them, retrying with backoff on transient failures. It stops when the
// control plane no longer serves the volume (the actor moved, was suspended
// or deleted) or the profile stops refreshing.
func (m *volumeCredentials) startRefresh(owner volumeOwner, volumeName string, first *ateapipb.MintVolumeCredentialResponse, remount func(context.Context, map[string]string) error) {
	if first.GetRefreshTime() == nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &volumeRefresher{cancel: cancel, done: make(chan struct{})}
	m.mu.Lock()
	m.refreshers[owner.actorUID] = append(m.refreshers[owner.actorUID], r)
	m.mu.Unlock()

	go func() {
		defer close(r.done)
		log := slog.With(slog.String("actor_uid", owner.actorUID), slog.String("volume", volumeName))
		refreshAt := first.GetRefreshTime().AsTime()
		expireAt := first.GetExpireTime().AsTime()
		backoff := volumeCredentialRetryMin
		for {
			select {
			case <-ctx.Done():
				return
			case <-m.after(max(0, refreshAt.Sub(m.now()))):
			}
			resp, err := m.mint(ctx, owner, volumeName)
			if err == nil {
				err = remount(ctx, resp.GetSecrets())
			}
			if ctx.Err() != nil {
				return
			}
			if err != nil {
				if permanentMintFailure(err) {
					log.WarnContext(ctx, "Stopped refreshing volume credentials", slog.Any("error", err))
					return
				}
				if !m.now().Before(expireAt) {
					log.ErrorContext(ctx, "Volume credentials expired before they could be refreshed", slog.Any("error", err))
				} else {
					log.WarnContext(ctx, "Failed to refresh volume credentials; retrying", slog.Any("error", err), slog.Duration("backoff", backoff))
				}
				refreshAt = m.now().Add(backoff)
				backoff = min(2*backoff, volumeCredentialRetryMax)
				continue
			}
			backoff = volumeCredentialRetryMin
			expireAt = resp.GetExpireTime().AsTime()
			log.InfoContext(ctx, "Refreshed volume credentials", slog.Time("expire_time", expireAt))
			if resp.GetRefreshTime() == nil {
				return
			}
			refreshAt = resp.GetRefreshTime().AsTime()
		}
	}()
}

// stopActor stops refreshing every volume of the actor and waits for any
// remount in flight, so a following unmount does not race it.
func (m *volumeCredentials) stopActor(actorUID string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	rs := m.refreshers[actorUID]
	delete(m.refreshers, actorUID)
	m.mu.Unlock()
	for _, r := range rs {
		r.cancel()
	}
	for _, r := range rs {
		<-r.done
	}
}

// permanentMintFailure reports a refusal that retrying will not change.
func permanentMintFailure(err error) bool {
	switch apierror.Code(err) {
	case codes.NotFound, codes.FailedPrecondition, codes.PermissionDenied, codes.Unauthenticated, codes.InvalidArgument:
		return true
	}
	return errors.Is(err, context.Canceled)
}

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

package access

import (
	"context"
	"errors"
	"maps"
	"net/url"
	"strings"
	"time"
)

type Broker struct {
	resolver Resolver
	provider Provider
	now      func() time.Time
}

func NewBroker(resolver Resolver, provider Provider, now func() time.Time) *Broker {
	if now == nil {
		now = time.Now
	}
	return &Broker{resolver: resolver, provider: provider, now: now}
}

// Lease is an opaque approval pinned to an issuing broker and authority snapshot.
// It is not a revocation mechanism for secrets already delivered to a driver.
type Lease struct {
	broker     *Broker
	executor   Executor
	request    Request
	snapshot   Snapshot
	approved   ApprovedAccess
	credential Credential
}

func (l *Lease) Approved() ApprovedAccess {
	if l == nil {
		return ApprovedAccess{}
	}
	return l.approved
}

func (l *Lease) Secrets() map[string]string {
	if l == nil {
		return nil
	}
	return maps.Clone(l.credential.Secrets)
}

func (b *Broker) Exchange(ctx context.Context, executor Executor, request Request) (*Lease, error) {
	if strings.TrimSpace(request.BindingUID) == "" || request.Revision == 0 || strings.TrimSpace(request.ActivationUID) == "" || request.Mode == "" || request.MaxCredentialLifetime <= 0 {
		return nil, ErrInvalidRequest
	}
	if request.Mode != ReadOnly && request.Mode != ReadWrite {
		return nil, ErrUnsupported
	}
	if b == nil || b.provider == nil {
		return nil, ErrUnavailable
	}
	snapshot, err := b.resolve(ctx, request.BindingUID)
	if err != nil {
		return nil, err
	}
	now := b.now()
	approved, err := authorize(snapshot, executor, request, now)
	if err != nil {
		return nil, err
	}
	approved.Deadline = now.Add(min(request.MaxCredentialLifetime, snapshot.Profile.MaxLifetime))
	for _, expiry := range []time.Time{snapshot.Binding.ExpiresAt, snapshot.Grant.ExpiresAt} {
		if expiry.Before(approved.Deadline) {
			approved.Deadline = expiry
		}
	}
	if approved.Deadline.Sub(now) < snapshot.Profile.MinLifetime {
		return nil, ErrUnsupported
	}
	credential, err := b.provider.Acquire(ctx, approved)
	if err != nil {
		return nil, ErrUnavailable
	}
	credential.Secrets = maps.Clone(credential.Secrets)
	current, err := b.resolve(ctx, request.BindingUID)
	if err != nil {
		return nil, err
	}
	now = b.now()
	if err := reauthorize(current, snapshot, executor, request, now); err != nil {
		return nil, err
	}
	if credential.Scope != approved.Scope || credential.Kind != approved.Profile.CredentialKind || credential.ProfileName != approved.Profile.Name || credential.ProfileVersion != approved.Profile.Version ||
		credential.ExpiresAt.IsZero() || !credential.ExpiresAt.After(now) || credential.ExpiresAt.After(approved.Deadline) {
		return nil, ErrDenied
	}
	if credential.ExpiresAt.Sub(now) < approved.Profile.MinLifetime {
		return nil, ErrUnsupported
	}
	if len(credential.Secrets) != 3 || credential.Secrets["accessKey"] == "" || credential.Secrets["secretKey"] == "" || credential.Secrets["sessionToken"] == "" {
		return nil, ErrDenied
	}
	return &Lease{broker: b, executor: executor, request: request, snapshot: snapshot, approved: approved, credential: credential}, nil
}

// CheckLease is a local preflight: it checks ownership, target and expiry without
// reading authority. Success does NOT authorize credential delivery; callers must
// still Validate immediately before each Stage/Publish delivery.
func (b *Broker) CheckLease(ctx context.Context, executor Executor, lease *Lease, target Target) error {
	if err := b.checkLeaseIdentity(executor, lease, target); err != nil {
		return err
	}
	if b.now == nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	now := b.now()
	if ctx.Err() != nil {
		return ErrUnavailable
	}
	if !lease.credential.ExpiresAt.After(now) || !lease.approved.Deadline.After(now) {
		return ErrDenied
	}
	return nil
}

func (b *Broker) checkLeaseIdentity(executor Executor, lease *Lease, target Target) error {
	if b == nil || lease == nil || lease.broker != b || executor != lease.executor {
		return ErrDenied
	}
	a := lease.approved
	if target != (Target{ActorUID: a.ActorUID, ActivationUID: a.ActivationUID, Driver: a.Driver, Handle: a.Handle}) {
		return ErrDenied
	}
	return nil
}

func (b *Broker) Validate(ctx context.Context, executor Executor, lease *Lease, target Target) error {
	if err := b.checkLeaseIdentity(executor, lease, target); err != nil {
		return err
	}
	current, err := b.resolve(ctx, lease.request.BindingUID)
	if err != nil {
		return err
	}
	now := b.now()
	if err := reauthorize(current, lease.snapshot, executor, lease.request, now); err != nil {
		return err
	}
	if !lease.credential.ExpiresAt.After(now) || !lease.approved.Deadline.After(now) {
		return ErrDenied
	}
	return nil
}

// pinned has already passed full authorization for this executor and request.
// We still read current authority every time. Equality lets us reuse only the
// structural proof, never the time-dependent decision or a stale cached result.
func reauthorize(current, pinned Snapshot, executor Executor, request Request, now time.Time) error {
	if current != pinned {
		if _, err := authorize(current, executor, request, now); err != nil {
			return err
		}
		return ErrDenied
	}
	if current.Grant.Revoked || !current.Binding.ExpiresAt.After(now) || !current.Grant.ExpiresAt.After(now) {
		return ErrDenied
	}
	return nil
}

func (b *Broker) resolve(ctx context.Context, uid string) (Snapshot, error) {
	if b == nil || b.resolver == nil || b.now == nil || ctx.Err() != nil {
		return Snapshot{}, ErrUnavailable
	}
	snapshot, err := b.resolver.Resolve(ctx, uid)
	if err != nil {
		if errors.Is(err, ErrDenied) {
			return Snapshot{}, ErrDenied
		}
		return Snapshot{}, ErrUnavailable
	}
	if ctx.Err() != nil {
		return Snapshot{}, ErrUnavailable
	}
	return snapshot, nil
}

func authorize(snapshot Snapshot, executor Executor, request Request, now time.Time) (ApprovedAccess, error) {
	binding := snapshot.Binding
	grant := snapshot.Grant
	volume := snapshot.Volume

	// Exchange already validated the request's identifiers and revision.
	if binding.UID != request.BindingUID || binding.Revision != request.Revision ||
		binding.ActivationUID != request.ActivationUID || binding.Mode != request.Mode {
		return ApprovedAccess{}, ErrDenied
	}
	if !matchesIdentity(snapshot.ActorUID, binding.ActorUID, grant.ActorUID, volume.OwnerActorUID) ||
		!matchesIdentity(snapshot.Atespace, grant.Atespace, volume.Atespace) ||
		!matchesIdentity(volume.UID, binding.VolumeUID, grant.VolumeUID) ||
		!matchesIdentity(grant.UID, binding.GrantUID) {
		return ApprovedAccess{}, ErrDenied
	}

	if executor.Component != "atelet" ||
		!matchesIdentity(binding.ClusterUID, executor.ClusterUID) ||
		!matchesIdentity(binding.NodeUID, executor.NodeUID) || strings.TrimSpace(binding.WorkerUID) == "" {
		return ApprovedAccess{}, ErrDenied
	}
	expectedAssignment := Assignment{
		ActorUID:      snapshot.ActorUID,
		ClusterUID:    binding.ClusterUID,
		NodeUID:       binding.NodeUID,
		WorkerUID:     binding.WorkerUID,
		ActivationUID: binding.ActivationUID,
	}
	if snapshot.Assignment != expectedAssignment {
		return ApprovedAccess{}, ErrDenied
	}

	if snapshot.PolicyRevision == 0 || grant.Revision == 0 || volume.Generation == 0 ||
		binding.ResourceGeneration != volume.Generation {
		return ApprovedAccess{}, ErrDenied
	}
	if grant.Revoked || binding.ExpiresAt.IsZero() || grant.ExpiresAt.IsZero() ||
		!binding.ExpiresAt.After(now) || !grant.ExpiresAt.After(now) {
		return ApprovedAccess{}, ErrDenied
	}

	scope := volume.Scope
	if strings.TrimSpace(volume.Driver) == "" || strings.TrimSpace(volume.Handle) == "" {
		return ApprovedAccess{}, ErrDenied
	}
	if strings.TrimSpace(scope.Endpoint) == "" || strings.TrimSpace(scope.Resource) == "" ||
		strings.TrimSpace(scope.Prefix) == "" || strings.TrimSpace(scope.ListPrefix) == "" {
		return ApprovedAccess{}, ErrDenied
	}
	if !volume.Exclusive {
		return ApprovedAccess{}, ErrUnsupported
	}
	profile := snapshot.Profile
	if profile.Name != StagePublishSecrets || profile.Version == 0 || profile.Driver != volume.Driver ||
		profile.CredentialKind != SessionCredential || profile.Delivery != StagePublishSecrets ||
		profile.MinLifetime <= 0 || profile.MaxLifetime < profile.MinLifetime ||
		profile.ReadOperations != Read|List || profile.WriteOperations != Read|Write|List {
		return ApprovedAccess{}, ErrUnsupported
	}

	endpoint, err := url.Parse(scope.Endpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" || endpoint.User != nil ||
		endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" || strings.Contains(scope.Endpoint, "#") {
		return ApprovedAccess{}, ErrDenied
	}
	if !strings.HasSuffix(scope.Prefix, "/") || scope.ListPrefix != scope.Prefix ||
		scope.Operations & ^(Read|Write|List) != 0 || grant.Operations & ^(Read|Write|List) != 0 {
		return ApprovedAccess{}, ErrDenied
	}
	operations := profile.ReadOperations
	if request.Mode == ReadWrite {
		operations = profile.WriteOperations
	}
	if scope.Operations&operations != operations || grant.Operations&operations != operations {
		return ApprovedAccess{}, ErrDenied
	}
	scope.Operations = operations
	return ApprovedAccess{
		BindingUID:    binding.UID,
		Revision:      binding.Revision,
		ActorUID:      snapshot.ActorUID,
		ActivationUID: binding.ActivationUID,
		VolumeUID:     volume.UID,
		Driver:        volume.Driver,
		Handle:        volume.Handle,
		Scope:         scope,
		Profile:       profile,
		Mode:          request.Mode,
	}, nil
}

// Validate one canonical identity, then compare references without normalizing them.
func matchesIdentity(identity string, references ...string) bool {
	if strings.TrimSpace(identity) == "" {
		return false
	}
	for _, reference := range references {
		if reference != identity {
			return false
		}
	}
	return true
}

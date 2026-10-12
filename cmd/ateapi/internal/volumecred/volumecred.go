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

// Package volumecred issues short-lived, volume-scoped storage credentials for
// the external volumes of hosted actors.
//
// An administrator configures a Profile per CSI driver. The Broker derives a
// volume's Scope from the provisioning context recorded on the actor, never
// from the caller, and asks the profile's Provider for credentials that reach
// only that scope. Deciding whether the caller may ask is the caller's job:
// WorkerService checks that the calling node hosts the actor.
package volumecred

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
)

var (
	// ErrNoProfile reports a volume whose driver has no credential profile.
	ErrNoProfile = errors.New("no volume credential profile for the volume's driver")
	// ErrInvalidScope reports a volume whose recorded context does not name a
	// scope the profile can issue credentials for.
	ErrInvalidScope = errors.New("volume has no valid credential scope")
	// ErrUnavailable reports that the provider could not issue credentials.
	ErrUnavailable = errors.New("volume credential provider unavailable")
)

// Scope is the storage one credential may reach.
type Scope struct {
	// Bucket is the bucket, file system or share that holds the volume.
	Bucket string
	// Prefix is the volume's key or directory prefix within Bucket. It is
	// never empty and always ends in "/".
	Prefix string
	// ReadOnly limits the credential to reads.
	ReadOnly bool
}

// Request is one credential request to a Provider.
type Request struct {
	Scope Scope
	// Duration is the requested lifetime.
	Duration time.Duration
	// SessionName identifies the credential in the provider's audit logs.
	SessionName string
}

// Credential is what a Provider issues.
type Credential struct {
	// Secrets are CSI secrets, keyed by the names the driver expects.
	Secrets map[string]string
	// Expiration is when the credential stops working.
	Expiration time.Time
}

// Provider turns a Scope into credentials. It must not widen the scope: a
// scope it cannot express is an error, never a broader credential.
type Provider interface {
	Issue(ctx context.Context, req Request) (Credential, error)
}

// Profile is an administrator's credential configuration for one CSI driver.
type Profile struct {
	// Driver is the CSI driver name, matched against the volume's type.
	Driver string
	// Provider issues the credentials.
	Provider Provider
	// BucketKey and PrefixKey name the volume_context entries, written by the
	// driver at CreateVolume, that hold the volume's bucket and prefix.
	BucketKey, PrefixKey string
	// ReadOnly issues read-only credentials for every volume of the driver.
	ReadOnly bool
	// Duration is the lifetime requested for each credential.
	Duration time.Duration
	// RefreshBefore is how long before expiry atelet mints replacements and
	// republishes the volume. Zero disables refresh: the driver cannot reload
	// credentials into a mounted volume, so Duration must cover the mount.
	RefreshBefore time.Duration
}

func (p Profile) validate() error {
	switch {
	case strings.TrimSpace(p.Driver) == "":
		return errors.New("driver is required")
	case p.Provider == nil:
		return fmt.Errorf("driver %q: provider is required", p.Driver)
	case p.BucketKey == "" || p.PrefixKey == "":
		return fmt.Errorf("driver %q: bucket and prefix context keys are required", p.Driver)
	case p.Duration <= 0:
		return fmt.Errorf("driver %q: duration must be positive", p.Driver)
	case p.RefreshBefore < 0 || p.RefreshBefore >= p.Duration:
		return fmt.Errorf("driver %q: refreshBefore must be at least zero and less than duration", p.Driver)
	}
	return nil
}

// Issued is a credential with the time atelet should replace it.
type Issued struct {
	Secrets    map[string]string
	ExpireTime time.Time
	// RefreshTime is zero when the profile does not refresh.
	RefreshTime time.Time
}

// Broker issues credentials for the external volumes of actors.
type Broker struct {
	profiles map[string]Profile
	now      func() time.Time
}

// NewBroker returns a Broker serving profiles, one per driver.
func NewBroker(profiles ...Profile) (*Broker, error) {
	b := &Broker{profiles: make(map[string]Profile, len(profiles)), now: time.Now}
	for _, p := range profiles {
		if err := p.validate(); err != nil {
			return nil, err
		}
		if _, dup := b.profiles[p.Driver]; dup {
			return nil, fmt.Errorf("driver %q has more than one profile", p.Driver)
		}
		b.profiles[p.Driver] = p
	}
	return b, nil
}

// Brokered reports whether volumes of driver are mounted with brokered
// credentials. A nil Broker brokers nothing.
func (b *Broker) Brokered(driver string) bool {
	if b == nil {
		return false
	}
	_, ok := b.profiles[driver]
	return ok
}

// Issue issues credentials for the actor's external volume volumeName. The
// caller has already established that it may act for the actor.
func (b *Broker) Issue(ctx context.Context, actor *ateapipb.Actor, volumeName string) (Issued, error) {
	var vol *ateapipb.ExternalVolume
	for _, v := range actor.GetStatus().GetExternalVolumes() {
		if v.GetName() == volumeName {
			vol = v
			break
		}
	}
	if vol == nil || vol.GetStorageVolumeId() == "" {
		return Issued{}, fmt.Errorf("%w: volume %q is not provisioned", ErrInvalidScope, volumeName)
	}
	if b == nil {
		return Issued{}, ErrNoProfile
	}
	profile, ok := b.profiles[vol.GetVolumeType()]
	if !ok {
		return Issued{}, ErrNoProfile
	}
	scope, err := scopeOf(profile, vol.GetVolumeContext())
	if err != nil {
		return Issued{}, err
	}
	cred, err := profile.Provider.Issue(ctx, Request{
		Scope:       scope,
		Duration:    profile.Duration,
		SessionName: "ate-" + actor.GetMetadata().GetUid(),
	})
	if err != nil {
		return Issued{}, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	now := b.now()
	if len(cred.Secrets) == 0 || !cred.Expiration.After(now) {
		return Issued{}, fmt.Errorf("%w: provider returned an empty or expired credential", ErrUnavailable)
	}
	issued := Issued{Secrets: cred.Secrets, ExpireTime: cred.Expiration}
	if profile.RefreshBefore > 0 {
		issued.RefreshTime = cred.Expiration.Add(-profile.RefreshBefore)
		if !issued.RefreshTime.After(now) {
			// The provider issued less than asked for; refresh halfway.
			issued.RefreshTime = now.Add(cred.Expiration.Sub(now) / 2)
		}
	}
	return issued, nil
}

// scopeOf derives the volume's scope from its recorded context. Prefixes are
// literal key prefixes: they are normalized to "a/b/" and rejected if they
// could be read as a pattern or a relative path.
func scopeOf(p Profile, volumeContext map[string]string) (Scope, error) {
	bucket := volumeContext[p.BucketKey]
	prefix := strings.Trim(volumeContext[p.PrefixKey], "/")
	if bucket == "" || prefix == "" || strings.ContainsAny(bucket+prefix, "*?$\\:\"'{} \t\r\n") {
		return Scope{}, ErrInvalidScope
	}
	for _, part := range strings.Split(prefix, "/") {
		if part == "" || part == "." || part == ".." {
			return Scope{}, ErrInvalidScope
		}
	}
	return Scope{Bucket: bucket, Prefix: prefix + "/", ReadOnly: p.ReadOnly}, nil
}

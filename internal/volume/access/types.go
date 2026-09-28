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

// Package access implements an experimental, process-local authorization broker.
// Executors and coherent resolver snapshots must come from trusted boundaries;
// this package does not authenticate callers or enforce backend access policies.
package access

import (
	"context"
	"errors"
	"time"
)

type Operations uint8

const (
	Read Operations = 1 << iota
	Write
	List
)

type Mode string

const (
	ReadOnly  Mode = "read-only"
	ReadWrite Mode = "read-write"
)

const StagePublishSecrets = "stage-publish-secrets-v1"
const SessionCredential = "session-v1"

var (
	ErrDenied         = errors.New("volume access denied")
	ErrUnsupported    = errors.New("volume access unsupported")
	ErrUnavailable    = errors.New("volume access unavailable")
	ErrInvalidRequest = errors.New("invalid volume access request")
)

type Executor struct{ Component, ClusterUID, NodeUID string }

type Request struct {
	BindingUID            string
	Revision              uint64
	ActivationUID         string
	Mode                  Mode
	MaxCredentialLifetime time.Duration
}

type Scope struct {
	Endpoint, Resource, Prefix, ListPrefix string
	Operations                             Operations
}

type Binding struct {
	UID                                           string
	Revision                                      uint64
	ActorUID, VolumeUID, GrantUID                 string
	ResourceGeneration                            uint64
	ClusterUID, NodeUID, WorkerUID, ActivationUID string
	Mode                                          Mode
	ExpiresAt                                     time.Time
}

type Grant struct {
	UID                           string
	Revision                      uint64
	ActorUID, VolumeUID, Atespace string
	Operations                    Operations
	ExpiresAt                     time.Time
	Revoked                       bool
}

type Assignment struct{ ActorUID, ClusterUID, NodeUID, WorkerUID, ActivationUID string }

type Volume struct {
	UID                                     string
	Generation                              uint64
	Atespace, OwnerActorUID, Driver, Handle string
	Scope                                   Scope
	Exclusive                               bool
}

// Profile supports only StagePublishSecrets for both Name and Delivery.
type Profile struct {
	Name                             string
	Version                          uint64
	Driver, CredentialKind, Delivery string
	MinLifetime, MaxLifetime         time.Duration
	ReadOperations, WriteOperations  Operations
}

// Snapshot is comparable and contains no mutable collections. Resolve must
// return a coherent snapshot of live authority, not an earlier approval.
type Snapshot struct {
	ActorUID, Atespace string
	PolicyRevision     uint64
	Binding            Binding
	Grant              Grant
	Assignment         Assignment
	Volume             Volume
	Profile            Profile
}

// Resolver reads current Substrate authority by immutable binding UID, not cloud
// credentials. Implementations must provide coherent snapshots and support
// concurrent calls. A stale TTL cache cannot establish current authorization.
// Missing state returns ErrDenied; other errors mean authority is unavailable.
type Resolver interface {
	Resolve(context.Context, string) (Snapshot, error)
}

type ApprovedAccess struct {
	BindingUID                                         string
	Revision                                           uint64
	ActorUID, ActivationUID, VolumeUID, Driver, Handle string
	Scope                                              Scope
	Profile                                            Profile
	Deadline                                           time.Time
	Mode                                               Mode
}

type Credential struct {
	Scope          Scope
	Kind           string
	ProfileName    string
	ProfileVersion uint64
	ExpiresAt      time.Time
	Secrets        map[string]string
}

// Provider receives a value-only approval. Returned secrets are copied before
// re-resolving authority; providers must not concurrently mutate that map.
// Acquire may run concurrently for independent bindings.
type Provider interface {
	Acquire(context.Context, ApprovedAccess) (Credential, error)
}

type Target struct{ ActorUID, ActivationUID, Driver, Handle string }

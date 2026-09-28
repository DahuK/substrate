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
	"context"
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/agent-substrate/substrate/internal/volume/access"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// AuthorizedMount is an opaque, process-local cleanup capability for one attempt.
// Keep it even when MountAuthorizedVolume returns an error. It contains no secrets.
type AuthorizedMount struct {
	driver, handle, targetPath, stagingPath string
}

func (AuthorizedMount) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("csi.AuthorizedMount[opaque]"))
}

// MountAuthorizedVolume is an experimental entry point, not wired into atelet.
// The caller supplies a trusted executor and runtime-owned target path. Use one
// Plugin per driver/node; do not mix protected and legacy operations on its handles.
// Nonconflicting attempts can run concurrently; there is no restart-safe reconciliation.
func (p *Plugin) MountAuthorizedVolume(ctx context.Context, broker *access.Broker, executor access.Executor, lease *access.Lease, target access.Target, targetPath string) (*AuthorizedMount, error) {
	if p == nil || p.client == nil {
		return nil, access.ErrUnavailable
	}
	if err := broker.CheckLease(ctx, executor, lease, target); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(targetPath) || filepath.Clean(targetPath) != targetPath || strings.ContainsRune(targetPath, 0) ||
		!filepath.IsAbs(p.stagingDirPrefix) || pathsOverlap(p.stagingDirPrefix, targetPath) {
		return nil, access.ErrInvalidRequest
	}
	driver, err := p.DriverName(ctx)
	if err != nil {
		return nil, access.ErrUnavailable
	}
	if driver != target.Driver {
		return nil, access.ErrDenied
	}
	// Encode the opaque driver/handle pair, never rewrite the handle sent to CSI.
	digest := sha256.Sum256([]byte(driver + "\x00" + target.Handle))
	stagingPath := filepath.Join(p.stagingDirPrefix, "protected", fmt.Sprintf("%x", digest))
	mount, err := p.reserveProtectedMount(AuthorizedMount{driver: driver, handle: target.Handle, targetPath: targetPath, stagingPath: stagingPath})
	if err != nil {
		return nil, err
	}
	// Even a pre-Stage revocation can leave a directory. Keep the owner on error.
	defer p.finishProtectedMount(mount, false)
	a := lease.Approved()
	err = p.mountVolume(ctx, target.Handle, targetPath, map[string]string{
		"endpoint": a.Scope.Endpoint, "resource": a.Scope.Resource, "prefix": a.Scope.Prefix,
	}, mountOptions{
		stagingPath: stagingPath, readonly: a.Mode == access.ReadOnly, protected: true,
		prepare: func() (map[string]string, error) {
			if err := broker.Validate(ctx, executor, lease, target); err != nil {
				return nil, err
			}
			return lease.Secrets(), nil
		},
	})
	return mount, err
}

// UnmountAuthorizedVolume requires the original attempt's cleanup capability,
// even after its authorization expires. Any failure leaves its reservation intact.
// An in-flight mount or cleanup for this owner returns ErrUnavailable; retry later.
// A successful fake-driver cleanup is not evidence of cloud revocation or fencing.
func (p *Plugin) UnmountAuthorizedVolume(ctx context.Context, mount *AuthorizedMount) error {
	if p == nil {
		return access.ErrDenied
	}
	p.protectedMu.Lock()
	record, ok := p.protectedMounts[mount]
	if !ok {
		p.protectedMu.Unlock()
		return access.ErrDenied
	}
	if record.busy {
		p.protectedMu.Unlock()
		return access.ErrUnavailable
	}
	record.busy = true
	p.protectedMounts[mount] = record
	p.protectedMu.Unlock()

	err := p.unmountVolume(ctx, record.handle, record.targetPath, record.stagingPath, true)
	p.finishProtectedMount(mount, err == nil)
	return err
}

type protectedMount struct {
	AuthorizedMount
	busy bool
}

// reserveProtectedMount atomically reserves canonical absolute target/stage paths.
// Only registry state is touched under protectedMu, never external calls or I/O.
func (p *Plugin) reserveProtectedMount(record AuthorizedMount) (*AuthorizedMount, error) {
	p.protectedMu.Lock()
	defer p.protectedMu.Unlock()
	key := [2]string{record.driver, record.handle}
	if _, exists := p.protectedHandles[key]; exists || p.protectedPaths.overlaps(record.targetPath) || p.protectedPaths.overlaps(record.stagingPath) {
		return nil, access.ErrUnsupported
	}
	if p.protectedMounts == nil {
		p.protectedMounts = make(map[*AuthorizedMount]protectedMount)
		p.protectedHandles = make(map[[2]string]struct{})
		p.protectedPaths = make(protectedPathIndex)
	}
	// The caller can overwrite the handle's value; only its pointer is authority.
	owner := new(AuthorizedMount)
	*owner = record
	p.protectedMounts[owner] = protectedMount{AuthorizedMount: record, busy: true}
	p.protectedHandles[key] = struct{}{}
	p.protectedPaths.add(record.targetPath, 1)
	p.protectedPaths.add(record.stagingPath, 1)
	return owner, nil
}

func (p *Plugin) finishProtectedMount(owner *AuthorizedMount, remove bool) {
	p.protectedMu.Lock()
	defer p.protectedMu.Unlock()
	record, ok := p.protectedMounts[owner]
	if !ok {
		return
	}
	if remove {
		delete(p.protectedMounts, owner)
		delete(p.protectedHandles, [2]string{record.driver, record.handle})
		p.protectedPaths.add(record.targetPath, -1)
		p.protectedPaths.add(record.stagingPath, -1)
	} else {
		record.busy = false
		p.protectedMounts[owner] = record
	}
}

// Each entry counts reservations at this path and in its subtree (including self).
// Lookups and updates visit only ancestors, independent of resident mount count.
type protectedPathIndex map[string]struct{ exact, subtree int }

func (index protectedPathIndex) overlaps(path string) bool {
	if index[path].subtree != 0 {
		return true
	}
	for {
		if index[path].exact != 0 {
			return true
		}
		parent := filepath.Dir(path)
		if parent == path {
			return false
		}
		path = parent
	}
}

func (index protectedPathIndex) add(path string, delta int) {
	entry := index[path]
	entry.exact += delta
	index[path] = entry
	for {
		entry = index[path]
		entry.subtree += delta
		if entry.subtree == 0 {
			delete(index, path)
		} else {
			index[path] = entry
		}
		parent := filepath.Dir(path)
		if parent == path {
			return
		}
		path = parent
	}
}

func pathsOverlap(a, b string) bool {
	a, b = filepath.Clean(a), filepath.Clean(b)
	return a == b || strings.HasPrefix(a, b+string(filepath.Separator)) || strings.HasPrefix(b, a+string(filepath.Separator)) || a == string(filepath.Separator) || b == string(filepath.Separator)
}

func csiOperationError(operation string, err error, protected bool) error {
	if protected {
		// Drivers can echo credential material in their status descriptions.
		if status.Code(err) == codes.Unimplemented {
			err = access.ErrUnsupported
		} else {
			err = access.ErrUnavailable
		}
	}
	return fmt.Errorf("CSI %s failed: %w", operation, err)
}

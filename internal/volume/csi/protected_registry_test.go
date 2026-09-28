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
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"sync"
	"testing"

	"github.com/agent-substrate/substrate/internal/volume/access"
)

func TestProtectedPathIndex(t *testing.T) {
	paths := []string{"/a/b", "/a/bc", "/a/d/e", "/ab/b", "/a/b", "/stage/protected/one", "/a", "/"}
	queries := []string{"/", "/a", "/a/b", "/a/b/child", "/a/bc", "/a/bcd", "/a/c", "/a/d", "/a/d/e", "/ab", "/ab/b", "/abc", "/stage", "/stage/protected", "/stage/protected/one", "/stage/protected/two", "/unrelated"}
	index := make(protectedPathIndex)
	var residents []string
	check := func() {
		t.Helper()
		for _, query := range queries {
			want := false
			for _, path := range residents {
				want = want || pathsOverlap(path, query)
			}
			if got := index.overlaps(query); got != want {
				t.Fatalf("overlaps(%q)=%v want %v with residents %v", query, got, want, residents)
			}
		}
	}
	if (protectedPathIndex)(nil).overlaps("/a/b") {
		t.Fatal("zero-value index overlaps")
	}
	check()
	for _, path := range paths {
		index.add(path, 1)
		residents = append(residents, path)
		check()
	}
	for len(residents) > 0 {
		index.add(residents[len(residents)-1], -1)
		residents = residents[:len(residents)-1]
		check()
	}
	if len(index) != 0 {
		t.Fatalf("empty index retained %d ancestor entries", len(index))
	}
}

func TestProtectedRegistryConflicts(t *testing.T) {
	first := AuthorizedMount{driver: "driver", handle: "one", targetPath: "/actors/a/volume", stagingPath: "/stage/protected/one"}
	independent := AuthorizedMount{driver: "driver", handle: "two", targetPath: "/actors/b/volume", stagingPath: "/stage/protected/two"}
	for _, tc := range []struct {
		name   string
		change func(*AuthorizedMount)
		allow  bool
	}{
		{"same_handle", func(m *AuthorizedMount) { m.handle = first.handle }, false},
		{"different_driver", func(m *AuthorizedMount) { m.driver, m.handle = "other-driver", first.handle }, true},
		{"target_equal", func(m *AuthorizedMount) { m.targetPath = first.targetPath }, false},
		{"target_parent", func(m *AuthorizedMount) { m.targetPath = filepath.Dir(first.targetPath) }, false},
		{"target_child", func(m *AuthorizedMount) { m.targetPath = first.targetPath + "/child" }, false},
		{"stage_equal", func(m *AuthorizedMount) { m.stagingPath = first.stagingPath }, false},
		{"stage_parent", func(m *AuthorizedMount) { m.stagingPath = filepath.Dir(first.stagingPath) }, false},
		{"stage_child", func(m *AuthorizedMount) { m.stagingPath = first.stagingPath + "/child" }, false},
		{"target_over_stage", func(m *AuthorizedMount) { m.targetPath = first.stagingPath }, false},
		{"stage_over_target", func(m *AuthorizedMount) { m.stagingPath = first.targetPath }, false},
		{"shared_ancestors", func(*AuthorizedMount) {}, true},
		{"component_not_prefix", func(m *AuthorizedMount) {
			m.targetPath, m.stagingPath = first.targetPath+"-other", first.stagingPath+"-other"
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &Plugin{}
			owner, err := p.reserveProtectedMount(first)
			if err != nil || !p.protectedMounts[owner].busy {
				t.Fatalf("initial reservation: %v", err)
			}
			paths, handles := maps.Clone(p.protectedPaths), maps.Clone(p.protectedHandles)
			candidate := independent
			tc.change(&candidate)
			next, err := p.reserveProtectedMount(candidate)
			if tc.allow {
				if err != nil || next == nil {
					t.Fatalf("independent reservation: %v", err)
				}
				p.finishProtectedMount(next, true)
			} else if next != nil || !errors.Is(err, access.ErrUnsupported) {
				t.Fatalf("conflict: owner=%v err=%v", next, err)
			}
			p.finishProtectedMount(owner, false)
			if len(p.protectedMounts) != 1 || p.protectedMounts[owner].busy || !maps.Equal(paths, p.protectedPaths) || !maps.Equal(handles, p.protectedHandles) {
				t.Fatal("failure or independent cleanup changed the retained reservation")
			}
			p.finishProtectedMount(owner, true)
			if len(p.protectedMounts) != 0 || len(p.protectedPaths) != 0 || len(p.protectedHandles) != 0 {
				t.Fatal("complete cleanup leaked index entries")
			}
			replacement, err := p.reserveProtectedMount(first)
			if err != nil {
				t.Fatal(err)
			}
			p.finishProtectedMount(owner, true)
			p.finishProtectedMount(owner, false)
			if len(p.protectedMounts) != 1 || !p.protectedMounts[replacement].busy || !maps.Equal(paths, p.protectedPaths) || !maps.Equal(handles, p.protectedHandles) {
				t.Fatal("old owner changed the replacement's state or indexes")
			}
		})
	}
}

// This measures registry reserve/release overhead only: no broker, RPC, filesystem
// or actual mount. The linear oracle models the old scan for comparison, not a
// production fallback. Resident setup and path generation are outside the timer.
func BenchmarkProtectedRegistry(b *testing.B) {
	for _, count := range []int{1000, 10000} {
		b.Run(fmt.Sprintf("residents_%d", count), func(b *testing.B) {
			residents := make([]AuthorizedMount, count)
			for i := range residents {
				residents[i] = AuthorizedMount{
					driver: "driver", handle: fmt.Sprintf("handle-%08d", i),
					targetPath:  fmt.Sprintf("/run/substrate/actors/%08d/volumes/data", i),
					stagingPath: fmt.Sprintf("/var/lib/substrate/staging/protected/%064x", i),
				}
			}
			candidate := AuthorizedMount{driver: "driver", handle: "next", targetPath: "/run/substrate/actors/next/volumes/data", stagingPath: "/var/lib/substrate/staging/protected/next"}
			b.Run("indexed", func(b *testing.B) {
				p := &Plugin{}
				for _, record := range residents {
					if _, err := p.reserveProtectedMount(record); err != nil {
						b.Fatal(err)
					}
				}
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					owner, err := p.reserveProtectedMount(candidate)
					if err != nil {
						b.Fatal(err)
					}
					p.finishProtectedMount(owner, true)
				}
			})
			b.Run("linear_oracle", func(b *testing.B) {
				mounts := make(map[*AuthorizedMount]AuthorizedMount, count+1)
				for _, record := range residents {
					owner := new(AuthorizedMount)
					*owner = record
					mounts[owner] = record
				}
				var mu sync.Mutex
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					mu.Lock()
					for _, record := range mounts {
						if record.driver == candidate.driver && record.handle == candidate.handle || pathsOverlap(record.targetPath, candidate.targetPath) || pathsOverlap(record.stagingPath, candidate.stagingPath) {
							b.Fatal("unexpected oracle conflict")
						}
					}
					owner := new(AuthorizedMount)
					*owner = candidate
					mounts[owner] = candidate
					mu.Unlock()
					mu.Lock()
					delete(mounts, owner)
					mu.Unlock()
				}
			})
		})
	}
}

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

package access_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/agent-substrate/substrate/internal/volume/access"
)

// An indexed, immutable fixture isolates broker CPU/allocation cost. It is not a
// production authority store and does not measure database or cloud latency.
type benchmarkResolver map[string]access.Snapshot

func (r benchmarkResolver) Resolve(_ context.Context, uid string) (access.Snapshot, error) {
	state, ok := r[uid]
	if !ok {
		return access.Snapshot{}, access.ErrDenied
	}
	return state, nil
}

func BenchmarkValidate(b *testing.B) {
	for _, size := range []int{1, 1000, 10000} {
		b.Run(fmt.Sprintf("bindings=%d", size), func(b *testing.B) {
			f := newFixture()
			states := make(benchmarkResolver, size)
			broker := access.NewBroker(states, f, func() time.Time { return f.now })
			leases := make([]*access.Lease, size)
			targets := make([]access.Target, size)
			ctx := context.Background()
			for i := range size {
				uid := fmt.Sprintf("binding-%d", i)
				actor := fmt.Sprintf("actor-%d", i)
				s := f.state
				s.ActorUID, s.Binding.ActorUID, s.Grant.ActorUID, s.Assignment.ActorUID, s.Volume.OwnerActorUID = actor, actor, actor, actor, actor
				s.Binding.UID, s.Binding.GrantUID, s.Grant.UID = uid, uid+"-grant", uid+"-grant"
				s.Binding.VolumeUID, s.Grant.VolumeUID, s.Volume.UID, s.Volume.Handle = uid+"-volume", uid+"-volume", uid+"-volume", uid+"-handle"
				s.Volume.Scope.Prefix, s.Volume.Scope.ListPrefix = actor+"/", actor+"/"
				states[uid] = s
				request := f.request
				request.BindingUID = uid
				lease, err := broker.Exchange(ctx, f.executor, request)
				if err != nil {
					b.Fatal(err)
				}
				leases[i] = lease
				targets[i] = access.Target{ActorUID: actor, ActivationUID: s.Binding.ActivationUID, Driver: s.Volume.Driver, Handle: s.Volume.Handle}
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				index := i % size
				if err := broker.Validate(ctx, f.executor, leases[index], targets[index]); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkExchange(b *testing.B) {
	f := newFixture()
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := f.broker.Exchange(ctx, f.executor, f.request); err != nil {
			b.Fatal(err)
		}
	}
}

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

package controlapi

import (
	"testing"

	"github.com/agent-substrate/substrate/internal/proto/ateletpb"
)

type brokeredDrivers map[string]bool

func (d brokeredDrivers) Brokered(driver string) bool { return d[driver] }

func TestMarkBrokeredVolumes(t *testing.T) {
	newSpec := func() *ateletpb.WorkloadSpec {
		return &ateletpb.WorkloadSpec{Volumes: []*ateletpb.Volume{
			{Name: "oss", Source: &ateletpb.Volume_External{External: &ateletpb.ExternalVolumeSource{VolumeType: "oss.csi"}}},
			{Name: "disk", Source: &ateletpb.Volume_External{External: &ateletpb.ExternalVolumeSource{VolumeType: "disk.csi"}}},
			{Name: "scratch", Source: &ateletpb.Volume_DurableDir{DurableDir: &ateletpb.DurableDirVolume{}}},
		}}
	}

	spec := newSpec()
	markBrokeredVolumes(spec, brokeredDrivers{"oss.csi": true})
	if !spec.GetVolumes()[0].GetExternal().GetBrokeredCredentials() {
		t.Error("volume of a brokered driver is not marked")
	}
	if spec.GetVolumes()[1].GetExternal().GetBrokeredCredentials() {
		t.Error("volume of another driver is marked")
	}

	spec = newSpec()
	markBrokeredVolumes(spec, nil)
	for _, v := range spec.GetVolumes() {
		if v.GetExternal().GetBrokeredCredentials() {
			t.Errorf("volume %q marked with no broker", v.GetName())
		}
	}
}

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

package authz

import (
	"testing"

	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"github.com/google/go-cmp/cmp"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

func TestExternalVolumeChecks(t *testing.T) {
	ref := &ateapipb.ObjectRef{Atespace: "team-a", Name: "corpus"}
	path := field.NewPath("external_volume")
	vol := "external_volume:team-a/corpus"

	tests := []struct {
		name      string
		checks    func() ([]check, field.ErrorList)
		want      []check
		wantField string
	}{
		{
			name:   "create provisions through a storage class",
			checks: func() ([]check, field.ErrorList) { return externalVolumeCreateChecks("team-a", false, path) },
			want:   []check{{RelationCanCreateExternalVolume, "atespace:team-a"}},
		},
		{
			name:   "create imports an existing volume ID",
			checks: func() ([]check, field.ErrorList) { return externalVolumeCreateChecks("team-a", true, path) },
			want: []check{
				{RelationCanCreateExternalVolume, "atespace:team-a"},
				{RelationCanImportExternalVolume, GlobalRootObject},
			},
		},
		{
			name:      "create without an atespace",
			checks:    func() ([]check, field.ErrorList) { return externalVolumeCreateChecks("", true, path) },
			wantField: "external_volume",
		},
		{
			name:   "get",
			checks: func() ([]check, field.ErrorList) { return onExternalVolume(RelationCanGet, ref, path) },
			want:   []check{{RelationCanGet, vol}},
		},
		{
			name:   "delete",
			checks: func() ([]check, field.ErrorList) { return onExternalVolume(RelationCanDelete, ref, path) },
			want:   []check{{RelationCanDelete, vol}},
		},
		{
			name: "get with an invalid name",
			checks: func() ([]check, field.ErrorList) {
				return onExternalVolume(RelationCanGet, &ateapipb.ObjectRef{Atespace: "team-a", Name: "Corpus"}, path)
			},
			wantField: "external_volume.name",
		},
		{
			name:   "update keeps the delete trigger",
			checks: func() ([]check, field.ErrorList) { return externalVolumeUpdateChecks(ref, false, path) },
			want:   []check{{RelationCanUpdate, vol}},
		},
		{
			name:   "update sets the last-actor delete trigger",
			checks: func() ([]check, field.ErrorList) { return externalVolumeUpdateChecks(ref, true, path) },
			want:   []check{{RelationCanUpdate, vol}, {RelationCanDelete, vol}},
		},
		{
			name: "update without an atespace",
			checks: func() ([]check, field.ErrorList) {
				return externalVolumeUpdateChecks(&ateapipb.ObjectRef{Name: "corpus"}, true, path)
			},
			wantField: "external_volume.atespace",
		},
		{
			name: "bindings are checked once each in sorted order",
			checks: func() ([]check, field.ErrorList) {
				return externalVolumeBindingChecks("team-a", []string{"corpus", "ctx", "corpus"}, field.NewPath("actor"))
			},
			want: []check{{RelationCanMount, vol}, {RelationCanMount, "external_volume:team-a/ctx"}},
		},
		{
			name: "no bindings",
			checks: func() ([]check, field.ErrorList) {
				return externalVolumeBindingChecks("team-a", nil, field.NewPath("actor"))
			},
			want: []check{},
		},
		{
			name: "a binding with an invalid volume name",
			checks: func() ([]check, field.ErrorList) {
				return externalVolumeBindingChecks("team-a", []string{"ctx", "../other"}, field.NewPath("actor"))
			},
			wantField: "actor.external_volume_bindings[../other]",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, errs := tc.checks()
			if tc.wantField != "" {
				if len(errs) == 0 {
					t.Fatalf("checks = %v, want a validation error on %s", got, tc.wantField)
				}
				if errs[0].Field != tc.wantField {
					t.Errorf("error field = %q, want %q (%v)", errs[0].Field, tc.wantField, errs)
				}
				if got != nil {
					t.Errorf("checks = %v alongside errors, want none", got)
				}
				return
			}
			if len(errs) > 0 {
				t.Fatalf("unexpected errors: %v", errs)
			}
			if diff := cmp.Diff(tc.want, got, cmp.AllowUnexported(check{})); diff != "" {
				t.Errorf("checks mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

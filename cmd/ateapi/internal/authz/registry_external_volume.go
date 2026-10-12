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
	"slices"

	"k8s.io/apimachinery/pkg/util/validation/field"
)

// Checks for the atespace-scoped ExternalVolume RPCs and for the volumes an
// actor binds at CreateActor. Each builder takes the request fields its
// extractor reads, so a defaultRPCPermissions entry is one checksOf call.
// Listing uses onAtespaceOrGlobal with RelationCanListExternalVolumes.

// externalVolumeCreateChecks requires can_create_external_volume on the
// atespace. Importing a volume that already exists in the storage system (the
// request names its volume ID) also requires can_import_external_volume on
// global:root: the ID can name any volume the driver reaches, including one
// another atespace or tenant uses.
func externalVolumeCreateChecks(atespace string, imported bool, fldPath *field.Path) ([]check, field.ErrorList) {
	checks, errs := onAtespace(RelationCanCreateExternalVolume, atespace, fldPath)
	if len(errs) > 0 || !imported {
		return checks, errs
	}
	return append(checks, check{relation: RelationCanImportExternalVolume, object: GlobalRootObject}), nil
}

// onExternalVolume checks relation on one external volume.
func onExternalVolume(relation string, ref resourceRef, fldPath *field.Path) ([]check, field.ErrorList) {
	if errs := validateRef(ref, fldPath); len(errs) > 0 {
		return nil, errs
	}
	return []check{{relation: relation, object: ExternalVolumeObject(ref.GetAtespace(), ref.GetName())}}, nil
}

// externalVolumeUpdateChecks requires can_update on the volume. Setting the
// last-actor delete trigger also requires can_delete: it hands the deletion of
// the storage volume to whoever deletes the volume's last actor.
func externalVolumeUpdateChecks(ref resourceRef, lastActorTrigger bool, fldPath *field.Path) ([]check, field.ErrorList) {
	checks, errs := onExternalVolume(RelationCanUpdate, ref, fldPath)
	if len(errs) > 0 || !lastActorTrigger {
		return checks, errs
	}
	return append(checks, check{relation: RelationCanDelete, object: checks[0].object}), nil
}

// externalVolumeBindingChecks requires can_mount on each external volume an
// actor in atespace binds by name. Bound volumes always live in the actor's
// own atespace. Names are checked once each, in sorted order.
//
// The names a template fixes in its volume refs are not in the CreateActor
// request; the handler checks those after resolving the template, against the
// actor's atespace and the caller's own principal.
func externalVolumeBindingChecks(atespace string, names []string, fldPath *field.Path) ([]check, field.ErrorList) {
	errs := validateName(atespace, fldPath.Child("metadata", "atespace"))
	sorted := slices.Sorted(slices.Values(names))
	sorted = slices.Compact(sorted)
	for _, name := range sorted {
		errs = append(errs, validateName(name, fldPath.Child("external_volume_bindings").Key(name))...)
	}
	if len(errs) > 0 {
		return nil, errs
	}
	checks := make([]check, 0, len(sorted))
	for _, name := range sorted {
		checks = append(checks, check{relation: RelationCanMount, object: ExternalVolumeObject(atespace, name)})
	}
	return checks, nil
}

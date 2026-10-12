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

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/agent-substrate/substrate/cmd/ateapi/internal/volumecred"
	"github.com/agent-substrate/substrate/cmd/ateapi/internal/volumecred/aliyunoss"
)

// volumeCredentialConfig is the --volume-credential-config file: one profile
// per CSI driver whose volumes are mounted with brokered credentials.
type volumeCredentialConfig struct {
	Profiles []volumeCredentialProfile `json:"profiles"`
}

type volumeCredentialProfile struct {
	Driver               string `json:"driver"`
	BucketContextKey     string `json:"bucketContextKey"`
	PrefixContextKey     string `json:"prefixContextKey"`
	ReadOnly             bool   `json:"readOnly,omitempty"`
	DurationSeconds      int64  `json:"durationSeconds"`
	RefreshBeforeSeconds int64  `json:"refreshBeforeSeconds,omitempty"`

	// Exactly one provider is set.
	AliyunOSS *aliyunoss.Config `json:"aliyunOSS,omitempty"`
}

// loadVolumeCredentialBroker reads the config at path. An empty path disables
// brokered credentials and returns a nil Broker.
func loadVolumeCredentialBroker(path string) (*volumecred.Broker, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var cfg volumeCredentialConfig
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	if len(cfg.Profiles) == 0 {
		return nil, errors.New("no profiles configured")
	}
	profiles := make([]volumecred.Profile, 0, len(cfg.Profiles))
	for _, p := range cfg.Profiles {
		if p.AliyunOSS == nil {
			return nil, fmt.Errorf("driver %q: no provider configured", p.Driver)
		}
		provider, err := aliyunoss.New(*p.AliyunOSS)
		if err != nil {
			return nil, fmt.Errorf("driver %q: %w", p.Driver, err)
		}
		profiles = append(profiles, volumecred.Profile{
			Driver:        p.Driver,
			Provider:      provider,
			BucketKey:     p.BucketContextKey,
			PrefixKey:     p.PrefixContextKey,
			ReadOnly:      p.ReadOnly,
			Duration:      time.Duration(p.DurationSeconds) * time.Second,
			RefreshBefore: time.Duration(p.RefreshBeforeSeconds) * time.Second,
		})
	}
	return volumecred.NewBroker(profiles...)
}

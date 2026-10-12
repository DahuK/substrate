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
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validVolumeCredentialConfig = `{
  "profiles": [{
    "driver": "ossplugin.csi.alibabacloud.com",
    "bucketContextKey": "bucket",
    "prefixContextKey": "path",
    "durationSeconds": 3600,
    "refreshBeforeSeconds": 900,
    "aliyunOSS": {
      "roleArn": "acs:ram::1234567890:role/substrate-volumes",
      "oidcProviderArn": "acs:ram::1234567890:oidc-provider/ack-rrsa-c1",
      "oidcTokenFile": "/var/run/secrets/ack.alibabacloud.com/rrsa-tokens/token",
      "stsEndpoint": "https://sts-vpc.cn-hangzhou.aliyuncs.com",
      "secretKeys": {"accessKeyId": "akId", "accessKeySecret": "akSecret", "securityToken": "securityToken"}
    }
  }]
}`

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "volume-credentials.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadVolumeCredentialBroker(t *testing.T) {
	b, err := loadVolumeCredentialBroker("")
	if err != nil || b != nil {
		t.Fatalf("empty path = %v, %v; want disabled", b, err)
	}

	b, err = loadVolumeCredentialBroker(writeConfig(t, validVolumeCredentialConfig))
	if err != nil {
		t.Fatalf("valid config: %v", err)
	}
	if !b.Brokered("ossplugin.csi.alibabacloud.com") || b.Brokered("diskplugin.csi.alibabacloud.com") {
		t.Error("brokered drivers do not match the config")
	}

	for name, content := range map[string]string{
		"not json":         "{",
		"unknown field":    strings.Replace(validVolumeCredentialConfig, `"durationSeconds"`, `"lifetime": 1, "durationSeconds"`, 1),
		"no profiles":      `{"profiles": []}`,
		"no provider":      `{"profiles": [{"driver": "d", "bucketContextKey": "b", "prefixContextKey": "p", "durationSeconds": 3600}]}`,
		"invalid provider": strings.Replace(validVolumeCredentialConfig, "https://sts-vpc", "http://sts-vpc", 1),
		"invalid profile":  strings.Replace(validVolumeCredentialConfig, `"refreshBeforeSeconds": 900`, `"refreshBeforeSeconds": 3600`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadVolumeCredentialBroker(writeConfig(t, content)); err == nil {
				t.Error("loaded an invalid config")
			}
		})
	}
	if _, err := loadVolumeCredentialBroker(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Error("loaded a missing file")
	}
}

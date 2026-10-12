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

package aliyunoss

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agent-substrate/substrate/cmd/ateapi/internal/volumecred"
	"github.com/google/go-cmp/cmp"
)

const (
	testRole     = "acs:ram::1234567890:role/substrate-volumes"
	testProvider = "acs:ram::1234567890:oidc-provider/ack-rrsa-c1"
	testToken    = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln"
)

var testKeys = SecretKeys{AccessKeyID: "akId", AccessKeySecret: "akSecret", SecurityToken: "securityToken"}

// fakeSTS records AssumeRoleWithOIDC calls and answers with handler.
type fakeSTS struct {
	mu      sync.Mutex
	queries []url.Values
	forms   []url.Values
	handler func(w http.ResponseWriter)
}

func (f *fakeSTS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	f.queries = append(f.queries, r.URL.Query())
	f.forms = append(f.forms, r.PostForm)
	f.mu.Unlock()
	f.handler(w)
}

func credentialsResponse(expire time.Time) func(w http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		fmt.Fprintf(w, `{"RequestId":"r-1","Credentials":{"AccessKeyId":"STS.id","AccessKeySecret":"secret","SecurityToken":"token","Expiration":%q}}`,
			expire.UTC().Format(time.RFC3339))
	}
}

func newTestProvider(t *testing.T, sts *fakeSTS, mutate ...func(*Config)) *Provider {
	t.Helper()
	srv := httptest.NewTLSServer(sts)
	t.Cleanup(srv.Close)
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte(testToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		RoleARN:         testRole,
		OIDCProviderARN: testProvider,
		OIDCTokenFile:   tokenFile,
		STSEndpoint:     srv.URL,
		BucketOwnerID:   "1234567890",
		SecretKeys:      testKeys,
		HTTPClient:      srv.Client(),
	}
	for _, m := range mutate {
		m(&cfg)
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

type policyDoc struct {
	Version   string
	Statement []struct {
		Effect    string
		Action    []string
		Resource  []string
		Condition map[string]map[string]string
	}
}

func TestIssue(t *testing.T) {
	expire := time.Now().Add(time.Hour).Truncate(time.Second)
	for _, readOnly := range []bool{true, false} {
		t.Run(fmt.Sprintf("readOnly=%v", readOnly), func(t *testing.T) {
			sts := &fakeSTS{handler: credentialsResponse(expire)}
			p := newTestProvider(t, sts, func(c *Config) { c.SecretKeys.Expiration = "expiration" })

			cred, err := p.Issue(context.Background(), volumecred.Request{
				Scope:       volumecred.Scope{Bucket: "team-a-data", Prefix: "vols/data/", ReadOnly: readOnly},
				Duration:    time.Hour,
				SessionName: "ate-3c9a1f2e-4b5d-4e6f-8a7b-9c0d1e2f3a4b",
			})
			if err != nil {
				t.Fatalf("Issue: %v", err)
			}
			wantSecrets := map[string]string{
				"akId": "STS.id", "akSecret": "secret", "securityToken": "token",
				"expiration": expire.UTC().Format(time.RFC3339),
			}
			if diff := cmp.Diff(wantSecrets, cred.Secrets); diff != "" {
				t.Errorf("secrets mismatch (-want +got):\n%s", diff)
			}
			if !cred.Expiration.Equal(expire) {
				t.Errorf("expiration = %v, want %v", cred.Expiration, expire)
			}

			if len(sts.forms) != 1 {
				t.Fatalf("STS calls = %d, want 1", len(sts.forms))
			}
			q, form := sts.queries[0], sts.forms[0]
			if q.Get("Action") != "AssumeRoleWithOIDC" || q.Get("OIDCToken") != "" {
				t.Errorf("query = %v; want the action and no token in the URL", q)
			}
			for key, want := range map[string]string{
				"RoleArn":         testRole,
				"OIDCProviderArn": testProvider,
				"OIDCToken":       testToken,
				"RoleSessionName": "ate-3c9a1f2e-4b5d-4e6f-8a7b-9c0d1e2f3a4b",
				"DurationSeconds": "3600",
			} {
				if got := form.Get(key); got != want {
					t.Errorf("form %s = %q, want %q", key, got, want)
				}
			}

			var policy policyDoc
			if err := json.Unmarshal([]byte(form.Get("Policy")), &policy); err != nil {
				t.Fatalf("session policy is not JSON: %v", err)
			}
			if len(policy.Statement) != 2 {
				t.Fatalf("statements = %d, want 2", len(policy.Statement))
			}
			objects, list := policy.Statement[0], policy.Statement[1]
			wantActions := []string{"oss:GetObject"}
			if !readOnly {
				wantActions = append(wantActions, "oss:PutObject", "oss:DeleteObject", "oss:AbortMultipartUpload", "oss:ListParts")
			}
			if diff := cmp.Diff(wantActions, objects.Action); diff != "" {
				t.Errorf("object actions mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff([]string{"acs:oss:*:1234567890:team-a-data/vols/data/*"}, objects.Resource); diff != "" {
				t.Errorf("object resources mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff([]string{"oss:ListObjects"}, list.Action); diff != "" {
				t.Errorf("list actions mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff([]string{"acs:oss:*:1234567890:team-a-data"}, list.Resource); diff != "" {
				t.Errorf("list resources mismatch (-want +got):\n%s", diff)
			}
			if got := list.Condition["StringLike"]["oss:Prefix"]; got != "vols/data/*" {
				t.Errorf("list prefix condition = %q, want %q", got, "vols/data/*")
			}
			for _, s := range policy.Statement {
				if s.Condition["Bool"]["acs:SecureTransport"] != "true" {
					t.Errorf("statement %v does not require HTTPS", s.Action)
				}
			}
		})
	}
}

func TestIssueRejectsWithoutCallingSTS(t *testing.T) {
	scope := volumecred.Scope{Bucket: "team-a-data", Prefix: "vols/data/"}
	session := "ate-3c9a1f2e-4b5d-4e6f-8a7b-9c0d1e2f3a4b"
	for name, req := range map[string]volumecred.Request{
		"short duration":       {Scope: scope, Duration: 10 * time.Minute, SessionName: session},
		"long duration":        {Scope: scope, Duration: 13 * time.Hour, SessionName: session},
		"bad session name":     {Scope: scope, Duration: time.Hour, SessionName: "a b"},
		"invalid bucket":       {Scope: volumecred.Scope{Bucket: "Team_A", Prefix: "p/"}, Duration: time.Hour, SessionName: session},
		"wildcard prefix":      {Scope: volumecred.Scope{Bucket: "team-a-data", Prefix: "p*/"}, Duration: time.Hour, SessionName: session},
		"prefix without slash": {Scope: volumecred.Scope{Bucket: "team-a-data", Prefix: "p"}, Duration: time.Hour, SessionName: session},
		"oversized policy":     {Scope: volumecred.Scope{Bucket: "team-a-data", Prefix: strings.Repeat("a", 1100) + "/"}, Duration: time.Hour, SessionName: session},
	} {
		t.Run(name, func(t *testing.T) {
			sts := &fakeSTS{handler: credentialsResponse(time.Now().Add(time.Hour))}
			p := newTestProvider(t, sts)
			if _, err := p.Issue(context.Background(), req); err == nil {
				t.Fatal("Issue succeeded, want an error")
			}
			if len(sts.forms) != 0 {
				t.Errorf("STS called %d times for a rejected request", len(sts.forms))
			}
		})
	}
}

func TestIssueSTSFailures(t *testing.T) {
	req := volumecred.Request{
		Scope:       volumecred.Scope{Bucket: "team-a-data", Prefix: "vols/data/"},
		Duration:    time.Hour,
		SessionName: "ate-3c9a1f2e-4b5d-4e6f-8a7b-9c0d1e2f3a4b",
	}
	for name, handler := range map[string]func(w http.ResponseWriter){
		"refused": func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `{"Code":"AuthenticationFail.OIDCToken.Invalid","Message":"bad token","RequestId":"r-2"}`)
		},
		"expired credential": credentialsResponse(time.Now().Add(-time.Minute)),
		"incomplete credential": func(w http.ResponseWriter) {
			fmt.Fprint(w, `{"Credentials":{"AccessKeyId":"STS.id","Expiration":"2099-01-01T00:00:00Z"}}`)
		},
		"redirect": func(w http.ResponseWriter) {
			w.Header().Set("Location", "https://example.com/")
			w.WriteHeader(http.StatusFound)
		},
		"not json": func(w http.ResponseWriter) { fmt.Fprint(w, "<html>") },
	} {
		t.Run(name, func(t *testing.T) {
			p := newTestProvider(t, &fakeSTS{handler: handler})
			if _, err := p.Issue(context.Background(), req); err == nil {
				t.Fatal("Issue succeeded, want an error")
			}
		})
	}

	t.Run("missing token file", func(t *testing.T) {
		sts := &fakeSTS{handler: credentialsResponse(time.Now().Add(time.Hour))}
		p := newTestProvider(t, sts, func(c *Config) { c.OIDCTokenFile = "/nonexistent/token" })
		if _, err := p.Issue(context.Background(), req); err == nil {
			t.Fatal("Issue succeeded without a token")
		}
		if len(sts.forms) != 0 {
			t.Error("STS called without a token")
		}
	})
}

func TestNewValidation(t *testing.T) {
	base := Config{
		RoleARN:         testRole,
		OIDCProviderARN: testProvider,
		OIDCTokenFile:   "/var/run/token",
		STSEndpoint:     "https://sts-vpc.cn-hangzhou.aliyuncs.com",
		SecretKeys:      testKeys,
	}
	if _, err := New(base); err != nil {
		t.Fatalf("New(valid) = %v", err)
	}
	for name, mutate := range map[string]func(*Config){
		"bad role":           func(c *Config) { c.RoleARN = "role" },
		"bad provider":       func(c *Config) { c.OIDCProviderARN = "provider" },
		"accounts differ":    func(c *Config) { c.OIDCProviderARN = "acs:ram::999:oidc-provider/x" },
		"bad owner":          func(c *Config) { c.BucketOwnerID = "owner" },
		"relative token":     func(c *Config) { c.OIDCTokenFile = "token" },
		"http endpoint":      func(c *Config) { c.STSEndpoint = "http://sts.cn-hangzhou.aliyuncs.com" },
		"endpoint path":      func(c *Config) { c.STSEndpoint = "https://sts.cn-hangzhou.aliyuncs.com/x" },
		"missing secret key": func(c *Config) { c.SecretKeys.SecurityToken = "" },
	} {
		t.Run(name, func(t *testing.T) {
			c := base
			mutate(&c)
			if _, err := New(c); err == nil {
				t.Error("New accepted an invalid config")
			}
		})
	}
}

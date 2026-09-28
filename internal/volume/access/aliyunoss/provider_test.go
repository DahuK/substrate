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

package aliyunoss

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"

	"github.com/agent-substrate/substrate/internal/volume/access"
)

const secretMarker = "SYNTHETIC-SECRET-MARKER"

// This literal is an independent wire-policy expectation, not a call to the builder.
const policyTemplate = `{"Version":"1","Statement":[{"Effect":"Allow","Action":["oss:GetObject"],"Resource":["acs:oss:*:9876543210987654:%s/%s*"],"Condition":{"Bool":{"acs:SecureTransport":"true"}}},{"Effect":"Allow","Action":["oss:ListObjects"],"Resource":["acs:oss:*:9876543210987654:%s"],"Condition":{"Bool":{"acs:SecureTransport":"true"},"StringLike":{"oss:Prefix":["%s*"]}}}]}`

var testNow = time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)

func testConfig() (Config, access.ApprovedAccess) {
	cfg := Config{
		RoleARN: "acs:ram::1234567890123456:role/substrate", OIDCProviderARN: "acs:ram::1234567890123456:oidc-provider/cluster", BucketOwnerID: "9876543210987654",
		STSEndpoint: "https://sts.example.invalid", OSSEndpoint: "https://oss.example.invalid", MaxSessionDuration: time.Hour, RequestTimeout: time.Second,
		TokenSource: func(context.Context) (string, error) { return secretMarker + "-oidc", nil },
		Profile: access.Profile{Name: access.StagePublishSecrets, Version: 1, Driver: "oss-test-driver", CredentialKind: access.SessionCredential, Delivery: access.StagePublishSecrets,
			MinLifetime: 15 * time.Minute, MaxLifetime: time.Hour, ReadOperations: access.Read | access.List, WriteOperations: access.Read | access.Write | access.List},
	}
	a := access.ApprovedAccess{BindingUID: "binding", Revision: 2, ActorUID: "actor", ActivationUID: "activation", VolumeUID: "volume", Driver: cfg.Profile.Driver, Handle: "dataset",
		Mode: access.ReadOnly, Profile: cfg.Profile, Deadline: testNow.Add(30 * time.Minute),
		Scope: access.Scope{Endpoint: cfg.OSSEndpoint, Resource: "dataset-bucket", Prefix: "actors/actor/dataset/", ListPrefix: "actors/actor/dataset/", Operations: access.Read | access.List}}
	return cfg, a
}

func testProvider(t *testing.T, cfg Config) *Provider {
	t.Helper()
	p, err := New(cfg)
	if err != nil {
		t.Fatal("valid configuration rejected")
	}
	p.now = func() time.Time { return testNow }
	return p
}

func testResponse(expiry time.Time) string {
	return fmt.Sprintf(`{"Credentials":{"AccessKeyId":%q,"AccessKeySecret":%q,"SecurityToken":%q,"Expiration":%q}}`, secretMarker+"-access", secretMarker+"-secret", secretMarker+"-session", expiry.Format(time.RFC3339Nano))
}

func assertFailure(t *testing.T, c access.Credential, err, want error) {
	t.Helper()
	if err != want {
		t.Error("failure did not return the exact expected sentinel")
	}
	if !reflect.DeepEqual(c, access.Credential{}) {
		t.Error("failure returned a partial credential")
	}
	if strings.Contains(fmt.Sprintf("%v %+v %#v", err, err, err), secretMarker) {
		t.Error("failure exposed secret material")
	}
}

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type observedBody struct {
	io.ReadCloser
	closed  bool
	bytes   int
	onClose func() error
}

func (b *observedBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.bytes += n
	return n, err
}

func (b *observedBody) Close() error {
	b.closed = true
	err := b.ReadCloser.Close()
	if b.onClose != nil {
		return b.onClose()
	}
	return err
}

func TestDeliveryCheckedAfterResponseClose(t *testing.T) {
	for _, tc := range []struct {
		name     string
		elapsed  time.Duration
		cancel   bool
		closeErr error
		want     error
	}{
		{name: "cleanup cancels request", cancel: true, want: access.ErrUnavailable},
		{name: "cleanup outlasts expiration", elapsed: 21 * time.Minute, want: access.ErrDenied},
		{name: "cleanup consumes minimum lifetime", elapsed: 6 * time.Minute, want: access.ErrDenied},
		{name: "cleanup fails", closeErr: errors.New(secretMarker), want: access.ErrUnavailable},
		{name: "cleanup leaves sufficient lifetime", elapsed: time.Minute},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, a := testConfig()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			now := testNow
			body := &observedBody{
				ReadCloser: io.NopCloser(strings.NewReader(testResponse(testNow.Add(20 * time.Minute)))),
				onClose: func() error {
					now = now.Add(tc.elapsed)
					if tc.cancel {
						cancel()
					}
					return tc.closeErr
				},
			}
			cfg.HTTPClient = &http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Body: body}, nil
			})}
			p := testProvider(t, cfg)
			p.now = func() time.Time { return now }
			credential, err := p.Acquire(ctx, a)
			if tc.want != nil {
				assertFailure(t, credential, err, tc.want)
			} else if err != nil || !credential.ExpiresAt.Equal(testNow.Add(20*time.Minute)) {
				t.Error("valid credential was rejected or its expiration was relabeled")
			}
			if !body.closed {
				t.Error("response cleanup was skipped")
			}
		})
	}
}

func TestConfig(t *testing.T) {
	for name, change := range map[string]func(*Config){
		"zero":                  func(c *Config) { *c = Config{} },
		"role missing":          func(c *Config) { c.RoleARN = "" },
		"role wildcard":         func(c *Config) { c.RoleARN = "acs:ram::1234567890123456:role/*" },
		"role type":             func(c *Config) { c.RoleARN = "acs:ram::1234567890123456:user/substrate" },
		"role account":          func(c *Config) { c.RoleARN = "acs:ram::abc:role/substrate" },
		"role too long":         func(c *Config) { c.RoleARN += strings.Repeat("a", 128) },
		"OIDC missing":          func(c *Config) { c.OIDCProviderARN = "" },
		"OIDC type":             func(c *Config) { c.OIDCProviderARN = c.RoleARN },
		"OIDC wildcard":         func(c *Config) { c.OIDCProviderARN = "acs:ram::1234567890123456:oidc-provider/*" },
		"OIDC foreign account":  func(c *Config) { c.OIDCProviderARN = "acs:ram::1:oidc-provider/cluster" },
		"owner missing":         func(c *Config) { c.BucketOwnerID = "" },
		"owner invalid":         func(c *Config) { c.BucketOwnerID = "*" },
		"source":                func(c *Config) { c.TokenSource = nil },
		"profile missing":       func(c *Config) { c.Profile = access.Profile{} },
		"profile name":          func(c *Config) { c.Profile.Name = "other" },
		"profile version":       func(c *Config) { c.Profile.Version = 0 },
		"profile driver":        func(c *Config) { c.Profile.Driver = " \t" },
		"credential kind":       func(c *Config) { c.Profile.CredentialKind = "static" },
		"delivery":              func(c *Config) { c.Profile.Delivery = "publish-only" },
		"read operations":       func(c *Config) { c.Profile.ReadOperations = access.Read },
		"read escalation":       func(c *Config) { c.Profile.ReadOperations |= access.Write },
		"write operations":      func(c *Config) { c.Profile.WriteOperations = access.Read | access.List },
		"unknown operations":    func(c *Config) { c.Profile.WriteOperations |= 128 },
		"min missing":           func(c *Config) { c.Profile.MinLifetime = 0 },
		"min negative":          func(c *Config) { c.Profile.MinLifetime = -1 },
		"max missing":           func(c *Config) { c.Profile.MaxLifetime = 0 },
		"max below min":         func(c *Config) { c.Profile.MaxLifetime = 14 * time.Minute },
		"max below STS minimum": func(c *Config) { c.Profile.MinLifetime = time.Second; c.Profile.MaxLifetime = time.Minute },
		"cap missing":           func(c *Config) { c.MaxSessionDuration = 0 },
		"cap below minimum":     func(c *Config) { c.MaxSessionDuration = 15*time.Minute - time.Second },
		"cap above maximum":     func(c *Config) { c.MaxSessionDuration = 12*time.Hour + time.Second },
		"cap fractional":        func(c *Config) { c.MaxSessionDuration += time.Nanosecond },
		"timeout missing":       func(c *Config) { c.RequestTimeout = 0 },
		"timeout negative":      func(c *Config) { c.RequestTimeout = -1 },
		"timeout above maximum": func(c *Config) { c.RequestTimeout = time.Minute + 1 },
	} {
		t.Run(name, func(t *testing.T) {
			cfg, _ := testConfig()
			change(&cfg)
			if p, err := New(cfg); p != nil || err != access.ErrInvalidRequest {
				t.Fatal("invalid config did not fail closed with its sentinel")
			}
		})
	}
	for _, field := range []string{"STS", "OSS"} {
		for _, endpoint := range []string{"", "http://example.invalid", "https:", "https:///path", "https://user:pass@example.invalid", "https://example.invalid/", "https://example.invalid/path", "https://example.invalid/%2e", "https://example.invalid?x=1", "https://example.invalid?", "https://example.invalid#fragment", "https://example.invalid#", "https://%invalid"} {
			t.Run(field+"/"+endpoint, func(t *testing.T) {
				cfg, _ := testConfig()
				if field == "STS" {
					cfg.STSEndpoint = endpoint
				} else {
					cfg.OSSEndpoint = endpoint
				}
				if p, err := New(cfg); p != nil || err != access.ErrInvalidRequest {
					t.Fatal("unsafe endpoint accepted")
				}
			})
		}
	}
	for _, cap := range []time.Duration{15 * time.Minute, 12 * time.Hour} {
		cfg, _ := testConfig()
		cfg.MaxSessionDuration, cfg.RequestTimeout, cfg.Profile.Version = cap, time.Minute, 2
		testProvider(t, cfg)
	}
}

func TestAcquireHTTPSRequestAndIsolation(t *testing.T) {
	requests := make(chan *http.Request, 6)
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error("cannot parse STS form")
		}
		requests <- r
		body := strings.ReplaceAll(testResponse(testNow.Add(20*time.Minute)), secretMarker+"-session", fmt.Sprintf("%s-session-%d", secretMarker, calls.Add(1)))
		_, _ = io.WriteString(w, body)
	}))
	defer server.Close()
	cfg, base := testConfig()
	cfg.STSEndpoint, cfg.HTTPClient = server.URL, server.Client()
	var tokenCalls int
	cfg.TokenSource = func(context.Context) (string, error) {
		tokenCalls++
		return fmt.Sprintf("%s-oidc-%d", secretMarker, tokenCalls), nil
	}
	p := testProvider(t, cfg)
	sessions := map[string]bool{}
	var firstSession string
	for i, tc := range []struct {
		name   string
		change func(*access.ApprovedAccess)
	}{
		{"first", func(*access.ApprovedAccess) {}},
		{"repeat", func(*access.ApprovedAccess) {}},
		{"binding", func(a *access.ApprovedAccess) { a.BindingUID = "other-binding" }},
		{"revision", func(a *access.ApprovedAccess) { a.Revision++ }},
		{"activation", func(a *access.ApprovedAccess) { a.ActivationUID = "other-activation" }},
		{"independent volume", func(a *access.ApprovedAccess) {
			a.BindingUID, a.VolumeUID, a.Handle = "binding-2", "volume-2", "dataset-2"
			a.Scope.Resource = "second-bucket"
			a.Scope.Prefix, a.Scope.ListPrefix = "actors/other/dataset/", "actors/other/dataset/"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := base
			tc.change(&a)
			c, err := p.Acquire(t.Context(), a)
			if err != nil {
				t.Fatal("valid exchange failed")
			}
			var r *http.Request
			select {
			case r = <-requests:
			default:
				t.Fatal("Acquire returned cached material without an HTTP exchange")
			}
			if r.TLS == nil || r.Method != http.MethodPost || r.URL.Path != "/" || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || r.Header.Get("Accept") != "application/json" {
				t.Error("incorrect HTTPS request envelope")
			}
			query := url.Values{"Action": {"AssumeRoleWithOIDC"}, "Version": {"2015-04-01"}, "Format": {"JSON"}, "Timestamp": {"2026-09-28T12:00:00Z"}}
			if !reflect.DeepEqual(r.URL.Query(), query) || strings.Contains(r.RequestURI, secretMarker) || r.Header.Get("Authorization") != "" || strings.Contains(fmt.Sprint(r.Header), secretMarker) {
				t.Error("public query or unsigned authentication contract violated")
			}
			form := r.PostForm
			wantForm := url.Values{"RoleArn": {cfg.RoleARN}, "OIDCProviderArn": {cfg.OIDCProviderARN}, "OIDCToken": {fmt.Sprintf("%s-oidc-%d", secretMarker, i+1)}, "RoleSessionName": {form.Get("RoleSessionName")}, "DurationSeconds": {"1794"}, "Policy": {form.Get("Policy")}}
			if !reflect.DeepEqual(form, wantForm) {
				t.Error("expected exactly six form fields and a freshly read OIDC token")
			}
			var policy, wantPolicy any
			if json.Unmarshal([]byte(form.Get("Policy")), &policy) != nil || json.Unmarshal([]byte(fmt.Sprintf(policyTemplate, a.Scope.Resource, a.Scope.Prefix, a.Scope.Resource, a.Scope.ListPrefix)), &wantPolicy) != nil || !reflect.DeepEqual(policy, wantPolicy) {
				t.Error("policy is not exactly GET on the object prefix and LIST with a prefix condition, both HTTPS-only")
			}
			session := form.Get("RoleSessionName")
			if !regexp.MustCompile(`^substrate-[0-9a-f]{40}$`).MatchString(session) {
				t.Error("unsafe role session name")
			}
			if i == 0 {
				firstSession = session
			}
			if i == 1 {
				if session != firstSession {
					t.Error("same binding did not have stable session attribution")
				}
			} else if sessions[session] {
				t.Error("distinct binding/revision/activation reused a role session")
			}
			sessions[session] = true
			want := access.Credential{Scope: a.Scope, Kind: access.SessionCredential, ProfileName: access.StagePublishSecrets, ProfileVersion: 1, ExpiresAt: testNow.Add(20 * time.Minute),
				Secrets: map[string]string{"accessKey": secretMarker + "-access", "secretKey": secretMarker + "-secret", "sessionToken": fmt.Sprintf("%s-session-%d", secretMarker, i+1)}}
			if !reflect.DeepEqual(c, want) {
				t.Fatal("incorrect credential, cached secrets, or clamped expiration")
			}
			c.Secrets["secretKey"] = "caller-mutation"
		})
	}
	if tokenCalls != 6 || calls.Load() != 6 {
		t.Error("Acquire cached a token or credential")
	}
}

func TestAcquireUnsupportedBeforeTokenOrHTTP(t *testing.T) {
	cases := map[string]func(*access.ApprovedAccess){
		"RW":                   func(a *access.ApprovedAccess) { a.Mode = access.ReadWrite },
		"mode missing":         func(a *access.ApprovedAccess) { a.Mode = "" },
		"read missing":         func(a *access.ApprovedAccess) { a.Scope.Operations = access.List },
		"list missing":         func(a *access.ApprovedAccess) { a.Scope.Operations = access.Read },
		"write escalation":     func(a *access.ApprovedAccess) { a.Scope.Operations |= access.Write },
		"unknown operation":    func(a *access.ApprovedAccess) { a.Scope.Operations |= 128 },
		"profile name":         func(a *access.ApprovedAccess) { a.Profile.Name = "other" },
		"profile version pin":  func(a *access.ApprovedAccess) { a.Profile.Version++ },
		"profile driver pin":   func(a *access.ApprovedAccess) { a.Profile.Driver = "other" },
		"profile minimum pin":  func(a *access.ApprovedAccess) { a.Profile.MinLifetime++ },
		"profile maximum pin":  func(a *access.ApprovedAccess) { a.Profile.MaxLifetime++ },
		"profile delivery pin": func(a *access.ApprovedAccess) { a.Profile.Delivery = "other" },
		"profile kind pin":     func(a *access.ApprovedAccess) { a.Profile.CredentialKind = "other" },
		"profile read pin":     func(a *access.ApprovedAccess) { a.Profile.ReadOperations |= access.Write },
		"profile write pin":    func(a *access.ApprovedAccess) { a.Profile.WriteOperations = access.Read },
		"driver":               func(a *access.ApprovedAccess) { a.Driver = "other" },
		"binding":              func(a *access.ApprovedAccess) { a.BindingUID = "" },
		"revision":             func(a *access.ApprovedAccess) { a.Revision = 0 },
		"activation":           func(a *access.ApprovedAccess) { a.ActivationUID = "" },
		"endpoint":             func(a *access.ApprovedAccess) { a.Scope.Endpoint = "https://other.invalid" },
		"endpoint path":        func(a *access.ApprovedAccess) { a.Scope.Endpoint += "/path" },
		"LIST mismatch":        func(a *access.ApprovedAccess) { a.Scope.ListPrefix = "actors/" },
		"LIST missing":         func(a *access.ApprovedAccess) { a.Scope.ListPrefix = "" },
	}
	for _, bucket := range []string{"", "ab", strings.Repeat("a", 64), "Uppercase", "bucket*", "bucket?", "bucket/name", "bucket.name", "-bucket", "bucket-"} {
		cases["bucket/"+bucket] = func(a *access.ApprovedAccess) { a.Scope.Resource = bucket }
	}
	for _, prefix := range []string{"", "/", "a", "/a/", "a//b/", "a///", "./", "../", "a/./b/", "a/../b/", "a/*/", "a/?/", "a/[x]/", "a/${x}/", "a/%2e/", "a/\\b/", "a/ b/", "a/\nb/", "a/\x00/", "a/\u4e2d/"} {
		cases["prefix/"+prefix] = func(a *access.ApprovedAccess) { a.Scope.Prefix, a.Scope.ListPrefix = prefix, prefix }
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			cfg, a := testConfig()
			var sourceCalls, httpCalls int
			cfg.TokenSource = func(context.Context) (string, error) { sourceCalls++; return secretMarker, nil }
			cfg.HTTPClient = &http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) { httpCalls++; return nil, errors.New(secretMarker) })}
			p := testProvider(t, cfg)
			change(&a)
			c, err := p.Acquire(t.Context(), a)
			assertFailure(t, c, err, access.ErrUnsupported)
			if sourceCalls != 0 || httpCalls != 0 {
				t.Error("unsupported scope reached token source or HTTP")
			}
		})
	}
}

func TestPolicySizeBoundary(t *testing.T) {
	cfg, a := testConfig()
	// Every variable field occurs twice; valid policies have odd byte lengths.
	// The nearest reachable sizes around 2048 are therefore 2047 and 2049.
	prefix := "p/"
	for len(fmt.Sprintf(policyTemplate, a.Scope.Resource, prefix, a.Scope.Resource, prefix)) < 2048 {
		prefix = "p" + prefix
	}
	for _, value := range []string{prefix[1:], prefix, "p" + prefix} {
		size := len(fmt.Sprintf(policyTemplate, a.Scope.Resource, value, a.Scope.Resource, value))
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			var sourceCalls, httpCalls int
			cfg.TokenSource = func(context.Context) (string, error) { sourceCalls++; return secretMarker, nil }
			cfg.HTTPClient = &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
				httpCalls++
				if r.ParseForm() != nil || len(r.PostForm.Get("Policy")) != size {
					t.Error("wire policy size differs from the boundary fixture")
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(testResponse(testNow.Add(20 * time.Minute))))}, nil
			})}
			a.Scope.Prefix, a.Scope.ListPrefix = value, value
			c, err := testProvider(t, cfg).Acquire(t.Context(), a)
			if size >= 2048 {
				assertFailure(t, c, err, access.ErrUnsupported)
				if sourceCalls != 0 || httpCalls != 0 {
					t.Error("oversized policy reached a dependency")
				}
			} else if err != nil || sourceCalls != 1 || httpCalls != 1 {
				t.Error("policy immediately below the limit was rejected")
			}
		})
	}
}

func TestTokenFileRotationAndNoFallback(t *testing.T) {
	dir := t.TempDir()
	path, link := filepath.Join(dir, "token"), filepath.Join(dir, "projected")
	if err := os.WriteFile(path, []byte(secretMarker+"-first"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ALIBABA_CLOUD_OIDC_TOKEN_FILE", path)
	t.Setenv("ALIBABA_CLOUD_ACCESS_KEY_ID", secretMarker+"-fallback-access")
	t.Setenv("ALIBABA_CLOUD_ACCESS_KEY_SECRET", secretMarker+"-fallback-secret")
	cfg, a := testConfig()
	var tokens []string
	cfg.HTTPClient = &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		if err := r.ParseForm(); err != nil {
			t.Error("invalid form")
		}
		tokens = append(tokens, r.PostForm.Get("OIDCToken"))
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(testResponse(testNow.Add(20 * time.Minute))))}, nil
	})}
	cfg.TokenSource = TokenFile(link)
	p := testProvider(t, cfg)
	for _, phase := range []string{"first", "rewrite", "symlink"} {
		if phase == "rewrite" {
			if err := os.WriteFile(path, []byte("\n"+secretMarker+"-rewrite\n"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		if phase == "symlink" {
			next := filepath.Join(dir, "next-token")
			if err := os.WriteFile(next, []byte(secretMarker+"-symlink"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(next, link+"-next"); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(link+"-next", link); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := p.Acquire(t.Context(), a); err != nil {
			t.Fatal("rotated file token rejected")
		}
	}
	if !reflect.DeepEqual(tokens, []string{secretMarker + "-first", secretMarker + "-rewrite", secretMarker + "-symlink"}) {
		t.Error("token file or symlink target was cached")
	}
	if err := os.Remove(filepath.Join(dir, "next-token")); err != nil {
		t.Fatal(err)
	}
	c, err := p.Acquire(t.Context(), a)
	assertFailure(t, c, err, access.ErrUnavailable)
	for name, data := range map[string]string{"empty": "", "whitespace": " \n", "short": "abc", "embedded whitespace": "abcd ef", "newline": "abcd\nef", "invalid": "abcd+/=", "unicode": "abcd\u4e2d", "large": strings.Repeat("a", 20001), "missing": "", "directory": "", "relative": "", "no path": ""} {
		t.Run(name, func(t *testing.T) {
			file := filepath.Join(dir, name)
			switch name {
			case "missing":
			case "directory":
				file = dir
			case "relative":
				file = "relative-token"
			case "no path":
				file = ""
			default:
				if err := os.WriteFile(file, []byte(data), 0600); err != nil {
					t.Fatal(err)
				}
			}
			source := TokenFile(file)
			if token, err := source(t.Context()); token != "" || err != access.ErrUnavailable {
				t.Error("invalid token file did not return an empty token and sentinel")
			}
			cfg.TokenSource = source
			c, err := testProvider(t, cfg).Acquire(t.Context(), a)
			assertFailure(t, c, err, access.ErrUnavailable)
		})
	}
	if len(tokens) != 3 {
		t.Error("bad token file fell back to cached credentials or ambient identity")
	}
	if err := os.WriteFile(path, []byte(strings.Repeat("a", 20000)), 0600); err != nil {
		t.Fatal(err)
	}
	if token, err := TokenFile(path)(t.Context()); err != nil || len(token) != 20000 {
		t.Error("maximum-size valid token rejected")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if token, err := TokenFile(path)(ctx); token != "" || err != access.ErrUnavailable {
		t.Error("canceled token file read succeeded")
	}
}

func TestLifetimeBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name                                                              string
		minimum, maximum, cap, deadline, sourceCost, responseCost, expiry time.Duration
		duration                                                          string
		want                                                              error
		sourceCalls                                                       int
	}{
		{"actual expiration", 15 * time.Minute, time.Hour, time.Hour, 30 * time.Minute, 0, 0, 20 * time.Minute, "1794", nil, 1},
		{"floor seconds", 15 * time.Minute, time.Hour, time.Hour, 30*time.Minute + 999*time.Millisecond, 0, 0, 20 * time.Minute, "1794", nil, 1},
		{"profile maximum", 15 * time.Minute, 25 * time.Minute, time.Hour, 2 * time.Hour, 0, 0, 25 * time.Minute, "1500", nil, 1},
		{"administrator cap", 15 * time.Minute, time.Hour, 25 * time.Minute, 2 * time.Hour, 0, 0, 25 * time.Minute, "1500", nil, 1},
		{"profile maximum exceeded", 15 * time.Minute, 25 * time.Minute, time.Hour, 2 * time.Hour, 0, 0, 25*time.Minute + time.Nanosecond, "1500", access.ErrDenied, 1},
		{"cap exceeded", 15 * time.Minute, time.Hour, 25 * time.Minute, 2 * time.Hour, 0, 0, 25*time.Minute + time.Nanosecond, "1500", access.ErrDenied, 1},
		{"deadline equality", 15 * time.Minute, time.Hour, time.Hour, 30 * time.Minute, 0, 0, 30 * time.Minute, "1794", nil, 1},
		{"deadline exceeded not clamped", 15 * time.Minute, time.Hour, time.Hour, 30 * time.Minute, 0, 0, 30*time.Minute + time.Nanosecond, "1794", access.ErrDenied, 1},
		{"minimum equality", 15 * time.Minute, time.Hour, time.Hour, 30 * time.Minute, 0, 0, 15 * time.Minute, "1794", nil, 1},
		{"minimum lost", 15 * time.Minute, time.Hour, time.Hour, 30 * time.Minute, 0, 0, 15*time.Minute - time.Nanosecond, "1794", access.ErrDenied, 1},
		{"custom minimum", 21 * time.Minute, time.Hour, time.Hour, 30 * time.Minute, 0, 0, 20 * time.Minute, "1794", access.ErrDenied, 1},
		{"expired equality", 15 * time.Minute, time.Hour, time.Hour, 30 * time.Minute, 0, 0, 0, "1794", access.ErrDenied, 1},
		{"past expiration", 15 * time.Minute, time.Hour, time.Hour, 30 * time.Minute, 0, 0, -time.Second, "1794", access.ErrDenied, 1},
		{"deadline too short", 15 * time.Minute, time.Hour, time.Hour, 15 * time.Minute, 0, 0, 0, "", access.ErrUnsupported, 0},
		{"expired deadline", 15 * time.Minute, time.Hour, time.Hour, 0, 0, 0, 0, "", access.ErrUnsupported, 0},
		{"minimum delivery budget", 15 * time.Minute, time.Hour, time.Hour, 15*time.Minute + 11999*time.Millisecond, 0, 0, 0, "", access.ErrUnsupported, 0},
		{"minimum delivery equality", 15 * time.Minute, time.Hour, time.Hour, 15*time.Minute + 12*time.Second, 0, 0, 15 * time.Minute, "906", nil, 1},
		{"STS minimum never rounded up", time.Second, time.Hour, time.Hour, 15*time.Minute + 5999*time.Millisecond, 0, 0, 0, "", access.ErrUnsupported, 0},
		{"STS minimum equality", time.Second, time.Hour, time.Hour, 15*time.Minute + 6*time.Second, 0, 0, 15 * time.Minute, "900", nil, 1},
		{"cap cannot meet delivery minimum", 15 * time.Minute, time.Hour, 15 * time.Minute, 30 * time.Minute, 0, 0, 0, "", access.ErrUnsupported, 0},
		{"profile cannot meet delivery minimum", 15 * time.Minute, 15 * time.Minute, time.Hour, 30 * time.Minute, 0, 0, 0, "", access.ErrUnsupported, 0},
		{"source consumes budget", 15 * time.Minute, time.Hour, time.Hour, 30 * time.Minute, 17 * time.Second, 0, 20 * time.Minute, "1777", nil, 1},
		{"source exhausts budget", 15 * time.Minute, time.Hour, time.Hour, 30 * time.Minute, 15 * time.Minute, 0, 0, "", access.ErrUnsupported, 1},
		{"response consumes minimum", 15 * time.Minute, time.Hour, time.Hour, 30 * time.Minute, 0, 6 * time.Minute, 20 * time.Minute, "1794", access.ErrDenied, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, a := testConfig()
			now := testNow
			var sourceCalls, httpCalls int
			cfg.Profile.MinLifetime, cfg.Profile.MaxLifetime, cfg.MaxSessionDuration = tc.minimum, tc.maximum, tc.cap
			a.Profile, a.Deadline = cfg.Profile, testNow.Add(tc.deadline)
			cfg.TokenSource = func(context.Context) (string, error) {
				sourceCalls++
				now = now.Add(tc.sourceCost)
				return secretMarker, nil
			}
			body := &observedBody{ReadCloser: io.NopCloser(strings.NewReader(testResponse(testNow.Add(tc.expiry))))}
			cfg.HTTPClient = &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
				httpCalls++
				if r.ParseForm() != nil || r.PostForm.Get("DurationSeconds") != tc.duration || r.URL.Query().Get("Timestamp") != now.Format("2006-01-02T15:04:05Z") {
					t.Error("duration/timestamp ignored deadline, limits, source time, or rounding")
				}
				now = now.Add(tc.responseCost)
				return &http.Response{StatusCode: 200, Body: body}, nil
			})}
			p := testProvider(t, cfg)
			p.now = func() time.Time { return now }
			c, err := p.Acquire(t.Context(), a)
			if tc.want != nil {
				assertFailure(t, c, err, tc.want)
			} else if err != nil || !c.ExpiresAt.Equal(testNow.Add(tc.expiry)) {
				t.Error("actual STS expiration was rejected or relabeled")
			}
			wantHTTP := 0
			if tc.duration != "" {
				wantHTTP = 1
			}
			if sourceCalls != tc.sourceCalls || httpCalls != wantHTTP || body.closed != (wantHTTP == 1) {
				t.Error("incorrect dependency ordering or response not closed")
			}
		})
	}
}

func TestResponseFailuresAreClosedAndRedacted(t *testing.T) {
	valid := testResponse(testNow.Add(20 * time.Minute))
	for _, tc := range []struct {
		name                      string
		status                    int
		payload                   string
		readError, transportError bool
		want                      error
	}{
		{"success closes", 200, valid, false, false, nil},
		{"created", 201, valid, false, false, access.ErrUnavailable},
		{"empty status", 204, secretMarker, false, false, access.ErrUnavailable},
		{"bad request", 400, secretMarker, false, false, access.ErrUnavailable},
		{"unauthorized", 401, secretMarker, false, false, access.ErrUnavailable},
		{"forbidden", 403, secretMarker, false, false, access.ErrUnavailable},
		{"throttled", 429, secretMarker, false, false, access.ErrUnavailable},
		{"server error", 500, secretMarker, false, false, access.ErrUnavailable},
		{"business Code with credentials", 200, `{"Code":"` + secretMarker + `",` + valid[1:], false, false, access.ErrUnavailable},
		{"malformed", 200, secretMarker, false, false, access.ErrUnavailable},
		{"truncated", 200, valid[:len(valid)-1], false, false, access.ErrUnavailable},
		{"trailing JSON", 200, valid + `{}`, false, false, access.ErrUnavailable},
		{"missing credentials", 200, `{}`, false, false, access.ErrUnavailable},
		{"null credentials", 200, `{"Credentials":null}`, false, false, access.ErrUnavailable},
		{"wrong credential type", 200, `{"Credentials":[]}`, false, false, access.ErrUnavailable},
		{"missing access key", 200, strings.ReplaceAll(valid, `"AccessKeyId"`, `"OtherKey"`), false, false, access.ErrDenied},
		{"missing secret", 200, strings.ReplaceAll(valid, `"AccessKeySecret"`, `"OtherKey"`), false, false, access.ErrDenied},
		{"missing session", 200, strings.ReplaceAll(valid, `"SecurityToken"`, `"OtherKey"`), false, false, access.ErrDenied},
		{"empty access", 200, strings.ReplaceAll(valid, secretMarker+"-access", ""), false, false, access.ErrDenied},
		{"blank secret", 200, strings.ReplaceAll(valid, secretMarker+"-secret", " "), false, false, access.ErrDenied},
		{"blank session", 200, strings.ReplaceAll(valid, secretMarker+"-session", " "), false, false, access.ErrDenied},
		{"missing expiration", 200, strings.ReplaceAll(valid, `"Expiration"`, `"OtherKey"`), false, false, access.ErrDenied},
		{"bad expiration", 200, strings.ReplaceAll(valid, testNow.Add(20*time.Minute).Format(time.RFC3339), secretMarker), false, false, access.ErrDenied},
		{"oversized response", 200, valid + strings.Repeat(" ", 1<<20), false, false, access.ErrUnavailable},
		{"read error after valid JSON", 200, valid, true, false, access.ErrUnavailable},
		{"transport error", 0, "", false, true, access.ErrUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, a := testConfig()
			var reader io.Reader = strings.NewReader(tc.payload)
			if tc.readError {
				reader = io.MultiReader(reader, iotest.ErrReader(errors.New(secretMarker)))
			}
			body := &observedBody{ReadCloser: io.NopCloser(reader)}
			cfg.HTTPClient = &http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) {
				if tc.transportError {
					return nil, errors.New(secretMarker)
				}
				return &http.Response{StatusCode: tc.status, Body: body}, nil
			})}
			c, err := testProvider(t, cfg).Acquire(t.Context(), a)
			if tc.want != nil {
				assertFailure(t, c, err, tc.want)
			} else if err != nil || len(c.Secrets) != 3 {
				t.Error("valid response failed")
			}
			if body.closed == tc.transportError || body.bytes > (1<<20)+1 {
				t.Error("response not closed or read without a size bound")
			}
		})
	}
}

func TestTokenSourceFailures(t *testing.T) {
	for name, source := range map[string]func(context.Context) (string, error){
		"raw error with token": func(context.Context) (string, error) {
			return secretMarker, fmt.Errorf("%s: %w", secretMarker, access.ErrDenied)
		},
		"empty":         func(context.Context) (string, error) { return "", nil },
		"short":         func(context.Context) (string, error) { return "abc", nil },
		"bad character": func(context.Context) (string, error) { return secretMarker + "/", nil },
		"whitespace":    func(context.Context) (string, error) { return secretMarker + "\n", nil },
		"oversized":     func(context.Context) (string, error) { return strings.Repeat("a", 20001), nil },
	} {
		t.Run(name, func(t *testing.T) {
			cfg, a := testConfig()
			cfg.TokenSource = source
			cfg.HTTPClient = &http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) {
				t.Error("invalid source reached HTTP")
				return nil, access.ErrUnavailable
			})}
			c, err := testProvider(t, cfg).Acquire(t.Context(), a)
			assertFailure(t, c, err, access.ErrUnavailable)
		})
	}
	cfg, a := testConfig()
	cfg.TokenSource = func(context.Context) (string, error) {
		t.Error("canceled request reached source")
		return secretMarker, nil
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, p := range []*Provider{nil, {}, testProvider(t, cfg)} {
		c, err := p.Acquire(ctx, a)
		assertFailure(t, c, err, access.ErrUnavailable)
	}
}

func TestRedirectsNeverForwardTokens(t *testing.T) {
	for _, status := range []int{301, 302, 307, 308} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			var calls, forwarded atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.URL.Path != "/" {
					forwarded.Add(1)
					_, _ = io.WriteString(w, testResponse(testNow.Add(20*time.Minute)))
					return
				}
				if err := r.ParseForm(); err != nil || r.PostForm.Get("OIDCToken") != secretMarker+"-oidc" {
					t.Error("redirect test did not receive token exchange")
				}
				if r.Header.Get("Cookie") != "" {
					t.Error("provider sent ambient cookies")
				}
				http.SetCookie(w, &http.Cookie{Name: "sts", Value: secretMarker})
				w.Header().Set("Location", "/leak?marker="+secretMarker)
				w.WriteHeader(status)
				_, _ = io.WriteString(w, secretMarker)
			}))
			defer server.Close()
			cfg, a := testConfig()
			cfg.STSEndpoint, cfg.HTTPClient = server.URL, server.Client()
			jar, err := cookiejar.New(nil)
			if err != nil {
				t.Fatal(err)
			}
			u, err := url.Parse(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			jar.SetCookies(u, []*http.Cookie{{Name: "ambient", Value: "present"}})
			cfg.HTTPClient.Jar = jar
			var redirected int
			cfg.HTTPClient.CheckRedirect = func(*http.Request, []*http.Request) error { redirected++; return nil }
			transport := cfg.HTTPClient.Transport
			var body *observedBody
			cfg.HTTPClient.Transport = transportFunc(func(r *http.Request) (*http.Response, error) {
				response, err := transport.RoundTrip(r)
				if err == nil {
					body = &observedBody{ReadCloser: response.Body}
					response.Body = body
				}
				return response, err
			})
			c, err := testProvider(t, cfg).Acquire(t.Context(), a)
			assertFailure(t, c, err, access.ErrUnavailable)
			if calls.Load() != 1 || forwarded.Load() != 0 || redirected != 0 || body == nil || !body.closed {
				t.Error("redirect was followed or response leaked")
			}
			if cfg.HTTPClient.Jar != jar || cfg.HTTPClient.CheckRedirect(nil, nil) != nil || redirected != 1 || len(jar.Cookies(u)) != 1 {
				t.Error("provider mutated the caller's client or persisted STS cookies")
			}
		})
	}
}

func TestTimeoutAndCancellation(t *testing.T) {
	for _, phase := range []string{"source", "headers", "body"} {
		for _, explicit := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/cancel=%t", phase, explicit), func(t *testing.T) {
				entered, exited := make(chan context.Context, 1), make(chan struct{}, 1)
				release := make(chan struct{})
				wait := func(ctx context.Context) {
					entered <- ctx
					select {
					case <-ctx.Done():
					case <-release:
					}
					exited <- struct{}{}
				}
				server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_, _ = io.Copy(io.Discard, r.Body)
					if phase == "body" {
						_, _ = io.WriteString(w, `{"Credentials":`)
						w.(http.Flusher).Flush()
					}
					wait(r.Context())
				}))
				t.Cleanup(server.Close)
				t.Cleanup(func() { close(release) })
				cfg, a := testConfig()
				cfg.STSEndpoint, cfg.HTTPClient, cfg.RequestTimeout = server.URL, server.Client(), 250*time.Millisecond
				if phase == "source" {
					cfg.TokenSource = func(ctx context.Context) (string, error) { wait(ctx); return secretMarker, ctx.Err() }
				}
				p := testProvider(t, cfg)
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				type result struct {
					credential access.Credential
					err        error
				}
				resultCh := make(chan result, 1)
				go func() { c, err := p.Acquire(ctx, a); resultCh <- result{c, err} }()
				select {
				case sourceCtx := <-entered:
					if phase == "source" {
						if deadline, ok := sourceCtx.Deadline(); !ok || time.Until(deadline) > cfg.RequestTimeout {
							t.Error("source did not receive bounded context")
						}
					}
				case <-time.After(2 * time.Second):
					t.Fatal("dependency never started")
				}
				if explicit {
					cancel()
				}
				select {
				case result := <-resultCh:
					assertFailure(t, result.credential, result.err, access.ErrUnavailable)
				case <-time.After(2 * time.Second):
					t.Fatal("Acquire ignored timeout/cancellation")
				}
				select {
				case <-exited:
				case <-time.After(2 * time.Second):
					t.Fatal("dependency context was not canceled")
				}
			})
		}
	}
}

func TestLateCancellationNeverDeliversSecrets(t *testing.T) {
	for _, phase := range []string{"source", "response", "validation"} {
		t.Run(phase, func(t *testing.T) {
			cfg, a := testConfig()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			cfg.TokenSource = func(context.Context) (string, error) {
				if phase == "source" {
					cancel()
				}
				return secretMarker, nil
			}
			body := &observedBody{ReadCloser: io.NopCloser(strings.NewReader(testResponse(testNow.Add(20 * time.Minute))))}
			var calls, clocks int
			cfg.HTTPClient = &http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) {
				calls++
				if phase == "response" {
					cancel()
				}
				return &http.Response{StatusCode: 200, Body: body}, nil
			})}
			p := testProvider(t, cfg)
			p.now = func() time.Time {
				clocks++
				if phase == "validation" && clocks == 3 {
					cancel()
				}
				return testNow
			}
			c, err := p.Acquire(ctx, a)
			assertFailure(t, c, err, access.ErrUnavailable)
			wantCalls := 1
			if phase == "source" {
				wantCalls = 0
			}
			if calls != wantCalls || body.closed != (wantCalls == 1) {
				t.Error("late cancellation reached HTTP or left a response open")
			}
		})
	}
}

type resolverFunc func(context.Context, string) (access.Snapshot, error)

func (f resolverFunc) Resolve(ctx context.Context, uid string) (access.Snapshot, error) {
	return f(ctx, uid)
}

type acquireFunc func(context.Context, access.ApprovedAccess) (access.Credential, error)

func (f acquireFunc) Acquire(ctx context.Context, a access.ApprovedAccess) (access.Credential, error) {
	return f(ctx, a)
}

func TestBrokerWithProviderAndLocalSTS(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		want                    error
		acquires, sts, resolves int
	}{
		{"initial deny", access.ErrDenied, 0, 0, 1},
		{"revoked during acquire", access.ErrDenied, 1, 1, 2},
		{"success and secret ownership", nil, 1, 1, 2},
		{"unsupported bucket", access.ErrUnavailable, 1, 0, 1},
		{"unsupported profile version", access.ErrUnavailable, 1, 0, 1},
		{"unsupported RW", access.ErrUnavailable, 1, 0, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var sts atomic.Int32
			var revoked atomic.Bool
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				sts.Add(1)
				if r.ParseForm() != nil || r.PostForm.Get("OIDCToken") != secretMarker+"-oidc" {
					t.Error("broker did not perform a real OIDC exchange")
				}
				if tc.name == "revoked during acquire" {
					revoked.Store(true)
				}
				_, _ = io.WriteString(w, testResponse(testNow.Add(20*time.Minute)))
			}))
			defer server.Close()
			cfg, a := testConfig()
			cfg.STSEndpoint, cfg.HTTPClient = server.URL, server.Client()
			p := testProvider(t, cfg)
			state := access.Snapshot{
				ActorUID: "actor", Atespace: "space", PolicyRevision: 3,
				Binding: access.Binding{UID: "binding", Revision: 2, ActorUID: "actor", VolumeUID: "volume", GrantUID: "grant", ResourceGeneration: 4,
					ClusterUID: "cluster", NodeUID: "node", WorkerUID: "worker", ActivationUID: "activation", Mode: access.ReadOnly, ExpiresAt: testNow.Add(time.Hour)},
				Grant:      access.Grant{UID: "grant", Revision: 5, ActorUID: "actor", VolumeUID: "volume", Atespace: "space", Operations: access.Read | access.List, ExpiresAt: testNow.Add(time.Hour)},
				Assignment: access.Assignment{ActorUID: "actor", ClusterUID: "cluster", NodeUID: "node", WorkerUID: "worker", ActivationUID: "activation"},
				Volume:     access.Volume{UID: "volume", Generation: 4, Atespace: "space", OwnerActorUID: "actor", Driver: cfg.Profile.Driver, Handle: "dataset", Exclusive: true, Scope: a.Scope},
				Profile:    cfg.Profile,
			}
			executor := access.Executor{Component: "atelet", ClusterUID: "cluster", NodeUID: "node"}
			request := access.Request{BindingUID: "binding", Revision: 2, ActivationUID: "activation", Mode: access.ReadOnly, MaxCredentialLifetime: 30 * time.Minute}
			switch tc.name {
			case "initial deny":
				state.Grant.Revoked = true
			case "unsupported bucket":
				state.Volume.Scope.Resource = "bucket*"
			case "unsupported profile version":
				state.Profile.Version++
			case "unsupported RW":
				request.Mode, state.Binding.Mode = access.ReadWrite, access.ReadWrite
				state.Grant.Operations |= access.Write
				state.Volume.Scope.Operations |= access.Write
			}
			var retained map[string]string
			var resolves, acquires int
			now := testNow
			broker := access.NewBroker(resolverFunc(func(ctx context.Context, uid string) (access.Snapshot, error) {
				resolves++
				if ctx.Err() != nil || uid != state.Binding.UID {
					return access.Snapshot{}, access.ErrDenied
				}
				if resolves == 2 && retained != nil {
					retained["secretKey"] = "provider-mutation"
				}
				snapshot := state
				snapshot.Grant.Revoked = snapshot.Grant.Revoked || revoked.Load()
				return snapshot, nil
			}), acquireFunc(func(ctx context.Context, a access.ApprovedAccess) (access.Credential, error) {
				acquires++
				c, err := p.Acquire(ctx, a)
				retained = c.Secrets
				return c, err
			}), func() time.Time { return now })
			lease, err := broker.Exchange(t.Context(), executor, request)
			if err != tc.want || acquires != tc.acquires || int(sts.Load()) != tc.sts || resolves != tc.resolves {
				t.Fatal("incorrect broker sentinel or authority/provider/STS call ordering")
			}
			if tc.want != nil {
				if lease != nil {
					t.Fatal("failed exchange delivered a lease")
				}
				return
			}
			if lease == nil || lease.Approved() != a {
				t.Fatal("incorrect lease approval")
			}
			want := map[string]string{"accessKey": secretMarker + "-access", "secretKey": secretMarker + "-secret", "sessionToken": secretMarker + "-session"}
			if !reflect.DeepEqual(lease.Secrets(), want) {
				t.Error("broker did not copy provider secrets before reauthorization")
			}
			delete(retained, "accessKey")
			copy := lease.Secrets()
			copy["secretKey"] = "caller-mutation"
			delete(copy, "sessionToken")
			if !reflect.DeepEqual(lease.Secrets(), want) {
				t.Error("lease exposes shared mutable secret material")
			}
			target := access.Target{ActorUID: "actor", ActivationUID: "activation", Driver: cfg.Profile.Driver, Handle: "dataset"}
			if broker.Validate(t.Context(), executor, lease, target) != nil {
				t.Error("valid lease failed validation")
			}
			now = testNow.Add(20 * time.Minute)
			if broker.Validate(t.Context(), executor, lease, target) != access.ErrDenied || sts.Load() != 1 {
				t.Error("lease did not expire at the actual STS expiration")
			}
		})
	}
}

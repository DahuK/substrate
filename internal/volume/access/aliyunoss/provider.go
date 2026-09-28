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

// Package aliyunoss acquires read-only, single-prefix OSS sessions using a
// control-plane RRSA identity. It does not authenticate actors, qualify a CSI
// driver, refresh mounted clients, or terminate already-issued access.
package aliyunoss

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/agent-substrate/substrate/internal/volume/access"
)

const (
	minSessionDuration = 15 * time.Minute
	expiryMargin       = 5 * time.Second
	maxTokenBytes      = 20000
	maxResponseBytes   = 1 << 20
	maxPolicyBytes     = 2048
)

var (
	roleARNPattern     = regexp.MustCompile(`^acs:ram::([0-9]{1,32}):role/[A-Za-z0-9._@-]{1,128}$`)
	providerARNPattern = regexp.MustCompile(`^acs:ram::([0-9]{1,32}):oidc-provider/[A-Za-z0-9._-]{1,128}$`)
	ownerPattern       = regexp.MustCompile(`^[0-9]{1,32}$`)
	bucketPattern      = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`)
	prefixPattern      = regexp.MustCompile(`^[A-Za-z0-9._/-]+/$`)
)

// Config is administrator-owned, not actor or node request input. Endpoints,
// token source and any custom HTTP transport must be trusted. Profile pins the
// experimental delivery contract; it is not evidence of driver compatibility.
type Config struct {
	RoleARN, OIDCProviderARN, BucketOwnerID string
	STSEndpoint, OSSEndpoint                string
	Profile                                 access.Profile
	MaxSessionDuration, RequestTimeout      time.Duration
	// TokenSource must bound its own reads/allocations, honor context cancellation,
	// and support concurrent calls. A timeout cannot interrupt an uncooperative source.
	TokenSource func(context.Context) (string, error)
	HTTPClient  *http.Client
}

type Provider struct {
	roleARN, oidcProviderARN, bucketOwnerID string
	stsEndpoint, ossEndpoint                string
	profile                                 access.Profile
	maxSessionDuration, requestTimeout      time.Duration
	tokenSource                             func(context.Context) (string, error)
	client                                  http.Client
	now                                     func() time.Time
}

var _ access.Provider = (*Provider)(nil)

func New(config Config) (*Provider, error) {
	role := roleARNPattern.FindStringSubmatch(config.RoleARN)
	provider := providerARNPattern.FindStringSubmatch(config.OIDCProviderARN)
	p := config.Profile
	if len(role) == 0 || len(provider) == 0 || role[1] != provider[1] || !ownerPattern.MatchString(config.BucketOwnerID) ||
		!validEndpoint(config.STSEndpoint) || !validEndpoint(config.OSSEndpoint) || config.TokenSource == nil ||
		config.RequestTimeout <= 0 || config.RequestTimeout > time.Minute ||
		config.MaxSessionDuration < minSessionDuration || config.MaxSessionDuration > 12*time.Hour || config.MaxSessionDuration%time.Second != 0 ||
		p.Name != access.StagePublishSecrets || p.Version == 0 || strings.TrimSpace(p.Driver) == "" ||
		p.CredentialKind != access.SessionCredential || p.Delivery != access.StagePublishSecrets ||
		p.MinLifetime <= 0 || p.MaxLifetime < p.MinLifetime || p.MaxLifetime < minSessionDuration ||
		p.ReadOperations != access.Read|access.List || p.WriteOperations != access.Read|access.Write|access.List {
		return nil, access.ErrInvalidRequest
	}
	client := http.Client{}
	if config.HTTPClient != nil {
		client = *config.HTTPClient
	}
	// Never forward the OIDC token through a redirect or persist response cookies.
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	client.Jar = nil
	return &Provider{
		roleARN: config.RoleARN, oidcProviderARN: config.OIDCProviderARN, bucketOwnerID: config.BucketOwnerID,
		stsEndpoint: config.STSEndpoint, ossEndpoint: config.OSSEndpoint, profile: p,
		maxSessionDuration: config.MaxSessionDuration, requestTimeout: config.RequestTimeout,
		tokenSource: config.TokenSource, client: client, now: time.Now,
	}, nil
}

// TokenFile reads a trusted local projected-token file anew on each exchange,
// following the current projection rather than pinning a symlink target or FD.
// It performs no Kubernetes TokenRequest and has no default path or fallback.
// The directory and projection must remain trusted regular local files, not
// pipes, devices or network filesystems. Context checks cannot interrupt file I/O.
func TokenFile(path string) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		if ctx.Err() != nil || !filepath.IsAbs(path) {
			return "", access.ErrUnavailable
		}
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() || info.Size() > maxTokenBytes {
			return "", access.ErrUnavailable
		}
		file, err := os.Open(path)
		if err != nil {
			return "", access.ErrUnavailable
		}
		info, err = file.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Size() > maxTokenBytes {
			_ = file.Close()
			return "", access.ErrUnavailable
		}
		data, err := io.ReadAll(io.LimitReader(file, maxTokenBytes+1))
		closeErr := file.Close()
		if err != nil || closeErr != nil || len(data) > maxTokenBytes || ctx.Err() != nil {
			return "", access.ErrUnavailable
		}
		token := strings.TrimSpace(string(data))
		if !validToken(token) {
			return "", access.ErrUnavailable
		}
		return token, nil
	}
}

func (p *Provider) Acquire(ctx context.Context, approved access.ApprovedAccess) (access.Credential, error) {
	if p == nil || p.tokenSource == nil || p.now == nil || ctx.Err() != nil {
		return access.Credential{}, access.ErrUnavailable
	}
	scope := approved.Scope
	if approved.Mode != access.ReadOnly || scope.Operations != access.Read|access.List ||
		approved.Profile != p.profile || approved.Driver != p.profile.Driver ||
		approved.BindingUID == "" || approved.Revision == 0 || approved.ActivationUID == "" ||
		scope.Endpoint != p.ossEndpoint || !bucketPattern.MatchString(scope.Resource) ||
		!prefixPattern.MatchString(scope.Prefix) || scope.ListPrefix != scope.Prefix {
		return access.Credential{}, access.ErrUnsupported
	}
	// Prefixes are literal keys, never RAM patterns or normalized filesystem paths.
	for _, part := range strings.Split(strings.TrimSuffix(scope.Prefix, "/"), "/") {
		if part == "" || part == "." || part == ".." {
			return access.Credential{}, access.ErrUnsupported
		}
	}
	resource := "acs:oss:*:" + p.bucketOwnerID + ":" + scope.Resource
	type condition struct {
		Bool       map[string]string   `json:"Bool"`
		StringLike map[string][]string `json:"StringLike,omitempty"`
	}
	type statement struct {
		Effect    string    `json:"Effect"`
		Action    []string  `json:"Action"`
		Resource  []string  `json:"Resource"`
		Condition condition `json:"Condition"`
	}
	policy, err := json.Marshal(struct {
		Version   string      `json:"Version"`
		Statement []statement `json:"Statement"`
	}{"1", []statement{
		{"Allow", []string{"oss:GetObject"}, []string{resource + "/" + scope.Prefix + "*"}, condition{
			Bool: map[string]string{"acs:SecureTransport": "true"},
		}},
		{"Allow", []string{"oss:ListObjects"}, []string{resource}, condition{
			Bool:       map[string]string{"acs:SecureTransport": "true"},
			StringLike: map[string][]string{"oss:Prefix": {scope.ListPrefix + "*"}},
		}},
	}})
	if err != nil || len(policy) >= maxPolicyBytes {
		return access.Credential{}, access.ErrUnsupported
	}
	if p.sessionDuration(approved.Deadline, p.now()) == 0 {
		return access.Credential{}, access.ErrUnsupported
	}
	ctx, cancel := context.WithTimeout(ctx, p.requestTimeout)
	defer cancel()
	token, err := p.tokenSource(ctx)
	if err != nil || ctx.Err() != nil || !validToken(token) {
		return access.Credential{}, access.ErrUnavailable
	}
	now := p.now()
	duration := p.sessionDuration(approved.Deadline, now)
	if duration == 0 {
		return access.Credential{}, access.ErrUnsupported
	}
	session, _ := json.Marshal([]string{approved.BindingUID, strconv.FormatUint(approved.Revision, 10), approved.ActivationUID})
	digest := sha256.Sum256(session)
	query := url.Values{
		"Action": {"AssumeRoleWithOIDC"}, "Version": {"2015-04-01"}, "Format": {"JSON"},
		"Timestamp": {now.UTC().Format("2006-01-02T15:04:05Z")},
	}
	form := url.Values{
		"RoleArn": {p.roleARN}, "OIDCProviderArn": {p.oidcProviderARN}, "OIDCToken": {token},
		"RoleSessionName": {"substrate-" + hex.EncodeToString(digest[:20])},
		"DurationSeconds": {strconv.FormatInt(int64(duration/time.Second), 10)}, "Policy": {string(policy)},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, p.stsEndpoint+"/?"+query.Encode(), strings.NewReader(form.Encode()))
	if err != nil {
		return access.Credential{}, access.ErrUnavailable
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	response, err := p.client.Do(request)
	if err != nil {
		return access.Credential{}, access.ErrUnavailable
	}
	if response.StatusCode != http.StatusOK {
		_ = response.Body.Close()
		return access.Credential{}, access.ErrUnavailable
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	// Finish external cleanup before deciding whether material is still deliverable.
	closeErr := response.Body.Close()
	if err != nil || closeErr != nil || len(body) > maxResponseBytes || ctx.Err() != nil {
		return access.Credential{}, access.ErrUnavailable
	}
	var result struct {
		Code        string
		Credentials *struct {
			AccessKeyId, AccessKeySecret, SecurityToken, Expiration string
		}
	}
	if json.Unmarshal(body, &result) != nil || result.Code != "" || result.Credentials == nil {
		return access.Credential{}, access.ErrUnavailable
	}
	c := result.Credentials
	expires, err := time.Parse(time.RFC3339, c.Expiration)
	now = p.now()
	if err != nil || strings.TrimSpace(c.AccessKeyId) == "" || strings.TrimSpace(c.AccessKeySecret) == "" || strings.TrimSpace(c.SecurityToken) == "" ||
		!expires.After(now) || expires.After(approved.Deadline) || expires.Sub(now) < p.profile.MinLifetime ||
		expires.Sub(now) > min(p.maxSessionDuration, p.profile.MaxLifetime) {
		return access.Credential{}, access.ErrDenied
	}
	if ctx.Err() != nil {
		return access.Credential{}, access.ErrUnavailable
	}
	return access.Credential{
		Scope: scope, Kind: p.profile.CredentialKind, ProfileName: p.profile.Name, ProfileVersion: p.profile.Version,
		ExpiresAt: expires,
		Secrets:   map[string]string{"accessKey": c.AccessKeyId, "secretKey": c.AccessKeySecret, "sessionToken": c.SecurityToken},
	}, nil
}

func (p *Provider) sessionDuration(deadline, now time.Time) time.Duration {
	// Reserve the entire exchange budget plus a clock margin. Never round up to
	// STS's 900-second minimum or relabel a longer-lived credential as shorter.
	budget := p.requestTimeout + expiryMargin
	duration := min(p.maxSessionDuration, p.profile.MaxLifetime, deadline.Sub(now)-budget).Truncate(time.Second)
	if duration < minSessionDuration || duration < p.profile.MinLifetime+budget {
		return 0
	}
	return duration
}

func validEndpoint(endpoint string) bool {
	u, err := url.Parse(endpoint)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.Path == "" &&
		u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && !strings.Contains(endpoint, "#")
}

func validToken(token string) bool {
	if len(token) < 4 || len(token) > maxTokenBytes {
		return false
	}
	for _, r := range token {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

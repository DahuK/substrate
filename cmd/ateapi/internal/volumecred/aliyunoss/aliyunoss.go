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

// Package aliyunoss issues prefix-scoped Alibaba Cloud OSS credentials.
//
// It exchanges the control plane's own OIDC token (an RRSA ServiceAccount
// token on ACK) for an STS session with AssumeRoleWithOIDC, and always attaches
// a session policy limiting the session to one bucket prefix. The effective
// permission is the intersection of the role's policy and the session policy,
// so the role may be shared by many volumes while each credential reaches
// only its own. The package makes no other cloud call and has no fallback to
// default credentials.
package aliyunoss

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/agent-substrate/substrate/cmd/ateapi/internal/volumecred"
)

const (
	// STS refuses sessions shorter than 15 minutes and longer than the role's
	// maximum session duration, which is at most 12 hours.
	minDuration      = 15 * time.Minute
	maxDuration      = 12 * time.Hour
	maxTokenBytes    = 16 << 10
	maxResponseBytes = 64 << 10
	// STS limits the session policy to 2048 characters.
	maxPolicyBytes = 2048
	defaultTimeout = 10 * time.Second
)

var (
	roleARNPattern     = regexp.MustCompile(`^acs:ram::([0-9]{1,32}):role/[A-Za-z0-9._@-]{1,128}$`)
	providerARNPattern = regexp.MustCompile(`^acs:ram::([0-9]{1,32}):oidc-provider/[A-Za-z0-9._-]{1,128}$`)
	accountPattern     = regexp.MustCompile(`^[0-9]{1,32}$`)
	// Bucket names are 3-63 lowercase letters, digits and hyphens.
	bucketPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`)
	// Prefixes are literal object keys; RAM resource wildcards are excluded.
	prefixPattern  = regexp.MustCompile(`^[A-Za-z0-9._/-]+/$`)
	sessionPattern = regexp.MustCompile(`^[A-Za-z0-9.@_-]{2,64}$`)
)

// SecretKeys names the CSI secrets the driver reads the three parts of an STS
// credential from. They are driver-specific, so there is no default.
type SecretKeys struct {
	AccessKeyID     string `json:"accessKeyId"`
	AccessKeySecret string `json:"accessKeySecret"`
	SecurityToken   string `json:"securityToken"`
	// Expiration, if set, also passes the credential's RFC 3339 expiry.
	Expiration string `json:"expiration,omitempty"`
}

// Config is administrator-owned provider configuration.
type Config struct {
	// RoleARN is the RAM role assumed for every credential, and
	// OIDCProviderARN the RAM OIDC provider that trusts the token. Both must
	// belong to the same account.
	RoleARN         string `json:"roleArn"`
	OIDCProviderARN string `json:"oidcProviderArn"`
	// OIDCTokenFile is the control plane's projected OIDC token, re-read for
	// every request so token rotation is picked up.
	OIDCTokenFile string `json:"oidcTokenFile"`
	// STSEndpoint is the STS base URL, e.g. https://sts-vpc.cn-hangzhou.aliyuncs.com.
	STSEndpoint string `json:"stsEndpoint"`
	// BucketOwnerID pins policy resources to the account that owns the
	// buckets. Empty matches any account.
	BucketOwnerID string     `json:"bucketOwnerId,omitempty"`
	SecretKeys    SecretKeys `json:"secretKeys"`

	// HTTPClient overrides the client used to call STS. Tests only.
	HTTPClient *http.Client `json:"-"`
}

// Provider implements volumecred.Provider for OSS.
type Provider struct {
	cfg    Config
	owner  string
	client http.Client
	now    func() time.Time
}

var _ volumecred.Provider = (*Provider)(nil)

// New validates cfg and returns a Provider.
func New(cfg Config) (*Provider, error) {
	role := roleARNPattern.FindStringSubmatch(cfg.RoleARN)
	oidc := providerARNPattern.FindStringSubmatch(cfg.OIDCProviderARN)
	switch {
	case role == nil:
		return nil, fmt.Errorf("invalid roleArn %q", cfg.RoleARN)
	case oidc == nil:
		return nil, fmt.Errorf("invalid oidcProviderArn %q", cfg.OIDCProviderARN)
	case role[1] != oidc[1]:
		return nil, errors.New("roleArn and oidcProviderArn belong to different accounts")
	case cfg.BucketOwnerID != "" && !accountPattern.MatchString(cfg.BucketOwnerID):
		return nil, fmt.Errorf("invalid bucketOwnerId %q", cfg.BucketOwnerID)
	case !strings.HasPrefix(cfg.OIDCTokenFile, "/"):
		return nil, errors.New("oidcTokenFile must be an absolute path")
	case !validEndpoint(cfg.STSEndpoint):
		return nil, fmt.Errorf("stsEndpoint %q must be an https URL with no path", cfg.STSEndpoint)
	case cfg.SecretKeys.AccessKeyID == "" || cfg.SecretKeys.AccessKeySecret == "" || cfg.SecretKeys.SecurityToken == "":
		return nil, errors.New("secretKeys must name accessKeyId, accessKeySecret and securityToken")
	}
	cfg.STSEndpoint = strings.TrimSuffix(cfg.STSEndpoint, "/")
	client := http.Client{Timeout: defaultTimeout}
	if cfg.HTTPClient != nil {
		client = *cfg.HTTPClient
	}
	// Never forward the OIDC token through a redirect or keep cookies.
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	client.Jar = nil
	owner := cfg.BucketOwnerID
	if owner == "" {
		owner = "*"
	}
	return &Provider{cfg: cfg, owner: owner, client: client, now: time.Now}, nil
}

// Issue implements volumecred.Provider.
func (p *Provider) Issue(ctx context.Context, req volumecred.Request) (volumecred.Credential, error) {
	duration := req.Duration.Truncate(time.Second)
	if duration < minDuration || duration > maxDuration {
		return volumecred.Credential{}, fmt.Errorf("duration %s is outside STS's %s to %s", req.Duration, minDuration, maxDuration)
	}
	if !sessionPattern.MatchString(req.SessionName) {
		return volumecred.Credential{}, fmt.Errorf("invalid session name %q", req.SessionName)
	}
	policy, err := p.sessionPolicy(req.Scope)
	if err != nil {
		return volumecred.Credential{}, err
	}
	token, err := readToken(p.cfg.OIDCTokenFile)
	if err != nil {
		return volumecred.Credential{}, err
	}

	query := url.Values{
		"Action":    {"AssumeRoleWithOIDC"},
		"Version":   {"2015-04-01"},
		"Format":    {"JSON"},
		"Timestamp": {p.now().UTC().Format("2006-01-02T15:04:05Z")},
	}
	// The token travels in the body, not the URL, so proxies do not log it.
	form := url.Values{
		"RoleArn":         {p.cfg.RoleARN},
		"OIDCProviderArn": {p.cfg.OIDCProviderARN},
		"OIDCToken":       {token},
		"RoleSessionName": {req.SessionName},
		"DurationSeconds": {strconv.FormatInt(int64(duration/time.Second), 10)},
		"Policy":          {policy},
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.cfg.STSEndpoint+"/?"+query.Encode(), strings.NewReader(form.Encode()))
	if err != nil {
		return volumecred.Credential{}, err
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpReq.Header.Set("Accept", "application/json")
	resp, err := p.client.Do(httpReq)
	if err != nil {
		return volumecred.Credential{}, fmt.Errorf("calling STS: %w", err)
	}
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	_ = resp.Body.Close()
	if readErr != nil || len(body) > maxResponseBytes {
		return volumecred.Credential{}, fmt.Errorf("reading STS response: %v", readErr)
	}

	var result struct {
		Code        string
		Message     string
		RequestID   string `json:"RequestId"`
		Credentials *struct {
			AccessKeyID     string `json:"AccessKeyId"`
			AccessKeySecret string
			SecurityToken   string
			Expiration      string
		}
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return volumecred.Credential{}, fmt.Errorf("decoding STS response (HTTP %d): %w", resp.StatusCode, err)
	}
	if resp.StatusCode != http.StatusOK || result.Code != "" || result.Credentials == nil {
		return volumecred.Credential{}, fmt.Errorf("STS refused AssumeRoleWithOIDC (HTTP %d, code %q, request %q): %s",
			resp.StatusCode, result.Code, result.RequestID, result.Message)
	}
	c := result.Credentials
	expires, err := time.Parse(time.RFC3339, c.Expiration)
	if err != nil || c.AccessKeyID == "" || c.AccessKeySecret == "" || c.SecurityToken == "" || !expires.After(p.now()) {
		return volumecred.Credential{}, errors.New("STS returned an incomplete or expired credential")
	}
	secrets := map[string]string{
		p.cfg.SecretKeys.AccessKeyID:     c.AccessKeyID,
		p.cfg.SecretKeys.AccessKeySecret: c.AccessKeySecret,
		p.cfg.SecretKeys.SecurityToken:   c.SecurityToken,
	}
	if k := p.cfg.SecretKeys.Expiration; k != "" {
		secrets[k] = expires.UTC().Format(time.RFC3339)
	}
	return volumecred.Credential{Secrets: secrets, Expiration: expires}, nil
}

// sessionPolicy limits a session to objects under the scope's prefix, and
// listing to keys under it. It fails rather than widen a scope it cannot
// express exactly.
func (p *Provider) sessionPolicy(scope volumecred.Scope) (string, error) {
	if !bucketPattern.MatchString(scope.Bucket) || !prefixPattern.MatchString(scope.Prefix) {
		return "", fmt.Errorf("scope %s/%s is not a literal OSS bucket prefix", scope.Bucket, scope.Prefix)
	}
	objectActions := []string{"oss:GetObject"}
	if !scope.ReadOnly {
		objectActions = append(objectActions, "oss:PutObject", "oss:DeleteObject", "oss:AbortMultipartUpload", "oss:ListParts")
	}
	bucket := "acs:oss:*:" + p.owner + ":" + scope.Bucket
	type statement struct {
		Effect    string                       `json:"Effect"`
		Action    []string                     `json:"Action"`
		Resource  []string                     `json:"Resource"`
		Condition map[string]map[string]string `json:"Condition"`
	}
	https := map[string]string{"acs:SecureTransport": "true"}
	policy, err := json.Marshal(struct {
		Version   string      `json:"Version"`
		Statement []statement `json:"Statement"`
	}{"1", []statement{
		{"Allow", objectActions, []string{bucket + "/" + scope.Prefix + "*"}, map[string]map[string]string{"Bool": https}},
		{"Allow", []string{"oss:ListObjects"}, []string{bucket}, map[string]map[string]string{
			"Bool":       https,
			"StringLike": {"oss:Prefix": scope.Prefix + "*"},
		}},
	}})
	if err != nil {
		return "", err
	}
	if len(policy) > maxPolicyBytes {
		return "", fmt.Errorf("session policy for %s/%s exceeds %d bytes", scope.Bucket, scope.Prefix, maxPolicyBytes)
	}
	return string(policy), nil
}

func readToken(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("opening OIDC token: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxTokenBytes+1))
	if err != nil || len(data) > maxTokenBytes {
		return "", fmt.Errorf("reading OIDC token: %v", err)
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", errors.New("OIDC token file is empty")
	}
	return token, nil
}

func validEndpoint(endpoint string) bool {
	u, err := url.Parse(endpoint)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil &&
		(u.Path == "" || u.Path == "/") && u.RawQuery == "" && u.Fragment == ""
}

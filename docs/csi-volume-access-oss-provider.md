# OSS Volume Access Provider

The [aliyunoss provider](../internal/volume/access/aliyunoss/provider.go) makes a
direct, single-hop HTTP `AssumeRoleWithOIDC` exchange for RO access to one bucket
prefix, using Go's standard library and the local contract: no cloud SDK dependencies,
ambient AccessKey lookup, metadata, or role chaining. Inspired by ACK's RRSA/policy
flow, it needs no ACK identity CRs or template service.

This is experimental, not wired into `ateapi` or `atelet`, and not a qualified OSS
CSI integration. The [local experiment](csi-volume-access-experiment.md) uses a fake
provider and fake CSI server. Local STS checks are not cloud validation; no
real-cloud STS, OSS, or mount success is claimed here.
**Do not feed the current three-key result directly to a production OSS driver.**

## Configure the Trusted Identity

Acquire in the trusted control plane, not an actor sandbox. Explicitly project a dedicated
SA's OIDC token with `serviceAccountToken.audience: sts.aliyuncs.com`, `path: token`,
and, for example, `expirationSeconds: 3600`. Mount `/var/run/secrets/substrate-oss`
read-only, without file `subPath` pinning. A Kubernetes API audience token is unsuitable.

RAM trust needs `Action: sts:AssumeRole`, the fixed OIDC provider ARN as
`Principal.Federated`, and exact `StringEquals` for `oidc:iss`, `oidc:aud`, and
`oidc:sub: system:serviceaccount:<namespace>:<name>` identifying the control-plane SA.
The trust-policy action is not `sts:AssumeRoleWithOIDC`. See [RRSA][rrsa].

`RoleARN` and `OIDCProviderARN` must share an account; `New` checks their numeric IDs.
`BucketOwnerID` is the actual OSS owner and may differ. Cross-account access needs RAM
and bucket authorization; changing this ID grants nothing. The role must allow intended
reads/listing. STS intersects role and session policies; sessions cannot expand the role.

## Construct the Provider

This compilable API shape belongs inside the Substrate module (`internal` imports).
Replace identities/endpoints with trusted configuration. Construction does not call STS.

```go
package volumeconfig

import (
	"time"

	"github.com/agent-substrate/substrate/internal/volume/access"
	"github.com/agent-substrate/substrate/internal/volume/access/aliyunoss"
)

func newOSSProvider() (*aliyunoss.Provider, error) {
	profile := access.Profile{
		Name:            access.StagePublishSecrets,
		Version:         1,
		Driver:          "fake.oss.csi.example",
		CredentialKind:  access.SessionCredential,
		Delivery:        access.StagePublishSecrets,
		MinLifetime:     15 * time.Minute,
		MaxLifetime:     time.Hour,
		ReadOperations:  access.Read | access.List,
		WriteOperations: access.Read | access.Write | access.List,
	}
	return aliyunoss.New(aliyunoss.Config{
		RoleARN:            "acs:ram::1234567890123456:role/substrate-oss-reader",
		OIDCProviderARN:    "acs:ram::1234567890123456:oidc-provider/ack-rrsa-example",
		BucketOwnerID:      "1234567890123456",
		STSEndpoint:        "https://sts.cn-hangzhou.aliyuncs.com",
		OSSEndpoint:        "https://oss-cn-hangzhou.aliyuncs.com",
		Profile:            profile,
		MaxSessionDuration: time.Hour,
		RequestTimeout:     10 * time.Second,
		TokenSource:        aliyunoss.TokenFile("/var/run/secrets/substrate-oss/token"),
	})
}
```

This is the fake `stage-publish-secrets-v1` / `session-v1` contract, not driver
qualification. `New` requires both operation masks even though `Acquire` rejects RW.
The resolver must supply the identical profile/driver. Durations have no defaults:
the example sets a 1-hour cap and 10-second timeout. The RAM role must permit that cap.

Only after authentication and a production, coherent current-authority resolver exist,
use `broker := access.NewBroker(authorityResolver, p, nil)` (`nil` selects the real clock).
A self-asserted `Executor`/fixture is not production authority. Keep the driver gate closed.
Requests must not choose roles, token paths, endpoints, or raw `ApprovedAccess`.

## Scope and Session Policy

One resolver-owned scope: `Endpoint` is the configured OSS endpoint, `Resource` is
`"example-dataset"`, `Prefix` and `ListPrefix` are `"datasets/actor-a/"`, and
`Operations` is `access.Read | access.List`. Require `Mode: access.ReadOnly`, the pinned
profile/driver, nonempty binding and activation IDs, and nonzero binding revision.

- `Resource` is a bare bucket name, not an ARN, URL, or `bucket/path`: 3-63
  lowercase ASCII letters, digits, or hyphens, starting and ending alphanumeric.
- `Prefix` is literal ASCII using only letters, digits, `.`, `_`, `-`, and `/`,
  ending in `/`. Empty, `.` and `..` segments are rejected, including leading
  and repeated slashes. Wildcards, escapes, spaces, and Unicode are rejected.
- `ListPrefix` must exactly equal `Prefix`; neither is normalized or repaired.
  `datasets/actor-a/` does not additionally authorize the same-name object
  `datasets/actor-a` without the slash. No parent-navigation grant is added.

The compact JSON policy has `Version: "1"` and exactly two `Allow` statements:

| Action | Resource | Additional condition |
| --- | --- | --- |
| `oss:GetObject` | `acs:oss:*:<BucketOwnerID>:<bucket>/<Prefix>*` | None |
| `oss:ListObjects` | `acs:oss:*:<BucketOwnerID>:<bucket>` | `StringLike: {"oss:Prefix": ["<ListPrefix>*"]}` |

Both include `Bool: {"acs:SecureTransport": "true"}`. LIST is bucket-level and its
request prefix must stay inside the approved prefix; omitting `oss:Prefix` would
allow bucket-wide discovery. Only the provider adds the `*` suffix. Serialized policy
size must be **strictly less than 2048 bytes**; oversized policies fail before STS
without broadening. See [policy examples][policies] and [syntax][syntax].

No RW, multipart-upload, multi-scope, BucketSpace/AgenticBucket, bucket creation,
or policy templates. Do not widen permissions for filesystem probes; qualify the client.

## Lifetime and Revocation

STS's **900-second minimum** is the requested issuance duration, not guaranteed
remaining lifetime. `Profile.MinLifetime` is required remaining lifetime at provider
return and the broker's post-acquisition delivery check: a different constraint.

Reserve `RequestTimeout + 5 seconds` (15 seconds here). Take the minimum of the
provider cap, `Profile.MaxLifetime`, and approval time remaining minus that budget,
then truncate to whole seconds. Reject durations below 900 seconds or
`Profile.MinLifetime + budget`; never round up. Token acquisition shares the timeout.

Use **30 minutes of approval remaining** with **15 minutes `MinLifetime`**, not 15 for
both. The example requests about 29m45s before elapsed work. The broker deadline also
respects request/profile maxima and binding/grant expirations; leave enough headroom.

Actual STS `Expiration` is preserved as `Credential.ExpiresAt`, never clamped or
relabeled. Expired, over-deadline, too-short, or over-cap results are rejected.
Revocation gates later delivery/validation, not credential recall, atomic access
revocation, or mounted I/O. There is no credential cache, retry loop, or driver refresh.

## HTTP and Transport Boundary

`TokenFile` reopens the explicit absolute pathname each exchange, following the
projection rather than retaining an FD or resolved symlink. No default path,
environment credentials, metadata fallback, or Kubernetes TokenRequest is used.
Missing/invalid tokens fail closed. STS validates OIDC trust; never log tokens/secrets.

`TokenSource` callbacks must be concurrency-safe, bound their own upstream reads and
allocations, and honor context cancellation. The provider checks returned token size;
it cannot forcibly stop a callback that ignores its context. `TokenFile` supports
trusted local regular-file projections only, not pipes, devices or network filesystems.
It checks the opened file as well as the pathname and limits reads, but context checks
cannot interrupt kernel file I/O. Keep the directory/projection trusted, including during
rotation. HTTP transports must likewise honor request cancellation and finish cleanup;
the provider closes the response body before its final delivery-time checks.

`STSEndpoint` is the exchange destination; `OSSEndpoint` is the data endpoint and
must exactly match `Scope.Endpoint`. Both are fixed, trusted HTTPS origins with
**no trailing slash**, path, userinfo, query, or fragment. Validation is syntactic,
not a hostname allowlist. The provider does not contact OSS or verify bucket routing.

HTTP POST uses `application/x-www-form-urlencoded`, not JSON. URL common parameters:
`Action=AssumeRoleWithOIDC`, `Version=2015-04-01`, `Format=JSON`, and UTC `Timestamp`.
The body (`PostForm`) has `RoleArn`, `OIDCProviderArn`, `OIDCToken`, `RoleSessionName`,
`DurationSeconds`, and `Policy`. No AccessKey signature; session names hash binding UID,
revision, and activation UID. Inspect URL and `PostForm` separately; `ParseForm` merges both.

`HTTPClient` is optional **trusted transport injection**, not request input. `New`
copies it, blocks redirects, and clears its cookie jar, but cannot sandbox a custom
`RoundTripper`. TLS verification, roots, DNS, proxies, and transport behavior must be
trusted. Audit default-transport proxy environment settings. Never disable TLS verification
in production, log the form body, or bypass redirect restrictions inside the transport.

## OSS CSI Compatibility Gate

Provider/broker secrets are exactly `accessKey`, `secretKey`, and `sessionToken`;
expiration is separate metadata. The [Alibaba parser][driver] uses `AccessKeyId`,
`AccessKeySecret`, `SecurityToken`, and `Expiration` (optional in the reviewed parser).
This is not just capitalization. The [adapter](../internal/volume/csi/authorized.go)
sends VolumeContext `endpoint`/`resource`/`prefix`, not the driver's `url`/`bucket`/`path`.

Do not rename a driver ID and send these keys to production, or omit the token and
treat temporary keys as static. Unrecognized keys can trigger ambient-credential
fallback. A separate fail-closed adapter/profile must preserve scope, expiration,
and RO intent, disable fallback, and qualify Stage/Publish and refresh. None is
supplied here. The fake contract requires Stage and no controller attach.

## Local Checks

From the repository root with the toolchain required by `go.mod`:

```sh
go test -count=1 -v ./internal/volume/access/aliyunoss
go test -count=1 -v ./internal/volume/csi -run TestVolumeAccessDemo
go test -count=1 -race ./internal/volume/...
go vet ./internal/volume/...
```

The provider tests use local STS fixtures with synthetic tokens, including the real
Broker's post-acquisition revocation check. They do not prove RAM trust, OSS enforcement,
or driver support. Run the commands above against the current checkout to reproduce.

On September 28, 2026, the volume packages passed uncached race-enabled tests and
`go vet`; this provider had 96.1% statement coverage. The repository-wide
`go test -race ./...` phase also passed. `make verify` then stopped at code generation's
clean-worktree precondition, so the complete verification target has not passed.

## Real-Cloud Acceptance Checklist

Run only after explicit operator approval, in an isolated account/bucket with
disposable data. No cloud test runner is supplied or automatically invoked here.

- [ ] Pin revision, region, role/provider ARNs, bucket owner, endpoints, and test window.
  Restrict SA trust, remove ambient credentials, block metadata, and verify token rotation.
- [ ] Use an operator-owned in-module harness to call this provider with a trusted
  RO approval, a 30-minute deadline, and the example profile. Record only sanitized
  timing, requested duration, policy size, and returned expiration, never credentials.
- [ ] With those exact credentials held in memory, use a trusted OSS API client:
  GET `datasets/actor-a/item.txt` and LIST `prefix=datasets/actor-a/` must succeed;
  GET a sibling or `datasets/actor-a`, and LIST with empty/parent/sibling prefixes
  must fail authorization. Seed private objects using a separate admin identity; allow both
  test prefixes in the role's RO ceiling to verify that the session further narrows it.
- [ ] PUT, DELETE, multipart initiation/listing, and another bucket must be denied.
  Check the HTTPS condition in an isolated transport test with disposable credentials;
  do not expose real data or reusable secrets over an untrusted plaintext network.
- [ ] Wrong SA/audience/issuer, missing/expired tokens, and insufficient lifetime must
  withhold credentials. Test cross-account access if used. Confirm expiration and blocked
  delivery after revocation; do not claim immediate invalidation of issued sessions.
- [ ] Keep real mounts blocked until the separate driver adapter is qualified.
  Then test absent/malformed credentials with fallback disabled, exact path scope,
  RO writes, expiration during I/O, cleanup, and restart/uncertain RPC outcomes.
- [ ] Preserve sanitized evidence and unexpected denials; do not widen the policy
  to obtain a pass. Remove test resources and revoke test trust under operator control.

[rrsa]: https://www.alibabacloud.com/help/en/ack/ack-managed-and-ack-dedicated/user-guide/use-rrsa-to-authorize-pods-to-access-different-cloud-services
[policies]: https://www.alibabacloud.com/help/en/oss/user-guide/common-examples-of-ram-policies
[syntax]: https://www.alibabacloud.com/help/en/oss/user-guide/authorization-syntax-and-elements
[driver]: https://github.com/kubernetes-sigs/alibaba-cloud-csi-driver/blob/e3a56818f79ae27f0ccca70807cb040726b78858/pkg/oss/utils.go

STS API: [AssumeRoleWithOIDC](https://www.alibabacloud.com/help/en/ram/developer-reference/api-sts-2015-04-01-assumerolewithoidc).
Cross-account setup: [OSS bucket policies](https://www.alibabacloud.com/help/en/oss/user-guide/common-examples-of-bucket-policy).

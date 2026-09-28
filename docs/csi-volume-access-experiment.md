# CSI Volume Access Experiment

This local experiment exercises the real authorization broker and existing CSI
adapter with an in-memory authority fixture, fake provider, and fake CSI server.
It is not wired into `ateapi` or `atelet`, deploys nothing, and leaves the default
mount path unchanged.

For the September 28 performance changes, measurements, and limits, see the
[performance guide](csi-volume-access-performance.md). These remain local experiments,
not production authority integration or cloud-capacity results.

## Run Locally

From the repository root, with the Go toolchain required by [go.mod](../go.mod):

```sh
go test -count=1 -v ./internal/volume/csi -run TestVolumeAccessDemo
```

No cloud access, cluster, root privileges, or real credentials are needed. The
fixture uses temporary directories and a local Unix socket; no real mount occurs.
Optional broader checks (race detection requires a supported platform/C toolchain):

```sh
go test -count=1 -race ./internal/volume/...
go vet ./internal/volume/...
```

Expected demo observations, not a recorded verification result:

| Demo case | Acquire / Stage / Publish | Expected outcome |
| --- | --- | --- |
| `allow_read_only_dataset` | 1 / 1 / 1 | `ALLOW`: original handle, reader-only capability, Publish `Readonly=true`; owner cleanup unpublishes and unstages. |
| `workspace_does_not_broaden_dataset` | 1 / 0 / 0 | `ISOLATED`: separate read/write workspace lease; using it for the dataset is denied, not a workspace mount. |
| `foreign_actor_binding_denied` | 0 / 0 / 0 | `DENY`: foreign actor/activation rejected before acquisition. |
| `revoked_during_acquisition` | 1 / 0 / 0 | `REVOKED`: post-acquisition authorization withholds material. |
| `revoked_between_stage_and_publish` | 1 / 1 / 0 | `REVOKED`: Publish blocked; a fresh exchange adds no calls; owner cleanup remains allowed. |

Tests assert requests and call counts, not just log messages. Provisioning and
controller attach counts stay zero. Stage secrets already delivered are not recalled.

## Follow the Code

```text
fixture identity/state -> real Broker.Exchange -> fake Provider.Acquire -> broker recheck/Lease
  -> MountAuthorizedVolume -> existing CSI adapter/client -> local fake CSI server
```

Read in this order:

1. [types.go](../internal/volume/access/types.go): trusted `Executor`, untrusted `Request`, coherent current-authority `Resolver`, `Provider`, and `Target` contracts.
2. [broker.go](../internal/volume/access/broker.go): `Exchange` authorizes before acquisition, rechecks afterward, and pins authority/scope/expiry; `CheckLease` is local preflight only, while `Validate` reads live authority before delivery.
3. [authorized.go](../internal/volume/csi/authorized.go): entry preflight, target/driver checks, short-lock indexed reservations, and owner-only cleanup handles.
4. [plugin.go](../internal/volume/csi/plugin.go): the existing `mountVolume` path revalidates before Stage and Publish, delivering material only through their `Secrets` fields. Protected failures never fall back to legacy mounting.
5. [authorized_test.go](../internal/volume/csi/authorized_test.go): fixture setup, the five demo cases, and failure tests; [plugin_test.go](../internal/volume/csi/plugin_test.go) supplies the reused fake CSI server.
6. [protected_registry_test.go](../internal/volume/csi/protected_registry_test.go): path-index equivalence, reservation conflicts, and registry-only benchmarks against a test-only linear oracle.

## Current Authority and Delivery

`Resolver.Resolve(bindingUID)` reads current Substrate `Binding`, `Grant`,
`Assignment`, `Volume`, `Profile`, and `PolicyRevision`, plus actor/atespace identity,
as one coherent snapshot. A production resolver must support concurrent calls and
establish current authority through real versions/database reads or equivalent
coherent reads. That implementation is still missing. The in-memory test fixture
is neither a TTL authorization cache nor cloud validation.

The [OSS provider](csi-volume-access-oss-provider.md) has a different responsibility:
translate an already-approved scope into a restrictive STS request and temporary
credentials. Its local TLS STS tests do not establish Substrate authority or prove
real OSS/driver enforcement. Adding this provider does not implement the resolver.

At mount entry, `CheckLease` checks issuer, executor, exact target, credential expiry,
approval deadline, and context locally. It performs no Resolve or Acquire and does
not authorize secret delivery. Each actual `Validate` still resolves fresh authority.
Successful `Exchange` plus `MountAuthorizedVolume` now makes **four, not five**
Resolve calls: two around Acquire, zero at entry, one before Stage and one before
Publish. None of these four fresh gates can be removed using a stale TTL approval.

`reauthorize` reuses only structural proof when the complete fresh snapshot equals
the already-validated snapshot for that executor/request. It still checks live
binding/grant time limits; credential expiry and approval deadline are also checked
before delivery. A changed snapshot runs full `authorize`, preserving its error
category; even an otherwise valid change denies use of the pinned lease. This is
not cached authorization, credential reuse across Exchanges, or refresh.

## API Sketch

Inside a caller returning `(*csi.AuthorizedMount, error)`, assume the fixture
broker/plugin and request are configured. Identity and target variables come from
the trusted runtime, not actor input. `cleanupApproved` is an explicit owner
decision to tear down an idle fixture mount; otherwise return it for use.
`cleanupCtx` is a live, owner-controlled context.

```go
lease, err := broker.Exchange(ctx, executor, request)
if err != nil { return nil, err }
target := access.Target{ActorUID: actorUID, ActivationUID: activationUID, Driver: driver, Handle: handle}
mount, err := plugin.MountAuthorizedVolume(ctx, broker, executor, lease, target, targetPath)
if err != nil { return mount, err } // Preserve a nonnil owner handle, even on failure.
if !cleanupApproved { return mount, nil }
if err := plugin.UnmountAuthorizedVolume(cleanupCtx, mount); err != nil { return mount, err }
return nil, nil
```

The caller must retain every nonnil handle, including on mount or cleanup errors.
Do not blindly `defer` teardown or retry after a timeout: the RPC outcome may be
unknown. Keep the reservation and resolve that uncertainty before explicit owner
cleanup using the original pointer and same Plugin. Only successful Unpublish,
Unstage, and local cleanup release it; cleanup needs no fresh lease. This experiment
provides no automatic reconciliation of uncertain outcomes.

The Plugin owns an independent snapshot of each mount record. The returned pointer
identifies its owner; overwriting the handle's value cannot redirect cleanup or
remove another mount's reservation.

An observable change: revocation after Exchange is now rejected by the fresh
pre-Stage gate, not the local entry preflight. A reservation and staging directory
can already exist, so that failure returns a **nonnil owner plus an error**, with
zero Stage/Publish calls. Retain it and complete owner cleanup even in this case.
Local preflight failure returns nil, without a reservation or another Resolve.

## Registry Coordination

The Plugin mutex protects only in-memory registry changes, not an entire mount or
cleanup. It is never held across Resolver calls, CSI RPCs, or filesystem I/O.
Nonconflicting handles/paths can progress independently. A second reservation for
the same driver/handle, or an overlapping target/staging path, returns
`ErrUnsupported`. The handle remains exclusive; sharing is not enabled.

Each owner record has a `busy` bit. Cleanup of that same owner while its mount or
cleanup is in flight fails fast with `ErrUnavailable`, without a CSI cleanup call.
Finishing a failed attempt clears busy but retains its record and indexes; only
complete successful cleanup removes them. Clearing busy does not prove a timed-out
driver operation stopped: retain the owner and resolve uncertainty before retrying.

Handle membership uses an index; path conflicts use `exact`/`subtree` counts and
ancestor traversal, including target-versus-stage overlaps. This replaces an
O(k) resident-record scan with O(depth) ancestor visits, not shared-publisher
bookkeeping, symlink defense, restart reconciliation, or fencing.

## Boundaries

- Identity and current scheduler assignments are simulated only by trusted in-memory fixtures. The broker does not authenticate callers or consult the production scheduler; a self-asserted `Executor` is not authentication.
- Only the declared `stage-publish-secrets-v1` filesystem profile with `session-v1` credentials is supported: exactly three nonempty keys, `accessKey`, `secretKey`, and `sessionToken`, in both Stage and Publish `Secrets`. Stage is required, with no controller attach. Do not supply or log real credentials.
- Each binding approves one actor-exclusive scope. Dataset read/list and workspace read/write/list remain separate. Provider endpoint, resource, prefix, LIST prefix, and operations must match exactly, along with credential kind/profile/version and valid expiry. This is not general cloud IAM policy containment or proof of cloud-side enforcement.
- The OSS HTTP acquisition adapter has only local STS-fixture validation, not real-cloud or cloud-mount qualification. There is no production resolver, credential refresh, durable lease manager, restart reconciliation, or fencing. Revocation gates later delivery; it cannot recall Stage secrets, atomically revoke credentials, or stop already-mounted I/O.
- Reservations belong to one Plugin and work only within the same process. Use a single Plugin for a given driver/node; do not mix multiple Plugin instances or the legacy mount/unmount path on that driver/node. Shared-volume operation is unsupported.
- `targetPath` must be an absolute, clean path supplied by the trusted runtime. Lexical overlap checks provide no symlink defense or host-path authorization. Never accept an actor-selected arbitrary host path.

[Community issue #1637](https://github.com/agent-substrate/substrate/issues/1637)
describes user-facing shared-volume semantics and actor-independent lifecycle,
including authorized sharing within an atespace and no shared-data rollback on
actor restore. It is not evidence of implemented NodeStage isolation or safe
multi-publisher bookkeeping. This experiment continues to reject shared volumes.

## Verification Recorded

For the September 28, 2026 performance round,
`go test -count=1 -race ./internal/volume/...` and `go vet ./internal/volume/...` passed. Independent review
recorded PASS, and repeated race-enabled concurrency checks passed 20 runs.
The repository-wide `go test -race ./...` phase also passed. `make verify` then
stopped at code generation's clean-worktree precondition; the complete target
has not passed. See the performance guide for the recorded
benchmark environment and results; no cloud test or real mount was performed.

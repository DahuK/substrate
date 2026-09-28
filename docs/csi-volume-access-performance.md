# CSI Volume Access Performance

This guide records the September 28, 2026 local authorization/registry experiment.
It is not evidence of production integration, 10,000 concurrent cloud actors,
cloud enforcement, or end-to-end mount capacity. Start with the
[experiment guide](csi-volume-access-experiment.md) for API and cleanup requirements.

## Authority Is Not STS

`Resolver.Resolve(bindingUID)` reads current Substrate `Binding`, `Grant`,
`Assignment`, `Volume`, `Profile`, and `PolicyRevision`, plus actor/atespace identity,
as a coherent snapshot. See [types.go](../internal/volume/access/types.go#L104-L122).
A real production resolver is still missing. Its version/database/coherent-read
costs are not measured here. An immutable indexed fixture is not a TTL approval
cache, a production authority store, or cloud validation.

The [OSS provider](csi-volume-access-oss-provider.md) instead translates an
already-approved scope into restrictive STS policy and calls `AssumeRoleWithOIDC`.
It neither resolves Substrate authority nor replaces that resolver. Its local TLS
fixture tests do not prove RAM trust, OSS enforcement, or CSI compatibility.
Each Exchange reaching acquisition still calls Acquire once; with the OSS adapter,
an otherwise successful exchange still makes one STS request. There is no issuance
cache, STS-call reduction, refresh loop, or production driver integration here.

## Four Fresh Gates

The successful, complete `Exchange` plus `MountAuthorizedVolume` path has changed
from five Resolve calls to four, not from fresh authorization to cached approval:

| Point | Previous Resolve calls | Current Resolve calls |
| --- | ---: | ---: |
| Before Acquire | 1 | 1 |
| After Acquire | 1 | 1 |
| Mount entry | 1 | 0 |
| Before Stage | 1 | 1 |
| Before Publish | 1 | 1 |
| Total | 5 | 4 |

`CheckLease` at entry is local preflight for issuer, executor, exact target,
credential expiry, approval deadline, and context. It does not Resolve, Acquire,
or authorize delivery. `Validate` still resolves fresh authority after its identity
check; it does not substitute the preflight for the current read or change that
read's error precedence. See [broker.go](../internal/volume/access/broker.go#L118-L198)
and the sequence assertion in
[authorized_test.go](../internal/volume/csi/authorized_test.go#L474-L498).

`reauthorize` reuses structural proof only when the complete fresh snapshot equals
the already-validated snapshot for the same executor/request. It still checks live
binding/grant deadlines; Exchange and Validate also enforce credential expiry and
the approval deadline. A changed snapshot runs full `authorize`, retaining its
error category; an otherwise valid changed snapshot still returns `ErrDenied` for
the pinned approval. No authorization result is cached across stale reads.
The four remaining fresh points cannot be removed by adding a TTL cache.

Revocation after Exchange is therefore observed at the fresh pre-Stage gate, not
entry. A staging directory and reservation may already exist: return and retain
the nonnil owner together with the error, then complete explicit owner cleanup.
No Stage/Publish secrets are delivered in that case. Local preflight failure
returns nil without reserving or resolving. See
[authorized_test.go](../internal/volume/csi/authorized_test.go#L393-L472).

## Registry Concurrency

[authorized.go](../internal/volume/csi/authorized.go#L85-L197) holds short locks only
over registry memory, never over Resolver, CSI, or filesystem I/O. Nonconflicting
handles/paths can progress independently; there is no whole-Plugin serialization.
Same driver/handle reservations remain exclusive. Conflicts return
`ErrUnsupported`; same-owner cleanup while mount/cleanup is busy fails fast with
`ErrUnavailable` and does not issue cleanup RPCs.

Handle lookup is indexed. Path lookup/update uses `exact` and `subtree` reservation
counts while visiting ancestors, including target-versus-stage conflicts. It takes
O(depth) ancestor visits rather than scanning O(k) resident records. This is a
lexical index, not host-path authorization or protection from symlinks.

Failure clears busy but retains the owner record and indexes. Only successful
Unpublish, Unstage, and local cleanup remove them. A cleared busy bit is not proof
that a timed-out driver call stopped. No shared-volume support, restart
reconciliation, durable ownership, or fencing is added. Use one Plugin per
driver/node; multiple Plugins or protected/legacy mixing remain unsafe.

Callers must bound concurrency and retries for authority reads, STS, CSI, and
filesystem work. This change adds no limiter or admission queue. Concurrent
Resolver/Provider implementations and token sources must honor their contracts.
The concurrency tests prove independent progress and fail-fast conflicts with
local fixtures, not sustainable cloud concurrency or worker reuse after a crash.

## Reproduce Microbenchmarks

Recorded environment: **2026-09-28, Darwin arm64, Apple M5 Pro, Go 1.27**.
From the repository root:

```sh
go test -run '^$' -bench 'Benchmark(Validate|Exchange)$' -benchmem -benchtime=500ms -count=3 ./internal/volume/access
go test -run '^$' -bench BenchmarkProtectedRegistry -benchmem -benchtime=500ms -count=3 ./internal/volume/csi
```

[Broker benchmarks](../internal/volume/access/broker_benchmark_test.go) isolate
local CPU/allocations. Validate rotates through 10,000 resident binding snapshots;
fixture/lease setup is outside timing. Exchange uses a fake provider, not STS.
[Registry benchmarks](../internal/volume/csi/protected_registry_test.go#L126-L186)
measure reserve/release with prebuilt resident paths, no broker, RPC, filesystem,
or actual mount. They are not parallel 10,000-actor cloud workloads.

## Recorded Results

Medians of three samples. Broker "previous" values were measured on the actual
previous implementation. Registry comparison is different: `linear_oracle` is a
test-only model of the old scan algorithm, not an old full-mount measurement or
production fallback. All allocation figures are per operation.

| Operation | Previous / linear oracle | Current | Bytes/op | Allocs/op |
| --- | ---: | ---: | ---: | ---: |
| Validate, 10,000 bindings | 390.9 ns | 199.4 ns | 144 -> 0 | 1 -> 0 |
| Exchange, fake provider | 995.5 ns | 861.5 ns | 2240 -> 2096 | 7 -> 6 |
| Registry, 1,000 residents | 268119 ns | 1465 ns | 256064 -> 64 | 4001 -> 1 |
| Registry, 10,000 residents | 2950525 ns | 1437 ns | 2560064 -> 64 | 40001 -> 1 |

Raw timing samples, in ns/op, preserve the observed variability:

| Operation | Previous / linear oracle samples | Current samples |
| --- | --- | --- |
| Validate, 10,000 bindings | 384.0 / 405.0 / 390.9 | 187.7 / 199.4 / 200.1 |
| Exchange | 942.6 / 1026 / 995.5 | 861.5 / 1002 / 761.9 |
| Registry, 1,000 residents | 275028 / 268119 / 260614 | 1549 / 1443 / 1465 |
| Registry, 10,000 residents | 2840141 / 3146778 / 2950525 | 1437 / 1443 / 1411 |

Exchange CPU timings are noisy; do not emphasize a CPU speedup from three short
runs. The clearer observation is one fewer allocation and 144 fewer bytes/op.
At 10,000 residents the registry comparison is about **2.95 ms -> 1.437 us**,
not evidence that a complete mount became about 2,000 times faster. Authority
reads, STS latency/quotas, CSI/client startup, filesystem work, and bounded caller
concurrency still determine production cost and capacity and remain unmeasured.

## Verification and Limits

Recorded passing checks for this round:

```sh
go test -count=1 -race ./internal/volume/...
go vet ./internal/volume/...
```

Independent review recorded **PASS**; repeated race-enabled concurrency checks
passed **20 runs**. The repository-wide `go test -race ./...` phase also passed.
`make verify` then stopped at code generation's clean-worktree precondition;
the complete verification target has not passed. No cloud tests were performed.

[Issue #1637](https://github.com/agent-substrate/substrate/issues/1637) specifies
user-facing authorized sharing and actor-independent volume lifecycle, including
not rolling shared data back on actor restore. It is not implementation evidence
for NodeStage isolation or multi-publisher bookkeeping. PublishContext/access-mode
work alone would not prove those properties either. Sharing remains disabled;
production authority, recoverable lifecycle, and real provider/driver enforcement
qualification remain separate gates.

# Rust Root feature worker

Updated 2026-10-28. The branch implements a separate development feature
worker and fixed host caller. All 645 Mac migration tests and warnings-denied
Mac/ARM Clippy pass. Fresh owned-VM execution, live restart/recovery proofs and
final operator integration remain open. Parent acceptance stays 24/62.

## Ownership and fixed inputs

The Root executable is `gauntlet-feature-worker`; the Mac caller is
`gauntlet-host-feature-audit`. A closed host intent binds the existing
11-field executor spec, exact completed build result, complete controller
tree, builder/base images, rendered audit policy, four VM helper hashes and
the actual Root worker executable. It admits no arbitrary command, selector,
candidate path or resource override.

Root independently opens the successful build result and source/archive,
checks the nested wheel and actual Native bytes as data, verifies the full
controller tree and immutable local image, and repeats those checks after
execution. It never imports or executes a candidate package as Root. The
executor and fixed Node are separately captured as inert, content-addressed
ARM ELFs. Partial asset slots remain consumed.

The feature profile remains two CPUs, 12 GiB, 2048 tasks and a four-hour
deadline. The Root Podman client has its own fixed cgroup and bounded
128-KiB stdout/stderr. Existing candidate/dependency limits remain unchanged.
The unprivileged PID-1 executor still owns the complete fixed 28-group,
52-selector schedule and the source/installed context boundary.

## Durable lifecycle

Initialization v4 creates the private `feature-state` and `feature-jobs`
namespaces and `feature-assets` directory. Existing directories and locks
must already have safe custody; initialization never repairs their modes or
adopts existing job IDs. Historical initialization receipts remain intact.

Under the shared Rust and Python worker leases, the Root owner commits the
complete canonical intent as the one-use reservation before creating its
audit directory, loading a policy or creating a container. An incomplete
intent write consumes the ID and blocks admission. The separate feature
lease covers all feature journal writes.

Container ownership requires a full 64-character CID, exact intent label,
fixed unprivileged user, immutable image and exact security/resource settings.
The CID receipt precedes start. The running marker binds the actual client
PID/start ticks and feature cgroup. Cleanup targets that identity, and keeps
confinement enforced when teardown cannot be proved.

After exact container/client/profile cleanup, Root compares its captured
stdout with the exported report, independently recomputes every XML/log
digest, count and status, and retains immutable Root copies. A closed result
binds those artifacts to the original outside intent. A complete result
always has terminal status `invalid-evidence`; `audit_status` separately
preserves `passed`, `failed`, `incomplete` or `invalid-evidence`.
Qualification, artifact admission and Guard causality remain false; model
requests and tokens remain zero.

New native, candidate and dependency dispatch checks reject unresolved feature
state. Orphan files, unknown sidecars, partial JSON and conflicting completion
records block further admission. Reading a completed result repeats custody,
artifact verification and present cleanup checks.

## Restart and recovery boundary

The host durably records dispatch before opening the VM connection. An
uncertain transport consumes the attempt. A second invocation refuses instead
of replaying the work. Restart opens the retained guest result using the
audit ID and original complete intent digest.

The Mac host caller now exposes an explicit `read` action for that restart
path. It requires the exact durable intent and dispatch bytes before invoking
the pinned Root worker's `--read` action. It sends no run intent, checks the
canonical completed result against the original outside pins, and commits or
compares a private host copy. A missing or changed dispatch, substituted
intent digest, changed result and attempted repeated `run` refuse. The fake
Lima process test covers these cases; all 31 host library tests and Mac/ARM
warnings-denied Clippy pass. This is local process validation only. It has
not read a real guest result, and the host still lacks an explicit repair
command for the guest's quiescent aborted receipt. Exact source and built
host-binary digests are retained in workspace evidence
`gauntlet-rust-pr-ready-evidence-20261026/feature-host-read-proof-001.json`
against base commit `a47b133b`.

Quiescent recovery appends a separate `aborted` receipt with an unknown exit.
It requires the original client identity to be gone, the exact container and
cgroups absent, and the profile removed. It never signals a historical or
reused PID and never replaces a result, repairs partial records in place or
re-executes an audit. Recovery of still-active resources and other uncertain
states needs further implementation/proof; their presence continues to block
dispatch.

The first new live run will use the already retained product/build inputs.
It must remain explicitly attributed to that product source rather than the
newer migration implementation or upstream merge. Current-source product
qualification, full operator wiring, interruption coverage and cutover remain
separate acceptance requirements. Required cloud CI remains user-owned and
pending.

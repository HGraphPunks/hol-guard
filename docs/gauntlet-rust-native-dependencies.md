# Native dependency preparation

The current candidate requires MCP >=1.30.0. The retained dependency prefix
has 1.28.1, so it cannot supply the new installed-prefix proof unchanged.

`gauntlet-dependency-exporter` is the new fixed **unprivileged** adapter for
creating compatible data. It requires Linux ARM64, UID/GID 65532 throughout,
zero permitted/effective capabilities, no-new-privileges, seccomp mode 2 and
the expected job AppArmor attachment. It refuses host/VM Root. Its fixed
inputs are Root-owned mode-0444 `pyproject.toml` and `uv.lock` under `/input`,
each bounded at 4 MiB and checked against outside SHA-256 pins before use.

Rust creates one-use `/work/home` and `/work/project`, then invokes the pinned
image's UV with frozen locking, no dev/project install, no builds, its existing
Python executable and no Python download. Explicit copy mode avoids mutable
cache hardlinks. The child has a 300-second deadline and bounded reap; the
outer Root owner must still own and drain the entire container.

Rust then writes only ordinary site-package bytes and a versioned manifest to
exclusive mode-0600 `/output/dependencies.zip`. The ZIP writer uses held
descriptors, rejects links/special objects, unsafe ownership/modes and changing
files/directories, and bounds 100,000 visited objects, depth 128, 512 MiB decoded
bytes and 256 MiB of compressed output. It fsyncs the file/directory and hashes
the actual ZIP. The manifest binds job, source, both input hashes and a framed
digest over all exported file bytes. No dependency is imported or executed by
the archiver. Every report remains unadmitted and execution-ineligible with
zero model requests.

Three Mac tests verify binary ZIP readback, preservation on replay refusal,
no execution of `.pth` content, linked-file/root refusal, and byte/seek bounds
without allocating a 256-MiB test file. ARM64 compilation and warnings-denied
Mac/ARM64 worker Clippy pass. This adapter has **not yet run in a live container**.

The Rust host command `gauntlet-host-prepare-dependency-inputs` now creates a
closed three-file capsule under an existing one-use local source slot. It
reverifies that archive/ref/Git graph, reads the two exact committed ordinary
blobs without checkout, and accepts only an outside-pinned owned static ARM64
ELF adapter. It writes and reads back the private capsule, rechecks the graph
and commits a separate canonical receipt. Real Git tests cover an advanced
worktree, immutable source/replay, linked project files and wrong/dynamic
exporter formats. The ZIP dependency adds only a locked graph edge; no package
version changes.

The native worker's explicit `--capture-dependency-inputs` operation receives
that capsule through its existing bounded cancellable stdin copier. Both
permanent leases, the actual worker generation, captured source hash and
strict native source receipt are required. Root validates exactly the three
ordinary members and outside hashes, writes 0444 project/lock files and a 0555
adapter under a private partial tree, independently reads them back, and
publishes without replacement. The archive and receipt stay source/job-bound;
failed partials remain consumed. No adapter or installer executes during this
operation. The [source-sized live VM capture proof](gauntlet-rust-native-dependency-input-vm-proof-20261026.md)
now passes, including both competing leases, wrong generation/source/hash,
truncation, overflow, member-hash mismatch and replay preservation. Independent
host readback verifies all 36 retained evidence members. The current Mac
workspace passes 413 tests across 213 targets with no failures or ignores;
the actual Root ARM64 library passes 126 tests with 24 preexisting fixture
ignores. The first ARM run exposed a stale current-context test expectation;
its failed log is retained alongside the corrected, independently recomputed
oracle. The exporter itself still has not run in a live container.

`gauntlet-host-run-dependencies` now has a distinct one-use prelaunch intent
journal binding the exact VM/transport, source/capsule/capture receipt, exporter,
controller, image, policy, runtime and runner, plus a fresh host nonce. The
shared closed contract rejects arbitrary command/path/resource fields. Private
descriptor custody, durable readback, restart, replay, linked-record and replaced
directory tests pass. Existing candidate pin schemas remain separate.

The native worker's `--prepare-native-dependencies` composition validates that
intent and its actual executable, takes both permanent worker leases and a
separate durable dependency reservation, and repeats image/input/policy/runtime
preflight. It creates one exact-ID container with a pinned intent label and
fixed UID, capabilities, AppArmor, seccomp, memory, CPU, PID and slirp controls.
The attached client has bounded logs, deadline, cancellation and disk checks.
Cleanup rechecks container identity before stopping it, then verifies the
container, systemd cgroup, client cgroup and policy are absent. Successful
exports are copied once into Root-owned 0444 data with independent readback.
The terminal stays `invalid-evidence`. Unresolved dependency state blocks later
dependency, native worker and candidate runs; it is never automatically retried.
The v3 inert initializer adds only the separate private dependency journal.
ARM64 compilation and warnings-denied Mac/ARM64 Clippy pass. **This full
composition has not yet run on the VM.**

The complete Mac workspace passes 416 tests across 215 targets with zero
failures/ignores. Log `rust-workspace-native-dependency-run-009.log` has SHA-256
`2745c680bde743e5741016ad9c56a504acc6263e935fc7606a807442f4546a63`.
The earlier sandboxed run is retained as `008.log`, SHA-256
`4863f5598c2cc66d75df2a10798cbf29c0280b5daed8298852328d66c1fb2ccc`:
both bridge interop fixtures refused local Unix socket creation. The complete
run used the approved local socket capability without changing those tests.

The remaining composition and verification are explicit:

- Verify the new prelaunch host intent, actual unprivileged exporter and Root
  supervision together on the owned VM, including independent kernel/cleanup
  observations, replay and interrupted-job reconciliation.
- After verified cleanup, Root must independently capture/inspect the ZIP,
  construct an inert dependency prefix and validate the candidate's complete
  declared requirements against it before any control can use that prefix.

The inner attachment check does not establish the kernel policy's enforcement
mode by itself; the Root owner must observe that independently. An adapter
report or successful package installation supplies no Guard verdict, artifact
admission, conformance or inference authorization.

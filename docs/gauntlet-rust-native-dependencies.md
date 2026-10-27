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

The remaining composition is explicit:

- The Rust host must record the exact target, image and runner/adapter pins
  before launching the dependency job.
- A Root Rust owner must stage those inputs once under both permanent leases,
  verify the builder image, helpers and enforced job policy, and supervise the
  bounded unprivileged container with durable unknown-job blocking and cleanup.
- After verified cleanup, Root must independently capture/inspect the ZIP,
  construct an inert dependency prefix and validate the candidate's complete
  declared requirements against it before any control can use that prefix.

The inner attachment check does not establish the kernel policy's enforcement
mode by itself; the Root owner must observe that independently. An adapter
report or successful package installation supplies no Guard verdict, artifact
admission, conformance or inference authorization.

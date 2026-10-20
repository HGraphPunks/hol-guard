# Gauntlet Rust migration

This independent Cargo workspace is an implementation slice of the
[Gauntlet Rust migration plan](../../docs/gauntlet-rust-migration.md). It builds
Gauntlet's trusted code separately from the HOL Guard product workspace in
`rust/`; a candidate product build must never supply its own verifier.

`gauntlet-contracts` accepts bounded JSON byte records, rejects
duplicate keys and nonfinite values, reproduces the Python canonical JSON
bytes and SHA-256 digest, and applies the Python depth, node, byte and decimal
integer limits. It recognizes Python's UTF-8/16/32 byte-input encodings. The
golden cases and 256 deterministic float vectors were produced by
`ci/gauntlet/benchmark/json_data.py` at
[`b4efd817`](https://github.com/HGraphPunks/hol-guard/blob/b4efd8171b06d0e13cbe12a077c376ecdc891fd1/ci/gauntlet/benchmark/json_data.py)
in [Gauntlet PR #5263](https://github.com/hashgraph-online/hol-guard/pull/5263),
whose file SHA-256 is recorded in the tests. That benchmark implementation is
not yet on `main`. It also checks the 22 copied Draft 2020-12 schemas,
Python's strict integer typing, all seven runner declaration versions, exact
external config digests, asset-role declarations, and candidate/test-merge
source identity claims. It also binds frozen campaign and gate-policy bytes
to all seven declarations, checks selected-cell policy/reservations/shards,
and hashes ordinary asset files through bounded no-symlink descriptors.
The composite v1–v7 inert config loader also reproduces Python's runtime/path
declarations, rejects symlinked private-cell paths, and checks v5–v7 installed
version metadata against outside source/native/version pins. It does not
authenticate the full installed prefix or admit a candidate to execution.
An inert SDK and installed-prefix inventory hashes metadata and bytes through
descriptor-relative directory enumeration. Linux `openat2` confines symlink
resolution, and a retained VM deployment gave positive Python/Rust parity for
all 13 asset roles. Concurrent mutation and the full negative reason corpus
still need proof. No Rust input check authorizes execution.
An optional full inert inventory also checks all declared file and tree roles
and the Root-owned private-cell artifact set. Its private-cell manifest must
match 36 bootstrap files embedded from this controller generation, the exact
fixed file set, and the outside initializer pin; the embedded source-map digest
matches the current Python producer. The retained v7 VM deployment passed the
positive inventory comparison and 13 altered asset-digest refusal cases; see
the [Linux proof](../../docs/gauntlet-rust-linux-asset-proof.md). Metadata,
path and older-version parity remain open before execution admission.

`gauntlet-evidence` reads a workflow public bundle through no-symlink,
descriptor-relative paths. It checks externally pinned manifest and source
identities, Ed25519 signatures, file inventory and hashes, signed World
receipt chains, campaign inventory, and scheduled episode bindings. The
pure episode reducer matches 17 Python gate cases when supplied already
audited scores, native surfaces and cleanup observations. A pure campaign
reducer matches 16 Python ledger/accounting cases. Neither function
authenticates those observations or grants a production campaign verdict. The
bounded HMAC VM bridge codec matches Python frame bytes and poisons replayed,
tampered or misdirected connections; it has no live transport or key delivery.
The `gauntlet-verify` binary reports integrity and completeness only. Every
successful report remains `exploratory` and `qualification_eligible: false`;
it does not independently score Guard behavior or publish a CI status.
Python-exported valid and signed hostile fixtures provide differential tests.
The [parity manifest](parity-manifest.v1.json) records SHA-256 hashes for all
420 pinned Gauntlet source files and a preliminary owner phase.
The separate [integration source delta](integration-source-delta.v1.json) records the
37 files changed and five files added when that pinned source is combined with
current `main` in draft PR #5402. A Rust test reconstructs and hashes all 425
tracked `ci/gauntlet` files; the original 420-file manifest remains the
immutable #5263 fixture baseline. Neither manifest makes candidate code a
trusted controller generation.
`gauntlet-contracts` also parses fixed, versioned [VM worker requests and responses](../../docs/gauntlet-rust-worker-protocol.md)
with no command or path selectors and explicit unknown/unavailable states; no worker dispatcher or receipt authenticator exists yet.
`gauntlet-evidence` checks the pinned Python worker's terminal receipt against independently supplied source, job, deployment and config pins and the exact report bytes. It does not read Root-owned VM paths or award benchmark eligibility.

`gauntlet-dashboard` is a read-only shadow server for the existing public status directory. It embeds the current dashboard HTML, JavaScript and CSS, reads only bounded regular files through no-symlink descriptors, and serves the same `/api/status` and `/healthz` values on loopback. It does not own the observer, VM, queue or port 8791. To compare it with the Python dashboard, run it on port 8792 with the absolute **public** directory (never the private state root):

```sh
cargo +1.88.0 run --locked --manifest-path ci/gauntlet-rs/Cargo.toml --bin gauntlet-dashboard -- --state /absolute/path/to/.gauntlet-ops/public --port 8792
```

On 2026-10-20, a side-by-side read of the live public directory produced equal status JSON after excluding the time-sampled `collector_age_seconds`; the health values were equal and the three static assets were byte-identical. The Rust server does not change the authoritative Python controller or its port.

`gauntlet-worker-state` is an inert durable journal library for the future Linux worker. It consumes a fixed `run` request only after independently supplied source, deployment and worker-generation pins match, creates one-time canonical started and running markers with exclusive no-symlink file creation, and fsyncs the files and directory. It can also persist bounded canonical report bytes and a versioned terminal receipt bound to the started marker and process identity. Restart reads detect orphan, partial, symlinked or changed evidence and block replay. It does not launch a process or authorize benchmark execution.
Its read-only response projection emits the fixed v1 protocol: an untouched job is `not-started` for progress, a started job is `running` only when a fresh Linux pidfd/start-tick/cgroup sample matches its durable marker, and a changed report cannot become terminal success. `inspect` and unstarted `run` remain unavailable until the Linux worker has complete trusted deployment and dispatch code.
The separate `open_root_owned` entrypoint is reserved for a live Linux worker: it requires effective Root, no symlink path components, Root-owned non-writable ancestors and a final directory with no group/world permissions. Its nonblocking `active.lock` lease is descriptor-held through reservation and terminal writing, and fails if the visible lock file changes. Tests use the inert `open` entrypoint to prove lock contention without Root. Linux process/cgroup observations are implemented, but the live dispatcher and independently authenticated report are still absent.

`gauntlet-vm-worker-shadow` is an uninstalled Linux ARM64 read-only entrypoint. It accepts one bounded fixed request on stdin and three independently supplied source/deployment/generation hashes, reads only `/var/lib/hol-gauntlet-rust/worker-state`, and prints a v1 response. It refuses other platforms, CLI path/command selectors and untrusted state ancestry. `inspect` and an untouched `run` are unavailable; a reserved job is `running` only with a valid durable marker and fresh kernel sample. It cannot create a journal, reserve a job, launch a candidate or replace the current Python worker. The latest static 1.2 MB ARM64 shadow binary had SHA-256 `b498f6723a09c48daf3c2e0dc94bb3616dd6a74c3686499bb9298cd4959e932b` on both host and VM; an unprivileged request exited 2 with the expected Root-custody refusal. The separate Rust state directory there is empty and mode 0700.

The separate uninstalled `gauntlet-deployment-shadow` diagnostic reads the fixed `/opt/hol-gauntlet/candidates/<source>` declaration with a caller-supplied raw manifest digest. It checks Root-owned no-symlink ancestry and files, the exact manifest fields, canonical config digest, config source SHA and Root-owned controller/interpreter parent directories. It does not read controller source bytes, follow the interpreter, verify all assets or report a staged worker. A static ARM64 binary with SHA-256 `424c545eef4c5ac62807563bd68e6112f9185d0317b42c21b22db3dedd698d3f` matched on both host and VM; the read-only invocation matched the pinned v7 deployment and refused a wrong outside digest. Eleven worker-state unit tests passed unprivileged there. This does not qualify the draft artifacts for Root installation or candidate execution.

Run the checks from the repository root:

```sh
cargo +1.88.0 fmt --manifest-path ci/gauntlet-rs/Cargo.toml --all --check
cargo +1.88.0 test --manifest-path ci/gauntlet-rs/Cargo.toml --locked
cargo +1.88.0 clippy --manifest-path ci/gauntlet-rs/Cargo.toml --all-targets --locked -- -D warnings
```

Run the read-only verifier with an absolute bundle directory and a separate
absolute JSON pin-file path:

```sh
cargo +1.88.0 run --locked --manifest-path ci/gauntlet-rs/Cargo.toml --bin gauntlet-verify -- \
  /absolute/path/to/public-bundle /absolute/path/to/trusted-external-pins.json
```

The pin file contains `controller_public_key` (base64 Ed25519 public key),
`manifest_sha256`, `source_identities`, and `effect_anchors`. The test fixtures
under `crates/gauntlet-evidence/tests/fixtures/` show the exact shape. Pins
must come from the trusted caller outside the candidate bundle.

Inspect pinned runner documents and ordinary file assets with a separate
trusted SHA-256 pin and a canonical absolute public asset root:

```sh
cargo +1.88.0 run --locked --manifest-path ci/gauntlet-rs/Cargo.toml --bin gauntlet-inputs-verify -- \
  /absolute/path/to/config.json EXTERNAL_CONFIG_SHA256 /absolute/path/to/assets
```

Add `--full-inert-assets` after the asset root to hash the declared SDK/cache
trees, installed prefix and private-cell artifact set as well. The JSON reports
the selected episode count, shard assignment, aggregate reservations and
installed version metadata when applicable. `execution_eligible` is always
`false`: even the full inert inventory does not prove OS execute access,
Linux symlink-race safety, independent verdicts or live candidate execution.

The next slices must finish Phase 0's behavioral matrix and Phase 1's full
asset/configuration custody, legacy evidence and independent scoring parity before moving
to the Linux VM worker and host observer. The existing Python Gauntlet, VM
jobs, model provider, dashboard and optional PR gate remain the authoritative
execution path until fresh source-bound parity and recovery checks justify a
controlled cutover. This workspace does not start a job or publish a status.

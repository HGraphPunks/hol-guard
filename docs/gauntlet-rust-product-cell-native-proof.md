# Native Rust product-cell actor and execution gate

Commit `cc6948cdb4c25b36f6d41651e02071769861a828` adds
`gauntlet-product-cell`, a separate Rust executable for the unprivileged
product apparatus. Its `actor` command implements the existing eight private
RPC operations. Its `exec-gate` command holds a child before product execution,
emits the existing measurement marker and requires one release byte before
replacing itself with the requested unprivileged program.

At this commit, the actor was not yet wired into the VM artifact/rootfs path.
The subsequent [versioned native deployment](gauntlet-rust-native-cell-deployment.md)
adds explicit artifact and executable pins, measured arguments and adapter
readers while retaining the existing AppArmor profile. Its actual VM launch
and Guard conformance remain separate work. The PR gate remains passive.

## Implemented behavior

- Native Linux ARM64 only; the actor requires PID1 and UID/GID 10004. Its
  syscall installer additionally verifies all four UID/GID fields, empty
  supplementary groups, no new privileges and zero effective, permitted,
  inheritable, bounding and ambient capabilities.
- The Root layout accepts only the two existing workspace/PATH combinations.
  Root input readers reject symlinks, unsafe modes, hardlinks, changed
  descriptors, wrong owners and oversized files.
- Two syscall layers reproduce the pinned Python floor. The fixed OCI profile
  and complete libseccomp ELF are SHA-256 checked before unprivileged dynamic
  loading. The native socket layer permits Unix and route-netlink sockets,
  with IP sockets only for the separately declared, kernel-checked private
  loopback profile. Startup exits on a partial/failed installation.
- The same `hello`, `spawn`, `release`, `write`, `end_input`, `read`, `retire`
  and `close` operations use the existing Rust authenticated product-cell
  bridge. Limits retain 64 active children, 1,024 total spawns, 100-ms read
  waits, 8-MiB input/output budgets and bounded base64 chunks.
- Child commands start a new session and stop at the Rust gate. Product
  execution receives only the fixed PATH, HOME, LANG and allocator setting.
  The Rust gate also bounds its release wait to 30 seconds. Only the actor
  reaps its children; terminal PIDs are never signalled again.
- Close continues to report `outside_descendant_cleanup_required:true`.
  Actor data, HMAC transport and this process test cannot qualify a benchmark
  or replace outside kernel/Guard/effect observation.

## Validation and retained identity

Six macOS unit tests and all eight ARM64 unit tests passed. The ARM64 count
includes the explicitly privileged Root filesystem fixture, run separately in
the isolated test container with `--include-ignored`; ordinary non-Root CI
leaves that test explicitly ignored. Warnings-denied all-target/all-feature
Clippy passed on macOS and ARM64, and Rustfmt and the proof tool's Ruff check
passed. The migration workflow now includes this crate.

The release executable was built offline with locked Rust 1.88 dependencies,
LTO disabled and 16 codegen units. Retained artifacts live in
`/Users/construct/Documents/projects/hol-guard-refinement/gauntlet-rust-product-cell-proof-20261022`.

| Item | Identity |
| --- | --- |
| Executable | `gauntlet-product-cell`, 1,193,488 bytes |
| Executable SHA-256 | `0bb1447bc3f14e4e629b8a04c76c0a5ca75b3e814632daaca565cc2d731d052f` |
| libseccomp SHA-256 | `3d128123b494ca9e88f3c237b0912397145af1754e86ea99f460af6857441f19` |
| OCI floor SHA-256 | `c904570e61ccaf7d03b9814796c625913650d08f97144e32e7030c19adbbfee5` |
| Process result | `process-attempt-001/result.json` |
| Result SHA-256 | `440ec918da69f2bc87c1955e013941b410e8ec1dcef6a4e4ce642b422d979ba2` |

The process proof runs two disposable Linux ARM64 containers through Colima,
using the existing Python `CellCodec`/`BridgeClient` against the actual Rust
actor. The containers have no network, 1 GiB memory, one CPU and 128 tasks.
Trusted Root setup copies the pinned apparatus files, then drops to UID/GID
10004, empties groups/capabilities and sets no new privileges before actor
execution. Both Unix-only and private-loopback startup passed with the fixed
libseccomp bytes copied from the benchmark VM and independently hash checked.

Both profiles exercised all eight operations. An outside Docker read confirmed
that the gated program had not created its marker before release. After one
release it created the expected marker, ran as UID 10004, kept the fixed
environment and returned exact stdout/stderr. Duplicate release, unknown
operations/handles, invalid read waits, malformed/oversized input and an output
larger than 8 MiB refused. Actual binary stdin, EOF, drain, terminal retirement
and clean actor exit passed. Cleanup targets only the newly created container
ID after checking its private CID file and unique ownership label.

This tested the native actor in ARM64 containers, not an installed Guard
candidate in the 16-GiB benchmark VM. It made zero model requests and keeps
`execution_eligible:false`. AppArmor/rootfs integration, outside process and
effect authentication, complete failure parity, source-matched conformance and
reviewed production deployment remain open. No parent migration exit closes
solely from this subproof.

The explicit repeatable proof tool is
`ci/gauntlet-rs/proofs/native_product_cell_process_proof.py`; it requires an
outside executable SHA-256, the pinned library, and a fresh output directory.
It uses Python only as the independent legacy protocol client/test driver.
The actor and child gate execute in Rust.

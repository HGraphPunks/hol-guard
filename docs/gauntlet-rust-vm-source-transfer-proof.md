# One-use host-to-VM source transfer proof

Code pin: `5313f6ad`. The uninstalled macOS `gauntlet-host-shadow-source-transfer` binary built from that commit had SHA-256 `a6638de38fea0487daa2e400dbdd8caad1fc36628543139b40e6b62eb40980a8`. It reads the existing private VM operations config but uses a separate 0700 temporary host state. It does not take the Python observer lease or write a Python job record.

The host copied the previously retained local-candidate Git-object archive from job `e2f042a7344bbbb0` into synthetic job `b70d59e2681c4a3f`. The copy was 45,439,546 bytes, regular, owner-only mode 0600, link count one and SHA-256 `bedd98ab7da8ca728484799e1ef6b13c854f7fcbb31a17ebdcc469c4c772af43`. Rust reverified its Git graph: `refs/heads/local-76c31929833b5571d25a56d9783e24a0997d5422` resolved to exact commit `76c31929833b5571d25a56d9783e24a0997d5422`. The host state and VM destination were inspected as absent before transfer.

On 2026-10-21 the binary streamed the archive to the running 2-vCPU, 16-GiB ARM VM `hol-beta-bootstrap-20261016-004`. Its exclusive guest publish created `/home/construct.guest/hol-gauntlet-source-b70d59e2681c4a3f.tar.gz`. An independent subsequent Rust VM readback matched all 45,439,546 bytes and the outside SHA-256; guest `stat` reported UID 501, mode 0600 and link count one. A second invocation exited 2 with `GuestUncertain`; another independent readback showed the original digest and metadata unchanged, and the deterministic partial name was absent. The result reported `execution_eligible: false` throughout.

Local validation: the full locked `gauntlet-host-state` test suite, workspace formatting check and warnings-denied host Clippy passed. The seven source/archive integration tests also passed as an unprivileged process in the ARM VM using a SHA-matched ARM binary `c9a39f25f77d31f57f1f90cad6f1feb0ab61610cec81e83270dcc6655d4f1655`. That ARM test binary preceded the final private-field change to the transfer proof; the transfer path itself was unchanged, and the ARM CI workflow now includes the integration test for the exact PR head.

Trust limit: this is source custody, not a builder or Guard verdict. The source pin came from retained host evidence rather than independently reviewed release authority. The guest upload and readback helpers still use fixed Python scripts invoked by Rust. A later [Root source capture diagnostic](gauntlet-rust-builder-source-capture-proof.md) consumed the same synthetic archive, but a reviewed Rust guest executable, Podman image/profile custody, artifact staging and a fresh benchmark run remain open. Any failed or interrupted upload is classified as uncertain and requires inspection before retry.

## Primary Rust transfer into the build slot

Source `76a5604fe4ae30c0bf07f739ff46f81a8deea61d` adds the transfer operation
to the existing host command:

```text
gauntlet-host build transfer PRIVATE_SOURCE_STATE PRIVATE_TRANSFER_DIR JOB_ID SOURCE_SHA SOURCE_ARCHIVE_SHA256 CAPTURE_BINARY_SHA256 [--vm VM_NAME]
```

Both private directories must already exist with mode 0700. The source state
and job come from `build source`. Rust checks descriptor custody, the archive
digest and the exact local Git graph over the same bytes it transfers. It
fsyncs a one-use dispatch binding the source, worker and VM before transport,
uses the existing bounded stream owner and calls the fixed Rust guest source
receiver. Only its exact canonical capture response permits a retained result.
Existing, partial, linked or orphaned records block another dispatch; uncertain
transport cannot authorize a retry. The historical inbox reader remains supported.

All 686 Mac workspace tests, formatting and warnings-denied Mac/ARM Clippy pass.
Six selected ARM tests pass as UID/GID 65532, with empty supplementary groups
and capabilities, no new privileges and measured ELF/pidfd identity. They cover
concurrent dispatch, restart, wrong source/archive, links, orphaned records,
forged replies, early receiver exit and a blocked receiver's deadline. No source
file, crate, executable target or dependency is added. The two changed Rust
files remain below 500 lines.

Frozen host `5c8b6801…` transfers job `c8a491e0d27bf653` in 10.656 seconds
against Root receiver `d71ca8b2…`. Its 63,233,548-byte archive has SHA-256
`23c93580d6eefe531e6f96504502ceca9b776de0385173328eb4568dd8ebdadb`
and resolves to product source `74d8d00814bfb281e4cf8a8823b083b3656db9bb`.
Independent readback under all four leases matches every byte, the Root-owned
single-link 0444 archive, its capture receipt and the actual receiver ELF.
Both a restarted invocation and a changed VM target refuse before transport,
preserving the host records and guest files. All 333 historical worker records
and their lock retain identical metadata; their contents are not read.

That source slot then feeds the primary Rust dependency command. Its export
exits zero in 82.381 seconds, with independently observed UID/GID 65532, pinned
exporter/input bytes, confinement and final resource absence. The resulting
2,290-file dependency prefix composes with the separately pinned candidate
build for the same commit. The build and dependency Git archives have distinct
byte hashes; both exact-commit graph checks and project/lock bindings are retained.

Evidence is outside Git under `gauntlet-rust-pr-ready-evidence-20261026`:
`source-transfer-20261108-host-001` and
`current-source359-dependency-host-state-20261108-001`. Frozen-tool record
`95c8a6c7…`, ARM result `1438f962…`, live transfer `e975a730…` and independent
readback `fcf0941d…` bind the code, binaries and observations. This proves the
inert transfer and its downstream export. Independent review, source admission,
Guard causality, conformance and production cutover remain open; all eligibility
flags stay false and model usage is zero.

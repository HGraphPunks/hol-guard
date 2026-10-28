# Current Native worker: retained first attempt

Attempt `e2c701baf1471801` used Rust source
`8e1f288bd0b3fbd5cacf9d5ee6c391feb066cd27`, exact product source
`62aa7ba777a5a4cc0806c34ee94e9822eaa58d32`, Native from upstream `9dd2fefb`,
and the [published source-matched runtime](gauntlet-rust-native-runtime-publication-vm-proof-20261026.md).
It failed before actor readiness. The management RPC returned 0 because it
successfully recorded the failure; its controller exit was **2**, its
controller report was null, and its status remained `invalid-evidence`.

The retained cell stderr is `pinned native libseccomp installation failed`.
The actor was a 1,017,008-byte static musl binary, SHA-256
`03066f188111226855fc8e59083bb8adc01fcdbe7a39ba06ed9528f024c651a5`.
It has no ELF interpreter and cannot dynamically load the pinned glibc
library. Independent examination of the executor's OCI layers verifies the
133,296-byte `/usr/lib/aarch64-linux-gnu/libseccomp.so.2.5.5`, SHA-256
`3d128123b494ca9e88f3c237b0912397145af1754e86ea99f460af6857441f19`.
Neither the library pin nor the filter/isolation requirements are changed.

Root state retains started digest
`0f2221b9c348a94ade63581e70f3f8f3b3da474e1ef64664d592412423830bfa`
and report digest
`8eb3108e3037c41215fb0b4cb83ec6d46ac69b2aa526047d053d78d3d10bdb8f`.
The supervisor journal records the actual initializer UID/GID 10004,
zero capabilities, no-new-privileges, enforced AppArmor, private namespaces
and no egress before the failed gate. It records complete cleanup. A
separate post-run kernel inspection confirms no container, job cgroup or
job mount remains, and the slice is inactive with an empty control group.
Original failed state and artifact namespace `e2c701baf1471800` remain intact.
Prepared timeout/cancel jobs `1802`/`1803` were not executed or rewritten.

The local `gauntlet-rust-pr-ready-evidence-20261026` directory retains
`native-current-failed-vm-results-018.tar`: 24 members, 51,200 bytes, SHA-256
`ea46f25d92e877aeaa9c0ae0ccb96bc612459dbc1986e6e5feb46cea251b5a6b`.
`native-current-failed-host-verify-018.json` independently verifies every
member hash, the job/preparation/report bindings, supervisor event chain,
failure and outside cleanup observations. The private controller key is
excluded from the export.

The executor image transfer is separately retained as
`native-current-executor-image-e43d3b4e-018.oci.tar`: 184,542,208 bytes,
SHA-256 `c0e1e0e6c1adb11f0a66c666f5d1d6032c3731ca920fc9f088a2f600fa3980ae`.
Host verification checks all ten blobs and eight compressed/decoded layers,
the exact image/config identity, ARM64 architecture and manifest. No old
image/history was pruned to make room. The first host verifier used system
Python 3.9 and refused `zip(strict=True)`; the corrected run used the
existing Python 3.12 test environment. An attempted debug actor exceeded
the unchanged 2-MiB limit; it was not installed. The initial guessed rustup
path was absent; the actual Homebrew rustup installed the Rust 1.88 GNU
target. These preparation failures supply no execution credit.

The follow-up adds bounded ELF ABI preflight before native artifact creation
and to complete native artifact readback, plus a standalone inert build
reader and ARM64 CI release-artifact check. Static, wrong-architecture,
wrong-loader, duplicate-interpreter, truncated and overflowing inputs refuse.
The [build contract](gauntlet-rust-native-actor-build.md) requires a GNU actor
with the exact glibc loader and the existing size bound. The complete Mac
workspace passes 427 tests across 216 targets with zero failures/ignores;
log `rust-workspace-native-actor-abi-019.log` has SHA-256
`ce161fdcea10a4837e1330172c77cd62102d383e968879f2d185a97a7b1dfd17`.
Warnings-denied Mac Clippy passes. Fresh VM preflight/lifecycle evidence is
still pending at this checkpoint.

The separate [current-worker proof](gauntlet-rust-native-current-worker-vm-proof-20261026.md)
records the later fresh GNU actor success/timeout/cancellation cases. This
original failed job and its evidence remain unchanged.

No model request, Guard-causality verdict, conformance, admission, cutover or
completed parent checklist exit is claimed.

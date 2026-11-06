# Rust Native boundary artifact verification

Rust source `cec21c2c4ddc2ce9d179334ba069376bd49bd2ec` independently
recomputes the retained boundary diagnostic's public capture and physical
relations. This extends the [input-binding verifier](gauntlet-rust-native-binding-artifact-verifier.md)
without completing deterministic authority or changing the 24/62 parent exits.

The offline completion CLI accepts the distinct optional mode
`--boundary-artifacts PUBLIC_USTAR SHA256`. It retains the existing eight-argument
envelope mode and input-binding mode. The shared bounded, no-follow archive
reader authenticates the report, preparation, declaration, source and role
against the prior host journal before interpreting public artifacts.

The evidence library checks every indexed digest and length and the supervisor
capture hash chain. Each positive capture must contain the exact stdout and
paired stderr bytes. It independently reconstructs all three synthetic canary
literals and their original physical inode, device, owner, mode and single
link. Positive SDK, command/container and Native captures establish visibility.
Six fixed path probes and two network probes must each contain an actual
closed errno refusal; a timeout, boolean errno, unavailable probe, wrong address
family or forged kernel claim refuses. The physical report and exact versioned
fixture bytes must agree, and every original canary must remain unchanged.

These are artifact relations under authenticated Root-controller custody.
The verifier explicitly retains `independent_process_custody_checked:false`
and `child_kernel_claims_authenticated:false`. It grants no outside signing-key
admission, Guard causality, qualified role or execution eligibility. Independent
live request/process/SDK/MCP custody and complete six-role grading remain open.

## Actual retained evidence

The retained executable `native-boundary-artifact-verifier-001` is 2,500,832
bytes, SHA-256
`5918fa2e4ebfa80ab8f6203adb0b9d1bf5755582c6b1af4a7348a6729f35dc42`.
It reads actual v7 job `e2c701baf1475105`: historical Rust runtime `f53bc490`
and product `62aa7ba7` / 3.57.0. Archive
`native-host-keyed-vm-results-001-boundary.tar` has SHA-256
`f6f838f80636da3a73afe36ca4272f6113fc8c2c82b449d0c26f114f88842670`.
This is historical evidence, not a fresh current-source execution.

The inert [proof courier](../ci/gauntlet-rs/proofs/verify_native_boundary_artifacts_20261027.py)
passes fifteen cases: six envelope regressions, actual boundary verification,
byte-identical restart, the byte-identical input-binding regression, and six
refusals. Wrong digest, cross-job archive and wrong role refuse. Separate
mutation archives with recomputed outside digests also reject a substituted
canary inode, timeout probe and missing SDK positive capture. Originals and
the host journal remain unchanged. All refusals exit 2 with empty stdout.

Actual and restart stdout share SHA-256
`f2fc5fffffc210b9cda9f96cafc45c8e25d0d96bb0167d48d7258274b7ee75a0`.
The 4,236-byte `native-boundary-artifact-proof-001.json` index hashes to
`756554b392744806f0114c97a0b22c23df34669f9342035894630f5ff6e930c7`.

## Mac and native ARM validation

The full macOS workspace passes 515 tests across 217 targets with zero failures
or ignores. Log `native-boundary-rust-workspace-002.log` hashes to
`525d66d952f8f2396cc0bd966cfba81136dc3efbefbb9ab96148d6488f321a91`.
Mac warnings-denied all-target/all-feature Clippy passes, log SHA-256
`7041681e26232ddbab9d9544902f71c1a728db514037f23df772a01ab5de559b`.
ARM workspace Clippy also passes, log SHA-256
`68a343231bf5f0c3ecf7dd53fec19a64cc839bc58da847236553d86516b04990`.

Five new evidence tests and both archive/path tests pass natively under Root
in owned VM `hol-gauntlet-rust-build-20261026-001`. Both worker leases remain
held; all 284 old worker records retain their hashes; owned product cgroups
remain absent. These seven tests do not represent a full native workspace run.
The executable pins are
`c0f97884c1b93fb72126a85e5ae3cc812ae9f2aefcd44f2cc7fe7569431450ce`
and `45047ef1ea36bc1e60777efeb206ff68833021beef4450025703d2ae0e3345ed`.
Their logs hash to
`e9283455ca13a1772fc76f93fde7e67b48923dbada626594d030d910286f2496`
and `68b0e1d88b930dbe43b7262bb8d69b7940bbb23309caae50fae43bd86abeae81`.

The 28,282,880-byte three-member input has SHA-256
`f521ca695bf3bf5144ef8f3b9e89d55c492e62688bb1b0f520ca8289dc7ac7ad`.
The 20,480-byte eight-member public result export has SHA-256
`226394f2a1cae48e7f038fa9edde17b840cfe46792d325513b4d3b55be3a3156`.
Root hashes the held archive before handing it to transport UID 501.
The independent [fixed-generation reader](../ci/gauntlet-rs/proofs/verify_native_boundary_arm_20261027.py)
checks every public file, source/ELF/log pin and filesystem observation.
Its successful `native-boundary-arm-independent-readback-002.stdout` hashes to
`a8ea24f91ee4ec8dabeb7ccfcac2e9cb5e0a22adaf999dd8c05c75788e10bde4`.
The initial host-reader attempt lacked `cryptography` in system Python; its
failure remains retained. The configured integration Python passes unchanged.
Both proof scripts pass Ruff formatting and lint. No model requests ran.

The separate [3.58.0 runtime publication](gauntlet-rust-current358-runtime-proof-20261027.md)
now passes. Twelve current-source staging/installed controls, independent process grading and the remaining operational, workflow,
legacy and cutover exits remain open. Required CI is user-owned and pending.

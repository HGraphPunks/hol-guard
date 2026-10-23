# Native product-cell launch in the benchmark VM

The real Rust actor and exec gate passed success, deadline and cancellation
tests on `hol-beta-bootstrap-20261016-004`, at 2 vCPU, 16 GiB RAM and a
48-GiB virtual disk. Each fresh cell started the retained installed Guard
3.49.0 native daemon. These are zero-model apparatus tests, with eligibility
false; they do not qualify every Guard feature or a current-main build.

## Outside source and artifact pins

The host Rust Git reader checked all 427 files at
`dfc948e98c6a1ab94e074dd164c25cbd60831ee1` against the immutable baseline and
explicit source delta. An independent exact-Git archive check agreed on all
file hashes. The transferred archive SHA-256 was
`173024e2f8e677fde9c7f659a400d22176db5a2248744c6dee649d714dd540f6`;
the 427-file source-map SHA-256 was
`8ec9c093a48ec9d05a6ce1c0c1278c872ef484529e458ded6b848b93317040ad`.

The separate Root installer created
`/opt/hol-gauntlet/controller-dfc948e98c6a1ab9`. An independently invoked Rust
reader matched 396 installed files, 407 entries and controller-tree digest
`33ef5c12f907c80e8d05aa5af10c76510fae5097b23fc2f0a4dcab85c6a21537`.
The complete tree matched again before and after each VM test. No existing
controller generation or v1 artifact directory was replaced.

The Root Rust artifact writer created the distinct 25-file v2 bundle under
retained build `b70d59e2681c4a3f`. Both Rust and the separately invoked Python
inventory agreed on 2,026,777 file bytes and manifest SHA-256
`af9beb41798a8dec6901637acdfae1706f3053d690940c78a1f9fc3b69a5c477`.
The actual kernel actor executable matched outside SHA-256
`0bb1447bc3f14e4e629b8a04c76c0a5ca75b3e814632daaca565cc2d731d052f`.
The native config writer then verified all 13 inert asset roles and wrote a
new provisional file with canonical digest
`303675901036772e772b02573ab7c0b7cf34af54bba9f902d4c12b29f52829f3`.
Its template's executor image remains historical until a separate immutable
image-ID revision; the direct VM tests used the already pinned current image.

## Actual launch and failure containment

The outside collector measured `/public/gauntlet-product-cell actor` as PID1
in the private namespaces, with all four UID/GID slots 10004, empty groups,
no new privileges, zero capabilities, two syscall filters and an enforcing
AppArmor profile. The existing cgroup limits held: 1 GiB memory, 128 tasks,
one CPU of quota and the explicitly narrowed CPU set. No AppArmor permission
was relaxed.

The success test observed a physical task file absent while its Rust exec
gate waited. Release created the expected bytes through the real idmapped
mount, with physical UID/GID 10001. Binary stdin including NUL/non-UTF8 bytes,
stdout, stderr and process retirement also passed. Timeout and cancellation
each interrupted an actual sleeping process and closed the entire cell.
Every case ended with the product cgroup and rootfs mounts absent, the owned
image lease released, an unchanged installed prefix and complete cleanup.

| Case | Retained result SHA-256 |
| --- | --- |
| success | `1593b120f7c3e8a6b7ce47b23f67981953a64c49da72129dfddedc0420b84da8` |
| timeout | `709da9f2ad258f10506a1f486a26a25fbff735059042c6ec79f12a93e5e5ccda` |
| cancellation | `6916f655c49dad312358b0eaaa3dd570faae9e110102f00f3ff95c67db81aede` |

The 276,480-byte host/guest result archive has SHA-256
`c3c474ae7b14c84a244798d5ac2e634df85a4f7c8e0e28c31c13638677a65188`.
It retains the full result and outside plane observations for each case in
`gauntlet-rust-product-cell-proof-20261022/deployment-dfc948e98c6a1ab9/vm-results.tar`.
The reusable test driver is `ci/gauntlet-rs/proofs/native_product_cell_vm_proof.py`;
it holds both worker leases and requires fresh output and outside digest pins.
Its final SHA-256 is
`8e9075b313a453e5e048b4df2ec456ebdcfb2ed166b7035ab242fcd6895ca9d3`.
The success run used the same driver before its console-only summary change,
SHA-256 `986dc8fb5e497de45191f5c7aa06f9b1c170b3840e541ad9f265d89f70982d99`.

The installed candidate remains historical source
`76c31929833b5571d25a56d9783e24a0997d5422`. Root orchestration is still Python;
the actor/gate execute in Rust. Full deterministic-control causality,
source-matched current-build conformance, model inference, reviewed production
pin provenance and complete Root Rust ownership remain open. No provider quota
was reset or consumed, and the PR gate remains passive.

## Broader staging integration follow-up

The first broader success and input-binding attempts, IDs `1f72068a31b90e6e`
and `8c2a43bc17499667`, retained controller exit 2 with complete outside
cleanup. They produced no SDK tap journal. Their startup logs exposed a
remaining Python staging-adapter check that accepted only `cell-artifacts`.
These failed attempts remain retained and cannot become passes.

The adapter now authenticates the manifest and initializer against the
outside pins, binds its v1/v2 runtime to exactly one of the two fixed artifact
directories, then performs the existing complete inert asset verification.
Regression cases cover both versions, foreign jobs, traversal, substituted
runtime paths, changed bytes, cross-version paths and wrong pins. This changes
the controller plan digest to
`b3d45bdeb0afe653ec8e6874ed1e36680c2f87bee62e5c7734fee8fbe8b45603`;
it leaves the v2 artifact source map and retained successful VM proofs intact.
Fresh broader controls require a separate installation of this new generation.

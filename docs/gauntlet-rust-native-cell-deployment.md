# Versioned native product-cell deployment

`product-cell-artifacts.v2` explicitly binds the Rust actor executable to the
outside-pinned artifact manifest. Its public set contains only the initializer,
`gauntlet-product-cell` and the existing OCI syscall profile. The 23 fixed Root
adapter/profile source files must match the controller generation. The v1
Python bundle retains its original 38-file layout and reader behavior.

The Root Rust artifact writer accepts `--rust-actor`, creates only the distinct
one-use `cell-artifacts-rust-v2` directory, and checks both worker leases,
source hashes, initializer and actor pins before readback. The corresponding
candidate config writer also requires `--rust-actor`; it projects the fixed
native artifact path into a new provisional config. Neither writer admits a
benchmark or replaces a retained v1 bundle/config.

The existing Python Root adapter now reads either explicit artifact version.
It retains exact manifest bytes in private staging, verifies the public bytes
again before namespace construction, and runs the fixed native actor/gate
arguments for v2. Signed runtime observations can select those arguments only
when the complete manifest bytes match the outside config and initializer
pins. Duplicate, extra, relabelled or substituted observations refuse. The
existing AppArmor profile already permits execution of the mounted public
artifact; no AppArmor rule, namespace, UID or capability floor was relaxed.

## Current source identities

| Selection | Files/entries | SHA-256 |
| --- | --- | --- |
| Python v1 fixed source map | 36 files | `6db98fdb27fb0290fa8cf4af38663bbfe4445ee39dcd0498fd384d3d1bbdc8a9` |
| Native v2 fixed source map | 23 files | `05b2510a6d822ddb105c55acb030e24e38e20c9e2a35ed7a980a6545c80a7f77` |
| Complete controller install plan | 396 files, 407 entries | `33ef5c12f907c80e8d05aa5af10c76510fae5097b23fc2f0a4dcab85c6a21537` |

The immutable Python baseline and earlier installed generations remain intact.
The explicit source delta covers all 427 Gauntlet files, with 63 reviewed
changes and seven additions relative to that baseline. A stale 426-file
constant in the host Git verifier was corrected and now has a startup test.

## Validation and remaining work

The focused Python loader, staging, custody, rootfs, networking and syscall
regression suite passed 151 tests. macOS evidence/worker libraries passed 57
tests, and source inventory, controller plan and host Git-map tests passed.
ARM64 evidence/worker libraries passed 171 tests, with 24 explicitly privileged
VM tests left separate. The container test environment must expose the host
cgroup namespace and repository fixtures; private Docker cgroup paths are
correctly refused by the unchanged canonical cgroup reader.
Warnings-denied all-target/all-feature Clippy passed on macOS and ARM64;
Rustfmt, Ruff and whitespace checks passed.

The follow-on [real VM proof](gauntlet-rust-native-cell-vm-proof.md) exercises
this artifact version with the installed Guard daemon, actual gated effects,
binary streams, timeout and cancellation. Native control causality and fresh
conformance remain open. The Root adapter is still Python; the unprivileged
actor and exec gate are Rust. These changes do not complete the isolation
migration or enable the PR gate.

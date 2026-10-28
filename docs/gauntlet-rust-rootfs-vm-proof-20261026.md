# Rust Root constructor: owned VM proof

The native constructor passed fresh success, deadline and cancellation cases
on `hol-beta-bootstrap-20261016-004` on 2026-10-26. The VM has 2 vCPU, 16 GiB
RAM and a 48-GiB disk. Every case started the retained Guard 3.49.0 Native
daemon, made zero model requests and completed the outside cleanup checks.
The collector and installed candidate remain historical; the results retain
`rust_supervisor_owned:false` and `execution_eligible:false`.

## Source and artifact custody

Constructor source was committed at `7a44fff591e3329ab8ba38dee0514c803b084069`.
The corrected proof wrapper was committed at
`ad797602a46cb7670d8254a8dc7d62a0d34dec9b`. The Rust 1.88 static ARM64
constructor hashes to
`37bad594d0dc54ce052fccf713be3023b9aeefac0ba4ca72b1872fc58e408718`;
host and Root-installed VM bytes agreed. Its eight native ARM64 unit tests
passed; the test binary hashes to
`15dc4cbe0a191d96e3bf7aec748676fdee7721bbd82ef90a3738be235a753815`.
Seven macOS tests and three proof-launch/interface regressions also passed.
Warnings-denied ARM64 Clippy passed.

The five-file transfer archive hashes to
`d7716e74b147a27c0e8d63a3b8f57caa1dd84f0a790fb1863ebae2e9ebcad7e1`.
A separate Root installer checked its complete fixed entry set and every
manifest hash before exclusive installation under
`/opt/hol-gauntlet/native-rootfs-input-20261026-002`. Generation 001 remains
retained, including its two pre-construction harness failures: a missing
system-Python dependency, then a process-class annotation incompatibility.
The corrected wrapper uses the existing dependency-complete prefix interpreter
and preserves the Popen class interface. Neither failed invocation created a
product cell or model request.

The original controller verifier independently matched all 396 installed files,
407 entries and tree digest
`33ef5c12f907c80e8d05aa5af10c76510fae5097b23fc2f0a4dcab85c6a21537`
before and after every case. That controller is source
`dfc948e98c6a1ab94e074dd164c25cbd60831ee1`. The retained candidate is source
`76c31929833b5571d25a56d9783e24a0997d5422`, with native actor
`0bb1447bc3f14e4e629b8a04c76c0a5ca75b3e814632daaca565cc2d731d052f`
and v2 artifact manifest
`af9beb41798a8dec6901637acdfae1706f3053d690940c78a1f9fc3b69a5c477`.

## Live observations

The wrapper substituted only the constructor launch. The existing collector
held both worker leases and independently checked the actual process before
and after the launch/filter gates, task idmaps, namespace identities, executable,
AppArmor, descriptors, UID/GID/capabilities and resource ceilings. The three
fresh Root declarations, service names and process IDs are retained in the
outside-pinned bundle.

| Case | Actor PID | AppArmor service suffix | Root declaration SHA-256 |
| --- | --- | --- | --- |
| Success | 1615 | `efe0e9d4a0264a70a5ce72304526c6ed` | `f72efa9e11ebcae1a891178acb8401d8214c7cd02a30c8e814c87d9195e29625` |
| Timeout | 1869 | `ef3ca395d5764d2da4c80575449b98f1` | `274fd687b2dcb25879d23ea492a4217aab70f02909cf98f921fbfef58883951f` |
| Cancellation | 2109 | `6bdd0bb57e264341a8ebef86460192af` | `d3466b89d9124c03f1e34cec55784c903ad1d360e1d5682e1579583728427b15` |

Each actor was PID1 in its private namespace, with UID/GID10004, no extra
descriptors, empty groups/capabilities, no new privileges and the existing
enforcing AppArmor/two-filter boundary. Actual ceilings were 1 GiB memory,
128 tasks, one CPU of quota and effective CPU set `0`. Success checked an
absent-before-release task effect, its real UID/GID10001 bytes after release,
and binary stdin/stdout/stderr. The other cases interrupted a real sleeping
process. Every case reported absent cgroup/rootfs mounts, released image lease,
unchanged installed prefix and no cleanup errors.

The host and guest agree on the 276,480-byte, nine-record result bundle SHA-256
`818b2b7e8afd86657fb24f47fc008dfd53e4b8aa1e7d870e84bf6cfe8c8dc844`.
It is retained locally as
`gauntlet-rust-pr-ready-evidence-20261026/native-rootfs-vm-results-002.tar`.
The base result objects contain deterministic fields that reproduce historical
result digests. Fresh execution identity is established by this new bundle,
the constructor declarations and the measured service/process records in each
`plane.json`.

This closes the constructor apparatus subproof. Full Rust supervisor ownership,
current-main candidate conformance, independently attributed Guard effects,
all required deterministic/model profiles, rollout and exact-head CI remain
open. The parent migration count stays 24/62.

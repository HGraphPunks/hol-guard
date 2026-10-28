# Current Native hook transport on the ARM VM

Fresh job `e2c701baf1472301` passes the Rust-owned Native hook diagnostic at
source `6b901e2a8770bafacfb60186dc8eda28523ac540`. The worker report is
`3b3853391d228be0715da9bfca74958b2dfc4561b544fda44e8e8d90f1dfdf9f`.
This proves the normal hook/sink transport and its scoped cleanup. It remains
`invalid-evidence`, with no authenticated SDK, host signing-key pin, six-role
conformance or independently scored Guard request/decision/effect relation.
The parent checklist remains 24/62 complete.

The owned VM is `hol-gauntlet-rust-build-20261026-001`. Root executes the Rust
worker generation
`c832f31fafa5351c3480baf6c731a9494e65354a4c2815f970cd92c2bf2c1dbf`,
and the separately pinned Rust constructor has SHA-256
`6d79890aa1f0239e794939bb6bfa3846891d2a3e445694df9d90327e18619534`.
The GNU actor, fixed libseccomp, AppArmor, idmapped task, read-only image,
loopback-only private network, capability removal and two seccomp filters
retain the [current worker proof's boundary](gauntlet-rust-native-current-worker-vm-proof-20261026.md).
No approval or isolation policy changes.

The unchanged published runtime is HOL Guard 3.57.0, product source
`62aa7ba777a5a4cc0806c34ee94e9822eaa58d32`, Native ELF
`1632de1167b167ffe05d02ab4f2cdf157d9328addfcc054ceeffef640b8b9489`.
The runtime publication receipt remains
`3b5ed1b9d5ea1faa395aae6526d7ec746408d376fb134ae5e6b0bc9df930f432`.
The complete 4,411-entry prefix, including root as 4,412 rows, still hashes to
`cd092b3c0658a3aee2b436b3e4f3639627f244190ef255e1e3463487b6621637`.

## Actual execution and retained failures

| Attempt | Result |
| --- | --- |
| `e2c701baf1472101`, source `e1eb0a1a` | Native reached; readiness refused `invalid_workspace`; no semantic hooks or sink |
| `e2c701baf1472102`, same generation | Existing v1 Native apparatus regression passed |
| `e2c701baf1472103`, same generation | Wrong outside Native digest refused before product identity execution or hooks |
| `e2c701baf1472201`, source `119f51b4` | Correct explicit task home passed readiness and prompt; incomplete environment refused before sink |
| `e2c701baf1472301`, source `6b901e2a` | Complete fixed actor environment passed prompt, Pre, contained sink, Post, replay refusals and cleanup |

Native's successful Pre response requests `workspace-contained-v1` with
`decision:deny` and `policy_action:sandbox-required`. Rust consumes the
original input before creating its descriptor-held packet; the normal Native
sink independently reauthorizes that packet. The unchanged success fixture
runs one standard-library test and produces the physical UID/GID-10001
20-byte `native-contained.txt` containing `private plane effect`. Its SHA-256
is `93313832ed89058af22413b62b883ac6225572fc7e1b7551e8c224893ba542cc`.
The fixture also observes Node v22.22.2/npm 10.9.7 and the retained public Node
digest `3159f9115ab4be7d318b7c28e946837a4dceb7f2b3c43232aa2f2e3852550b90`.

Post receives only the original reviewed input and Rust's exact captured sink
output. Its `allow_original` response names the same output hash. Repeated
Pre, sink and Post identities refuse without another Native hook. The request
file/directory retire, both cgroups drain, the image mount/lease disappear,
and the full runtime prefix remains unchanged. Restart reconciliation returns
the original terminal/report digests; execution replay refuses.

Passive outside pidfd sampling retains 12, 17 and 24 actor/Native observations
for the first, corrected-home and final hook attempts. Each sampled process
has UID/GID 10004, empty groups, zero capability sets, NNP, two seccomp filters,
the enforcing cell label and the fixed 1-GiB/128-PID/one-CPU limits. These
samples do not authenticate a particular Native request or decision.

## Reproducible inert readback

The local evidence directory is `gauntlet-rust-pr-ready-evidence-20261026`.
The committed reader
[`verify_native_hook_transport_20261027.py`](../ci/gauntlet-rs/proofs/verify_native_hook_transport_20261027.py)
uses the existing bounded archive/strict JSON/event-chain helpers in the
adjacent current-worker reader. Run it with Python 3.12 and
`--evidence-dir /absolute/path/to/gauntlet-rust-pr-ready-evidence-20261026`.

| Export | Members / bytes | SHA-256 |
| --- | --- | --- |
| `native-hook-transport-vm-results-021.tar` | 103 / 1,095,680 | `cd3ee0eaf1c21a79396e21773b3c568abea7b6cb04668545e45aa431759bf098` |
| `native-hook-transport-vm-results-022.tar` | 51 / 972,800 | `0b19b236be6cb9589480d62222418070e325265f103c49efd8e12cd50ed4a5c6` |
| `native-hook-transport-vm-results-023.tar` | 56 / 1,013,760 | `01c1a8d8f6f354367439e8afdc48ae13a3b3a1a69f031a57e559ceb1883f76a6` |

The actual reader passes all 210 diagnostic export members, all 33 frozen
input members, three durable host prelaunch declarations, worker terminal
bindings, complete capture/event chains, exact Pre/packet/sink/Post output
relations, physical effect bytes, unchanged published prefix and preservation
of all 48 earlier worker files. It also checks the immutable 017 publication
and 019 worker exports. Product state and private keys are excluded.

Root passes all 136 current worker tests with 24 existing fixture-specific
ignores. The unchanged rootfs binary passes 29 tests plus its subprocess
check; the unchanged evidence and wire binaries retain their 59-test and
64-case passes from attempt 021. Affected Mac tests, warnings-denied Mac/ARM
Clippy, Rustfmt and proof-reader Ruff pass. The first proof courier's v1-only
field assertion error remains documented; its completed job was not retried.

Next work is Root Rust ownership of authenticated SDK ingress, the separate
Native MCP plane and service/oracle state, followed by all six fresh staging
and installed roles and independent physical-effect scoring. All admission,
Guard-causality and model-use flags remain false; model requests remain zero.

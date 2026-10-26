# Rust-owned cell preparation: VM proof

Source `69039ec680a30d281851949697ff2f3752cf99a9` passed six fresh
zero-model cases on the owned 2-vCPU/16-GiB/48-GiB Linux ARM64 VM on
2026-10-26. Rust now owns inert artifact/runtime staging, fixed Guard state,
image inspection/mount lease and its durable active pointer, as well as the
[previously proven supervisor](gauntlet-rust-supervisor-vm-proof-20261026.md).
The Python test adapter creates only the outside declaration and physical task
fixture, then independently reads final kernel/image state. It imports no
Python product factory or orchestrator and uses only the system Python standard
library. Product Python runs unprivileged inside the measured cell.

| Case | Verified behavior | Preparation declaration SHA-256 |
| --- | --- | --- |
| success | Native daemon, held execution gate, physical idmapped effect and binary I/O; complete Rust cleanup | `009ebeed45010f796a1d1394c5f22d72c2e7bfd09d1d03b261a3dca33afae478` |
| timeout | Real released process interrupted at its deadline; complete Rust cell/image cleanup | `f4bf6d34f9ab483f6bd94f26b83123b2261fdab32b34f5f8d63affaa07b4a56c` |
| cancel | Real asynchronous interruption; complete Rust cell/image cleanup | `a16e35ab13e6c5730fed808b001c1ea3c7179d0c75897d3dbb6281ab614da93d` |
| wrong-pin | Constructor hash refused before stage/image/service mutation | `3b220a58612d3644f0d16cf7d50d8ace10410f4efd4f9e89b5779f183690f616` |
| replay | Successful fresh cell followed by refusal of its reused preparation; existing journal unchanged | `4f72b70ecf791dfb60f31f966ad033b126fc97fb0e116cfc3bbc6ce74c0406fe` |
| borrowed-image | Preexisting image mount refused and left untouched; only the outside negative-fixture owner unmounted it | `8748610bcc85d820352ad00a5be27dbf690d4ffda85ca01f083a2db15833a462` |

Success, timeout, cancel and replay each started the retained Native daemon.
Their observed actor PID/start ticks were respectively 3564/779054,
3818/785754, 4085/789825 and 4355/799130. Fresh service identities and full
kernel/idmap/route/filter observations remain in their private journals.
Independent outside reads confirmed cgroup, AppArmor and rootfs mount absence.
Every case ended with the dependency image unmounted, its active lease pointer
absent and the controller tree unchanged. Normal cases needed no outside
image or cell cleanup. The borrowed-image fixture's outside cleanup is explicit
and does not count as Rust ownership of that intentionally preexisting mount.

## Input and output custody

The seven-file immutable input generation is
`/opt/hol-gauntlet/native-supervisor-input-20261026-004`. Its transfer archive
SHA-256 is `cd75db7e8c1698c4126a4fbe399b772b89a69049ef068dec9c42308ab042c0a7`.

| Input | SHA-256 |
| --- | --- |
| Constructor | `4bf23393a1e7141d6d20b8ba4c2f39f32fe457849a8ae7a69e9905e1cfd19af1` |
| Rust proof driver | `965d8a591906a93d2b258a8155cd7a2ef3f821afaa368a672ab89e2e1a7310ae` |
| Native tests | `17eac8e9aa4bf1b7b1f4d3c59e5413eb152749daf582877769f52a66f319a84d` |
| Podman dependency | `f93ee492920150e229b9b41729bfe675073a4df0569ee5d570a8106b5a64506a` |

The original records remain under
`/var/lib/hol-gauntlet-rust/native-preparation-proof-20261026-001/` on the VM.
The host retains `native-preparation-vm-results-001.tar` under the outer
workspace's `gauntlet-rust-pr-ready-evidence-20261026`: 286,720 bytes, 84
ordinary members, SHA-256
`d34cb3b4afbd1c916d1828df9b2182ace99d23cd33f41ba66424e6f7ca9f1ab0`.
Its declarations, process outcomes, image/supervisor journals, replay refusal
and raw capture sidecars passed outside archive and per-member hash/size checks.

All 20 native ARM64 tests passed, including actual exclusive image-lock
contention and refusal after a lock releases while its active pointer remains.
The complete all-feature macOS workspace passed 398 tests with zero failures
or ignores across 207 result targets. Its retained
`rust-workspace-native-preparation.log` has SHA-256
`1088ba390cff6f3dba993f80fbae35482129c86f362892db0f85765c0127fc3d`.
Fifteen macOS rootfs tests, ARM64 build/Clippy and all-feature whole-workspace
Clippy passed with warnings denied.

## Remaining exits

The installed controller is still historical `dfc948e9`, and the product,
image, prefix and actor pins are the retained diagnostic inputs documented in
the previous proof. This establishes Rust apparatus and image ownership; it
does not establish current-main product conformance, Guard request/effect
causality, independently reviewed provenance, model execution or rollout.
Worker dispatch and host lifecycle still need to compose this API under their
durable job/lease contracts. Every result remains `execution_eligible: false`,
and the 62-parent ledger stays 24 complete/38 open.

A read-only disk inspection measured 8,852,676,608 free VM bytes against the
builder's fixed 12-GiB starting floor. Small ordinary caches cannot close that
gap; retained source, candidate, image and proof history has not been deleted.
A fresh source build must obtain sufficient space while preserving that
history. This resource preflight and disabled fork Actions remain dependencies;
neither justifies lowering an admission floor or bypassing the five checks.

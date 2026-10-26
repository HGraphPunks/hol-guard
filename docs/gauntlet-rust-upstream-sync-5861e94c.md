# Upstream synchronization: 5861e94c

Merge `53af9d96316bed0b813f07bab58d5a880c05da72` incorporates upstream
`5861e94ce48f41b5dc763e0c329ff71d3e90903f` without conflicts or history
rewriting. Its 19 new commits touch 153 files, including Native posture,
resident handoff, quarantine, plugin installation and workflow findings.
They change no `ci/gauntlet` or `ci/gauntlet-rs` source. The immutable Python
baseline and explicit 431-file source delta remain unchanged.

The full all-feature migration workspace passes 404 tests, zero failures or
ignored tests, after this merge. All source/install inventory checks are in
that suite. Its 208 successful result targets are retained in
`gauntlet-rust-pr-ready-evidence-20261026/rust-workspace-after-5861e94c.log`,
SHA-256 `1a3017d4fae53af94cbcf46e669f8a1c0ec86826983d40dfda291076ae11534d`.

The matching locked Rust 1.88 release Native runtime and command compiler
rebuilt successfully. Their respective SHA-256 pins are
`711ee255e970a53ed562c6067a91d49062f14075b336f08f65af922f26a6e133` and
`6b655d1dfa2b80964b53a50c229bb84427817cb6f6db2c13dbec9261ec243a92`.
The full 1,418,914-byte command program and all 225 public extensions verify;
program digest is
`f8dd2d2b9c4879c05d28325212482b3bb3d31a91b76774a0e45b2f67d2a4caf4`.

The merged Native macOS Bash ownership, approval and delivery fixtures,
migration regressions, package context, stale launchers, inline approvals and
command capabilities pass, together with new upstream posture, sync outage,
workflow finding, replay judge and plugin CLI tests: **418 passed, zero failed,
errors or skipped**. The complete log and JUnit are retained as
`native-and-migration-after-5861e94c.log` and `.xml` in the same evidence
directory. Their SHA-256 pins are respectively
`4848d091b28e31a01ef196a116402b83a4532336408bf6485e097b1977cd09a7` and
`e5bb3c224f5aec821bd985af9c233d79124161ea7e94ccb9a0449b1fec98261b`.
Only the three generated extension documentation projections were retained in
the scoped stash `retain generated native projections after 5861e94c validation`.

The [Rust worker apparatus proof](gauntlet-rust-native-worker-vm-proof-20261026.md)
remains bound to its recorded historical candidate. The new
[separate build VM](gauntlet-rust-native-build-vm-20261026.md) provides the
required disk headroom without removing retained evidence. Fresh current-source
candidate/control/conformance work and the five required GitHub jobs remain
open. Product regressions and apparatus completion do not qualify a benchmark
verdict or authorize cutover.

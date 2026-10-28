# Upstream synchronization: b5a27d0a

Merge `5613889b488407156a042f37617d2e279bacd5ae` incorporates upstream
`b5a27d0a` without conflicts or history rewriting. The 15 intervening commits
update Native request evaluation, approvals, hook reconciliation and extensions.
They change no `ci/gauntlet` source: the explicit 431-file delta and independent
400-file controller plan remain valid. All three inventory/install-plan checks
passed after the merge. The immutable Python baseline remains untouched.

The matching release Native runtime and command compiler built with locked
Rust 1.88 dependencies. Their SHA-256 pins are respectively
`ca8ad4613541ef3ccf75ae62608a8aee046b398a980eb10496c948af079d4b31` and
`76307f2c321c231418d4491da59c507c9c3f98c05bac72fa2ca0225e0181b39d`.
The full 1,418,914-byte command program and 224-extension public directory
verified; program digest
`03ab9883ce044442564d1cfd67ac67341339eea70e2b23053398bc092db53727`.

The merged macOS Native Bash ownership/approval/delivery, migration readiness,
package-context, stale-launcher, inline-approval and command-capability suite
passed **206 tests, zero failures or skips**. The outer workspace retains
`gauntlet-rust-pr-ready-evidence-20261026/native-and-migration-after-b5a27d0a.xml`,
SHA-256 `509a43db6ec94afe95a30c795e2bd0a6aaa22cb9574dd435298959a57b4dad3b`,
and its complete log. Three generated documentation projections were retained
in a named, scoped stash rather than added to the migration patch.

These are current product-integration regressions. The VM apparatus proofs
still identify their historical product inputs, and final-head GitHub checks,
fresh-source conformance and qualification remain open.

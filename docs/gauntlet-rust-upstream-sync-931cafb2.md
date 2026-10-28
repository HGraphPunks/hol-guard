# Upstream synchronization through 931cafb2

Upstream `931cafb20a5385c4c0c7dcb79749175c9decb5d2` is merged without
conflicts as `795948ba7e6c18ff2100902a44c070790dbba16e`. The 30 imported
commits change 281 files. They include Git read/allow handling, heredoc and
process-substitution parsing, preserved Always approvals across rule updates,
resident receipt/review ownership, Cursor routing and workspace assessment.
Both migration runtime modules and the CPU-aware resident worker budget remain
present in the merged Native library.

The two changed Gauntlet files are reviewed: `git_allow_fixtures.py` adds
Git-ref reads after an allowed checkout and a Guard-named linked-worktree
fixture; `scenarios.json` adds those cases and a sibling-checkout Git-read
case. The source inventory remains 432 files, with 70 changed and 12 added
relative to the immutable 420-file Python baseline.

The refreshed delta hashes to
`15a2512513d53ec37831cd940bd2f50e2de7bff858fe1c6896fb9a71e19f4705`.
The baseline remains byte-identical at
`9c0418833bfa5795e382a4426ab327afbe630904823e49c07b2bbf6714a8ee0f`.
Both Rust inventory tests pass. Python's actual bootstrap selection and Rust
agree on 401 installed files, 412 entries and the new planned controller
digest `ff8d14598c7b1478b7220dfbb1dfde7dbf2619151581466d615ad1e2e0e92733`.
The full suite first retained a stale `5a135a5a…` expected digest; the test
expectation was updated only after the independent Python recomputation.
No retained VM controller, historical receipt or baseline was replaced.

## Validation

The merged product source builds with Rust 1.88, locked and offline. Frozen
macOS executables are diagnostic artifacts, stamped for source `795948ba`
and version 3.58.0:

| Executable | Bytes | SHA-256 |
| --- | --- | --- |
| `hol-guard-runtime` | 120,792,544 | `8a755c37215853e4e50030dea036489daa1e53922a556152ea79109873bbcc7c` |
| `guard-command-source` | 25,561,248 | `f05e477a7fe737a9bb7084c7a519a17954eef5ed3e0d59fc41214043eb032e36` |

All 45 focused Native tests pass: two worker-budget, 13 transport, two
cancellation, 13 runtime-finding, six edge-receipt, four edge-review and five
Cursor-route cases. Native all-target warnings-denied Clippy passes. The
initial edge-receipt filter selected zero tests and was rejected by the
validation wrapper; its log remains retained. The corrected actual module
paths run every reported case.

After the reviewed map/expectation refresh and feature environment correction,
all 634 migration workspace tests pass with no failures or skips. Mac/ARM
warnings-denied Clippy passes on source map
`2066f73615d4d0bff8c59a79bacbf8b6cec1c4ec9435b020e2eac52f8f9420ed`.
The full-suite log hashes to
`d593babc4e9cedded7bb739afefc65f0d617e22136617e9c5fcc1853bc4dc1d6`.
Logs and source maps use `upstream-931cafb2-…` and
`native-feature-audit-…` in the retained local evidence directory. Earlier
stale-expectation and zero-selection failures remain unchanged.

## Feature environment correction

The [first complete feature audit](gauntlet-rust-feature-audit.md) exposed an
installed Codex safe-Git assertion. The Rust runner had added its preparation
Git variables to pytest's environment. The unchanged test fails with those
variables and passes without them under the same frozen Native executable;
the test source digest is
`650879049d72562f3c56daa3a8b5f44e75bee3858de3ba5465c642b2d9247015`.
Native's conservative environment trust check correctly refuses to prove
ambient Git configuration whose value is not carried by the request.

Fix `cb9ea66e7848ef113735f69bf4658c6ea8024fb3` keeps configuration isolation
for preparation and removes its three added Git variables from product tests,
matching the original Python audit context. Every source/installed selector,
Native binary, assertion and resource bound remains intact.

Fresh owned-ARM audit `e2c701baf1475803` repeats all 28 groups against the
same product `dc3b9336`, wheel, actual Native ELF and source archive as the
retained failure. It records 1,288 passes, zero failures and the same one Pi
expected failure. All 59 Codex/Claude cases now pass. The aggregate remains
`incomplete`; no pass or qualification is inferred from that expected failure.
The source compiler is byte-identical across the two audits. Ten ARM executor
and reader tests, 70 outside resource observations and final exact-container,
cgroup/profile cleanup verify, with all 333 prior worker records unchanged.

The [environment comparison proof](../ci/gauntlet-rs/proofs/verify_feature_environment_20261028.py)
checks both complete exports, all 708 fixed-executor Git blobs at `cb9ea66e`,
every XML/log digest, actual and Python-baseline case counts, the unchanged
product inputs and identical Mac/ARM readback. The original failed audit
remains retained. This synchronization does not relabel the older product
execution as the newly merged product source.

## Remaining scope

Rust durable Root audit admission/recovery and operator invocation remain
open. The currently published unadmitted ARM runtime still belongs to product
`dc3b9336`; no new ARM publication, Native qualification, model inference,
provider-quota change, production gate or cutover occurs in this checkpoint.
The five required current-head cloud jobs remain user-owned and pending.
Parent migration exits remain 24/62.

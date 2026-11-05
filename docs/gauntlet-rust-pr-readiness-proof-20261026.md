# Rust migration restart: integration and regression proof

Date: 2026-10-26. Branch: `codex/gauntlet-rust-pr-ready-20261026`.
This is a local implementation checkpoint, with no new model requests,
conformance package, eligible benchmark verdict or production cutover.

The branch starts from integration `f143f9ac` and merges the committed
preparation `b0b0cdd8`. The original preparation worktree remains intact.
The active goal and [execution plan](gauntlet-rust-pr-readiness-plan.md)
preserve all 62 parent milestones and their original proof requirements.

## Historical custody oracle compatibility

The initial complete Rust run exposed three failing source-pin assertions:
`private_actor`, `private_cell_mounts`, and `private_hook_samples`. Their
immutable vectors name Python source SHA-256 `2de9c8c27d2b8f883291900ed3fe29f0f9aa7a318b03a195c4f20ba4f5a22cbb`.
Native-actor support changed the enclosing verifier file to
`5be923a6164459e79664419767e07591581355c8060bf941545b48a7adf859bd`.
The change imports the explicit native runtime selectors and extends the
outer verifier's actor/gate selection; it does not change the six functions
exercised by those vectors.

The repair retains the complete 269-line Python source from immutable commit
`b4efd8171b06d0e13cbe12a077c376ecdc891fd1` as inert test data. The tests verify
its original digest, require the separately reviewed current file digest,
and use Python's AST parser to prove the selected functions have identical
ASTs. The current file cannot drift outside that explicit compatibility
relation. The original JSON vectors and expected refusal messages are
unchanged. Four Rust tests now pass across the original 69 vector rows.
This establishes the unchanged pure relations; it does not qualify the new
outer verifier or independently authenticate a live product observation.

## Detached fixture readiness

The retained interrupted repair no longer treats a matching process command
line as proof that the detached fixture has started. Before cancellation it
requires the fixture's fixed readiness file to match the observed namespace
PID, session, process group and role token. The reader rejects wrong owners,
unsafe modes, symlinks, hardlinks, incomplete/oversized/ambiguous data and
changes during the bounded read.

Seven focused readiness cases include a watcher regression that sees the
process twice before the readiness predicate succeeds. With deterministic,
completion-lifecycle and staging-artifact regressions, 87 Python tests passed.
All five embedded deterministic fixture programs remain byte-identical to
the committed preparation. Source-inventory and controller-install-plan
checks also passed with the explicit readiness source delta.

## Tools and retained results

The installed Rust 1.88 toolchain was outside PATH. Locked dependencies were
recovered into a separate project cache without installing new toolchains.
The first sandboxed bridge test refused local IPC; the complete run with the
required local socket access passed. A stale retained Native compiler
correctly failed the current capability check. A new locked Rust 1.88 release
compiler passed all five existing projection/directory preparation checks.
The Python suite used its existing private-home isolation helper.

| Check | Observed result |
| --- | --- |
| Complete Rust migration workspace, all features, locked/offline | 380 passed, zero failed, zero ignored on macOS; Linux-only code remains separately required |
| Python readiness/deterministic/completion/staging regressions | 87 passed, zero skips |
| Current source inventory and controller install plan | Three tests passed |
| Rust workspace formatting and diff whitespace | Passed |
| `rust-workspace-before-main.log` | SHA-256 `dc2f6ee7af4901039804c95e5a07ab9ea096d75a3bfdf13c936b9043708182c0` |
| `detached-readiness-before-main.xml` | SHA-256 `8502d031c291d508c3cf79bdd359e0f7cc985085b85bab9530d421c68443ae27` |
| Matching `guard-command-source` executable | SHA-256 `4b4b4bd8570ee8cceec09441aeef72bb196f3fa11e474d9b6eceb28f54686e8a` |

Logs and JUnit are retained under
`/Users/construct/Documents/projects/hol-guard-refinement/gauntlet-rust-pr-ready-evidence-20261026`.
The owned 16-GiB ARM VM was observed stopped; no old live report is promoted
by this checkpoint. Upstream synchronization, the Root Rust constructor,
fresh VM proof and the complete acceptance matrix remain open. The parent
milestone count remains 24/62.

## Upstream synchronization

Merged upstream `7fb50978` without rewriting published history. Both scoped
secret-scanner fingerprint lists are retained, and the Native Unix feature
set includes migration `time` and upstream `hostname` support. Upstream retired
the Python CLI hook route and its wiring test; the merge preserves that
retirement. The unified Native/daemon route reviews PostToolUse output without
reopening command admission. Three new Rust regressions demonstrate ordinary
completed shell output, rejection of secret-bearing output despite a completion
hint, and refusal to treat PostToolUse evaluation as PreToolUse admission.
All three passed against the merged source. The merged Native library and CLI
also passed locked Rust 1.88 `cargo check` on macOS.

Four new legacy modules are explicitly assigned to the Rust migration:
approval retry action identity, Windows Codex contained-call binding, actual
decision-path coverage, and synthetic runtime launch cases. The latter adds
physical launch checks; model refusal or an unexercised decision remains
unproven. The frozen 420-file baseline is unchanged. The reviewed current delta
contains 67 changed files and 11 additions, for 431 files. Independent Python
and Rust controller planners agree on 400 installed files, 411 entries and
tree digest `9dcb5e8de575a89e2b2d27f8cc5b009ade6385251a21a050dfc8b357e717a47d`.
All three source-inventory/install-plan regressions passed. This plan does not
replace any retained installed controller or live result.

The owned ARM64 VM was started for subsequent zero-model diagnostics. These
merge checks do not constitute the five required GitHub jobs, Linux constructor
conformance, independent review, or qualification.

## Merged-tree verification and startup race

The complete merged workspace initially found two additional stale whole-file
pins in the historical host-call/transcript compatibility helper. Upstream
added decision-path assessment elsewhere in `evidence.py`; the normalized
`reconcile` and `read_events` AST digests remain unchanged. The explicit current
source pin is now `b5a2ba7d80f6bb16eb60d125299b0f7874e1befded2680b0394cb065e4ba2a51`.
The unchanged original generators replay all 31 host-call and 15 transcript
cases against this source, without modifying historical fixtures.

A subsequent full run exposed a separate startup contention failure. A status
reader's shared transaction lock could terminate a newly launched observer
before readiness. A held-reader process regression reproduced the actual
`Rust host lifecycle lock is already owned` failure. Observer open/start now
retry only pre-mutation Busy results for a bounded five seconds per operation.
Each start reacquires the exclusive observer lease and samples a fresh clock.
Identity, clock, invalid-state and uncertain-commit failures are final. Operator
mutations keep immediate contention refusal. Process tests cover temporary
reader contention, finite refusal with unchanged checkpoint, single ownership
and crash recovery; a regression ensures uncertain commits are never retried.

The final complete macOS workspace run passed **390 tests, zero failures and
zero ignores**, across 206 test targets. Full workspace warnings-denied Clippy
passed; the changed host crate's Clippy passed again after the startup repair.
The matching merged Native release runtime/compiler passed full projection
preparation and **140 macOS ownership/approval/delivery and migration tests**,
with zero skips. The three Native PostToolUse Rust regressions also passed.

| Retained artifact | SHA-256 |
| --- | --- |
| `rust-workspace-after-startup-repair.log` | `d7be6c989525554ceeed915549ada72ee463f930a664942a5c58b65e61599125` |
| `native-and-migration-after-main.xml` | `190447e6ba99ecd82f6803fdd40ad5e7dccc888ccb403d52f89028b9dbff6e75` |
| Matching merged `hol-guard-runtime` | `669b04f5f1223ae561c93e2d93d65653b859328a963ff9793b5a491b6554ad75` |
| Matching merged `guard-command-source` | `fe1417ebadfc0339007cf481ba63db156fb078a29de1f4babe0b1c91d1251fc4` |

Both failed full-workspace logs remain retained. Generated projection docs
were preserved in scoped named Git stashes, excluding unrelated generated
churn from this branch. The [constructor VM proof](gauntlet-rust-rootfs-vm-proof-20261026.md)
records its separate source pins and three fresh zero-model apparatus cases.

Fork PR #4 tracks this consolidated child. GitHub's dispatch endpoint returns
HTTP 422, `Actions has been disabled for this repository`, while Actions
permissions report enabled and the workflow reports active. No PR-triggered
run exists for the published head. The five required jobs remain unsatisfied;
local results do not authorize merging around that requirement.

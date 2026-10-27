# Gauntlet Rust migration: execution and PR readiness

Updated: 2026-10-26. Execution model: GPT-6.1 Sol, Max reasoning.
Status: active implementation; the Rust replacement is not qualified.

## Goal and completion contract

Finish the Gauntlet migration on a tested branch in `HGraphPunks/hol-guard`,
ready for a pull request into `hashgraph-online/hol-guard` `main`. This is the
active goal for Codex task `01a17937-c26d-7ec1-8c97-8e68530edd08`.
Writing this plan is the first deliverable, not goal completion.

Rust must own trusted orchestration, evidence verification, durable execution
state, the Linux worker and product-cell apparatus, host lifecycle, scheduling,
and the intended qualification/publication interfaces. The pinned OMP/Bun
adapter, host MLX inference process, product pytest executor, and explicitly
versioned historical readers remain external dependencies as specified in
[the migration design](gauntlet-rust-migration.md). External adapters may not
silently retain orchestration or verdict authority attributed to Rust.

The finish line is executable behavior with exact-source proof across the
local deterministic, workflow-benchmark and legacy lanes. No self-reported
pass, old Python run, synthetic fixture or successful build substitutes for
fresh required execution evidence. The existing
[62-parent checklist](gauntlet-rust-execution-checklist.md) remains the
acceptance ledger: 24 complete and 38 open at this plan's creation. Its
historical proofs remain immutable; only independently verified exits change
the count.

## Starting state and integration policy

| Input | Starting identity and disposition |
| --- | --- |
| Published migration | Draft upstream PR #5402; fork integration `f143f9ac8aa2cebba9c7d676fd9ff425bbf22e3e` |
| Pending macOS chunk | Fork PR #3 at `2ab0f15f226cea4c99d833f8e4a9af46f53ed076`; five required current-head checks absent |
| Newer preparation | Fork preparation `b0b0cdd8aa606dabc1ea00be87a808a0f4f4812c`; passive observer and native product actor/gate |
| Uncommitted preparation | Detached-child readiness repair, associated inventory updates/tests, and an unfinished `gauntlet-cell-rootfs` crate; preserve the original worktree |
| New execution branch | `codex/gauntlet-rust-pr-ready-20261026`, initially created from integration and merged with the committed preparation |
| Upstream observed at planning | `ed95bf53c998bb98715a2588e100bc9d3cd47320`; fetch and recheck before integration and final validation |
| Historical trusted baseline | Python PR #5263 at `b4efd8171b06d0e13cbe12a077c376ecdc891fd1`; do not regenerate its fixtures or receipts |

Use coherent child PRs following [the development workflow](../ci/gauntlet-rs/AGENTS.md).
Pending work can be carried into a fresh child and validated together; this
does not satisfy or bypass a missing check on another head. Preserve published
history, merge reviewed upstream changes, and refresh only the explicit source
delta after inspecting changed Gauntlet behavior. Keep a clean, recoverable
commit after each verified implementation slice. Leave existing dirty work
intact until its reviewed bytes have a separate retained checkpoint.

## Work packages and required proof

| Package | Implementation and acceptance | Checklist coverage | Starting state |
| --- | --- | --- | --- |
| R0 Integration and tools | Recover pinned Rust 1.88 and Python test tooling; retain WIP; merge current upstream; fix integration conflicts; run the five migration jobs and relevant product CI on the actual child head | Phase 0 integration and final-head CI | In progress |
| R1 Complete behavioral inventory | Map all three CLIs, command/profile/exit contracts, schema versions, assets, journals and state transitions to owners and tests; reconcile Python/Rust refusal classes, races and old evidence readers | Phases 0 and 1 | Partial |
| R2 Native product apparatus | Complete the Root Rust rootfs/namespace/mount constructor and supervisor around the existing unprivileged Rust actor/gate; preserve idmaps, proc masks, AppArmor, seccomp, networking and resource limits; prove actual success, timeout, cancellation and descendant cleanup | Phase 2 worker and isolation | Complete zero-model Rust apparatus worker and recovery cases pass; qualified benchmark admission remains open |
| R3 Deterministic authority | Capture authenticated Native requests/decisions and physical effects independently; bind exact request, product identity, file generation and cleanup; recompute each role's verdict; run six fresh staging plus six installed roles and construct fresh conformance | Phase 1 outcome verification and Phase 2 conformance | Diagnostics remain ineligible |
| R4 Build and deployment | Rust-owned source/archive custody, bounded unprivileged build, inert wheel/prefix staging, source-matched immutable deployments and feature-audit invocation; preserve failed/uncertain receipts | Phase 2 provenance, staging and failure matrix | Native image lease/cell staging proven; complete current-source build/deployment path open |
| R5 Operational lifecycle | Connect the passive Rust observer to the qualified worker, exact-tag queue and bounded progress transport; implement reconciliation/repair, history import, stale data and unknown-job blocking; prove interruption, restart and single ownership | Phase 3 | Passive native observer exists on preparation |
| R6 Workflow execution | Rust campaign freeze, exclusive journals, serial shards/attempts, authenticated OMP bridge, service/oracle ownership and complete reserve/settle/halt accounting; then fresh two-cell and twelve-cell real-inference profiles and contracted wider schedules | Phase 4 | Pure readers/reducers and bridge components exist |
| R7 Legacy and compatibility | Preserve the pinned legacy catalog and actual harness behavior, installed/repeat/aged-home acceptance, old/new bundle verification and trusted-base publication separation; test stale heads and forged producer claims | Phase 5 and remaining Phase 1 readers | Open |
| R8 Rollout and recovery | Build reviewed immutable host/worker generations, compare retained evidence with Python, demonstrate idle-only cutover and rollback without lost receipts, replay or duplicated provider use; publish the compatibility table | Phase 6 | Open |
| R9 Final fork handoff | Recheck upstream, obtain complete exact-head checks, document setup/operation/limits and evidence locations, and push the clean final branch with a reviewer-ready diff and PR description | Final migration readiness | Open |

Keep implementation modules within the repository's source-size guideline.
Use existing secure filesystem, bounded process, framing and custody helpers
where their contracts fit. Preserve the documented JSON data exemption.

## Execution order

1. R0: create the isolated branch, retain the interrupted work, restore test
   tooling and capture a baseline. Commit this plan and the goal contract.
2. Complete the detached-readiness repair, then R2's Root constructor as a
   separately testable boundary. Unit tests must cover actual failure cases;
   the VM proof must observe kernel state and cleanup rather than repeat
   constructor assertions.
3. Compose R2/R4/R3 into one fresh source-bound deterministic candidate before
   enabling worker admission. Keep `invalid-evidence` and eligibility false
   until the independently checked acceptance conditions are met.
4. Complete R1 compatibility alongside these slices. Use the Python behavior
   as a differential oracle and record incompatible semantics explicitly.
5. Connect R5 only after the worker authority is qualified. Use isolated Rust
   state first and demonstrate interrupted-job reconciliation before cutover.
6. Complete R6 and R7, then R8 and final R9 validation. Actual inference begins
   only after deterministic admission and settled quota preflight pass.

The dependency order does not suspend independent implementation when CI,
review or inference authorization is unavailable. Track the specific external
dependency and continue work that does not depend on it.

## Validation and evidence rules

- Run locked Rust tests, format and warnings-denied Clippy on the affected
  workspace, then required macOS/Linux ARM64 and merged Native checks. Run
  relevant product regressions after a boundary or upstream change. A prior
  head's green run is historical evidence.
- Every live proof records controller, worker, candidate, configuration,
  installed prefix, assets and outside evidence pins. Use a fresh job ID and
  namespace after execution-affecting changes. Retain all failed attempts.
- Independently establish request/decision/effect relations. A signed
  controller statement authenticates its producer; it does not by itself
  prove Guard caused a physical effect or prevented an attack.
- Test refusal and recovery for identity substitutions, links, concurrent
  mutation, replay, stale process IDs, uncertain cleanup, interrupted writes,
  timeout and cancellation. Missing measurements remain unavailable.
- Preserve all required cells and distinguish baseline attack measurements,
  model refusal, service/VM enforcement, Guard intervention and task utility.
  Compile-time schedule inventory is not execution of the schedule.
- Charge all provider attempts to the retained authorization. This goal sets
  no new inference allowance. Inspect the existing exact-source allowance
  before a run; never reset a journal or infer an extension from elapsed time.
- Required independent review and trusted artifact provenance must actually
  exist before a production/cutover exit is checked. Author-generated tests
  and this goal do not supply that review.

## Authorized boundaries

The user authorizes implementation, local validation, owned disposable VM
work, commits, fork branches, incremental fork PRs and their required checks,
and preparing the final fork branch for an upstream PR. Preserve existing
approvals, isolation, evidence, failed attempts, journals and original work.

This goal does not authorize an upstream merge, production gate activation,
publishing a release, accessing secret files, broadening isolation, or
resetting/exceeding model quota. Prepare reviewable changes and evidence
before requesting any genuinely necessary external action. Do not add an
approval ceremony for routine work already authorized by this request.

## Current execution record

- 2026-10-26: registered this goal on the current GPT-6.1 Sol / Max task.
  Located the installed Rust 1.88 toolchain outside the shell's PATH.
  Created the isolated branch from integration and merged the committed
  preparation. The original preparation worktree and its WIP remain intact.
- 2026-10-26: restored locked dependencies, built a matching Native compiler,
  retained the detached-readiness repair, and repaired historical custody
  oracle compatibility without changing old vectors. The complete macOS Rust
  workspace passed 380 tests; the focused Python suite passed 87. Exact
  identities and limitations are in the
  [restart proof](gauntlet-rust-pr-readiness-proof-20261026.md).
- 2026-10-26: merged upstream `7fb50978`, preserved its retired Python hook
  route, and verified the resulting Native library/CLI plus three PostToolUse
  regressions. Independently reconciled the expanded 431-file Gauntlet source
  map and 400-file controller plan. Started the owned VM for Linux diagnostics.
- 2026-10-26: implemented the Root Rust constructor and ran fresh VM success,
  timeout and cancellation with the retained Native daemon, outside kernel
  checks and complete cleanup. Eight ARM64/seven macOS tests and three proof
  harness tests passed. The matching merged Native runtime passed 140 macOS
  ownership/approval/delivery and migration regressions. Fork PR #4 is open;
  GitHub refuses its required jobs because repository Actions are disabled.
- 2026-10-26: repaired the reproduced observer startup/status contention race
  with bounded retries that never retry uncertain writes. The final merged
  macOS workspace passed 390 tests with no failures/ignores; Clippy passed.
- 2026-10-26: implemented the Rust cell supervisor, outside kernel collector,
  private capture journal and a zero-model VM driver. Eleven macOS tests and
  the ARM64 build/Clippy pass; fresh native execution is pending. The image
  staging/lease adapter remains Python and is tracked separately under R4.
- 2026-10-26: Rust supervisor source `a61815a0` passed fresh VM success,
  timeout and cancellation with the retained Native daemon and no outside
  cleanup intervention. Sixteen native/12 macOS tests, the default-feature
  workspace and warnings-denied Clippy passed. Retained evidence includes the
  first two failed attempts; see [supervisor proof](gauntlet-rust-supervisor-vm-proof-20261026.md).
- 2026-10-26: native preparation source `69039ec6` passed six VM cases:
  success/timeout/cancel, wrong pin, replay and refusal to borrow an existing
  image. Rust now owns the image lease and cell staging. Twenty ARM64 tests
  and the 398-test all-feature macOS workspace pass. See the
  [preparation proof](gauntlet-rust-preparation-vm-proof-20261026.md). The
  existing VM is below the fixed 12-GiB candidate-build starting floor;
  retained history remains untouched.
- 2026-10-26: merged upstream `b5a27d0a` at `5613889b` without conflicts.
  Source/install inventories still match; the rebuilt matching Native runtime
  passed 206 macOS ownership, approval, delivery and new upstream regressions
  with zero skips. See [upstream synchronization](gauntlet-rust-upstream-sync-b5a27d0a.md).
- 2026-10-26: implemented an explicit native apparatus worker, descriptor-bound
  contained Rust controller, durable job markers/terminal and unknown-job
  admission blocking. Focused macOS tests and ARM64 build/Clippy pass; its
  [live job proof](gauntlet-rust-native-worker-vm-proof-20261026.md) now passes. It always
  treats apparatus completion as invalid evidence for Guard qualification.
- 2026-10-26: the first composed worker run (`0bab80ca`,
  `e2c701baf1470043`) refused completion after the worker's private umask
  removed public actor execute access. All processes/profile disappeared;
  the durable image lease and unknown job correctly remained. Added explicit
  staging-mode commits, conservative collected-unit cleanup and a separate
  versioned Rust quiescent repair receipt. Recovery never supplies an exit
  status or execution credit. Live quiescent recovery and six fresh worker
  cases pass at source `2a4c3fa0`, with failed attempts preserved. The Mac
  workspace passes 404 tests; native Root suites pass 23 rootfs/119 worker
  tests with 24 existing fixture-specific ignores reported separately.
  The host CLI heartbeat contention race is fixed without replaying uncertain
  commits. See the [worker proof](gauntlet-rust-native-worker-vm-proof-20261026.md).
- 2026-10-26: created separate owned build VM
  `hol-gauntlet-rust-build-20261026-001` from the pinned Ubuntu image using
  `ci/gauntlet-rs/profiles/native-vm-v1.yaml`. Its actual 2 vCPU/16 GiB/48 GiB
  profile has 46,939,676,672 free disk bytes before provisioning, above the
  unchanged 12-GiB start floor. No retained VM/history was resized or removed.
- 2026-10-26: merged upstream `5861e94c` at `53af9d96` without conflicts;
  no Gauntlet source changed. The full 404-test migration workspace and 418
  matching Native/product/migration regressions pass with zero failures/skips.
  See [current synchronization](gauntlet-rust-upstream-sync-5861e94c.md) and
  [provisioned build VM](gauntlet-rust-native-build-vm-20261026.md).
- 2026-10-26: Rust-only fixed-layout initialization at `bff9ed0d` passes on
  the separate fresh VM, including wrong-pin refusal before mutation, both
  competing worker leases, exact modes under 0077 and immutable receipt reopen.
  The actual Root suite passes 120 tests with 24 existing fixture-specific
  ignores separate. No Python control-plane worker is installed or job
  dispatched. See [initialization proof](gauntlet-rust-native-initialization-vm-proof-20261026.md).
- 2026-10-26: installed the exact 431-file current controller source through
  Rust on the new VM and independently verified its 400 files/411 entries.
  Build integration corrected v1's loose build parent using explicit layout
  v2 while retaining the measured empty original directory and receipt.
  Bounded Rust stdin capture at `c80ac788` now stages the actual 54.8-MB 3.57.0
  source archive through the downstream candidate reader; wrong hash/length,
  both leases and replay cases pass with rejected partials retained. The
  actual Root suite passes 122 tests with 24 existing fixture-specific ignores
  separate. See [native source proof](gauntlet-rust-native-source-vm-proof-20261026.md).
- 2026-10-26: source `afbff8e1` adds an explicit host candidate VM selector
  and v4 prelaunch pins binding its exact transport and target. Reconciliation
  refuses a different VM/transport; v2/v3 historical readers remain. The full
  all-feature Mac workspace passes 405 tests with zero failures/ignores.
  Two fresh candidate builds failed cleanly: wrong archive format, then Native
  tests running before compilation. Both remain consumed. Source `84549fd4`
  fixes the latter ordering, with 17 existing Python tests and three source
  inventory/plan tests passing. The immutable 420-file baseline stays intact;
  the current 431-file delta now has 68 changed and 11 added files, and the
  independently matched controller tree is `681f2043…`. Fresh current-source
  image/build execution is underway; Git-object archive creation remains an
  explicit proof courier, independently checked by Rust.
- 2026-10-26: fresh job `e2c701baf1471201` builds exact 3.57.0 source
  `84549fd4`, with four selected and 187 full contained tests passing. Rust
  captures its 24.2-MB artifact once, verifies/stages all 1,722 wheel entries,
  and reconciles the retained result against the original target-bound host
  pin. Outside kernel and final cleanup checks pass; Python independently
  matches the complete wheel/native bytes. See [current candidate build](gauntlet-rust-native-candidate-build-20261026.md).
  Rust source producer `6bb4cbfb` separately captures the full exact Git graph
  and preserves it on replay refusal, replacing the proof courier for future
  local captures. The complete Mac workspace now passes 407 tests across 210
  targets, with zero failures/ignores, and workspace Clippy passes. The
  retained dependency prefix's MCP 1.28.1 does not satisfy the candidate's
  >=1.30.0 requirement; a new compatible prefix remains necessary.
- Next: prepare compatible dependencies, then deterministic authority. No new
  conformance, model result, eligible verdict, cutover or completed parent
  exit is claimed.

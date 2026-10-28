# Gauntlet Rust migration: execution and PR readiness

Updated: 2026-10-27. Execution model: GPT-6.1 Sol, Max reasoning.
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
| R4 Build and deployment | Rust-owned source/archive custody, bounded unprivileged build, inert wheel/prefix staging, source-matched immutable deployments and feature-audit invocation; preserve failed/uncertain receipts | Phase 2 provenance, staging and failure matrix | Current 3.58.0 runtime published; feature audit, broader recovery and admission remain open |
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
- 2026-10-26: merged 33 newer upstream commits through `9dd2fefb` at
  `e76b3763` without conflicts or Gauntlet-source changes. Matching Native and
  command compiler rebuild/program verification pass. The expanded Mac
  suite passes 757 tests plus three subtests, with zero failures/errors/skips;
  three source/install-plan tests also pass. See [upstream synchronization](gauntlet-rust-upstream-sync-9dd2fefb.md).
- 2026-10-26: added a fixed Rust UID-65532 dependency exporter with frozen
  wheel-only UV installation and descriptor-bound bounded inert ZIP capture.
  Three Mac data/refusal tests and ARM64 compilation plus Mac/ARM64 worker
  Clippy pass. Live Root ownership, host intent and inert prefix composition
  remain in progress; see [dependency preparation](gauntlet-rust-native-dependencies.md).
- 2026-10-26: implemented exact-Git dependency input capsules on the host and
  lease-bound, generation/source/byte/hash-pinned native stdin capture. Two
  real Git tests and the closed ZIP decoder test pass; Mac/ARM64 Clippy passes.
  Source archive/receipts stay immutable, unsafe exporter formats refuse,
  partials remain consumed and all extracted files are independently read
  back before publication. The source-sized live VM proof now passes all
  generation/source/lease/hash/length/member/replay cases, with independent
  host verification of 36 evidence members. The current Mac workspace passes
  413 tests across 213 targets, with zero failures/ignores. Root ARM64 passes
  126 tests, with 24 preexisting fixture ignores; its first stale builder-context
  expectation and failed log remain retained. See [dependency input proof](gauntlet-rust-native-dependency-input-vm-proof-20261026.md).
  This operation executes no dependency code or installer.
- 2026-10-26: implemented the distinct dependency prelaunch host journal and
  native Root composition: closed pins/nonce/target, both permanent leases,
  durable unknown-job blocking, fixed unprivileged container creation, exact
  CID/intent checks before teardown, bounded attached client, independent
  Root output capture and invalid-evidence terminal. Three new contract/journal
  tests pass; the full Mac workspace passes 416 tests across 215 targets with
  zero failures/ignores. Warnings-denied Mac/ARM64 Clippy and ARM64 compilation
  pass. The unchanged pinned VM image, cgroup manager and job policy are
  prepared; the actual composed VM run remains next. No parent exit closes.
- 2026-10-26: the first composed dependency job installs all 62 locked packages
  and Rust captures its archive, but terminal publication correctly refuses a
  missing running-process marker. It remains unresolved and consumed; all
  logs/inputs/output and the failed observer are retained. The follow-up wires
  the observed Podman client into the durable marker and adds explicit
  quiescent dependency repair with aborted/null-exit semantics. ARM64 Clippy
  passes; actual recovery and a fresh complete run remain next.
- 2026-10-26: quiescent dependency recovery passes five pin/lease refusals,
  preserves all original files, and replays the same aborted/null-exit receipt.
  Fresh current-source jobs `e2c701baf1471401` and `1402` then complete through
  the Rust host and corrected Root supervisor. The latter has an independent
  actual-exporter/kernel/effective-limit observation; both have independently
  absent final resources. Wrong source/capsule/image/runtime/executable, both
  busy leases and host/guest replay refuse without changing retained files.
  Host verification checks all 80 exported evidence members, every byte/CRC
  of three dependency ZIPs and the same 2,302-file framed digest. Each contains
  62 distributions including MCP 1.30.0. All failed attempts/observers remain;
  no package is imported as Root or admitted. See [dependency run proof](gauntlet-rust-native-dependency-run-vm-proof-20261026.md).
  Inert prefix construction and candidate requirement validation remain next.
- 2026-10-26: repeat the Rust-owned current Native build at exact product
  source `62aa7ba7`, including upstream Native `9dd2fefb`. Four selected and
  187 complete contained tests pass. Host readback verifies all 22 members,
  the 1,705-entry wheel and actual Native bytes; old 1,722-entry proof remains
  retained. See [current build proof](gauntlet-rust-native-candidate-build-current-20261026.md).
- 2026-10-26: source-pinned Rust stager `c19dcfc7` constructs and publishes the
  successful dependency output as inert Root data. All 2,302 files match the
  ZIP; nine refusals/replay cases preserve 18 original files. The Root ARM64
  library passes 129 tests with 24 preexisting ignores; the full Mac workspace
  passes 419. Independent host readback verifies all 29 members and reconstructs
  the complete prefix digest. See [prefix proof](gauntlet-rust-native-dependency-prefix-vm-proof-20261026.md).
- 2026-10-26: corrected composition at `fc80aecd` passes on fresh candidate
  job `e2c701baf1471601`, after preserving the earlier mode-mismatch partial
  and snapshot-courier refusal. The rebuilt candidate again passes four
  selected and 187 complete contained tests. Root composition verifies all
  4,411 prefix entries and six CLI aliases; twelve composition and two
  dependency refusals preserve all 4,041 original files/links. All 13 active
  requirements pass over 63 installed distributions, including MCP 1.30.0.
  Independent host verification checks all 46 export members, reconstructs
  the complete tree and matches the actual source-pinned Python dependency
  loop with explicit Linux markers. See [composition proof](gauntlet-rust-native-candidate-prefix-vm-proof-20261026.md).
- 2026-10-26: implemented one-use source-path runtime publication with closed
  clone receipts, complete typed requirements, both leases, repeated data
  custody, private partials, no-replace publication and dual receipts. The
  full Mac workspace passes 425 tests; Mac/ARM64 Clippy pass with warnings
  denied. Live publication and independent controls remain next. The user
  will handle disabled fork CI; continue implementation and owned-VM work.
- 2026-10-26: one-use runtime publication at `c89e0008` passes in the owned
  ARM VM. Ten wrong-pin/lease/replay cases preserve 8,059 original files/links;
  the complete 4,411-entry published tree and both receipts match. Host readback
  verifies all 23 export members against the independently reconstructed
  prefix and exact Python requirement oracle. Actual Root ARM64 passes 135
  library tests with 24 preexisting fixture ignores. All data stays unadmitted;
  see [publication proof](gauntlet-rust-native-runtime-publication-vm-proof-20261026.md).
- 2026-10-26: the first current Native apparatus worker fails before readiness
  because a static musl actor cannot load pinned glibc libseccomp. Its actual
  controller exit 2, null report, invalid-evidence terminal and complete
  independent cleanup remain retained. Add GNU actor ABI preflight before
  artifact mutation and at full readback, a bounded inert build reader and
  ARM64 CI release-artifact check. All 427 Mac workspace tests and
  warnings-denied Clippy pass. The new GNU artifact and fresh worker cases
  remain next; see [retained failure](gauntlet-rust-native-current-worker-failure-20261026.md).
- 2026-10-26: source `c3a75ccd` passes fresh current Native success, timeout and
  cancellation through the complete Rust worker. The new factory refuses the
  static actor before artifact creation. Two separate live kernel observations
  match the GNU actor, filter/namespace/resource tuple; all cases drain. Host
  readback verifies 117 export and ten input members, complete unchanged prefix,
  terminal bindings and retained failures. Root passes 135 worker tests with
  24 existing fixture ignores, all 59 evidence tests and 23 rootfs plus one
  subprocess check. The two initial evidence fixture-path failures and two
  proof-caller errors remain recorded; test-only `7f62bc36` embeds the same
  frozen data. See [current worker proof](gauntlet-rust-native-current-worker-vm-proof-20261026.md).
- 2026-10-26: add the separate closed v2 Native hook transport profile. Rust
  owns normal prompt/Pre/sink/Post invocation, one-use input/output binding,
  descriptor-held request creation/readback/cleanup and physical-effect capture.
  The actual Python response oracle supplies 64 cases (20 accepts/44 refusals).
  The 435-test/217-target Mac workspace and warnings-denied Mac/ARM64 Clippy
  pass, alongside Ruff and ARM compilation. The first v2 live worker
  remains next; the fixed diagnostic explicitly has no SDK or Guard score.
  See [transport contract](gauntlet-rust-native-hook-transport.md).
- 2026-10-27: retain the first live v2 job's `invalid_workspace` readiness
  failure, the passed v1 regression and the wrong-Native-pin refusal. Native
  uses its explicit configured home for path trust, so the Rust adapter now
  supplies the fixed task home to its normal CLI calls. Mac rootfs/worker tests,
  warnings-denied Mac/ARM Clippy and ARM compilation pass. The corrected
  context still needs a fresh job. No approval or isolation policy changes.
- 2026-10-27: the fresh corrected-home job passes Native readiness and prompt;
  its Pre request refuses because the diagnostic's empty execution context
  lacks Native's required fields. Retain the failure and supply the fixed
  actor environment with a canonical sender commitment. Sink execution still
  requires its own normal Native reauthorization. No SDK identity is claimed.
- 2026-10-27: fresh job `e2c701baf1472301` at `6b901e2a` passes actual Native
  prompt/Pre/sink/Post, exact captured-output binding, physical effect,
  replay/refusal and cleanup. The inert reader verifies all 210 diagnostic
  export members and 33 input members, host prelaunch bindings and 48 retained
  earlier worker files. Root passes 136 worker tests with 24 existing ignores;
  unchanged evidence/wire/rootfs binaries retain their earlier actual ARM
  passes. SDK, independent Guard causality and conformance remain open. See
  [Native hook VM proof](gauntlet-rust-native-hook-vm-proof-20261027.md).
- 2026-10-27: Root Rust source `8c868cbf` publishes the inert SDK/Bun pair
  under both worker leases. Actual pin/lease/replay refusals pass, complete
  source/published inventories match the explicit Root ownership normalization,
  and all 54 prior worker files remain unchanged. The inert host reader verifies
  42,324 source, 20 result and three binary-input members. Root passes 141
  tests with 24 existing fixture ignores. SDK/Bun remain unexecuted. See
  [SDK publication proof](gauntlet-rust-native-sdk-publication-vm-proof-20261027.md).
- 2026-10-27: source `c62ca717` adds the actual SDK/Bash transport and
  independent worker cleanup postcondition. The first live attempt refuses
  before agent creation because its new helper bound excludes the already
  pinned 35 MB Podman; original unknown-job bytes and all 44 failed export
  members remain retained. The corrected reader matches the existing image
  reader's Podman bound, and SDK quiescent recovery gets its own v2 receipt.
  Mac passes all 446 tests and Mac/ARM64 Clippy. Actual repair and a fresh SDK
  attempt remain next; no SDK/Guard/model credit is supplied.
- 2026-10-27: exact created-CID and closed-image SDK repairs preserve original
  failed bytes and record consumed/aborted jobs without fabricated exits.
  Fresh kernel diagnostics establish the exact delegated cgroup and
  `crun//&SDK` process label; strict source checks retain that complete stack.
- 2026-10-27: actual SDK job `e2c701baf1473201` at `426c7d93` completes Bun
  pre-import binding, same-UID refusal, genuine Native Pre/contained route/Post
  and exact SDK output delivery. The benign fixture fails with npm SIGABRT;
  the independent 98-member reader preserves the failed outcome and all 100
  worker files. No MCP, model or Guard-causality credit is inferred.
- 2026-10-27: the next source adds separate output/outcome checks and a v2
  stderr-retaining fixture. Its fresh startup refuses changed host null-device
  ownership before SDK launch, retaining an unknown job and exact pending
  image lease. The pre-repair export/host reader preserve 104 worker files.
  A scoped held-device restoration has a durable receipt. New Rust source
  isolates OCI stdin with EOF pipes, checks host-device custody and supports
  exact pending-image recovery; 454 Mac tests and Mac/ARM Clippy pass.
- 2026-10-27: source `5c09afa2` repairs the exact pending image lease, preserves
  104 original worker files and reopens the consumed/aborted receipt exactly.
  Its fresh SDK job passes the benign Node/npm command, captured delivery,
  replay refusals and cleanup, but the new host character-device timestamp
  predicate refuses; type/ownership/permissions and inode identity remain
  correct. The inert 126-member reader retains the failed outcome, missing
  outside post-exec Bun sample and all 117 worker files. A narrow identity
  check and executable-generation sampling are next. Upstream `759130ab`
  is fetched for the next consolidation; the current VM artifacts remain
  pinned to their recorded source.
- 2026-10-27: source `d4d81a4b` passes the fresh SDK/Bash benign diagnostic,
  including actual outside post-exec Bun identity, exact Native-reviewed
  captured output, Node/npm fixture, same-UID and route-replay refusals,
  unchanged host-device identity and independent cleanup. The 119-member
  host reader preserves all 129 worker files and earlier failures/repairs.
  Wrong-publication refusal, terminal reconcile and one-use replay pass.
  Root passes 157 worker tests (24 existing ignores), 31 rootfs tests and
  one subprocess check; ARM Clippy/builds pass. No MCP, scoring or admission
  is inferred; the diagnostic uses zero model requests.
- 2026-10-27: merge `7a473d21` consolidates upstream `759130ab` without
  conflicts. Nine reviewed Gauntlet files add Git-allow and exact prompt-hook
  replay coverage. The immutable Python baseline stays fixed; the explicit
  delta has 432 files (69 changed, 12 added). Python/Rust agree on a new
  401-file, 412-entry controller plan, digest `61871991…`. All 454 Mac
  workspace tests and Clippy pass. The matching source/version-pinned,
  symbol-stripped Native runtime passes readiness and 369 focused product
  tests; one Linux-Bun bridge fixture needs separate native-platform execution.
  See [synchronization proof](gauntlet-rust-upstream-sync-759130ab.md).
- 2026-10-27: `gauntlet-world` ports the seven-family transactional provider
  state, signed receipts and idempotency to Rust. It matches 153 frozen actual
  Python operations and every intermediate snapshot/receipt digest. Five more
  tests cover persistent reopen, atomic rollback, anchors, strict inputs and
  large integer versions. All 460 Mac tests and Mac/ARM Clippy pass; static
  ARM tests compile. Root file/socket/process ownership and MCP dispatch are
  separate pending components. See [world proof](gauntlet-rust-world-proof-20261027.md).
- 2026-10-27: native ARM execution at `6f308fae` passes all six world tests,
  including every frozen Python result/snapshot/receipt relation. The host
  reader verifies all nine result members and both pinned ELF inputs. The
  eight bridge vectors skipped on Mac pass separately with the exact Linux
  Bun pin as UID10001; no Native/model execution is claimed by those unit
  vectors. Root MCP dispatch/lifecycle and independent scoring remain open.
- 2026-10-27: `gauntlet-mcp-service` adds versioned base MCP dispatch with
  all 41 schemas frozen from the actual pinned MCP 1.30.0 runtime, canonical
  World results and persistent bounded Unix framing. Nine dispatch and five
  real socket tests pass. The full Mac workspace passes 474 tests; Mac/ARM
  Clippy and static ARM builds pass. Root listener/peer/proxy/SDK integration
  remains pending. See [MCP component proof](gauntlet-rust-mcp-service-proof-20261027.md).
- 2026-10-27: all 20 current MCP/world tests pass natively as Root on ARM at
  `5433f744`, with no failures/ignores. Independent host readback verifies
  the four ELF inputs, 15 result members and six actual catalog fixture
  producer records. No Root proxy/SDK integration or Guard score is inferred.
- 2026-10-27: Root-owned SQLite and all seven families' fixed listeners now
  enforce held/visible custody, exclusive initialization and scoped retirement.
  All seven new custody tests pass natively as Root on ARM; the worker suite
  passes 164 tests with 24 existing ignores. The independent reader checks
  both original VM result exports. This does not authenticate a connection or
  establish process/stream drain; see [Root boundary proof](gauntlet-rust-mcp-root-boundary-proof-20261027.md).
- 2026-10-27: the closed v4 Native MCP profile now wires Rust-owned container,
  peer binding, normal product CLI duplex transport and Root SQLite sessions.
  ARM component tests pass 170 cases with 24 existing ignores; shared macOS
  worker tests and both warnings-denied Clippy targets pass. The first live
  v4 execution remains pending at this checkpoint. See [Native MCP transport](gauntlet-rust-native-mcp-transport.md).
- 2026-10-27: actual v4 Native MCP job `e2c701baf1473801` passes at
  `eafefd5b`: both normal CLI proxies/resident children reach Root Rust
  sessions and SQLite. Host readback verifies 14 wire frames, two signatures
  and physical records, 20 outside process samples, preserved 137 prior files
  and cleanup. The original stale-systemd-pin reservation is explicitly
  aborted without inventing an exit; a wrong helper now refuses before
  reservation. The required-workspace-owner refusal remains retained.
  Actual SDK composition and independent scoring remain open. See
  [Native MCP transport](gauntlet-rust-native-mcp-transport.md).
- 2026-10-27: the closed v5 SDK/MCP/Bash profile now connects the actual locked
  SDK to normal Native proxies and Root Rust services, with per-frame Bun
  descendant authentication, both pre-import same-UID negative controls and
  one shared four-operation ingress ledger. Exact SDK-visible MCP/Bash result
  joins are implemented. Mac worker tests (80), Mac/ARM warnings-denied Clippy
  and static ARM builds pass; actual ARM tests and the composed VM execution
  remain pending. This is an implementation checkpoint, not a control pass;
  see [combined transport](gauntlet-rust-native-sdk-mcp-transport.md).
- 2026-10-27: at `dde4cb73`, actual combined job `e2c701baf1473901` passes.
  Independent readback checks both SDK tool results, 24 frontend/24 upstream
  frames, the signed SQLite receipt, captured Bash output, physical effect,
  50 outside samples and cleanup. Existing v4 reference job `e2c701baf1473902`
  also passes, with 24 samples. All 177 native ARM worker tests and 31 rootfs
  tests plus subprocess pass. The original replay courier's malformed
  reconcile refusal and later SDK replay timeout remain retained; corrected
  reconcile calls recover both original terminals without altering 155 worker
  files. An early consumed-ID refusal now avoids unrelated host preflight;
  its ARM Clippy/build pass, with fresh VM verification pending. See
  [combined transport](gauntlet-rust-native-sdk-mcp-transport.md).
- 2026-10-27: source `779bc841` passes fresh combined job
  `e2c701baf1474001` and independent outside readback: 24 frontend/24 upstream
  frames, exact SDK MCP/Bash results, one signed physical SQLite read and
  51 process samples. Replay refuses in 523.923 ms while the legacy lease
  is held; reconcile returns the original terminal and a wrong request pin
  refuses. All 161 worker files remain intact. The tested library ELF is
  unchanged, ARM Clippy/builds pass, and no model request occurs. The original
  timeout stays retained. See [combined transport](gauntlet-rust-native-sdk-mcp-transport.md).
- 2026-10-27: partial v6 deterministic diagnostics add a closed role field and
  real installed-Native request-binding recorder after actual SDK completion.
  All nine raw historical mutations require Native authorization refusal and
  an unchanged descriptor-held trap with no effect; unrelated failures cannot
  count as intervention. Other four roles still refuse as incomplete.
  Affected Mac tests (107), Mac/ARM Clippy and static ARM tests compile/pass;
  fresh native execution remains pending. See
  [deterministic controls](gauntlet-rust-native-deterministic-controls.md).
- 2026-10-27: at `f013438b`, fresh v6 job `e2c701baf1474101` passes all
  nine real Native request-binding refusals after actual SDK/MCP/Bash execution.
  Independent readback verifies raw malformed requests, exact CLI/capture
  joins, physical unchanged trap/SQLite state and 57 outside samples. Replay
  refuses while the legacy lease is held, and all 167 worker files stay
  intact. Native ARM tests pass 177 worker and 33 rootfs cases plus subprocess;
  Mac tests (107), Mac/ARM Clippy and binaries pass. This closes the bounded
  request-refusal proof; complete role scoring and other four roles remain
  open. See [deterministic controls](gauntlet-rust-native-deterministic-controls.md).
- 2026-10-27: the next input-binding implementation additionally records a
  real reachable synthetic deletion, reseeding, actual Native Pre decision,
  attempted contained sink and held-marker readback. Only deny/block plus
  exit 126 and physical preservation counts as the bounded diagnostic;
  runtime failure and sandbox routing cannot substitute. ARM Clippy, static
  tests and both main binaries compile. Fresh VM verification is pending.
- 2026-10-27: independently rejected the forbidden probe at `2063110d`, job
  `e2c701baf1474201`. Although Native Pre denies and the marker survives, the
  sink's exit 126 is an invalid-workspace planner error. The raw controller
  pass remains retained without qualification. The 171-member export,
  67 outside samples and 173 unchanged worker files are preserved. Corrected
  v6 setup creates a checked project marker and requires the real Native
  authorization-refusal prefix; ARM Clippy, tests and main binaries compile.
- 2026-10-27: corrected source `a62a328d` passes fresh job
  `e2c701baf1474301`: actual reachable synthetic deletion/reseeding, Native
  deny, real contained authorization refusal and physical marker preservation,
  plus all nine binding controls and actual SDK/MCP/Bash results. Independent
  host readback joins both original exports and continues to reject the
  earlier planner error. It checks 67 outside samples, captures, physical
  trap/marker/SQLite state and 179 intact worker files. Replay refuses in
  508.687 ms while the legacy lease is held. Native ARM suites and Clippy/
  builds pass; every qualification flag remains false.
- 2026-10-27: implemented the actual-SDK boundary role with held synthetic
  controller/SDK/product canaries, separate positive visibility, six path
  probes and IPv4/IPv6 refusal. Rust waits for SDK/MCP/product cleanup before
  physical canary/result readback and rejects planner/network unavailability
  as isolation. Identical-byte inode replacement and forged/unavailable probe
  cases have meaningful regressions. ARM Clippy, static tests and both main
  binaries compile; live native execution is pending.
- 2026-10-27: boundary source `0ae73f0f` passes fresh actual SDK job
  `e2c701baf1474401`. Independent readback verifies eight physical probe
  results, both positive visibility captures, all three unchanged canaries,
  exact fixture source, signed SQLite state, 51 outside samples and 185
  preserved worker files. Replay refuses in 519.181 ms under the legacy lease.
  Native ARM passes 177 worker/35 rootfs tests plus subprocess; Mac passes
  108 tests, with Mac/ARM Clippy clean. The diagnostic remains ineligible.
- 2026-10-27: implemented the injection role's actual upstream/Native/SDK
  disposition join with the exact compiled catalog payload, clean/withheld
  response separation, unchanged physical provider state and real forbidden
  command probe. ARM Clippy, static tests and binaries compile; live injection
  proof remains pending.
- 2026-10-27: injection source `034a750d` passes fresh job
  `e2c701baf1474501` and independent readback. Native forwards the injected
  catalog payload; actual upstream/Native/SDK frames and the physical SQLite
  record agree. The real forbidden-command counterfactual passes independently.
  Fifty-six outside samples, cleanup and all 191 worker files are retained;
  replay refuses in 519.501 ms with the legacy lease held. Native ARM passes
  178 worker/35 rootfs tests plus subprocess; Mac passes 109 tests, with Clippy
  and binaries clean. No model resistance, MCP withholding or qualification
  is inferred from this diagnostic.
- 2026-10-27: implemented timeout/cancel diagnostics with exclusive readiness,
  Root-held detached PID/ELF/argv/cgroup/session/Native-CLI ancestry checks,
  actual Native timeout output or scoped cancellation, retained pending SDK
  requests and cleanup-gated physical readback. Missing cancellation output/
  Post remains unavailable. ARM Clippy/static tests and binaries compile;
  111 affected Mac tests and Clippy pass. Live native verification is pending.
- 2026-10-27: retained failed timeout job `e2c701baf1474601` at `f01deadb`.
  Native returns 124 and the outside sampler observes the child, but readiness
  is not observed at the lower workspace. The role remains failed, without a claimed child death
  or late-effect absence. Independent readback checks its 138-member export,
  cleanup, 66 samples and 197 preserved worker files; replay refuses in
  521.009 ms. A new explicit fixture version retains child errors and removes
  the FFI dependency while preserving exclusive publication and kernel checks.
  ARM checks/binaries and 111 Mac tests/Clippy pass; corrected runs are pending.
- 2026-10-27: retained both failed v2-fixture attempts at `5dea4ffb`:
  timeout `e2c701baf1474701` and cancel `e2c701baf1474702`. Each returns
  124 without Root joining readiness; neither qualifies. Independent readback
  preserves both terminals and 209 worker files. The cancel observer directly
  sees a complete ready file in the child's overlay cwd while the lower task
  has none, confirming the historical product's discard-on-timeout behavior.
  Rust now discovers the kernel child first and holds that exact cwd and file
  through cleanup. Early unlink, same-bytes replacement and late writes
  refuse; overlay retirement is accepted only after held-child death with
  unchanged bytes. ARM Clippy/static tests compile and 113 affected Mac tests
  plus Clippy pass. Fresh native verification of this correction remains open.
- 2026-10-27: observer `0bd3254f` passes 179 native worker and 38 rootfs
  tests plus subprocess. Fresh timeout `e2c701baf1474801` now binds the
  actual child and overlay readiness, but remains failed because a live
  ready-file check interrupts teardown before the normal capture result.
  Independent readback retains this partial result and 215 worker files;
  replay refuses in 516.879 ms. A regression and pidfd recheck address the
  death-between-snapshots ordering, retaining detailed failure metadata.
  The 32-test Mac rootfs suite and affected Mac/ARM Clippy/static compilation
  pass. No completed timeout SDK join, role qualification or cutover is inferred.
- 2026-10-27: cancellation `e2c701baf1474802` at `0bd3254f` passes the
  actual Root/SDK/MCP diagnostic and independent host readback, including
  held overlay readiness, scoped cancellation, child death, cleanup and
  explicitly missing SDK result/Post. All 221 worker files remain intact;
  replay refuses in 522.862 ms. No role qualification is inferred.
  Timeout `e2c701baf1474901` at `fa409a89` remains failed and independently
  retained with 227 worker files. Metadata identifies a still-lookupable
  zero-link overlay dentry after death. The next observer accepts only its
  exact held inode and unchanged bytes; a regression rejects live-child or
  inode substitution. The 33-test Mac rootfs suite and Mac/ARM Clippy/static
  compilation pass; fresh native timeout verification remains open.
- 2026-10-27: timeout `e2c701baf1475001` at `35852bd6` passes the actual
  SDK/MCP/Root diagnostic and independent host readback. The genuine 124
  capture, SDK error content/flag and Post bind correctly; held-child death,
  retained zero-link readiness bytes, cleanup and physical lower absence
  are verified. Replay refuses in 526.615 ms with 233 worker files preserved.
  Native ARM passes 179 worker/40 rootfs tests plus subprocess; the 33-test
  Mac rootfs suite and affected Clippy/builds pass. A same-source cancellation
  regression remains underway. The lifecycle checkpoint is pushed to the
  fork, with failed attempts retained and all qualification flags false.
- 2026-10-27: same-source cancellation `e2c701baf1475002` at `35852bd6`
  also passes independent SDK/MCP/Root readback. Kernel-bound readiness
  precedes cancellation; held-child death, unchanged ready inode/bytes and
  cleanup are verified without manufacturing an execution result or Post.
  Replay refuses in 533.798 ms and preserves all 239 worker files. Both
  lifecycle paths now pass bounded actual diagnostics on the same Rust
  generation. All qualification, Guard causality and outside-key admission
  flags remain false; zero model calls ran.
- 2026-10-27: implemented an explicit v7 host-pinned Native profile, sealed
  Rust-controller key consumption/signing, durable Mac pin/ack transport and
  restart readback. A separate keyed pre-controller repair retains consumed
  reservations and requires unchanged empty task custody and absent resources.
  The affected Mac run passes 405 tests with no failures or ignores; corrected
  Mac Clippy passes. ARM Clippy and static tests compile, and the Mac host CLI
  builds. Root test execution and actual host-to-VM validation remain pending. See
  [host-pinned controls](gauntlet-rust-native-host-keyed-controls.md).
  The user will handle disabled GitHub Actions separately; continue authorized
  implementation and local/VM verification without bypassing required checks.
- 2026-10-27: source `f53bc490` passes 186 native worker tests (24 existing
  ignores), 64 evidence tests and 40 rootfs tests plus subprocess. Three fresh
  v7 roles now use the real Rust Mac host pin/ack and Root controller signer:
  success `e2c701baf1475102`, input binding `5103` and injection `5104`.
  Boundary `5105` also passes its canary and path/network checks, and timeout
  `5106` passes its real 124/SDK/Post/held-overlay relation. All five
  pass independent signature/kernel/SDK/MCP/physical readback; 277 worker
  files remain intact. A lost acknowledgement at `5101` is
  conservatively repaired aborted, with restart/wrong-pin/replay proofs and
  no fabricated terminal. A passive offline Rust completion verifier passes
  actual positive and five hostile-variant cases. Historical product source and all ineligible flags
  remain explicit; parent exits stay 24/62.
- 2026-10-27: cancellation `e2c701baf1475107` also passes actual host-pinned
  execution and independent readback, preserving missing SDK result/Post.
  All six distinct outside keys and completions pass the offline Rust verifier;
  a cross-job replay refuses. There are 420 outside kernel observations and
  284 unchanged worker files. Final outside inventory confirms all owned
  controller/product/SDK/MCP resources absent. The six-role index and exact
  hashes are in [host-pinned controls](gauntlet-rust-native-host-keyed-controls.md).
  This remains historical-product diagnostics; independent Rust grading,
  current-product-source publication/conformance and parent exits stay open.
- 2026-10-27: merged upstream `ee0b44f4` as `86fce565`, retaining both
  Native APIs at the one insertion conflict. Reviewed the required-extension
  permission-only fixture correction and refreshed all 432 source pins.
  The first workspace test exposes the stale controller-tree pin; actual
  Python bootstrap and Rust independently agree on the new 401-file,
  412-entry digest `a6b9a563…a6063d`. Only the current-source pin changes;
  historical baselines and proofs stay retained. Merged validation now passes
  at `3736c099`: 501 Rust tests, warnings-denied Clippy, the matching 3.58.0
  Native build, three output and seven image-hardening tests, all five program
  checks and 453 Python regressions. Four observer cases skipped for PATH
  reasons also pass separately with retained macOS Bun; the remaining local
  bridge skip requires the pinned Linux executable and retains its separate
  eight-vector VM proof. The validator's generated docs are preserved outside
  the branch before restoring their committed bytes. Required CI remains
  user-owned and pending; parent exits remain 24/62;
  see [upstream synchronization](gauntlet-rust-upstream-sync-ee0b44f4.md).
- 2026-10-27: Rust source `b059a590` adds bounded public USTAR custody and
  independently recomputes nine Native request refusals and the synthetic
  forbidden-command capture/decision/physical relations under the prior host
  completion pin. The actual retained VM archive and identical restart pass;
  six hostile cases refuse, and all six old envelope modes remain compatible.
  The full Mac workspace passes 510 tests and warnings-denied Clippy.
  Seven semantic and two archive/path regressions pass; transient observer
  fixture contention uses the existing bounded Busy retry. See
  [artifact verifier](gauntlet-rust-native-binding-artifact-verifier.md).
  ARM source `788eeeed` also passes warnings-denied workspace Clippy and
  all nine new tests natively under Root, with both leases held and all
  284 prior worker files unchanged. The public eight-member export passes
  independent exact-ELF/source/log readback.
  Independent live process/request custody and the other role grades remain
  open, as does fresh current-source conformance. Parent exits stay 24/62.
- 2026-10-27: boundary verifier `cec21c2c` independently checks physical
  canaries, positive visibility, six path/two network errno refusals, fixture
  bytes and capture chains against the host-authenticated completion. Fifteen
  retained-artifact cases pass; input-binding output remains byte-identical.
  Mac passes 515 tests; Mac/ARM Clippy and seven native Root evidence/archive
  tests pass. Independent public-export readback verifies source/ELF/log pins,
  both held leases and all 284 unchanged worker files. See
  [boundary artifact proof](gauntlet-rust-native-boundary-artifact-verifier.md).
  Live process custody and full role qualification remain open; no parent
  exit closes. The user will handle disabled CI separately.
- 2026-10-27: exact current product/tool source `9f42d9dd` passes a fresh
  3.58.0 build (four selected and 187 complete contained tests), independently
  observed locked dependency run, every wheel/dependency byte, complete inert
  prefix and immutable source-path publication. Thirty-six refusal/lease/
  positive/replay cases pass with an optimized source-matched Rust worker.
  Independent host reconstruction verifies all 104 public export members,
  four complete trees and the exact Python requirement loop: 63 distributions,
  23 requirements, 13 active and satisfied, 10 inactive. A stale interpreter
  pin, missed first observer and read-only export refusal stay retained;
  corrected observation uses a fresh job. All 284 old worker records and
  ineligible flags remain unchanged. See [current runtime proof](gauntlet-rust-current358-runtime-proof-20261027.md).
  No parent exit closes; fresh deterministic conformance remains open.
- 2026-10-27: verifier source `65a70076` adds source-selected MCP/provider
  artifact checking for all six roles, actual SDK/Native frame joins, signed
  receipt verification and bounded read-only physical SQLite reconstruction.
  All 31 retained-archive/regression/restart/refusal cases pass, including
  mutation archives with recomputed hashes. Mac passes 529 tests; Mac/ARM
  warnings-denied Clippy and 17 focused Root ARM tests pass. Public host
  readback verifies exact source/ELF/log/metadata pins, both worker leases and
  all 284 unchanged prior records. The initial runner count mismatch remains
  retained; a fresh proof uses the actual seven-test selector. Historical
  product, independent process custody and all ineligible flags remain
  explicit. See [MCP artifact proof](gauntlet-rust-native-mcp-artifact-verifier.md).
  No parent exit closes; CI remains user-owned and pending.
- 2026-10-27: process verifier `70c0d1d9` matches 48 primary SDK/MCP process
  tuples against 420 separate kernel samples across all six historical roles.
  Fifty artifact/restart/regression/refusal cases pass, preserving four missed
  negative probes and all missing raw SDK request bytes as unverified. Explicit
  interpreter/observer readback pins do not become historical prelaunch pins.
  Future executions now retain versioned raw SDK request/response captures.
  The workspace development run passes 537 tests; final eight focused tests,
  Mac/ARM warnings-denied Clippy and ten Root ARM tests pass. Host readback
  verifies every public export member and all 284 unchanged worker records.
  See [process artifact proof](gauntlet-rust-native-process-artifact-verifier.md).
  Fresh raw-capture execution, complete Native hook/Bash/lifecycle grading,
  observer/key admission and current-source conformance remain open; no parent
  exit closes and all qualification/causality flags remain false.
- 2026-10-27: add versioned Root capture-input bindings and delivery receipts
  so future Native graders can join exact stdin digests to gated handles,
  arguments and output captures. Partial/never-started delivery, early EOF,
  changed bytes and replay cannot become complete input. Mac rootfs passes
  36 tests; Mac/ARM rootfs warnings-denied Clippy and static ARM tests compile.
  Actual native execution and the consuming Native hook/Bash/lifecycle grader
  remain pending; old absent input receipts stay unverified. See
  [input receipts](gauntlet-rust-native-capture-input-receipts.md).
  No parent exit closes; all qualification/causality flags remain false.
- Next: finish independent deterministic role scoring and outside key custody,
  then twelve fresh source-matched staging/installed roles and conformance.
  The [SDK evidence](gauntlet-rust-native-sdk-transport.md)
  records each failure and acceptance boundary. Parent exits remain 24/62;
  qualification, inference, operational cutover and final handoff stay open.

# Finish the Gauntlet Rust migration

Updated: 2026-11-06. Executor: **GPT-6.1 Sol, Max reasoning**.

## Mission and completion rule

Finish the existing implementation and deliver a reviewed migration PR ready
for `hashgraph-online/hol-guard` `main`. Rust must own orchestration, durable
state, worker supervision, independent grading and publication across local
operations, workflow benchmarks and legacy qualification. Keep OMP/Bun, MLX,
product pytest and supported historical readers as pinned external dependencies.

Use the [design](gauntlet-rust-migration.md) for contracts, the
[ownership matrix](gauntlet-rust-surface-matrix.md) for interfaces and the
[execution checklist](gauntlet-rust-execution-checklist.md) as the sole acceptance
ledger: **24/62 parent exits complete, 38 open**. Close every remaining exit
with evidence. Code volume and checked substeps do not establish completion.

## Resume from this checkpoint

- Continue `codex/gauntlet-rust-finish-20261105`, preserving preparation and the
  merge of upstream `2b811b610f0bd52e182c1e9ba3592fcc7fbfd98e`.
  [Child PR #5](https://github.com/HGraphPunks/hol-guard/pull/5) stays draft.
  Fork integration remains `f143f9ac`; PR #3 is open and upstream PR #5402
  has conflicts. Fork dispatch still returns HTTP 422, Actions disabled.
  Obtain all five current-head checks before any authorized integration merge.
- The source map has 440 files, 78 changed and 20 added against the unchanged
  baseline. After thirteen more upstream commits, actual Python selection and
  Rust agree on 409 files, 420 entries and digest `24926e43…`. The installed
  Root controller remains `e81a214c…` for retained jobs. All 658
  Mac migration tests, Mac/ARM Native library/CLI compilation, formatting and
  Mac/ARM warnings-denied Clippy pass on the merge;
  all ten changed Gauntlet files match upstream and 39 changed Python files
  parse without imports. Validation record `upstream-20261106-merge-validation-002.json`
  hashes to `888fa5de417b065f5c0eb051b4c99b432c394bb38c9b1b8977732d9fe1744b35`.
  Fresh merged-source runtime validation remains open.
  Formal security review remains incomplete because its tool excludes `ci/`.
- Fixture-corrected 3.59.0 source `8920be8bd` completes fresh build
  `9ca1b850e63fd247`: four selected checks and all 185 contained contracts pass.
  Dependency job `22b1bd1ca737f37a`, inert staging, composition and local immutable
  publication complete: 4,316 prefix entries, six aliases, 62 distributions and
  all 21 requirements, including 11 active and satisfied. Independent completion
  verifies cleanup and all 333 historical records' unchanged metadata; host
  retained-result readback matches. Independent reconstruction verifies all four
  trees, every wheel/dependency byte, six aliases and all 21 requirements;
  the new public runtime export is `a0659ab3…`. See the
  [build/runtime pins](gauntlet-rust-hostbound-candidate-build-proof.md#fixture-corrected-3590-and-primary-host-dispatch).
- Audit `462a926cee8fcfff` completes all 28 groups/52 selectors through
  `gauntlet-host features`, with frozen host `6a2d8b61…`, Root worker
  `32135d91…` and executor `5c353aee…`. Outside observation verifies actual
  executor/argv, four read-only inputs, Root/init pidfds and confinement;
  receipt SHA-256 is `fd3dc46b0b7b4fb3c7bfcf12c72985f750d507429afd4e28d4ad12cc29a2c9ee`.
  Active readback and intentional consumed-run checks refuse. Terminal readback
  and independent Rust/Python artifact recomputation agree: 1,303 passes,
  zero failures/errors and one deliberate retired-Pi skip. Status remains
  incomplete, with no eligibility. Four-lease outside checks verify cleanup and
  unchanged metadata for all 333 older records. Public export is `0ccc6f24…`.
  See the
  [live command proof](gauntlet-rust-feature-worker.md#fresh-audit-through-the-primary-host-command).
- Prior source `023e0b641`, build `97bef577d8beb254` and dependency job
  `b20e4bd21efb86e9` retain independently replayed runtime inventories. Its full
  audit `df0cc730b3b23ef5` preserves 1,300 passes, three failures and one retired
  Pi skip. Cline EPIPE reproduction and the missing Kimi import correction
  preserve all 186 assertions and pass 173 separate ARM diagnostic executions.
  Failed build `d5a9c18e3bf20764`, unknown `b937d2e04a16c85f`, earlier audit
  `6fb9d42a017c83e5` and automatic repair `c42a9e3b701fd865` remain retained.
  The [feature proof](gauntlet-rust-feature-worker.md) records their claim limits
  and sanitized review bundle; current exports are local and remote delivery
  remains open.
- Candidate recovery now retains boot/device/inode custody before launching a
  child and uses the existing host/guest diagnostic executables. Fresh job
  `ea0ef712724b4957` survives a verified supervisor SIGKILL with its original
  candidate init live. Wrong-anchor repair refuses; Rust recovery completes in
  40.274 seconds with an aborted/null-exit receipt, exact resource cleanup and
  unchanged historical metadata. The rebuilt host reopens the same repair;
  consumed build readiness refuses. Root runner is `19bc3896…`, final host
  `58853cbb…`. All 660 Mac all-feature tests, Mac/ARM warnings-denied Clippy,
  formatting and four selected ARM cases pass. Validation aggregate
  `candidate-recovery-20261107-validation-002.json` hashes to
  `c66d038edc7a30c2d183d3b624ce3d55991770ab401f5a3cca6ce6ef7b4ecb03`.
  One necessary 278-line recovery module is added; no crate, executable target
  or dependency is added. See the
  [recovery proof](gauntlet-rust-hostbound-candidate-build-proof.md#interrupted-candidate-build-recovery).
- Next finish the broader interruption matrix and all twelve staging/installed
  roles. Explicit `gauntlet-host features record/run/read/repair` reuses the
  existing journal and diagnostic caller implementation. Both entrypoints
  return versioned public recording pins, keeping the nonce private. Primary
  recording, dispatch, active refusals and completed readback are observed;
  observer admission remains open. The host command slice adds no repository
  file, crate, target or dependency.
  [Native reply checks](gauntlet-rust-native-operation-reply-bindings.md) still
  leave atomic wire bytes, request semantics and actual effect writers
  unverified. All admission/qualification/causality flags remain false and
  model use is zero. Current publication and historical successes close no
  parent exit.
- Owned VM `hol-gauntlet-rust-build-20261026-001` is running at 2 CPUs,
  16 GiB and 48 GiB. Inspect retained jobs, all leases and actual resources
  before installing or dispatching a worker. The completed audit and repaired
  candidate have no owned resources remaining. Serialize VM mutations and never
  replay a consumed ID.

## Keep the implementation small

- Extend the existing 11 crates, modules, tests and operator commands. Default
  to **no new crates, binaries, proof scripts or Markdown files**. Add a file
  only for a necessary boundary, regression fixture or maintainable split;
  justify it in the PR. Preserve the 500-line source guideline, JSON exemption
  and privilege separation.
- Reuse existing custody, framing, process, journal and validation helpers.
  Wire behavior into supported commands. Avoid duplicate implementations,
  speculative frameworks and more one-purpose diagnostic CLIs.
- Update this plan's checkpoint, the existing ownership matrix and checklist
  in place. Keep large logs, transcripts, binaries and VM exports outside Git;
  retain hashes and reviewer-accessible evidence locations.
- Work toward one complete observable exit at a time: identify its missing
  behavior and acceptance test, implement it, run positive/refusal/recovery
  checks, record evidence and commit. Each substep must enable a named next
  test. Record external blockers and continue independent work.

## Execute in this order

| Step | Existing owners and work | Required exit |
| --- | --- | --- |
| 1. Reconcile and inventory | Follow [the branch workflow](../ci/gauntlet-rs/AGENTS.md): fetch integration/main, preserve local commits, resolve the pending child cycle and merge reviewed upstream changes. Refresh the explicit source delta. Map all remaining commands, schemas, state/status contracts, assets and adapters to existing owners and acceptance tests. | Coherent baseline and complete ownership/parity inventory; preserve the immutable 420-file baseline. |
| 2. Finish build and feature execution | Connect source/archive custody, unprivileged build, inert staging and the existing feature worker through worker-state, host-state and evidence crates. Finish host repair and active-resource recovery; exercise `run/read/repair`, transport loss, restart and partial records in the owned VM. | Fresh candidate and 28-group/52-selector audit with exact pins, independently verified reports, truthful incomplete/expected-failure outcomes and observed cleanup; consumed/uncertain jobs cannot rerun. |
| 3. Close deterministic authority | Finish evidence, product-cell/rootfs, World and MCP service paths. Authenticate request/decision observations and actual effect writers. Independently grade `success`, `input-binding`, `injection`, `boundary`, `timeout`, `cancel` in staging and installed contexts. | All twelve roles meet expected outcomes and the negative/cleanup matrix passes. Fresh signed conformance binds an immutable deployment to reviewed controller, worker and product generations before eligibility. |
| 4. Complete host operations | Connect host observer/dashboard to the qualified worker. Finish `up/status/doctor/hold/resume/down/reconcile/repair`, exact-tag admission, progress, history import and public snapshots. | Real operator flow survives interruption/restart without replay or concurrent owners; unknown jobs block admission and public telemetry is truthful and contains no private fields. |
| 5. Complete real workflows | Wire campaign freeze, serial scheduling, authenticated OMP traffic, independent service oracles and provider reserve/settle/halt accounting. Run the two-cell MCP pair, twelve-cell `beta-e2e`, then contracted 800/140/160 schedules using authorized quota. | Genuine inference/tool effects, independently scored outcomes, all cells/attempts accounted for, known usage and cleanup. Missing quota or execution evidence leaves the exit open. |
| 6. Finish legacy and compatibility | Complete the 128-scenario baseline plus reviewed catalog changes, exact-call judges, Watch/approval/Native diagnostics, installed/repeat/aged-home checks and old/new readers. Preserve per-harness claim limits and CLI statuses. | Python/Rust accept/refuse and reason-class parity plus fresh required legacy/installed runs; trusted-base verification and publication remain isolated from candidate execution. |
| 7. Prove rollout and prepare main | Build reviewed immutable host/worker generations. Compare Python/Rust verdicts, failure classes and resource use on retained data. Exercise idle-only cutover/rollback, then retire superseded orchestration after parity. | No lost receipt, replay, duplicated charge or concurrent owner; all 62 exits evidenced and merge gates below met. |

Finish steps 2–3 as the first complete delivery path before widening the
runtime surface. Continue compatibility work with each boundary; execution
admission follows the proved dependency order.

## Security and evidence invariants

- Treat candidate code, reports and paths as untrusted. Build/run candidates
  only under the existing unprivileged VM/container identities. Obtain trust
  anchors outside the candidate and separate trusted Gauntlet/product builds.
  Never import a candidate as Root or execute it on the host.
- Preserve namespace, UID, AppArmor, seccomp, network and cgroup limits; verify
  owned process identity and descendant death before claiming cleanup. Preserve
  [approval choices and reuse](guard/approval-invariant.md).
- Use bounded canonical parsers, descriptor-based custody, exclusive durable
  journals and one-use IDs. Test link/swap races, partial writes, stale PID reuse,
  replay, cancellation, timeout and surviving descendants. Unknown work stays
  unknown until reconciled; missing data cannot become a pass or a safe retry.
- Bind actual requests, Guard decisions and independently observed effects.
  Producer signatures and copied buffers alone cannot prove causality. Keep
  model refusal, service/VM enforcement, unprotected attack measurements,
  Guard intervention and task utility distinct. Preserve all failed evidence.
- Charge every provider attempt to the retained allowance; unsettled usage
  halts admission. This plan grants no additional quota. Retain historical
  schemas and hashes; version incompatible changes explicitly.

## Validation, cleanup and merge gates

Run relevant Python differential/regression and Rust positive/refusal/recovery
tests per slice. Before final readiness use the pinned toolchain (currently 1.88.0):

```sh
cargo +1.88.0 fmt --manifest-path ci/gauntlet-rs/Cargo.toml --all --check
cargo +1.88.0 test --manifest-path ci/gauntlet-rs/Cargo.toml --workspace --all-targets --all-features --locked
cargo +1.88.0 clippy --manifest-path ci/gauntlet-rs/Cargo.toml --workspace --all-targets --all-features --locked -- -D warnings
```

Execute macOS and Linux ARM64 tests, including explicit Root/VM cases, matching
Native compilation and affected product checks. Obtain independent security
review of privileged boundaries, recovery and qualification. Repeat passing
gates only for changed inputs, failures or required final checks; never weaken
tests to obtain green results.

Record source/binary/config pins, command, result, claim limits and artifact
hashes/location per slice. Reviewers must be able to retrieve sanitized evidence;
local-only paths and historical successes cannot qualify a new generation.

Before handing off for `main`:

1. Remove superseded diagnostics/duplicates and unused dependencies after
   checking callers and replacement coverage. Preserve versioned readers and
   fixtures; avoid unrelated refactors. Update existing operator/compatibility
   docs and inspect the staged diff for artifacts, credentials and unrelated work.
2. Follow the fork child PR cycle with all five current-head jobs:
   `contracts`, `macos-host`, `arm64-binaries`, `native-integration`,
   `macos-native-judge`, plus required repository checks. Obtain results from
   the CI owner where necessary; unavailable CI remains a merge blocker.
3. Fetch upstream again, resolve conflicts, and rerun affected/final checks
   against the actual proposed merge. Address review findings, verify all
   parents in the checklist, and update PR #5402's description with behavior,
   compatibility, evidence and rollout/rollback instructions. Keep it draft
   while required validation or independent review is missing.
4. Commit and push the intended branch; require an empty `git status --porcelain`
   and confirm remote HEAD matches. Report final SHA, checks, evidence and any
   remaining external gate. Follow the existing authorization boundary for
   upstream merge; release publication and PR-gate activation remain separate.

Prior detailed execution notes remain in Git at
`95b25964ec8d0e8a2576988a35db121d1ca5f02a:docs/gauntlet-rust-pr-readiness-plan.md`.
Existing proof documents and immutable artifacts remain the evidence record.

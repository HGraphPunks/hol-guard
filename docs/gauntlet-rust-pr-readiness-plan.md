# Finish the Gauntlet Rust migration

Updated: 2026-11-08 UTC. Executor: **GPT-6.1 Sol, Max reasoning**.

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

- Continue `codex/gauntlet-rust-finish-20261105`. Completion retirement is
  committed at `792a64ab5`; current main `84ba6e4da` merges cleanly as
  `ddc21cd6c`, preserving all six incoming files. [Child PR #5](https://github.com/HGraphPunks/hol-guard/pull/5)
  remains draft against integration `f143f9ac`. Obtain all five current-head
  jobs before its merge. Actions was disabled at the preceding checkpoint.
  No override or settings change is authorized; upstream main merge and release
  publication remain separate.
- Missing/exact-prefix preparation and partial completion now have explicit
  snapshot-bound retirement. Original files remain intact; completion retirement
  fsyncs them and requires absent resources without adoption or signals. It
  retains `aborted` with unknown exit and no eligibility. Full-report/absent-
  terminal finalization remains supported. See [completion retirement](gauntlet-rust-hostbound-candidate-build-proof.md#interrupted-dependency-completion-retirement)
  and the preceding preparation proof. Two necessary modules are added within
  existing crates, with no crate, binary, dependency, proof script or document.
- Worker `d71ca8b2…`, host `fde7281c…` and compatibility host `ea4024ac…`
  bind source `792a64ab5`. All 682 Mac workspace tests, formatting,
  warnings-denied Mac/ARM Clippy, final builds and nine selected ARM tests pass.
  Matching Native library/CLI/test targets compile on Mac/ARM; all 682 tests
  pass again at merged head `ddc21cd6c`.
  Validation `bfa7c278…` binds 145 records; source manifest is `aa198898…`.
- Live `6147ab2733bb774d` preserves a 64-byte report and retires in
  7.022 seconds. `f44a167f33be73b5` preserves a full report and 32-byte
  terminal and retires in 12.598 seconds. Twenty restart/refusal and seven
  historical-reader cases pass; direct Root reuse refuses. Normal
  `84267ae7556a6101` exits zero in 65.823 seconds and matches all 2,290
  files/51,318,588 bytes. Failed prelaunch `de145dd6f485a69f` has no
  intent/dispatch/runtime reservation or resource; its inert slot and failure
  remain. **Never replay any of these four IDs.** Export/setup failures remain.
- Bundle `1e58a24a…` has 177 members/18,503,680 bytes and excludes all
  thirty actual nonces, including decoded ZIPs. Remote delivery, independent
  review and five required cloud jobs remain open. The immutable 420-file
  baseline, 440-file map (79 changed/20 added) and controller plan `52da7281…`
  are unchanged. Live product evidence remains at `53c64ae96`; newer main
  is not execution-qualified.
- Next finish the fresh candidate and 28-group/52-selector audit at the required
  generations, then the twelve staging/installed roles with independent
  request/decision/effect authority. Keep unprovable custody gaps unknown.
  Preserve old unknown `b937d2e04a16c85f` and the unexplained first active
  refusal. Copied Native replies do not prove atomic wire bytes, concurrent
  memory, semantics or actual effect writers. Real workflows, legacy parity,
  reviewed cutover/rollback and admission remain open. **24/62** parent exits;
  model requests/tokens are zero. This goal grants no quota.
- The owned ARM VM is idle at 2 CPUs/16 GiB/48 GiB. Final four-lease snapshots
  match earlier recovery/control snapshots exactly and verify resource absence
  plus unchanged metadata for 333 historical records and their lock. Inspect
  exact pins, leases and resources before every operation; serialize VM changes
  and never read historical worker bytes or keys. Earlier checkpoints remain
  in Git and the existing proof documents.

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

# Finish the Gauntlet Rust migration

Updated: 2026-11-07. Executor: **GPT-6.1 Sol, Max reasoning**.

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

- Continue `codex/gauntlet-rust-finish-20261105`. Upstream
  `e43ca02cfb5178ad4276d9ffd4e8f9d4a575f1ab` is merged as `efa6f05e3`.
  The dependency implementation remains `cfdbf6a9f`; live product evidence
  retains exact source `53c64ae96`. [Child PR #5](https://github.com/HGraphPunks/hol-guard/pull/5)
  stays draft. Integration remains `f143f9ac`; PR #3 is open and upstream
  PR #5402 has conflicts. Fork Actions dispatch returns HTTP 422. Obtain all
  five current-head jobs before any authorized integration merge.
- The four-commit upstream followup preserves all 14 incoming files exactly
  and parses 12 Python files without imports. All 297 existing scenarios are
  unchanged; two Git Allow cases are added. The 440-file map and immutable
  420-file baseline agree. Python/Rust derive controller `39bde055…`, 409 files
  and 420 entries; this generation is not installed. All 672 Mac tests,
  formatting, Mac/ARM Clippy and Native library/CLI compilation pass; Guard
  command tests compile on Mac. The stale controller-pin failure is retained.
  Validation `a77e2a86…` verifies eleven records and eight logs. See the
  [upstream followup](gauntlet-rust-hostbound-candidate-build-proof.md#upstream-followup-after-dependency-recovery).
- The dependency reconciliation slice has **672 Mac all-feature tests**,
  formatting and warnings-denied Mac/ARM Clippy passing. Primary
  `gauntlet-host dependencies run/read` shares the existing diagnostic handler.
  Its fixed Root reader verifies the original intent, terminal, cleanup and
  captured ZIP under four leases, without scanning unrelated worker records or
  starting a workload. Source manifest is `34a6a356…`, live validation
  `3adedd4a…` verifies 29 records. Separately installed Root reader `96215aa2…`
  reconciles both retained generations through both host commands. Fresh
  job `f02a618c39de745b` recovers after actual host SIGKILL, with no local
  result or relaunch; repeat reads and consumed-run refusal pass. Independent
  ZIP decoding and four-lease cleanup pass, receipt `04b9cf39…`. See the
  [readback proof](gauntlet-rust-hostbound-candidate-build-proof.md#dependency-reconciliation-without-relaunch).
- The preceding live-proved slice has **669 Mac all-feature tests**, formatting and warnings-denied Mac/ARM
  Clippy pass. Merged Native library/CLI compilation also passes. The source
  map has 440 files, 79 changed and 20 added against the immutable 420-file
  baseline. Independent Python/Rust agree on the separately installed
  409-file/420-entry controller `123024f4…`; old `e81a214c…` is preserved.
- Primary `gauntlet-host build source/run/read/repair` and
  `features record/run/read/repair` share existing handlers. Candidate and
  dependency dispatch are durably consumed before transport; concurrent calls,
  uncertainty and restart cannot repeat them. Historical dependency intents
  without a fresh authorization stay read-only. Canonical dependency replies
  remain private at 0600; public stdout is typed and excludes the intent/nonce.
  This last implementation chunk changes six existing files, all within 500
  lines, and adds no repository file, crate, target or dependency.
- Product build `b7f0b85b31df49cc` at exact source `53c64ae96`, archive
  `c5c88fe8…`, passes four selected checks and 185 contained contracts.
  Dependency job `f7a1bf6e9d3482c0` and immutable local publication complete.
  Independent reconstruction verifies four trees, 4,327 prefix entries, six
  aliases, 62 distributions and all 21 requirements (11 active and satisfied).
  Runtime export is `831a469f…`. See the
  [build/runtime proof](gauntlet-rust-hostbound-candidate-build-proof.md#primary-host-build-command-and-merged-source-follow-up).
- Audit `a38df7e1b26c4905` completes all 28 groups/52 selectors with
  **1,303 passes, zero failures/errors and one deliberate retired-Pi skip**.
  Status stays incomplete. Independent Python/JUnit and Rust recomputation,
  primary readback, consumed-run refusal and cleanup agree. Worker
  `32135d91…` and executor `5c353aee…` are unchanged; public export is
  `d5485322…`. The upgraded primary host reopens the same result unchanged.
- Fresh dependency job `ce76a18b95d042ef` verifies host `00a37dd2…` from
  `58ee4c3f2`: actual kernel confinement, the new public/private response,
  cleanup, consumed-run refusal and all 2,290 exported file bytes pass.
  Validation `host-dispatch-20261107-validation-002.json` verifies 23 records,
  SHA-256 `cfde5d70adb296e534504aa55c8863e1ffcf1aabf1fbcd58f11ac3aec224d9cd`.
  Earlier supervisor-SIGKILL job `ea0ef712724b4957` retains its observed
  40.274-second Rust recovery and aborted/null-exit receipt. See the
  [dispatch/recovery proof](gauntlet-rust-hostbound-candidate-build-proof.md#durable-host-dispatch-and-private-dependency-results).
- Current review bundle `gauntlet-rust-review-evidence-20261107-005.tar`
  contains 90 public files, 84,275,200 bytes, SHA-256 `9e18b11d…`.
  Runtime, requirement and audit replayers reproduce the retained JSON exactly;
  six actual private nonces are excluded. It includes the actual host-loss
  recovery and retained readback. Remote delivery and independent
  review remain open. The formal security scan excludes `ci/` and is incomplete.
  Full pins, earlier bundles and failed attempts remain in the
  [feature proof](gauntlet-rust-feature-worker.md#review-bundle-for-the-merged-source).
  A separate 23-member, 317,440-byte upstream addendum (`3ec2903a…`) binds the
  newer map, independent controller plan and compile/test checks without
  relabelling the retained live product proof.
- Next finish broader interruption coverage and all twelve staging/installed
  roles, then independent request/decision/effect authority and conformance.
  Native copied replies still do not prove atomic wire bytes, request semantics
  or actual effect writers. Observer admission, real workflows, legacy parity
  and rollout remain open. Every admission/qualification/causality flag stays
  false; model use is zero. Unknown `b937d2e04a16c85f` stays unknown.
- Owned VM `hol-gauntlet-rust-build-20261026-001` is idle at 2 CPUs,
  16 GiB and 48 GiB. Completed jobs have no owned resources remaining; all
  333 historical records' metadata and their lock are unchanged. Inspect exact
  pins, leases and resources before the next operation; serialize mutations
  and never replay a consumed ID.

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

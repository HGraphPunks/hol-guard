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

- Private diagnostics at `b64ae753b` pass three ARM boundary/secure-file cases
  as UID/GID 65532. Fresh jobs `d16ae4c3b72509f8` and `e72bc0934fa81d56`
  verify actual supervisor loss, active wrong-pin noninterference and first-call
  repair success in 3.756/5.372 seconds, plus cleanup and restart reads. The old
  first-call error is not reproduced and remains unexplained. Final source
  manifest `2129982f…` adds an explicit Root-only private-writer fixture in the
  same 490-line module. All 675 Mac tests, formatting, Mac/ARM Clippy and builds
  pass (`e5d4389f…`). Freeze the final tools, execute the Root test and verify
  retained reads; no repository file, crate, target or dependency is added.
- Continue `codex/gauntlet-rust-finish-20261105`. Dependency recovery is
  implemented at `54cda0b80`; upstream `e43ca02cf` is merged as `efa6f05e3`.
  [Child PR #5](https://github.com/HGraphPunks/hol-guard/pull/5) stays draft.
  Integration remains `f143f9ac`; PR #3 is open and upstream PR #5402 has
  conflicts. Fork Actions is disabled; the last dispatch returned HTTP 422.
  Require all five current-head jobs before any integration merge.
- All **675 Mac all-feature tests**, formatting, warnings-denied Mac/ARM Clippy
  and executable builds pass. Frozen worker `c7b09e2d…`, primary host
  `6937e43b…` and compatibility host `690520de…` bind implementation
  `54cda0b80`. The new worker is installed separately; older generations stay
  intact. One necessary shared contract module is added, with no new crate,
  executable target or dependency. Local validation is `fbda5f9c…`.
- Dependency jobs `a6840d15c928fe37` and `c95ad2e6018bf743` verify actual
  supervisor pidfd SIGKILL and the surviving unprivileged exporter. Typed
  unknown reads authorize no cleanup; wrong reservation pins leave authorization
  absent. The second job verifies its container remains active after refusal.
  Its first repair fails; a Rust retry with the same authorization succeeds.
  Aborted/null exits, original unknown attempts and consumed dispatch remain
  intact. Restart/repeat reads and different-pin/consumed refusals pass.
  **Diagnose that first repair failure next**; its Root error detail was not
  retained by the bounded host error. The first job's delayed active check
  also remains a failure. No manual resource cleanup or workload replay occurs.
- Normal control `b8c32a6f519d470e` exits zero in 76.099 seconds. Independent
  decoding verifies all 2,290 dependency files, 51,318,588 decoded bytes and
  entry digest `b01fe0d3…`. Completed-job repair refuses before authorization.
  Both older completed generations remain readable through both commands.
  All three fresh jobs have independent four-lease cleanup and unchanged
  metadata for 333 historical records plus their lock. Live validation
  `af4f2bce…` binds 62 records. See the [dependency recovery proof](gauntlet-rust-hostbound-candidate-build-proof.md#dependency-supervisor-recovery).
- Live product evidence retains exact source `53c64ae96`, controller
  `123024f4…`, source archive `c5c88fe8…` and build `b7f0b85b31df49cc`:
  four selected checks and 185 contained contracts pass. Runtime reconstruction
  verifies four inventories, 4,327 entries, six aliases, 62 distributions and
  all 21 requirements. Audit `a38df7e1b26c4905` has 1,303 passes, no failures
  or errors and one deliberate retired-Pi skip across 28 groups/52 selectors;
  status stays incomplete. Candidate `ea0ef712724b4957` and feature
  `ed40a9c721e3685b` retain their proved supervisor-loss recovery.
- The upstream followup preserves all fourteen incoming files exactly and the
  immutable 420-file baseline. The 440-file map has 79 changed and 20 added
  files. Python/Rust agree on uninstalled controller plan `39bde055…`,
  409 files/420 entries. Native library/CLI compilation passes on Mac/ARM;
  Guard command tests compile on Mac without product execution. Validation
  `a77e2a86…` binds those checks; older live evidence is not relabelled.
- Public evidence stays outside Git. Main bundle `9e18b11d…` has 90 members;
  upstream and feature-recovery addenda are `3ec2903a…` and `49aa292a…`.
  The dependency-recovery addendum `5af77dcb…` has 86 members/17,121,280 bytes,
  reverified with ten actual private nonces excluded, including decoded ZIP
  contents. All failures and older bundles remain immutable. Remote delivery
  and independent review remain open; the formal scan excludes CI and is
  incomplete. Full pins are in the existing proof documents.
- After diagnosing active repair, cover pre-CID/partial records, then finish
  all twelve staging/installed roles and independent request/decision/effect
  authority. Native copied replies do not prove atomic wire bytes, request
  semantics or actual effect writers. Admission, real model workflows, legacy
  parity and rollout stay open. All authority flags are false; product model
  requests/tokens are zero. Unknown `b937d2e04a16c85f` remains unknown.
- The owned ARM VM is idle at 2 CPUs/16 GiB/48 GiB. Inspect exact pins, leases
  and resources before each operation, serialize mutations and never replay a
  consumed job. Never read the historical records' private bytes or keys.

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

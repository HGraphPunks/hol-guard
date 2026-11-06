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

- Execute on `codex/gauntlet-rust-finish-20261105`. Merge `1acc28a7a` preserves
  preparation through `6ddf29cb0` and imports upstream `b2da1b2b`. The branch
  now also imports `48d012fd7e846bd8a39d277a1c35a30fc239a813` without conflicts;
  never reset accumulated work to the older integration tip.
- Implementation `22d29e6e` adds host repair and exact kernel-resource recovery.
  That implementation passes 653 Mac tests and 12 explicit Linux ARM feature/recovery cases;
  the complete live flow and supervisor-crash repair are now observed below.
  [Child PR #5](https://github.com/HGraphPunks/hol-guard/pull/5)
  carries this work and stays draft pending all five checks and review.
- The accepted-socket HTTP path now shares one monotone request/response budget.
  Its pre-fix regression fails; all 656 Mac workspace tests and seven explicit
  ARM dashboard cases pass after the change. The formal security scan retains
  a candidate-registration gap because the tool excludes `ci/`; it is incomplete.
- Fork integration `codex/gauntlet-rust-integration-20261020` is at `f143f9ac`;
  PR #3 is open. Upstream PR #5402 is draft with conflicts. Main was fetched at
  `48d012fd7e846bd8a39d277a1c35a30fc239a813`. The current source map has 440
  files, 78 changed and 20 added against the unchanged baseline. Actual Python
  bootstrap selection and Rust agree on 409 files and 420 controller entries,
  digest `e81a214c9771095da22f2897aa5c25600d2016f416cd6562d4fd5511f6321e9a`.
  All 656 Mac Rust tests, 226 focused Python tests and seven subtests pass,
  along with formatting, Mac/ARM warnings-denied migration Clippy and Native
  library/CLI checks. The Git-source reader now
  validates its count against the embedded delta instead of a second constant.
  This controller is installed at a fresh path; retained VM trees stay intact.
- The [feature worker](gauntlet-rust-feature-worker.md) has a host `run/read/repair`
  path. Its first complete live attempt remains invalid because XML mode
  publication failed; its interrupted attempt reached an aborted receipt only
  after operator assistance for runtime signal denials. Private XML publication
  and the receive-only `crun` rule pass focused ARM tests and a real stop probe.
  The new controller digest is `409fe095fe10627e4c2ab7a14fe73e9d1b6177bbc3471364ca430cf4ddfb35f0`;
  all 656 Mac tests pass. Fresh audit `6fb9d42a017c83e5` now completes all
  28 groups with 1,286 passing tests, two Cline failures and one skip. Root
  independently verifies its artifacts and retains failed/incomplete outcomes.
  Supervisor-crash audit `c42a9e3b701fd865` recovers through the pinned Rust
  repair command, with outside cleanup, restart readback and consumed-run
  refusal verified. All 333 older records' metadata remains unchanged. Both
  attempts use the retained 3.58.0 candidate and stay ineligible. Current-source
  qualification, the broader interruption matrix and operator wiring remain open.
  Exact 3.59.0 source `83f079b5c4a45cc7aa01849189ad80e0c674386a` has a
  separately installed 409-file controller. Candidate `b937d2e04a16c85f` remains
  consumed/unknown after its supervisor/client disappear while the container
  survives. The [build proof](gauntlet-rust-hostbound-candidate-build-proof.md#current-3590-timeout-and-container-cleanup)
  retains the failure, observed confinement and operator-only profile cleanup.
  Rust now binds the full container ID before start and drains it on timeout;
  a bounded two-hour candidate budget covers current release LTO. The actual
  Root timeout/foreign-binding probe, all 656 Mac tests and Mac/ARM Clippy pass.
  Dependency job `5ea8b3c2907df614` completes; Rust and independent host readback
  agree on all 2,290 files and the 2,633-entry inert prefix. The corrected Root
  timeout probe captures and verifies the actual client cgroup; earlier receipts
  remain retained. Candidate `d5a9c18e3bf20764` completes under the fixed
  `8bb6d1b5f` supervisor: four selected checks and 183 contracts pass, while
  two contracts fail on one stale import of a removed Python runtime module.
  Commit `023e0b641` switches that test to the existing Native facts bridge
  and preserves its assertions; Ruff and syntax checks pass. Outside completion
  proves actual client/container/conmon cgroup and profile absence, original
  process death and unchanged metadata for all 333 older records. The failed
  wheel is captured and verified inertly; result readback refuses it.
  Fresh job `97bef577d8beb254` is running from corrected source `023e0b641`.
  Its independently observed source, read-only mount, Root/entrypoint pidfds,
  retained CID and confinement match. External receipt
  `native-current359-build-host-state-20261106-003/outside-kernel-001.json`
  hashes to `23d4cfdea7a061b4dae38c5b28e07cc55cb87db60b24bbab19cc57cc5ffc5f16`.
  Do not replay either consumed ID. Full build, a dependency prefix bound to
  the corrected source, inert publication and qualification remain open.
  [Native reply checks](gauntlet-rust-native-operation-reply-bindings.md) still
  leave wire authenticity, request semantics and physical effect attribution
  unverified. Existing product `dc3b9336` evidence is historical.
- Git transport works. Owned VM
  `hol-gauntlet-rust-build-20261026-001` is running (2 CPUs, 16 GiB, 48 GiB).
  Inspect retained jobs, leases and resources before worker installation or
  dispatch. On November 6, fork workflow dispatch still returns HTTP 422,
  `Actions has been disabled for this repository`. All five checks remain a
  merge blocker; continue independent implementation and owned-VM validation.

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

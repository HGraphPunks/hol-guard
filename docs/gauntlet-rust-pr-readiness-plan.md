# Finish the Gauntlet Rust migration

Updated: 2026-11-10 UTC. Executor: **GPT-6.1 Sol, Max reasoning**.

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

- Continue `codex/gauntlet-rust-finish-20261105` and draft
  [child PR #5](https://github.com/HGraphPunks/hol-guard/pull/5), based on
  integration `f143f9ac`. Published merge `0463695b4` includes upstream
  `4a0b5ab5a`. Catalog commit `5306c65cc` is preserved; the next merge
  incorporates upstream `d586334a9` with all seven incoming files exact.
- The fixed legacy inventory now covers 308 core, 16 approval-retry,
  11 connector-setup and 15 full-task rows in the existing JSON files.
  Reader `352fe6d5…` preserves all eleven fields/defaults and listing order.
  All 727 merged workspace tests, four focused tests, formatting and Mac/ARM
  Clippy pass. Merged Native library/CLI/tests compile with `--no-run` on
  Mac/ARM in 497.85/354.087 seconds. Validation `catalog-merged-validation-001.json`
  (`439fa574…`) binds seven checks and 7,161 unchanged source/asset inputs.
  One Rust module is added; no crate, binary, dependency or proof script.
  Historical 128-case parity, candidate-catalog admission, execution and judging
  remain open. The [matrix](gauntlet-rust-surface-matrix.md) records source
  inventory, all 29 public job keys and the known CLI exit semantics.
- Rust/MSRV/workflow/current builder use **1.89.0**. Existing SQLite pins are
  rusqlite 0.41.1/libsqlite3-sys 0.39.1; the package set remains 190.
  The immutable baseline has 420 files; the current Python map has 440,
  87 changed and 20 added. Independent controller selection matches
  `20650edd…` (409 files/420 entries). The catalog slice changes no Python,
  baseline fixture, lockfile, workflow, private key or installed VM state.
- At `0463695b4`, 723 Rust tests, 175 focused Python tests, formatting,
  Mac/ARM Clippy and Native library/CLI/test compilation on Mac/ARM pass.
  Native compilation uses `--no-run`; product code never executes on Host/Root.
  Evidence is retained under `budget-limits-20261110-001`; validation
  `merged-validation-002.json` hashes to `cc29285d…`.
- Actions permissions report enabled, but exact-head dispatch returns HTTP 422,
  "Actions has been disabled" at published merge `0463695b4`; no run is created.
  All five current-head jobs,
  independent review and reviewer-retrievable delivery remain required.
  No settings change or check override is authorized.
- Latest signed read-only Native job `015` (`4e4819769a5ab5c0`) uses older
  product `e0145e09b`, Native `2476dd16…` and worker `8201c839…`. Its
  162 pipe exchanges and five hook joins remain `invalid-evidence`: eight
  outer clients have checked floors, seventy other exec images are ungraded.
  Read the [captured relations](gauntlet-rust-native-copied-hook-relations.md)
  and [checklist](gauntlet-rust-execution-checklist.md) before further admission.
  Never replay consumed/failed/unknown jobs, including pipe `001`–`015` or
  failed prelaunch `013`/`014`. Historical success cannot qualify a new source.
- **Next delivery path:** reviewed source/preparation/observer/key admission,
  actual writer attribution, all twelve staging/installed roles and signed
  conformance, then qualified host operations and genuine workflows.
  Preserve all 333 historical worker records/334 metadata rows; custom
  inspection uses lstat metadata only. Root mutations require all four existing
  leases and original custody pins. Keep private captures/keys/nonces private.
  Writable-export storage/inode limits remain unresolved. Security scan
  `24cd36df…` failed on its CI-excluding inventory; it is not a clean report.
  This goal grants no model quota reset or additional allowance.

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
tests per slice. Before final readiness use the pinned toolchain (currently 1.89.0):

```sh
cargo +1.89.0 fmt --manifest-path ci/gauntlet-rs/Cargo.toml --all --check
cargo +1.89.0 test --manifest-path ci/gauntlet-rs/Cargo.toml --workspace --all-targets --all-features --locked
cargo +1.89.0 clippy --manifest-path ci/gauntlet-rs/Cargo.toml --workspace --all-targets --all-features --locked -- -D warnings
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

Detailed checkpoint history remains in Git at
`0463695b4a1e10a978624e3d0dc6af97b8f6868e:docs/gauntlet-rust-pr-readiness-plan.md`.
Prior execution notes also remain at
`95b25964ec8d0e8a2576988a35db121d1ca5f02a:docs/gauntlet-rust-pr-readiness-plan.md`.
Existing proof documents and immutable artifacts remain the evidence record.

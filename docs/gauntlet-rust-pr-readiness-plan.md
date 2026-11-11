# Finish the Gauntlet Rust migration

Updated: 2026-11-11 UTC. Executor: **GPT-6.1 Sol, Max reasoning**.

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

- Keep the original deadline: **2026-11-11 23:14 UTC**. Continue
  `codex/gauntlet-rust-finish-20261105` and draft
  [child PR #5](https://github.com/HGraphPunks/hol-guard/pull/5), targeting
  integration `f143f9ac`. Merge `168e9b33f` incorporates upstream
  `62fe5d5734b77d405195f9e3711a1e755088b3cf`; it preserves batches
  `055652542`, `5928a4596`, `1f60818cc` and `0ef1a0e59`.
  Verify the current local and remote heads before acting.
  Acceptance remains **24/62 parent exits complete, 38 open**.
- The current stable Gauntlet source passes **933 full macOS tests**, zero
  failures/skips, formatting and full warnings-denied macOS/ARM Clippy. The
  merged Native library/CLI/tests compile with `--no-run` on macOS and ARM. Final ARM
  Gauntlet checks and their exact source snapshots are recorded in the
  [proof index](gauntlet-rust-pr-readiness-proof-20261026.md).
  Compilation and test counts grant no runtime qualification.
- Current Python reproduces **360 historical current-generation results**.
  A separate small fixture supplies 27 eval/launchctl vectors; the original
  goldens and frozen suite of 128 cases remain unchanged. The new eval oracle
  requires the exact JS `sh` copy, a protection-class block, zero approvals and absent copy.
  Review/reapproval cannot count as protection. Current catalog: 310 Core,
  352 total. Source SDK 18.18.6 is separate from actual SDK 18.4.12.
- The source map is **441 files/93 changed/21 added**, against the unchanged
  420-file baseline. Independent actual Python bootstrap selection and Rust
  agree on 410 installed files, 11 directories, 421 entries and planned digest
  `eedaa25b8a3ea7eb642159a2e64d71ed47222c624e882a8e318aa478c618faf2`.
  The inert fixture archive matches every independent row; no new controller
  installation or final-source admission is claimed.
- Rust owns the supported source/build/dependency/staging/publication,
  Native run/read/report/export/retirement and recovery command paths.
  Earlier normal commands built and published `bb69ca40` using historical
  v1 storage; those results remain ineligible. Its latest normal bounded
  Native control failed during pipe forwarding and remains invalid evidence.
  Preserve both original build/dependency volumes while runtime verification
  needs them. No complete final-source role has passed.
- Finite Root-created tmpfs binds replace unsupported Podman 4.9.3 inode options.
  Frozen Worker `ab5f0230…` passes SDK-byte/MCP-inode ENOSPC, exact inside/outside
  mounts, teardown while full and restarted ext4 abort, with independent
  cleanup and 345 unchanged historical Worker rows. This earlier component
  proof does not qualify the newer lifecycle generation.
- The newer owner-loss/runtime fixture **failed**. Job `ceb3663cc45c4c45`
  retains an unverified 2-GiB backing, empty original owner cgroup and stale
  socket; no runtime, profile, mount or loop attachment remains observed.
  The original namespace owner is lost and pinned abort refuses missing
  authority. Fresh volume admission stays blocked. A fixture-only correction
  now checks the declared named-unconfined profile's presence; production
  enforcement checks are unchanged. No fresh physical rerun is credited.
  Resolve original authority and cleanup without deletion, adoption or replay.
- Sealed startup uses exact Root0444 config/no-op inputs, held read-only
  descriptors, startup.v2 and helpers.v3. Actual pinned Bun 1.3.14/SDK 18.4.12
  passes three hostile Settings configurations and a genuine fixed Bash call.
  A separate cold FIFO/LSM experiment also passes bounded output/memory-open
  checks. Neither proves the normal Rust peer, Native/model socket custody,
  per-call results, all inherited descriptors, descendants or cancellation.
  Production SDK output custody remains an implementation and proof gap.
- Next functional work must address that normal SDK boundary and a successful
  bounded control. The prior control's 9-second Native startup cancellation is
  consistent with repeated executable hashing and durable journal overhead;
  this is an evidence-backed inference, not per-event latency proof. Measure
  before optimizing. Preserve image identity checks, mutable-image regressions,
  approval behavior and existing timeouts.
- Observer `attach-job`/`refresh-job` links remain passive. Provider grading
  exhausts actual current-job turns and binds outside usage/quota snapshots.
  Missing review, execution or cleanup remains incomplete. Both unregistered
  legacy execution drafts are preserved privately outside the worktree and
  supply no execution credit. This compatibility batch adds one necessary
  reference JSON; it adds no runtime module, crate, binary or dependency.
- External gates remain open: Actions rejected dispatch with HTTP 422,
  “Actions has been disabled”; all five final-head jobs and independent
  repository approval remain required. Original model authorization does not
  cover current source. Last verified retained quota was 721,979 tokens,
  below the 1,600,000-token pair/beta reservation. Additional VM/capacity
  admission remains pending; host free space was separately observed at 89 GiB.
  No new Gauntlet model request, quota reset or allowance expansion is claimed.
- Preserve all historical evidence and failed attempts under the private
  `expedited-20261110-001` evidence directory. Custom historical Worker readers
  remain lstat-only. Deployment/independent checks hold all four leases; APIs
  acquire their own Worker/Python leases. The prior CI-excluding security scan
  is not a clean report. Internal source review does not replace repository
  approval. Toolchain/MSRV is 1.89.0. No upstream-main merge, release, protection
  change or active benchmark gate is authorized.

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

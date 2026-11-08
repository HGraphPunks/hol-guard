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

- Continue `codex/gauntlet-rust-finish-20261105` and draft [child PR #5](https://github.com/HGraphPunks/hol-guard/pull/5),
  based on integration `f143f9ac`. Upstream `311d63cb2` merges cleanly as
  `99c233ad4`, preserving thirteen incoming files. Diagnostic commit
  `6a764d42b0a566697c75c9a7ce768bfede92a555` preserves Native's generic
  failure line and exit 126, then prints its existing fixed boundary error.
  It adds no execution path, file, crate, target or dependency. All **703 Mac
  tests**, Gauntlet formatting, Mac/ARM Clippy and Native target compilation
  pass; validation `e1f3d824…` binds eighteen files.
- **Build `ed8f9da0b49ebde2` is active.** Resume managed exec session
  **33136**, launched by Host PID 49093, before starting any new VM work.
  The exact source is `6a764d42b…`; its 63,345,255-byte archive hashes to
  `2131170e3d9cc6d402072ab7cb3481d2d84cf0f67b9e6d6a95645e19220a37dd`.
  The primary Rust source/transfer commands verify Git history and deliver
  the exact archive. Preserve the consumed dispatch; an observation timeout
  is not permission to restart. Evidence is in the existing external
  `native-boundary-build-host-state-20261108-001` directory.
- The first build request refused before any Host pin, dispatch or candidate
  execution because it carried the earlier job's rendered AppArmor hash.
  Immutable refusal/readback records prove the unused state. The new job's
  policy hash is independently derived as `c5163109…`; existing Rust commands
  materialize the context, prove policy load/removal and pass readiness.
  Attempt 002 is the first actual builder execution. Preparation validation
  `92bca3a2…` binds seventeen records. All initial setup and observer failures
  remain retained.
- The separately installed controller at
  `/opt/hol-gauntlet/controller-6a764d42b0a56669` has 409 files/420 entries,
  independently matching tree `f2581135…`. The source map still has 440 files,
  79 changed/20 added against the immutable 420-file baseline. Kernel readback
  measures the builder as UID/GID 65532, empty capabilities, no-new-privileges,
  seccomp, isolated namespaces and a read-only source mount, with 12 GiB,
  two CPUs and 512 PIDs. Its actual stacked label retains the requested job
  profile in enforce mode. All 334 historical metadata rows are unchanged;
  custom wrappers read none of those worker records' bytes or keys.
- **Next:** obtain the active build's terminal result through the existing
  host-bound reader and independently verify artifacts and cleanup. Use a
  fresh dependency/export job to publish the exact inert runtime. Then run
  a fresh Native control, preparation v2/`python-readonly.v1`, to observe
  the fixed boundary error and prove real utility/write refusal. Never
  replay pipe jobs `001`–`006`. Job `006` used older product `74d8d008`
  and failed with exit 126 before tests; its 65 closed sessions, 470,846 bytes
  and 525 task histories are component evidence, not current-source qualification.
  Full SDK role modes still refuse the read-only preparation.
- Retain earlier product `74d8d0081`, controller `52da7281…`, successful
  build `c2e80b4915f76a3d`, transfer/export `c8a491e0d27bf653`, and audit
  `52b9d314e8a670cf` (28 groups/52 selectors, 1,304 passes, zero failures/errors,
  one deliberate retired-Pi skip; incomplete/ineligible). Never rerun them.
  Preserve failed/unknown `6147ab2733bb774d`, `f44a167f33be73b5`,
  `de145dd6f485a69f`, `84267ae7556a6101`, `b937d2e04a16c85f`
  and the unexplained first active refusal. See [build/runtime](gauntlet-rust-hostbound-candidate-build-proof.md#fresh-current-source-build-and-runtime-through-the-primary-commands),
  [source transfer](gauntlet-rust-vm-source-transfer-proof.md#primary-rust-transfer-into-the-build-slot),
  [primary audit](gauntlet-rust-feature-worker.md#fresh-primary-audit-at-the-current-build-generation)
  and [Native controls](gauntlet-rust-native-stdio-plan.md#explicit-read-only-control-checkpoint).
- Thirteen sanitized public archives remain local; the latest primary-transfer
  bundle has 118 members/53,258,240 bytes, SHA-256 `587ccd27…`, and excludes
  all 33 nonces known at its creation. New private build/pipe payloads are not
  published. Reviewer-retrievable delivery, independent review and all five
  current-head jobs remain open; Actions is disabled on the fork. No settings
  change or check override is authorized.
- Continue the full dependency order below: independent Native semantics,
  observer/key/source/preparation admission, actual writers, twelve fresh
  staging/installed roles and signed conformance, then host operations, real
  authorized workflows, legacy parity and cutover/rollback. **24/62 parent
  exits complete, 38 open.** All eligibility/causality flags remain false,
  model use is zero, and this goal grants no quota reset, upstream merge,
  release publication or PR-gate activation.

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

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

- The fixed deadline is **2026-11-11 23:14 UTC**; reserve the final three
  hours for integration and handoff. Continue branch
  `codex/gauntlet-rust-finish-20261105` and draft
  [child PR #5](https://github.com/HGraphPunks/hol-guard/pull/5), targeting
  integration `f143f9ac`. The pushed baseline is
  `3b807835df09b45ef7f962f0d33974ab3d1eb72f`, incorporating upstream
  `6b658c378c6d73718d081c7b4853982ca650cad4` and functional batch `055652542`.
  Verify the actual current branch/remote head before resuming.
  Parent exits remain **24/62 complete, 38 open**.
- The next registered batch passes **930 macOS workspace tests**, with zero
  failures/skips, plus full warnings-denied macOS/ARM Clippy and formatting.
  It adds explicit passive `attach-job`/`refresh-job` observer links, a closed
  SDK18.4.12 secret-copy denial consumer, exact provider-turn exhaustion and
  an outside hash of actual usage/quota snapshots. Missing review, execution
  or result custody remains incomplete. The legacy execution drafts are not
  registered, and no new model role is claimed.
- Pinned Podman 4.9.3 rejected the original `--tmpfs nr_inodes` arguments.
  Rust now creates finite kernel tmpfs mounts and binds their exact objects.
  The expanded ARM fixture passes separate SDK byte/MCP inode exhaustion,
  inside/outside identity checks, teardown while full and restarted ext4 abort.
  Independent four-lease cleanup verifies all eight temporary mounts, main
  volume/backing/loop, owner, containers, profiles and cgroups absent, with
  345 historical Worker rows unchanged (excluding `active.lock`). The actual
  ARM Native pipe live-process identity guard also passes. These component
  results do not establish a successful complete bounded build or SDK role.
- Sealed Bun arguments and cached genuine SDK Settings are implemented.
  Physical hostile-startup and normal-entrypoint evidence remains required.
  Actual original brush commands reopened Bun stdout/stderr and Bun memory;
  no memory contents were accessed. Ordinary Bash result custody stays
  unadmitted. A separate enforcing-profile/FIFO experiment is diagnostic only;
  it cannot qualify the normal agent, Native/model sockets or call lifecycle.
- The reviewed source map remains 440 files: 91 changed and 20 added against
  the unchanged baseline. Independent Python AST selection and Rust agree on
  409 installed files, 420 entries and controller digest `41955c2d2f7a91e0fb80fe8967436588e48da859c92a0adff291bb52c19e6869`.
  The merged product library/CLI/tests compile with `--no-run` on macOS and
  ARM; neither is a product execution or qualification.
- Normal Rust commands have completed a genuine unprivileged ARM build of
  `bb69ca40`, separate dependency resolution, inert dependency staging,
  candidate cloning and immutable runtime publication. Build result
  `e051986d…`, dependency result `aad6bf89…` and publication receipt
  `418818a7…` bind the same source. These use historical v1 storage and remain
  ineligible; they do not prove the new bounded flow, conformance or model use.
  Preserve both original build volumes while runtime verification needs them.
- New bounded jobs use finite ext4 volumes with byte/inode limits and a pinned,
  per-job mount-namespace owner. Host checks original initialization and storage
  claims before run/read/repair; public summaries omit process and owner details.
  The first physical storage test refused Linux's normalized mount-option
  listing and its failed partial job was retired without replay. The corrected
  Native-profile retest passes: UID/GID 10001 reached ENOSPC after 2,046,599,168
  bytes and separately after 65,513 files. Both full-volume teardowns removed
  their containers/policies without new volume logs; restarted abort removed
  backing, loop and owner. Evidence `vm-ext4-enospc-storage-002.json` hashes to
  `439da51165b39f6aa069a187848cb0f04b6b0adac7757bd342803ad2e78621c5`.
  This is a test-only initializer/owner pairing, not normal Host admission.
  Owner-loss cleanup exposed a dead-child reap-order bug; independent resumed
  empty abort and the corrected same-process retest both passed. New Worker
  `756ab02b…` and test initializer `0537012f…` also passed a fresh full-quota
  test with independent backing/loop/owner absence checks. Six cancellation
  tests passed in the actual ARM VM, including interrupted helper exits 0/1.
  Full bounded build/dependency/Native flow still requires separate validation.
- Normal bounded Native preparation recovered through `prepare-read` after the
  original Host transport timed out. Its first run then failed during the
  50-second prelaunch window with no Root start record or Host pin. The new
  explicit `initialize-abort-unreleased` route consumed that original dispatch,
  preserved preparation evidence and removed its volume/loop/owner; readback
  returned the identical receipt. Four independent leases verified no execution
  resources and all 341 historical Worker metadata rows unchanged. The same
  journal admitted a fresh job, whose caller then exposed the unchanged generic
  handshake's 60-second cap. That never-handed-off job was explicitly aborted.
  The corrected Native-only handoff keeps one 210-second deadline while generic
  APIs retain 60 seconds. Host library 138/138 and process 11/11 tests pass.
  Fresh job `27558527d8f3377b` then completed normal initialization, preparation,
  one-use run, separate read and private artifact/report retrieval with Worker
  `e4649a90…` and Host `50906e0b…`. Its signed control failed with `Native process
  changed before pipe forwarding`; Rust independently reports invalid evidence,
  not a passing control. The 3,761,664-byte archive remains private and pinned;
  normal completed-storage retirement and identical retirement readback passed.
  Four-lease independent checks found no owned execution resources or original
  backing/loop/owner; all 341 old metadata rows and five new terminal-job rows
  remain. No model inference or
  parent-exit success is credited by this failed control.
- The consolidated registered implementation passes 912 macOS workspace tests
  with zero failures/skips, formatting, and full all-target/all-feature
  warnings-denied Clippy on macOS and ARM musl. These checks do not replace the
  five required current-head CI jobs, independent review or actual qualifications.
- Supervisor v6 adds only the fixed, outside-pinned `/usr/bin/nsenter` helper
  to v5's Native pipe contract. V1–v5 retain their original helper sets.
  Eleven ARM declaration checks and an actual private-namespace/full-journal
  cleanup test passed. The latter observes the service's real namespace and
  private file, exhausts its journal filesystem, and removes the service and
  AppArmor policy while retaining unknown cleanup credit. It does not run a
  candidate. Evidence record `vm-rootfs-enospc-cleanup-003.json` hashes to
  `961577372564262e1676bdac46fa7130027964db9d531af9b964af9a0c4e1ccc`.
- The actual pinned OMP SDK passes the MCP-only tool-inventory check and four
  MCP bridge/formatter cases without inference. Rust has source-derived
  current/frozen legacy reducers and explicit signed AI-support evidence
  checks, but catalogs and reducer parity do not establish workflow execution.
  Ordinary allowed Bash still needs an execution lifecycle bound to the SDK's
  real persistent brush process; a different shell backend cannot supply parity.
  Full legacy and wider campaign execution remain open.
- Normal artifact retrieval, prefix publication, bounded source recovery,
  provider ownership and two-cell live commands are implemented or undergoing
  focused recovery validation. A successful completed read must retain original
  intents, consumed dispatch and outside authority; never replay a lost reply.
  Failed Native preparation `08fd53f059a2e548` exposed legitimate zero-byte
  Python package markers. Its job stays consumed; the narrow public-code fix
  requires a fresh job and does not permit empty private receipts.
- Preserve **341 historical Worker metadata rows** unchanged. Custom historical
  inspection remains lstat-only. Deployment and independent cleanup checks take
  all four existing leases; APIs acquire their own Worker/Python leases and
  must not be nested under those same external locks. All evidence and failed
  attempts remain in the private `expedited-20261110-001` evidence directory;
  sanitized reviewer delivery remains required. No new model request or quota
  mutation has occurred.
- External gates remain open: Actions dispatch returned HTTP 422, "Actions has
  been disabled"; five current-head jobs and independent review remain required.
  Current candidate source is outside the original model authorization, and
  721,979 retained tokens cannot cover the 1,600,000-token pair/beta reservation.
  Source reauthorization, any allowance increase, and additional VM/disk
  capacity require the pending operator actions. Do not infer approval from
  elapsed time. The failed CI-excluding security scan is not a clean report.
- Rust/MSRV/workflow/builder use **1.89.0**. Run the consolidated affected-platform
  checks after the batch stabilizes, refresh the explicit source delta, update
  the PR around the final behavior and preserve Python compatibility. No
  upstream-main merge, release, protection change or active PR gate is authorized.

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

# Rust migration restart: integration and regression proof

Date: 2026-10-26. Branch: `codex/gauntlet-rust-pr-ready-20261026`.
This is a local implementation checkpoint, with no new model requests,
conformance package, eligible benchmark verdict or production cutover.

The branch starts from integration `f143f9ac` and merges the committed
preparation `b0b0cdd8`. The original preparation worktree remains intact.
The active goal and [execution plan](gauntlet-rust-pr-readiness-plan.md)
preserve all 62 parent milestones and their original proof requirements.

## Historical custody oracle compatibility

The initial complete Rust run exposed three failing source-pin assertions:
`private_actor`, `private_cell_mounts`, and `private_hook_samples`. Their
immutable vectors name Python source SHA-256 `2de9c8c27d2b8f883291900ed3fe29f0f9aa7a318b03a195c4f20ba4f5a22cbb`.
Native-actor support changed the enclosing verifier file to
`5be923a6164459e79664419767e07591581355c8060bf941545b48a7adf859bd`.
The change imports the explicit native runtime selectors and extends the
outer verifier's actor/gate selection; it does not change the six functions
exercised by those vectors.

The repair retains the complete 269-line Python source from immutable commit
`b4efd8171b06d0e13cbe12a077c376ecdc891fd1` as inert test data. The tests verify
its original digest, require the separately reviewed current file digest,
and use Python's AST parser to prove the selected functions have identical
ASTs. The current file cannot drift outside that explicit compatibility
relation. The original JSON vectors and expected refusal messages are
unchanged. Four Rust tests now pass across the original 69 vector rows.
This establishes the unchanged pure relations; it does not qualify the new
outer verifier or independently authenticate a live product observation.

## Detached fixture readiness

The retained interrupted repair no longer treats a matching process command
line as proof that the detached fixture has started. Before cancellation it
requires the fixture's fixed readiness file to match the observed namespace
PID, session, process group and role token. The reader rejects wrong owners,
unsafe modes, symlinks, hardlinks, incomplete/oversized/ambiguous data and
changes during the bounded read.

Seven focused readiness cases include a watcher regression that sees the
process twice before the readiness predicate succeeds. With deterministic,
completion-lifecycle and staging-artifact regressions, 87 Python tests passed.
All five embedded deterministic fixture programs remain byte-identical to
the committed preparation. Source-inventory and controller-install-plan
checks also passed with the explicit readiness source delta.

## Tools and retained results

The installed Rust 1.88 toolchain was outside PATH. Locked dependencies were
recovered into a separate project cache without installing new toolchains.
The first sandboxed bridge test refused local IPC; the complete run with the
required local socket access passed. A stale retained Native compiler
correctly failed the current capability check. A new locked Rust 1.88 release
compiler passed all five existing projection/directory preparation checks.
The Python suite used its existing private-home isolation helper.

| Check | Observed result |
| --- | --- |
| Complete Rust migration workspace, all features, locked/offline | 380 passed, zero failed, zero ignored on macOS; Linux-only code remains separately required |
| Python readiness/deterministic/completion/staging regressions | 87 passed, zero skips |
| Current source inventory and controller install plan | Three tests passed |
| Rust workspace formatting and diff whitespace | Passed |
| `rust-workspace-before-main.log` | SHA-256 `dc2f6ee7af4901039804c95e5a07ab9ea096d75a3bfdf13c936b9043708182c0` |
| `detached-readiness-before-main.xml` | SHA-256 `8502d031c291d508c3cf79bdd359e0f7cc985085b85bab9530d421c68443ae27` |
| Matching `guard-command-source` executable | SHA-256 `4b4b4bd8570ee8cceec09441aeef72bb196f3fa11e474d9b6eceb28f54686e8a` |

Logs and JUnit are retained under
`/Users/construct/Documents/projects/hol-guard-refinement/gauntlet-rust-pr-ready-evidence-20261026`.
The owned 16-GiB ARM VM was observed stopped; no old live report is promoted
by this checkpoint. Upstream synchronization, the Root Rust constructor,
fresh VM proof and the complete acceptance matrix remain open. The parent
milestone count remains 24/62.

## Upstream synchronization

Merged upstream `7fb50978` without rewriting published history. Both scoped
secret-scanner fingerprint lists are retained, and the Native Unix feature
set includes migration `time` and upstream `hostname` support. Upstream retired
the Python CLI hook route and its wiring test; the merge preserves that
retirement. The unified Native/daemon route reviews PostToolUse output without
reopening command admission. Three new Rust regressions demonstrate ordinary
completed shell output, rejection of secret-bearing output despite a completion
hint, and refusal to treat PostToolUse evaluation as PreToolUse admission.
All three passed against the merged source. The merged Native library and CLI
also passed locked Rust 1.88 `cargo check` on macOS.

Four new legacy modules are explicitly assigned to the Rust migration:
approval retry action identity, Windows Codex contained-call binding, actual
decision-path coverage, and synthetic runtime launch cases. The latter adds
physical launch checks; model refusal or an unexercised decision remains
unproven. The frozen 420-file baseline is unchanged. The reviewed current delta
contains 67 changed files and 11 additions, for 431 files. Independent Python
and Rust controller planners agree on 400 installed files, 411 entries and
tree digest `9dcb5e8de575a89e2b2d27f8cc5b009ade6385251a21a050dfc8b357e717a47d`.
All three source-inventory/install-plan regressions passed. This plan does not
replace any retained installed controller or live result.

The owned ARM64 VM was started for subsequent zero-model diagnostics. These
merge checks do not constitute the five required GitHub jobs, Linux constructor
conformance, independent review, or qualification.

## Merged-tree verification and startup race

The complete merged workspace initially found two additional stale whole-file
pins in the historical host-call/transcript compatibility helper. Upstream
added decision-path assessment elsewhere in `evidence.py`; the normalized
`reconcile` and `read_events` AST digests remain unchanged. The explicit current
source pin is now `b5a2ba7d80f6bb16eb60d125299b0f7874e1befded2680b0394cb065e4ba2a51`.
The unchanged original generators replay all 31 host-call and 15 transcript
cases against this source, without modifying historical fixtures.

A subsequent full run exposed a separate startup contention failure. A status
reader's shared transaction lock could terminate a newly launched observer
before readiness. A held-reader process regression reproduced the actual
`Rust host lifecycle lock is already owned` failure. Observer open/start now
retry only pre-mutation Busy results for a bounded five seconds per operation.
Each start reacquires the exclusive observer lease and samples a fresh clock.
Identity, clock, invalid-state and uncertain-commit failures are final. Operator
mutations keep immediate contention refusal. Process tests cover temporary
reader contention, finite refusal with unchanged checkpoint, single ownership
and crash recovery; a regression ensures uncertain commits are never retried.

The final complete macOS workspace run passed **390 tests, zero failures and
zero ignores**, across 206 test targets. Full workspace warnings-denied Clippy
passed; the changed host crate's Clippy passed again after the startup repair.
The matching merged Native release runtime/compiler passed full projection
preparation and **140 macOS ownership/approval/delivery and migration tests**,
with zero skips. The three Native PostToolUse Rust regressions also passed.

| Retained artifact | SHA-256 |
| --- | --- |
| `rust-workspace-after-startup-repair.log` | `d7be6c989525554ceeed915549ada72ee463f930a664942a5c58b65e61599125` |
| `native-and-migration-after-main.xml` | `190447e6ba99ecd82f6803fdd40ad5e7dccc888ccb403d52f89028b9dbff6e75` |
| Matching merged `hol-guard-runtime` | `669b04f5f1223ae561c93e2d93d65653b859328a963ff9793b5a491b6554ad75` |
| Matching merged `guard-command-source` | `fe1417ebadfc0339007cf481ba63db156fb078a29de1f4babe0b1c91d1251fc4` |

Both failed full-workspace logs remain retained. Generated projection docs
were preserved in scoped named Git stashes, excluding unrelated generated
churn from this branch. The [constructor VM proof](gauntlet-rust-rootfs-vm-proof-20261026.md)
records its separate source pins and three fresh zero-model apparatus cases.

Fork PR #4 tracks this consolidated child. GitHub's dispatch endpoint returns
HTTP 422, `Actions has been disabled for this repository`, while Actions
permissions report enabled and the workflow reports active. No PR-triggered
run exists for the published head. The five required jobs remain unsatisfied;
local results do not authorize merging around that requirement.

## November 11 expedited storage and namespace checkpoint

This checkpoint uses product source `bb69ca40e301670b94cedc2a44090d5ec26bdd90`
and separately built trusted Gauntlet tools. The tool changes are still under
consolidated validation. All tests below used the owned 2-CPU/16-GiB/48-GiB ARM
VM, fixed outside executable pins and bounded services. No product runtime or
model ran in these tests. Parent acceptance remains **24/62**.

| Retained recording | Actual result | SHA-256 |
| --- | --- | --- |
| `vm-systemd-mount-property-probe-001.json` | systemd 255 refused unsupported `MountNamespacePath`; no service remained | `653fee7238e775a6611bc481b4873d2689a101cff456f6ad7b638d383066494a` |
| `vm-v6-rootfs-contracts-001.json` | Seven supervisor and four preparation ARM contracts passed | `a60a44708b189cee76441888a75a3291300df1a3dd945b97e8b5ae94dcda68db` |
| `vm-rootfs-enospc-cleanup-003.json` | Actual private namespace entry and owned service/policy teardown passed with a full journal; cleanup credit remained unknown | `961577372564262e1676bdac46fa7130027964db9d531af9b964af9a0c4e1ccc` |
| `vm-ext4-enospc-storage-002.json` | Native-profile byte/inode ENOSPC, teardown while full and restarted retirement passed | `439da51165b39f6aa069a187848cb0f04b6b0adac7757bd342803ad2e78621c5` |
| `storage-fixture-8a3fb4b1be269ba0.json` | Exact measurements and original storage/retirement bindings retained | `23a249f01fb59a1242e10cbec8ac635b9d81c52beb480e2229c5d0577ffabb94` |
| `vm-ext4-full-quota-readback-001.json` | Outside readback verified no original backing, loop reference or owner cgroup remained | `965122bdf2419a572195dbf582b0b9710619b7c41a3357875ae5b1d4e87a079b` |
| `vm-storage-owner-loss-001.json` | Failed: dead child reaping followed the cgroup drain check; no successful owner-loss fixture credited | `e2edab9ad81e85e963ee359e1b08e71ae0c115cf6af61f2fb8d9294332166308` |
| `vm-owner-loss-abort-001.json` | Original empty-owner abort resumed after initializer exit and removed the exact remaining cgroup | `6e76f8e21abdcdd3c12e89cb9a981da55db4f501cb4767f77929336d2f5ff91d` |
| `vm-empty-code-assets-001.json` | Empty public package markers accepted; empty private receipts refused | `4e1bb88f434c967fcc8622509cdcc84b9af113624a8c416f04d22dace6dfaa75` |
| `vm-storage-tests-reconciliation-001.json` | Four independent leases, no owned execution resources and 341 unchanged historical metadata rows | `a3ad6db568031415362a9c55cad50c0080622cbaa951e610c26648e264823bfa` |

The quota fixture reached ENOSPC as UID/GID 10001 after **2,046,599,168 bytes**
and separately after **65,513 files**. The inode case retained free data blocks;
the byte case retained free inodes. Both actual containers and AppArmor profiles
were removed while the volume was still full, without creating new volume logs.
Kernel full-options inspection confirmed `rw`, `nodiscard` and
`errors=remount-ro`; Linux omits the default error option from compact mountinfo.

Trusted release Worker SHA-256 is
`97cdd5bf49d1f1f3a61efbb0703e00a16b67276e7347c4b4d1454ba7608da7cd`;
the optimized test initializer is
`f3ee7d3a5b8cfb81a1f77bbd4159be92f27a8427796cdb8519d2a1690fe65cc8`.
Their different identities are an explicit test-only pairing. These recordings
do not establish normal Host admission or the bounded build/dependency flow.
The namespace regression used a trusted OS sleep and an owned empty policy;
it establishes namespace transfer and teardown, not candidate policy enforcement.

Recordings remain in the private `expedited-20261110-001` evidence directory
under the retained evidence root above. This public index preserves concrete
outcomes and byte pins; full sanitized artifact delivery, current-head CI,
independent review and qualification remain separate requirements. Failed
attempts and historical data remain intact. See the
[current checkpoint](gauntlet-rust-pr-readiness-plan.md#resume-from-this-checkpoint)
for subsequent fixes and remaining work.

The subsequent owner and cancellation fixes passed these independently retained
ARM checks. The fresh quota fixture pairs production Worker `756ab02b…` with
optimized initializer `0537012f…`; it repeats the actual byte and inode limits
above and verifies teardown while full. Earlier failed recordings remain intact.

| Retained recording | Actual result | SHA-256 |
| --- | --- | --- |
| `vm-storage-owner-loss-002.json` | Corrected lost-owner reentry refusal and empty abort passed | `b09d71e8c7ff0a6e51a37033cfb452d39ba226017654fdca7e7f0f30362df78d` |
| `vm-ext4-enospc-storage-003.json` | Fresh full-quota teardown and restarted abort passed in 85.34 seconds | `b21906cf23862bcbf0ac70d961e00863941f880a231bb2c5500c4fa75d1e447d` |
| `vm-ext4-full-quota-readback-002.json` | Outside custody read and backing/loop/owner absence passed | `6f9cffd11556eb5f2aeda195995014185066be0674c4b500f3046214373d9cc8` |
| `vm-process-cancellation-recovery-001.json` | Six actual ARM helper cancellation, output-bound and reaping tests passed | `f80020606c493428cd72304b30548fee7992d967d055a66ecd46a978e6cc9c0e` |
| `normal-native-bounded-prepare-read-001.json` | Supported CLI recovered the original completed inert preparation after transport timeout | `a4f2f333b545a5c2ee6251bf54804feb4905a3b0ba093691464e818668486897` |
| `normal-native-bounded-unreleased-abort-001.json` | Original failed-prelaunch dispatch consumed; initialized storage retired | `ab93b0b8e65eead91d9191ad26fcc3a45efa87d44afabee7392b4ca5f16f70d7` |
| `normal-native-bounded-unreleased-abort-read-001.json` | Separate normal read returned the identical abort receipt | `af8595f86f83b5e7a2e4080146451b0066d7dbadd05313299b26fbf47dfaccba` |
| `vm-normal-native-unreleased-abort-reconciliation-001.json` | Four leases verified original backing/loop/owner absence, no owned execution resources and 341 unchanged historical metadata rows | `c40952b4477a8237f4d3148a78b23f31ad75ca12c476db77109fd7cf669954e3` |
| `normal-native-bounded-initialize-002.json` | Same journal admitted a fresh bounded identity after verified abort | `144b2d4b6ba12b8b9637b50f3d2b321bd5beacd67df2fa45e9868c5d42e2e4de` |

The first bounded Native run failed before a Root start record or Host pin was
retained; it was never replayed. Its explicit unreleased cleanup keeps exit and
model usage `null`, preserves original preparation and dispatch evidence, and
refunds nothing. The next identity uses production Worker `e4649a90…` and Host
`1b308503…`; its execution validation remains separate. These results add no
model, candidate-conformance or parent-acceptance credit.

The consolidated registered code at tree `690b1d3641608b74344e89e23c92e094589af4ef`
passes **912 macOS tests across 240 targets, zero failures/skips**, formatting,
and full all-target/all-feature warnings-denied Clippy on macOS and ARM musl.
Recordings `macos-workspace-tests-003.json`, `macos-workspace-clippy-003.json`
and `arm-workspace-clippy-003.json` hash respectively to
`fadc049dcdc41b816589a33e7b105231590ce01aaeb4c6197d80ff04de1c03f1`,
`b2ee53328d2bd8900b4bb9683bc5399dff20f33e74acb8c1c0d88b6d3b965704`
and `6ade69d6dcb141d1f310991794c40311129394b67ede31d3f86f60b5e1809533`.
Only checkpoint prose changes after that tree; unfinished unregistered legacy
modules are excluded from this validation and commit.

Actual unprivileged job `27558527d8f3377b` then completes normal CLI preparation,
one-use execution, restart readback, private export, independent report and
storage retirement. Its **control fails** with `Native process changed before
pipe forwarding`; the independent judgment is `invalid-evidence`. The archive
is 3,761,664 bytes/38 members, SHA-256
`a9a19ea2cfa81e15326f2d290f58322640385db193b59c154f7271bd34fee60c`.
The unchanged signed failed report remains authoritative after storage retirement.

| Retained recording | Result | SHA-256 |
| --- | --- | --- |
| `normal-native-bounded-run-003.json` | Authenticated failed controller result retained; no retry | `ea82d3d24956dc971c42a9a0769cf71f0b525d7a73b575279d5938df642b25df` |
| `normal-native-bounded-read-003.json` | Same original completion read separately | `f49013385111faec3d2f25ed249787d48d31ecdece62bcf6129a008e28c46f45` |
| `normal-native-bounded-report-003.json` | Original archive and signed report matched; independent judgment remains invalid | `b6df041220a7a9198314fd4764b6946c7bf00927a471fb6be7b4cfe77ff9a023` |
| `normal-native-bounded-retire-003.json` | Completed bounded storage retired against original retained archive | `0002dd9ac0ae5aba55191509094abc4e8b1e7dd1eb0d62a3dc187ea485db99b3` |
| `normal-native-bounded-retire-read-003.json` | Separate read returned identical retirement receipt | `505689a29f874e7ce7371028900efd137caa1f6c089845e80ba80f6b29143abe` |
| `vm-normal-native-retired-record-measurement-003.json` | Four leases; no owned cgroup/container/profile/mount/backing/loop; 341 unchanged historical plus five retained new job rows | `404a4cca45a2346fce012f5dfb53e6685a43ea25506ea8968c8300f64f2302bf` |

The earlier metadata assertion expected controller streams in Worker state;
the measured five-record layout and exported streams are retained separately.
That failed diagnostic remains preserved. No passing control, model inference,
final-source qualification, current-head CI or independent approval is claimed.

## November 11 registered storage, startup and observer checkpoint

The batch based on `3b807835d` passes 930 complete macOS workspace tests with
zero failures/skips. Formatting and full warnings-denied macOS/ARM Clippy pass.
Only export ordering was formatted after that stable test run. No new crate,
binary or dependency is added. New source files hold the necessary temporary
mount boundary, the closed legacy denial consumer and its regression tests;
the two legacy execution drafts remain unregistered.

The expanded physical fixture uses frozen Worker `ab5f0230…` and test binary
`4b1090ce…`. It independently exhausts SDK temporary bytes and MCP temporary
inodes, checks all four inside/outside tmpfs identities for each scope, tears
down while full, then exhausts the ext4 volume and verifies restarted abort.
Independent four-lease inspection confirms all owned resources absent and
345 unchanged historical Worker rows excluding `active.lock`. The separate
actual ARM live-process pipe identity guard passes. No candidate/model runs.

| Retained private record | Result | SHA-256 |
| --- | --- | --- |
| `registered-macos-workspace-tests-001.json` | 930 passed, stable source inputs | `e45c2696a00b2613d6e1a4206c7039b83e268c1317da5e1da8080ee8c7012277` |
| `registered-final-format-clippy-001.json` | Format and macOS/ARM workspace Clippy pass | `549df05e1a68bd6a95060cb85ed0b124bba73a5f989d9c12b5c5d817e177032c` |
| `registered-arm-freeze-build-001.json` | Worker, constructor and both libtests; 1,604 unchanged inputs | `38f42b59b341b37a99526056e989946b5ae80cc222412a2821ced5b43885232b` |
| `vm-ext4-enospc-storage-004.json` | Expanded physical fixture passes | `ab699ca6d41625fae6154943b0b870cd30e6facb9fc9c6e03666338cfbbbacc5` |
| `vm-ext4-enospc-storage-004-independent-cleanup.json` | All resources absent; history unchanged | `1239ac204156d89dfe7d9a34de29a84ba4a7b7b727baaa3170ba7483d1446d27` |
| `vm-native-pipe-identity-unit-001.json` | Actual ARM identity guard passes | `7a74a8a4b46901c2b968e65c3e18928d86e62a39111ec1ee0b5bae4a8463b508` |
| `python-controller-plan-source91-20261111-001.json` | Independent Python AST oracle; 409 files/420 entries | `9f6606e4b8284e99e1b5a86a0fccb26df0d22e7f64055bb80714d4db2c8bd371` |
| `native-main6b-macos-compile-001.json` | Merged product library/CLI/tests compile only | `82f14812c787eb91fe6c3c4810d4ac1e064b98b1350ce5a68ac222891b17c4f9` |
| `native-main6b-arm-compile-001.json` | ARM compile only; existing libc deprecation retained | `134228732316d2313437ac16e54fc30674efafb9304da4291df5f5a2fc03d8e4` |

The source map is 440 files/91 changed/20 added; its independent controller
digest is `41955c2d2f7a91e0fb80fe8967436588e48da859c92a0adff291bb52c19e6869`.
SDK startup producers and consumers are implemented, but physical startup and
normal-agent result custody remain open. Original genuine brush probes proved
raw output forgery and writable access to Bun's memory object (no contents).
Separate diagnostic hardening experiments cannot supply normal-agent,
per-call authorization/result, descendant or qualification evidence.

Explicit observer attachments remain passive; unknown journals block admission.
Provider grading now exhausts current-job outside turns and binds actual usage
and quota snapshots. Missing review storage remains incomplete. The parent
count stays 24/62, all model and rollout claims remain withheld, and the five
current-head CI jobs plus independent review are still required before merge.

## November 11 upstream compatibility and sealed startup

Merge `168e9b33f` incorporates upstream `62fe5d573`; the immutable Python
baseline and historical goldens remain unchanged. The current catalog has
310 Core cases and 352 total cases. Independent current Python replay
reproduces all 360 historical current-generation results. A separate,
48,720-byte reference fixture supplies 27 new eval/launchctl result vectors;
its digest is `e902408b5baac3513faff5e9c27d13dcdae5649147ba8a2361fb1acc96ebcdd4`.
The eval oracle requires the exact JavaScript `sh` copy attempt, a
protection-class block, zero queued approvals and absent copied output.
Review and reapproval cannot satisfy that oracle. These are reducer and
compatibility results, with no live SDK 18.18 qualification.

The reviewed source delta is 441 files, 93 changed and 21 added. Independently
extracted actual Python bootstrap selection agrees with Rust on 410 installed
files and 11 directories, 421 entries, and planned controller digest
`eedaa25b8a3ea7eb642159a2e64d71ed47222c624e882a8e318aa478c618faf2`.
The existing fixture builder's corresponding exact counts are updated. Its
4,331,520-byte inert archive matches every independently derived member,
mode, owner header and file digest. It was neither extracted nor installed.
The first independent archive check mistakenly rejected its expected top-level
`ci` directory; the corrected check preserves the identical archive bytes.

The actual pinned Bun 1.3.14 rejects the old empty-preload config. The corrected
startup uses an exact 47-byte config and an 11-byte no-op module, embedded in
Rust and held as distinct Root0444 read-only objects. Startup observation v2
and public-helper schema v3 bind both objects; historical readers retain their
original schemas. A real SDK 18.4.12 Settings/startup fixture passes three hostile
project/agent/home configurations and a genuine fixed `executeBash` call. This
is standalone startup compatibility, not normal Rust peer capture or role
admission. Source SDK 18.18.6 remains separate from actual SDK 18.4.12.

The cold SDK output experiment also passes its bounded component checks:
Root holds and seals both actual output FIFOs before release; the loaded
enforcing profile denies the tested Bun-memory opens; child raw-output reopens
fail. Root observes 32 contiguous raw frames; checked Bash results match complete
captured callback bytes. Builtin output redirections can succeed inside captured
chunks, and the observed child retains
read-only random-device descriptors. No top-level forged marker is observed.
This does not prove only-stdio inheritance, other memory/descriptor mechanisms,
production Native/model sockets, per-call authorization/results, descendant
cleanup or cancellation. Production FIFO/LSM integration remains open.

The newer running-runtime owner-loss fixture **failed**. Strict retirement
refused unexpected private storage entries; no cleanup credit is granted.
Offline review found a fixture-only error: it loaded the named unconfined SDK
profile but checked for an enforcing profile. The correction uses the existing
bounded named-profile presence check; production enforcing checks are unchanged.
That correction has not had a fresh physical owner-loss rerun. Fresh job
`ceb3663cc45c4c45` retains an unverified 2-GiB backing, empty original owner cgroup
and stale socket. Independent checks find no owned runtime/container/profile,
mount or loop attachment, but the original namespace owner is lost. Existing
pinned abort correctly refuses that missing authority. Admission stays blocked;
the retained backing is neither deleted nor adopted.

| Retained private recording | Scope and result | SHA-256 |
| --- | --- | --- |
| `python-upstream-62fe-compatibility-001.json` | 360 historical Python results and old-branch AST compatibility | `7183564623d8b4322f5a8b243de08eccccc8d23d0dba59a627a49b04730c3f78` |
| `python-controller-plan-source93-20261111-001.json` | Independent actual Python selector/digest oracle | `90c37d455198ab4650b4a786a326bdd255516452d4ce9cbea35060346b76b2a6` |
| `controller-source93-fixture-oracle-join-003.json` | Exact inert archive joins independent Python rows | `e9c913cd17e9cb95129d44b609aa78b7657befce28cffd4228353fb0e68395df` |
| `upstream-eval-python-pure-tests-001.json` | 42 pure Python eval regressions pass; no product runtime | `935bb8944c985cd5134df61e2eaf57beead7368ed4ffe34d141edf6d93d87938` |
| `upstream-current-source-pin-recheck-001.json` | Unchanged host-call/transcript ASTs; 31+15 pure replays pass | `27fa595915702ab44027223ad399dfc51f282e7652ac1438a1f5b85a9ae8272b` |
| `vm-sdk-sealed-settings-002.json` | Genuine pinned SDK hostile Settings/startup component passes | `fea858aa1a67a29eb68ad25a8eddf53456e5657c100695338e36aadd834db5e2` |
| `vm-sdk-brush-fd-probe-011-cold.json` | Cold gated FIFO/LSM experiment; production admission withheld | `5be304ff45426c9065b8aff2cee4d889495323fbee7a68814841c14c4a45a251` |
| `vm-owner-loss-runtime-002.json` | Failed physical owner-loss test; original failure retained | `02239a078b97157d79ca9d415eb4d6a47ea491e2cdaa7859a72c23a6f8786acb` |
| `vm-owner-loss-runtime-independent-release-001.json` | Quiescence/history checks; backing remains unverified | `eb54470a69bad667226faa65e9dbac51c8becfddab4e89b78c6d9bd8ee2db2bb` |
| `unregistered-legacy-drafts-archive-001.json` | Both excluded drafts preserved privately outside worktree | `90adcf8793c87aa981e808bbb72555c0471ad921a7d1bac536277424f4bb52c8` |

All physical recordings retain their own executable/source generation. The
earlier positive storage proof cannot substitute for the failed newer owner-loss
flow or for a final-source qualification. Targeted internal source review found
no actionable issue in the startup/export and upstream compatibility changes;
it is not independent repository approval or a complete security scan. Parent
acceptance remains 24/62, with no new Gauntlet model requests or rollout credit.

## Final local integration checks on November 11

The final Gauntlet input snapshot contains 1,606 files and hashes to
`167cd786824d42dd9bc6460ba4a45991e0110141a18c387b8d522f149cf6181c`.
Inputs remained byte-identical through the complete tests, formatting, both
Clippy checks and ARM libtest build. Documentation updates are outside that
code snapshot. The two failed complete runs remain retained: the first found
a stale current catalog source pin; the second reached all 229 targets and
found only the stale 440-versus-441 source-count assertion. The assertions now
use the independently derived current source and counts; none was removed.

| Private recording | Actual result | SHA-256 |
| --- | --- | --- |
| `registered-macos-workspace-tests-004.json` | 933 passed, zero failed/ignored, 229 targets; 215.56s | `bf5b0408f4b305284cf30754d617b5933b10ef154c9b2e8eece34c68b3facf9d` |
| `registered-final-macos-format-clippy-003.json` | Full formatting and warnings-denied workspace Clippy pass | `9437d25f87b9da29411d179269599330755f1f22199bf51df7bc4f11c9366a82` |
| `registered-final-arm-clippy-002.json` | ARM all-target/all-feature warnings-denied Clippy passes; 146.72s | `6ffc808329525eac5fdb05a4810003246f3611b89256a7185f942768555d8bae` |
| `native-main62-macos-compile-002.json` | Merged Native library/CLI/tests compile with no execution; 1,160.36s | `bc5315737d933bfdce71b66bc1a9ddb72b4d49c79304bfc752a1fc4bc1908245` |
| `native-main62-arm-compile-002.json` | Same merged Native targets compile on ARM with no execution; 1,005.00s | `adf69fcc01e9e37524ca353e7c2950095bd1f5b5aff48ab0de3793ef082b21ec` |
| `final-arm-worker-tests-build-001.json` | Final ARM libtest built from the unchanged snapshot; 576.48s | `62405a84938643720800df7c6453186662f9859fcbd7114eb5e22a460b0cf6fe` |
| `vm-final-sdk-peer-tests-001.json` | Nine actual Linux regressions pass as UID/GID 65534, zero capabilities and NNP; no candidate/model | `54e5511def79e752a7103bf6d948578349f9df9ad9a62d7a69205d2832f43440` |

The actual Linux tests include changed-byte/owner/mode/inode startup refusal
and the fixed public-export allowlist, including exclusion of private/unlisted
files and symlink refusal. Test executable digest is
`e300a7832880150b61f5c7fe51da6f401e901827a7c69bb4bfcdc3131b259c46`.
Outside checks held all four leases, verified the transient unit cgroup gone,
and found all 345 historical metadata entries and the retained unknown backing
unchanged. They do not retire that backing or qualify the normal SDK path.
All five actual current-head CI jobs, independent repository review, successful
functional qualification and rollout requirements remain open.

# Host-bound candidate builds

## Historical local 3.49.0

The host-bound runner and result reader came from `7bd496e5`; the read-only prelaunch readiness check came from `d7e8d110`. This is a **shadow build**, with `artifact_admitted:false` and `execution_eligible:false` throughout. It did not stage or install Guard, run conformance or model inference, publish observer state, or enable the PR gate.

The first one-use job, `c6891bca61e59c95`, durably recorded its Mac host pin but stopped before a candidate container or host anchor existed. The missing prerequisite was the job-specific `Builder.apparmor`. That job remains consumed. The new Root-only readiness binary, SHA-256 `587ee52f6f70a9d530a175d811cc1f81205ab1cf688af642edb098fc80656c93`, rejected this incomplete job with `PolicyMismatch` before any new host pin was written. Its Mac caller also requires an exact canonical, matching readiness response before recording a pin. Targeted macOS tests cover the fixed VM argv, wrong policy, low disk, invalid binary pin and journal absence; the full host crate and warnings-denied host Clippy passed. The ARM64 readiness binary was built from the locked workspace, installed Root:Root mode 0500/nlink 1, and independently rehashed in the VM.

Fresh job `6446059453be1a15` used local 3.49.0 commit `76c31929833b5571d25a56d9783e24a0997d5422` and 45,439,546-byte source archive SHA-256 `bedd98ab7da8ca728484799e1ef6b13c854f7fcbb31a17ebdcc469c4c772af43`. The separately installed controller root `/opt/hol-gauntlet/controller-18d31910a8cefbd6` had tree digest `33c98333891743e6976bee9a123365fe7fe95dcf1bf9b65ee39a59fb41043c68`. Rust captured the source into a fresh Root slot, verified both local ARM64 base images, wrote the one-use builder image context and job-specific AppArmor policy SHA-256 `4aaa2cc5cbeb4e4e6578bb8927542be9ac344134f5db96a3c224b51a90489594`, and verified source-bound image ID `sha256:39a6e74e48b2619189e191b5f5038ce0e27fba1cb57177d713e2077e64c7bb29`. The readiness probe observed 12,916,948,992 free disk bytes before launch. The guest runner and result reader had outside binary SHA-256 pins `2f7330d46e41bf0f2b064e443752755293c15a1129c5d8d0bce7bfc80ab517a5` and `861ca5acaf4e797bdf3d5abf7a4a77cad07941a35e69e75c61a51ca389aaa3ee`.

The Mac wrote one private 0600 pin journal entry before spawning Lima. Its SHA-256 was `2400f4d8092424f46d49589d8a29970aa2c4400608e7dd130ba1588f122db388`; the Root guest wrote host anchor SHA-256 `da5f826cc926216dc13839335c1fe1c932a490d7cc81106c667634209a142943` before the candidate Podman run. The VM's 2-vCPU/16-GiB/48-GiB configuration held the fixed 12-GiB candidate container. The product build completed the release Rust compile in 6m 58s, built the wheel, and passed 4 selected Python tests plus 186 product contract tests. The bounded candidate run exited zero; independent Podman and cgroup reads found no remaining candidate container, job AppArmor profile or candidate cgroup. The canonical Root result SHA-256 was `6e8be6ee673f6c0f803ad5725180c794cb41955a7d4a2ffd7c9d6f221d57e220`.

The first read-only host result probe correctly refused the uncaptured export. A separate one-use Root capture copied the 20,274,622-byte unprivileged export into mode-0444 `candidate.zip`; its SHA-256 was `5283c839fc0e035f5b475d6837c9dc8bbe0f1e44e4fad7530a3cb48d9e854b14`. The host-bound reader then succeeded, checking the host journal, exact guest anchor bytes, result, captured source, stdout/stderr, exported and captured archive, wheel declaration, and cleanup. A separate inert wheel reader decoded all 1,727 entries and 53,396,514 uncompressed bytes, matched wheel SHA-256 `f3acbcd0476e1ecc3d119f29e56c9c1bd22401e76c5d83c8cb8255d214eab496`, and hashed the 29,732,624-byte native executable to `533d72c30de62b460556c7330067e1078b353b094ee2fc3f1edf0f6d6af83eed`. Both readers reported the artifact unadmitted.

This demonstrates a full host-pinned source build and retained-result reconciliation for one historical local commit. It does not independently review the source/controller/compiler pins, authenticate a signed deterministic worker verdict, stage an installed prefix, execute the six controls, or run a model-backed feature campaign. The current Rust host pin is an execution-intent record, not an admission decision. The archive-fixture fix at `aabdbd7d` passed the isolated Linux `contracts`, `macos-host` and `arm64-binaries` checks on [run 39590546631](https://github.com/hashgraph-online/hol-guard/actions/runs/39590546631). The product-wide rollup on that head had one Windows packaged-daemon failure and a pending benchmark-candidate job when inspected; the final-head CI exit remains open. The separate [release-tag proof](gauntlet-rust-release-tag-build-proof.md) covers the subsequent v3.48.0 source-ref correction and live build.

## Current 3.59.0 timeout and container cleanup

On November 6, job `b937d2e04a16c85f` captured exact product source
`83f079b5c4a45cc7aa01849189ad80e0c674386a`, archive SHA-256
`5d7ca00197896145d0ad07650a70acea1dc5f2eabdebec92367f79c321a8f8c8`.
The new 409-file controller has digest `e81a214c…`; prior generations remain
intact. Outside observation binds the actual Root supervisor, UID-65532 builder,
entry script, source/version/tag, source archive, enforced job profile, separate
namespaces, seccomp, 12-GiB/zero-swap/512-PID/two-CPU limits and held pidfds.

After 2,093 host seconds, the call is uncertain and its dispatch stays consumed.
The supervisor/client are gone while the exact container remains active. This
matches the 2,100-second timeout path: it killed the client cgroup but supplied
a no-op candidate-container drain callback. No OOM event was observed. The
container later disappears without a retained Root result or export. Under
all three leases, outside checks find its original processes and cgroups gone;
an operator removes only the remaining profile. No workload signal, fabricated
exit or replay is supplied. The attempt remains unknown and unqualified.

Rust now precreates a container with a request-binding label, verifies and
durably retains its full ID before starting the attached client, and reopens
that identity before removal. Shared validation checks full CID, exact job name,
immutable image, UID and binding. Both client cleanup and create/receipt failure
paths drain the verified container before the enforced profile can be removed.
The frozen Python run-vector reader is unchanged. Candidate release LTO now has
a fixed 7,200-second budget; host transport adds 120 seconds for teardown.
Dependency and feature deadlines stay 2,100 and 14,400 seconds.

The exact patch from base `dd621e614` has SHA-256
`ecefc9a2e32ed2b8fc2d37e472de1be9d97c8ebeafad6f5cd9fdd9bb6d38628d`
over `git diff --binary dd621e614 -- ci/gauntlet-rs`. Its ARM test ELF is
`69c6dacdefb579b00e8cda25e3e472ead9d65d8c7df9ad5bb48e42dc8b8d5ca8`.
An explicit Root probe starts only inert `/bin/sleep` as UID/GID 65532, with
zero capabilities, no-new-privileges, the enforced job policy, no network,
configured 128-MiB/zero-swap/16-PID/one-CPU limits and a 100-ms supervision timeout.
It refuses a foreign binding without changing the receipt, then proves actual
container/cgroup removal and original-init death. The profile is removed after
cleanup; repeat drain preserves the receipt. These fixture limits do not replace
the production limits observed above. Outside checks under all three leases
confirm complete absence and unchanged metadata for all 333 older worker records,
without reading their private bytes. All 656 Mac tests, Rustfmt and Mac/ARM
warnings-denied Clippy pass. No crate, Cargo target, codebase file or dependency is added.

Evidence is retained outside Git in `gauntlet-rust-pr-ready-evidence-20261026`:

| Receipt | SHA-256 |
| --- | --- |
| `native-current359-build-host-state-20261106-001/outside-kernel-003.json` | `610799559fb177c633c249a645b69e86a48e81992bf78f4330a4947d1d2b9d38` |
| Same directory, `run-command-002.json` | `08fc8015c97fe59f537a4e9412c84923b8f622cca0cb92289217ca7b44f0c96d` |
| Same directory, `operator-quiescence-001.json` | `3d8ef67a60ff181fc121f3317508d87d5075a62da1687e548a2ce320a5955db3` |
| `candidate-timeout-20261106-root-timeout-001.json` | `b1331b5bc58f83d229bf7dbdc52887e663235ddab9b0f7939f087d133506ddfc` |
| `candidate-timeout-20261106-outside-completion-001.json` | `a050007c64624270355b697e84930895d5f38f76f3b923cead162a6e3ff3aa9c` |
| `candidate-timeout-20261106-mac-all-001.log` | `d2d3daebc08297bc0ed389490212a017a9162d75c6573299acf81d04a2fd99f2` |

The first outside completion check named the image-builder group instead of
the candidate-client group. Its original receipt remains retained; it alone
does not independently establish client-group absence. A follow-up test captures
the actual client path from the supervisor and asserts that exact path is gone.
Test-only patch `fe5f5641…` over `8bb6d1b5f` compiles to ELF
`05c08242cfe31d25dc339b61a79193e270c5a2d22c41b90299531408d4bbbbf1`.
The explicit Root case and ARM warnings-denied Clippy pass. Its command receipt,
`candidate-timeout-20261106-root-timeout-002.json`, hashes to
`043724ac93bd3a8c9c1e3a299e9a67d601570f4b9394455aa59932e23f02bef3`;
the corrected independent outside receipt,
`candidate-timeout-20261106-outside-completion-002.json`, hashes to
`a173553923130ebca0c06fbc4dbc0d279becdd5250454643d3b39063ab059c45`.
It checks the actual candidate-client group, all container/conmon groups,
original-init death, profile absence and all 333 prior records' unchanged metadata.
The production code is unchanged by this follow-up.

The physical probe closes handled-timeout cleanup only. Full candidate
publication, crash recovery, conformance and admission remain open. Every
result stays ineligible, with zero model requests/tokens and no causality claim.

Fresh full attempt `d5a9c18e3bf20764` completes in 2,369.229 host seconds under
the fixed supervisor. Release compilation takes 36m 35s; the wheel is built,
four selected checks pass, and the contained suite retains **183 passes and two
failures**. Both failures are the same stale import of the removed Python
`commands_support_runtime_artifact_policy` module. Commit `023e0b641` changes
only that import to the maintained test bridge, which calls the Native resident;
both assertions stay intact. Ruff, syntax and diff checks pass. Product runtime,
project/lock and Python controller bytes remain unchanged from `83f079b5c`.

The failed Root result hashes to
`dea47386f989ed58d9421690309bcd0449849f3d1be3f7ecb58be658e9643226`.
Its 29,226,695-byte ZIP is captured once, SHA-256
`f34e2f70ff41665ba763f836fd07eb9cab042ff4ab45535cf793a438c7756455`.
Rust verifies all 1,626 wheel entries and 72,720,561 decoded bytes, including the
47,368,640-byte Native ELF. Host result readback refuses the failed build and
leaves its pin unchanged. This archive supplies diagnostic custody only.

Under all four leases, outside observation verifies original supervisor, init
and client death; exact CID/name, actual client and all container/conmon groups
absent; profile absent; and all 333 old records' metadata unchanged. External
`native-current359-build-host-state-20261106-002/outside-completion-002.json`
hashes to `6a6eb83600e1b3d6f6f56f197e198a07a5982f42ae2ada95daec39a5f0a65667`.
The first observer compared access times and refused after its own log read;
it remains retained. The corrected reader excludes access time while rechecking
device/inode, ownership, mode, links, size, modification and change times.

## Corrected 3.59.0 build and immutable runtime

Fresh job `97bef577d8beb254` completes corrected product source
`023e0b6418296cb50c5ca8c1505a1f508d7a58be`, with a distinct 62,957,603-byte
source archive, SHA-256
`d4abdebeb4d5167046773982bc6b98bf224d75a995a09d26ab2f346b16544637`.
Actual outside host-pin arguments, both held Root/init pidfds, source mount
read-only state, all empty capability sets and enforced kernel limits match.
Its live receipt, `native-current359-build-host-state-20261106-003/outside-kernel-001.json`,
hashes to `23d4cfdea7a061b4dae38c5b28e07cc55cb87db60b24bbab19cc57cc5ffc5f16`.
The run exits zero after 2,363.16 host seconds, with four selected checks and
all **185 contained contracts passing**. Root result SHA-256 is
`d62c1f337d69300ef656310f9def447d1508fbd323af66e9cf12e83595f94975`.
Independent completion under all four leases verifies original process death,
exact container/client/conmon cgroup and profile absence, and unchanged metadata
for all 333 older records. That outside completion receipt hashes to
`24d2c0175062c9a346c5ef7ff9370f3224223080fcf369a1ed2d6b200b0b20ab`.
The captured 29,226,797-byte candidate ZIP hashes to
`c39aeff19389eecfa75230dd414f679333d097ad32f2c584d15af86dcef56465`;
Rust verifies all 1,626 wheel files and the actual Native ELF, SHA-256
`9092baa4915c17a7cdafeb4bfd8144f1d0c361032eaa7d177335f6f92c983ed4`.
Frozen host result readback matches the private pin, Root anchor, source,
logs, result, archive, wheel and cleanup without changing the pin.

Fresh dependency job `b20e4bd21efb86e9` binds the corrected source and exits
zero in 40.874 seconds. Source archive and three-member input capsule are reused
only after independent byte comparisons; Root retains distinct single-link
source files and a fresh one-use intent, result and prefix receipt. Actual
exporter/argv, mounted inputs, confinement and cleanup are independently observed.
The first host observer refuses before guest execution because Python 3.9 lacks
the used `stat` keyword; its receipt is retained. The corrected `lstat` observer
captures the same running job without workload replay. Rust stages all 2,290
dependency files, then composes and publishes the candidate runtime as immutable
data at `/opt/hol-gauntlet/candidates/023e0b6418296cb50c5ca8c1505a1f508d7a58be/prefix`.
Its 4,316-entry, 124,040,037-byte tree has digest
`89036d113a0a5d94f66eb1338ec4e9bd43a7c8d4e2e5f8977d5b70c12a2eab80`;
both canonical publication receipts hash to
`0e893c5894d342c5e00a10fea4ad48c5ce373cad34276c9e091370dd46db5055`.

The external `native-current359-build-host-state-20261106-003` journal retains
`runtime-public-export-001.tar`: 48,025,600 bytes and 19 public members, SHA-256
`99e0b5ed755ece0f508fde52396103179efc2a9d29ee900ac9639bbc66961b4d`.
Independent host verification reads every wheel/dependency byte and reconstructs
all four actual inventories and six console scripts without candidate imports.
Its `independent-runtime-readback-001.json` hashes to
`cebc14f4e6772eb8aaed61e6e4d48ae0d0d6746636f00bc88c926eea61cd1948`.
The exact source-pinned Python requirement loop independently agrees with Rust
on 62 distributions, MCP 1.30.0 and all 21 requirements: 11 active and satisfied,
ten inactive. `independent-python-requirements-001.json` hashes to
`6126639343ca79ea4c8de7f9c407ccde1710615845e2dd0d1826e45eb4a14eef`.
Private intents, anchors, nonces and keys are excluded from the export.

The same external journal contains parameterized public replay programs:
`runtime-public-replay-001.py`, SHA-256
`7eac64d85e73b064a06ab7b0b65b36ef4b697ef58d6f6b5b5f2d03440ea2af77`,
and `python-requirements-public-replay-001.py`, SHA-256
`1367edc2ec84aba65573b47fe85527def7f9a937a65f969e3dfe4b8976f731ce`.
Both accept repository and public-evidence-directory arguments and reproduce
the retained results from their saved files. The first uses only the standard
library and six hash-pinned existing verifier helpers; the second additionally
uses the trusted host environment's locked `packaging` dependency. Neither
imports candidate or exported dependency code.

Fresh 28-group/52-selector audit `df0cc730b3b23ef5` completed from corrected
source with separately captured worker `32135d91…` and executor `5c353aee…`;
old generations remain intact. Outside observation verifies actual executor/argv,
four input hashes and read-only mounts, Root/init pidfds, UID/GID 65532, empty
capabilities, no-new-privileges, seccomp, enforced job policy and separate
namespaces. Effective limits are 12 GiB, zero swap, 2,048 PIDs and two CPUs.
The external `feature-worker-current359-host-20261106-001/outside-kernel-001.json`
hashes to `f55fa8de3841c066a44b2d153bdf595bd014a5d8c3924e37c101c474b947b906`.
The audit terminates in 2,510.775 host seconds with 1,300 passing tests, three
failures and one deliberately retired Pi skip. Rust and independent Python
recomputation agree on all 28 groups, 52 selectors and 56 XML/log artifacts.
The two Cline reason assertions and missing Kimi TOML import remain failures;
25 groups pass, two fail and one is incomplete. Fresh result readback matches,
consumed dispatch refuses, and independent checks under four leases establish
resource absence, original process death and unchanged metadata for all 333
older records. See the [current feature proof](gauntlet-rust-feature-worker.md#current-3590-audit)
for the public export and receipt pins. Do not rerun any consumed ID. Immutable
publication supplies no conformance, admission or causality credit; all related
flags stay false, with zero model requests/tokens. No parent exit closes.

## Fixture-corrected 3.59.0 and primary host dispatch

Source `8920be8bd4ed87d04c6110639633dff9de3545de` preserves the Cline/Kimi
assertions and corrects only their fixtures. Fresh build `9ca1b850e63fd247`
exits zero in 2,789.152 host seconds: four selected checks and all 185 contained
contracts pass. It uses the retained `e81a214c…` controller and fixed Root
runner `b11cc1dc…`. Independent completion under four leases verifies actual
container/client/profile absence, original process death and unchanged metadata
for all 333 historical records; its receipt hashes to
`2a2b049920623c742718dc9a9c4e1a77724edcc3a64cf5a5c08d39f6195b9795`.

| Captured object | SHA-256 |
| --- | --- |
| Source archive, 62,942,172 bytes | `42c3f3e3f165d81dcfb6743366d82af9c91c89fec15fda5842785d8a4e2f47bb` |
| Candidate ZIP, 29,226,900 bytes | `d7f13e5780f28cfa62eca1dfadae28d50e45dea2e79a144be5a76e5385a693b5` |
| Wheel, 29,475,971 bytes | `a3b3b9a1bc2a32633c5a3abf91bb561c2ff2d29d32ca10661d16ce8dcb86811f` |
| Actual Native ELF, 47,368,640 bytes | `b2b8b3948c42c75fc25321160232adfcbadb96df11f10c28a3072a0b2e09c156` |
| Immutable 4,316-entry candidate prefix | `4379b06fcfe9567146779862bb1f22e3dbdff1bd4371ccf4fe598c3f7f2b01a7` |

The inert reader verifies every wheel entry and Native byte; staging creates
1,677 entries without importing a candidate. Host retained-result readback
matches the original private pin without changing it; receipt SHA-256 is
`21c6e55de77a0501b951d648fc4f7e38bf34ba055f6e01695d7a0ca454721a1c`.

Fresh dependency job `22b1bd1ca737f37a` completes in 47.746 seconds with actual
exporter/input/kernel observation and independently verified cleanup. Its
canonical report hashes to `5a0ff27c3f6025eaf50ad491fe28840694f97d8e6e7e9ac5ccf44452eb07e17a`.
The 2,290-file dependency prefix retains digest `ae59b1bb…`; the fresh
source-bound receipt is `37ff2959f714231474a769d6a8d45f10a537044f1e65a250b5d9f8ce6959a7bb`.
Rust composition and local immutable publication complete, including six aliases,
62 distributions and all 21 requirements: 11 active and satisfied, ten inactive.
The publication receipt is `97fad4b5bfbea6b1695ec159b52a0fd627f54ead91414291314e3d68e57603b5`.

Evidence remains in external `native-current359-build-host-state-20261106-004`
and `native-current359-dependency-host-state-20261106-003`. Independent host
reconstruction verifies all four trees, every wheel/dependency byte, 4,316
published-prefix entries and six console scripts without importing either
export. The 19-member, 48,025,600-byte public runtime archive hashes to
`a0659ab3d5931cf46e8b6aa47853031822775173bd58dd1ad90ccc79fe34264a`.
In the build journal, `independent-runtime-readback-001.json` hashes to
`bf13b836ae3605c85e4df7ff6fc69c555aa5d82adc6b4fc8dc576f78c4378ea4`;
the independent Python requirement oracle matches all 21 requirements and
hashes to `a8bda70470a4035017812acf86da191acae9b8d53dea6b2a767bdc1a7f1a26c2`.
Audit `462a926cee8fcfff` completes through the primary host command with
1,303 passes, zero failures/errors and one deliberate Pi skip; see the
[live command proof](gauntlet-rust-feature-worker.md#fresh-audit-through-the-primary-host-command).
This source predates the latest upstream reconciliation. Fresh merged-source
validation, conformance and all eligibility/causality flags remain open or false;
model requests/tokens remain zero and no parent exit closes.

## Interrupted candidate build recovery

A host-bound build now fsyncs its client cgroup's boot/device/inode identity
before launching a child. The existing candidate runner and host retained-result
diagnostic gain explicit `--repair` modes. The host durably authorizes the exact
original VM, pin, anchor and repair binary. Under all four leases, Rust reopens
only the retained kernel group and full intent-bound CID, drains both before
unloading the exact policy, and records `aborted` with a null candidate exit.
Existing normal results, partial records and replaced/foreign identities refuse;
repair never starts or admits a workload.

Fresh job `ea0ef712724b4957` uses source `8920be8bd`, Root runner SHA-256
`19bc3896686351438654515f5e2d5d39e8c62a54989e62b807e2bb0c24e715ce`
and the retained controller/image. Outside observation binds the actual Root
supervisor, Podman client, UID-65532 init, original argv hashes, read-only source,
full CID and retained kernel identity. The container has 12 GiB, zero swap,
512 PIDs, two CPUs and enforced confinement. A verified pidfd SIGKILL stops
only the supervisor; the original candidate init remains live. The host preserves
an uncertain result, and a wrong-anchor repair refuses without changing its pins.

Rust recovery completes in 40.274 seconds without outside client/container
rescue. Independent four-lease checks verify all original processes and owned
resources absent, unchanged source/anchor/CID/cgroup/policy bytes, and unchanged
metadata for all 333 historical worker records. No normal build result is
created. The canonical 871-byte aborted receipt hashes to
`14c40b3cd99094edccc805e875a4a1f019ac51b20fd9ee2e1ac06494b570efa9`.
The rebuilt host repeats the same retained repair in 22.953 seconds with all
four host records unchanged; consumed build readiness refuses before dispatch.

All 660 Mac all-feature tests, formatting and warnings-denied Mac/ARM Clippy
pass. Four selected ARM tests also pass, including both candidate/feature
kernel replacement and descendant-drain cases and the real confined-container
timeout/foreign-binding probe. A new refusal test first exposes a nullable-field
substitution gap; the final host requires every response key, including explicit
null fields. The initial failing test and older artifacts remain retained.
One necessary 278-line recovery module is added; it and the changed cgroup and
host-response modules stay below 500 lines. No crate, executable target or
dependency is added.

Evidence is in external `candidate-recovery-20261107-host-001`:

| Record | SHA-256 |
| --- | --- |
| `outside-kernel-001.json` | `8f71b0faf4d54d16e9b8c4e791f523d2b44a64353a846e79fb44028aee62b9e3` |
| `supervisor-crash-001.json` | `58e12404f7d823fd87e634d1f7b7fb5cbe82c8ce1766024d359284a83f9a02ba` |
| `host-repair-001.json` | `0d7483f27a94cca1a14e824fa92ebe0b96d11e8dab634eb6e997fe39da0fca4f` |
| `outside-repair-completion-001.json` | `b2a918bb05690c332926c918d00e033aea3a06af90abb1e297a75864c0f959a3` |
| `host-repair-repeat-002.json` | `e96776f3fa16b54a9a1a7219590de1917e1773e140e7392bb45d609453fbde21` |
| `consumed-run-refusal-001.json` | `15279ec6d8198fd1395ae15305079fb6d9182846167d0c01b50be2b7ed510755` |

The external aggregate `candidate-recovery-20261107-validation-002.json`
hashes to `c66d038edc7a30c2d183d3b624ce3d55991770ab401f5a3cca6ce6ef7b4ecb03`.
Its final host executable is `58853cbb…`; ARM test binary is `f29338a8…`.
This proves one new-generation interruption case. Historical unknown job
`b937d2e04a16c85f` remains retained. Active groups without kernel identity and
jobs without a retained full CID refuse. Broader cancellation/transport/partial-record recovery,
independent review, merged-source qualification and merge gates remain open.
All admission/qualification/causality flags stay false, with zero model use;
no parent exit closes.

## Primary host build command and merged-source follow-up

`gauntlet-host build source|run|read|repair` now shares its command handler with
the existing source producer, host-bound runner and result/repair entrypoints.
The 89-line command module replaces their separate parsing and dispatch code;
no crate, executable target or dependency is added. Source capture remains
local Git-object capture without checkout or candidate execution. Run still
requires a pinned readiness executable before recording its private one-use
intent. Read and repair retain the original VM binding and existing response
verification. The nonce stays private; all admission flags remain false.

All 662 Mac workspace tests pass, including both source entrypoints capturing
an older commit without running a checkout hook, immutable consumed-job refusal,
both runner entrypoints refusing an unpinned readiness executable before any
record, and all four read/repair forms refusing a different VM without changing
the host journal. Formatting and warnings-denied Mac/ARM Clippy pass. Frozen
primary executable SHA-256 is
`9e856cfb28cf60151976ac180353481a8a9ba8b0610f59ba3e749226269efed2`.
The eight-file source manifest hashes to
`dee3db830879bc3654e458266d6dcf0df06cf502ffceb1610077a8c69b94b108`.

Merge `53c64ae960b1c373b18816fdc6ba1491bbbd06c6` incorporates upstream
`394be6de4a075d01a79b54e2a773cbbcc4eef775`. All 153 incoming files outside
the three Native merge points match upstream exactly; the migration's completion
operations and capabilities remain present. Seventy incoming Python files parse
without imports. The refreshed map has 440 files, 79 changed and 20 added; the
420-file baseline is unchanged. Actual Python selection and Rust agree on
409 installed files, 420 entries and tree `123024f4…`. Two stale count/digest
test failures remain retained. The new expected digest comes from independent
Python recomputation. Mac/ARM Native library and CLI compilation pass.

Fresh build `b7f0b85b31df49cc` completes from that exact merge, archive
`c5c88fe8940e2ea5171818064c9202e1962e9e1a918408841b3e97ad1cbe6d1b`
(63,115,844 bytes), Root runner `19bc3896…` and retained controller `e81a214c…`.
Outside observation verifies actual supervisor/client ELF and argv bindings,
retained boot/device/inode, UID/GID 65532, empty capabilities, enforced policy,
read-only archive, separate namespaces and effective limits. Its normal
1,492.129-second execution exits zero: four selected checks and all 185
contained contracts pass. Outside completion under four leases verifies the
original processes, container, cgroups, conmon and profile are absent, with
unchanged metadata for all 333 historical records and their lock.

The primary command refuses early readback with exit two and preserves the
host pin. Terminal readback first refuses because trusted artifact capture has
not occurred; that attempt is retained. After capture, the primary reader
matches the exact result and leaves the pin unchanged. An intentional consumed
run refuses before recording or execution. Primary `build repair` also reopens
the earlier `ea0ef712724b4957` aborted/null-exit receipt without changing its
four host records. These observations use frozen host `9e856cfb…`; the build
itself used the historical runner entrypoint.

Fresh dependency job `f7a1bf6e9d3482c0` uses the same source/archive and a
retained input capsule only after checking its project/lock bytes against that
exact Git commit. Its actual Rust exporter, argv, read-only inputs and kernel
limits are independently observed. The 40.872-second export exits zero and
retains `invalid-evidence`; outside cleanup passes. Rust verifies the wheel,
stages both inert inputs and publishes an immutable local runtime. Independent
host reconstruction verifies every byte and all four tree inventories without
importing candidate code or dependencies: 1,637 wheel files, 2,290 dependency
files, 4,327 prefix entries, 124,187,688 bytes and six launchers. The exact
Python requirement loop agrees with Rust on 62 distributions and all 21
requirements, including 11 active and satisfied and MCP 1.30.0.

The separate `/opt/hol-gauntlet/controller-53c64ae960b1c373` generation is
installed under four leases using exact Git source and frozen Rust tools.
All 440 source blobs match; the installer selects 409 files and 420 entries.
Separate Rust verification and an independent Python byte/metadata walk agree
on `123024f4e315cd969571475eb6096a3f19f34e614f374c1d58fdadc2347469b5`.
The prior `e81a214c…` tree and all 333 historical records' metadata remain
unchanged. No controller or candidate is imported by these installation
checks. This isolated generation does not activate production admission.

Public records are outside Git in
`gauntlet-rust-pr-ready-evidence-20261026`. Build records are under
`native-merged359-build-host-state-20261107-001`; controller records are under
`merged-controller-20261107-host-001`.

| Record or artifact | SHA-256 |
| --- | --- |
| `outside-kernel-001.json` | `f83cbba1cc2d7a752d244b18d0608defa7b0ccb017a9c0393184632595c09408` |
| `outside-completion-001.json` | `a3c4a47d766a8856092b04e5ab76e360f30af8429e38969b8de235551e165b35` |
| `primary-host-result-readback-002.json` | `67482889047f8a39d376343fcd26dabdf0a815551ed8710564ebd3e8e7d3f529` |
| Candidate ZIP, 29,294,462 bytes | `1c7d05cfb86fcb57bcd2d78467df2f7ac04030305253b94b710629e1c79d4999` |
| Wheel, 29,544,604 bytes | `a4d9f0415ed5d3209720d2e13ef4c42a13456380b65f68a5909ea2d14a3a9d26` |
| Actual Native ELF, 47,434,216 bytes | `8ff2b0994daa8734d79ebd5dc60543536940991ca1f784d6309ab45cc42ce440` |
| Published prefix tree | `4efb2be25c6173715338bfde5945be2de1d216887b18c3ba73233a8c8e373639` |
| `runtime-public-export-001.tar`, 48,097,280 bytes, 19 members | `831a469fe3807bfc3edcb44ce0aa67704c48fa1e7f463cd3959bf36907367056` |
| `independent-runtime-readback-001.json` | `d9593adccff02e4c789a09ca059366f3fe9a5fcc5bf96a25fa320daf944da8de` |
| `independent-python-requirements-001.json` | `015e92c74f897fc2f0282310fd6093e94eee6ffed75fc5287e9e5d4f3b67106d` |
| `guest-controller-install-001.json` | `8306790db6dc2a3941c9ff89e8a837be103e01797ce53abf0f0498ace4580e46` |
| `independent-controller-install-001.json` | `0a4c63c156f2503f741f7852b83b8f19482c7199bd380a9d01aa1e73b5695795` |

The updated external aggregate
`host-build-command-20261107-validation-002.json` verifies 41 retained records
and hashes to `ed6d8d183bead6608808ee35a490f86d1d103249e1395715e09a4ae58ce40401`.
The earlier pending checkpoint stays immutable. Fresh merged-source audit
`a38df7e1b26c4905` completes against the new controller with independently
recomputed 1,303 passes, zero failures/errors and one deliberate retired-Pi
skip; readback and cleanup match. Its status remains incomplete. Broader
recovery, independent authority and qualification remain open. All
admission/qualification/causality flags remain false, with zero model requests
or tokens and no parent-exit credit.

## Durable host dispatch and private dependency results

Candidate and dependency host APIs now commit a distinct dispatch record
before contacting Lima. Exclusive creation, file/directory fsync and stable
descriptor readback make a partial write, concurrent caller or transport loss
consume the attempt. Existing Root journals continue to enforce their own
one-use boundary. Eight simultaneous callers produce one transport attempt;
reopening the host journal or cloning an invocation cannot dispatch it again.
Partial, symlinked and hardlinked dispatch entries refuse without contacting
transport or changing the linked target.

New dependency intents also require a fresh, immutable host authorization.
Historical v1 intents remain readable; a missing authorization keeps them
read-only after upgrade. The Root v1 protocol is unchanged. Its reply contains
the private intent, so the host retains those canonical bytes in the 0600
`JOB.dependency-result.json` and returns the versioned
`hol-gauntlet-host-dependency-run-claim.v1` public projection. It checks the
complete original intent and typed exit/export fields, excludes arbitrary
reply fields and refuses any actual nonce in public values. Unknown exits
and absent exports remain null; they never become a successful result.

All **669 Mac workspace tests** pass, with zero failures or ignores, including
the actual bounded-process concurrency, transport failure, restart, upgrade,
linked/partial-record, private-output and malformed-response regressions.
Formatting and warnings-denied Mac/ARM all-feature Clippy pass. Six existing
implementation/test files change; all remain within 500 lines. No repository file, crate,
executable target or dependency is added.

Both original repeat-dispatch regressions fail before the fix. The initial
dependency fixture's invalid transport basename and a subsequent trait-import
compile error remain retained alongside the corrected regression and passing
checks. Source manifest `host-dispatch-20261107-source-001.json` hashes to
`2dd47a8bf0269725dec0983bd3e1088d347af03faebae82377f6a8f6beda0e22`;
validation aggregate `host-dispatch-20261107-validation-002.json` verifies 23
records and hashes to
`cfde5d70adb296e534504aa55c8863e1ffcf1aabf1fbcd58f11ac3aec224d9cd`.

Fresh VM job `ce76a18b95d042ef` exercises the changed dependency result path
through frozen host `00a37dd2…`, source `58ee4c3f2`. It exits zero in 24.746
seconds while retaining `invalid-evidence`. Actual exporter/argv/input/kernel
observation and four-lease cleanup pass. The 880-byte public stdout excludes
the actual nonce; the canonical private reply matches Root digest `c92d5d46…`.
An intentional consumed launch refuses with all five host records unchanged.
Independent export verifies all 2,290 dependency files and 51,318,588 decoded
bytes, matching the previously verified entry digest `b01fe0d3…`.

The new 16,690,635-byte public dependency ZIP hashes to
`53a414df5e48ba0ee70746e3f1ca840ea253dcba7d79f50fffda999a22b08a21`.
Its independent export record is `d07068a3…`; outside kernel, completion and
replay receipts are `27ae4954…`, `763772a7…` and `184846b8…` in external
`native-merged359-dependency-host-state-20261107-002`. All 333 historical
records' metadata and their lock remain unchanged. Frozen primary host
`58d56497…` also reopens the original audit result without changing its four
records (`aca343c8…`). Broader interruption coverage, independent authority,
qualification and admission remain open; no parent exit closes.

## Dependency supervisor recovery

The existing primary and compatibility dependency commands now accept explicit
`repair DIR JOB STARTED_SHA REPAIR_SHA`. Read-only reconciliation returns a
closed, canonical `unknown` observation for a reserved job without a terminal.
It exposes the reservation digest without authorizing cleanup or a new launch.
The host verifies that digest before durably committing separate cleanup
authorization; an incorrect pin leaves authorization unconsumed.

Dependency launch reuses the candidate cgroup owner to retain boot/device/inode
custody before spawning the attached client. Explicit recovery acquires all
four leases, binds the original intent and executable generation, reopens only
that kernel group, and verifies the full retained container ID, name, image,
UID and intent label before teardown. It drains the client, container and
conmon groups before removing the policy. Historical numeric PIDs are never
signalled. Missing custody, contradictory records, partial reports and keyed
jobs refuse this recovery path.

The separate v2 Root repair receipt records `aborted`, a null workload exit,
actual quiescence and all authority flags false. The original host attempt,
intent and consumed dispatch remain intact. Repeated repair/read operations
must match retained authorization and evidence; they cannot relaunch work.
The historical v1 quiescent repair and completed-result protocols remain.

All 675 Mac workspace tests pass without failures or ignores, including closed
schema tampering, fixed transport, wrong-pin, linked/partial authorization,
restart, repeat-read and consumed-launch cases. Formatting and warnings-denied
Mac/ARM Clippy pass; the ARM release worker and both Mac host
executables build. Source manifest
`dependency-active-repair-20261107-source-001.json` has SHA-256
`84d5ff64a5233a221d766280c7b3ba3cb0242c68230da2252d1ea90e6e45538e`.
Local validation `dependency-active-repair-20261107-validation-001.json`
verifies eleven records and ten logs, SHA-256
`fbda5f9c399f404939bdb53c4f1c5b5240d9c36d98bafbe7fa928058047a689c`.
One necessary shared contract module is added, with no new crate, executable
target or dependency. Domain/test files remain within 500 lines; the existing
worker module aggregator only gains exports. Parent completion stays 24/62,
and model requests/tokens remain zero.

Implementation `54cda0b8037c5e1c37bfad48d1bfcb00bc959f8e` freezes worker
`c7b09e2d…`, primary host `6937e43b…` and compatibility host `690520de…`.
The worker is installed separately at its full digest path, Root-owned,
single-linked and mode 0500. All live jobs below retain product source
`53c64ae96` and controller `123024f4…`; they do not qualify the newer upstream
controller plan. The frozen-tools and install receipts bind the full hashes.

Fresh job `a6840d15c928fe37` verifies the original Root supervisor's pidfd
SIGKILL and surviving UID/GID-65532 exporter. The host retains its consumed
unknown attempt. Both command forms read identical typed unknown observations;
a wrong reservation refuses without recording cleanup authorization. Repair
completes in 2.373 seconds, retaining aborted/null-exit state. Its delayed
active-container check fails and remains preserved, so this attempt alone does
not prove active-container teardown.

Fresh job `c95ad2e6018bf743` runs the observations and recovery consecutively.
After supervisor SIGKILL, the wrong-pin refusal leaves the original container,
client group and profile active under independent observation. The first
correctly authorized repair returns an error and stays retained; the bounded
host error does not expose the Root failure detail. A fixed Rust repair call
with the same verified authorization then succeeds, and host reconciliation
retains Root receipt `ef6d50d1…`. No workload is relaunched and no resource is
manually removed. Restarted reads through both commands match, repeat repair
is identical, and changed reservation/generation pins and consumed launches
refuse on both repaired jobs. The initial active repair refusal still needs
diagnosis; a successful retry does not establish its cause.

Normal control `b8c32a6f519d470e` completes in 76.099 seconds with exit zero.
Outside observation verifies actual exporter bytes, arguments, read-only
inputs, empty capabilities, namespaces, enforced profile and resource limits.
Independent decoding verifies all 2,290 dependency files and 51,318,588 decoded
bytes, matching entry digest `b01fe0d3…`. The 16,690,636-byte ZIP has SHA-256
`05b182f2ffed4e7720e3ebfe586a5c6203c422d621a09466a418d0aa2f33af5e`.
Both command forms return identical retained reads; consumed launch and repair
of the completed job refuse, with no cleanup authorization added. The new
reader also verifies both older completed generations without changing their
original host records or authorizing another launch.

For all three jobs, independent checks under four leases verify original
supervisor/client/init death, full CID/name, client/builder/libpod/conmon groups
and profile absence, and unchanged metadata for the 333 historical worker
records plus their lock. Their private record contents are not read by the
proof. Original unknown attempts, intents, dispatch and separate repair records
remain intact. Every admission, qualification and causality flag stays false.

| Evidence in the external evidence directory | SHA-256 |
| --- | --- |
| `dependency-active-repair-20261107-validation-002.json`, 62 verified records | `af4f2bce447806386585469dffec2253ea43c39500556881f7ce1e09d28f23fe` |
| `native-merged359-dependency-host-state-20261107-006/wrong-pin-noninterference-001.json` | `5dc3bc90d1941344d82a2ec7cf9fde8d6236d28cf81096f505e5b82802939f67` |
| Same directory, `outside-completion-001.json` | `a8e5bd2d1db052b45ce5a3b2cf4c70e325477618f8da76c4bece48293afb2934` |
| `native-merged359-dependency-host-state-20261107-005/independent-dependency-export-001.json` | `0686c7e68073a007c39cb1d8a70c40a537cacdc7c166e4b5a6ec4c20a748f770` |
| `dependency-active-repair-20261107-legacy-readback-001.json` | `d9b9efe2fceff1117736cfd259faa35f9936834a6812d70b9d61753879cd7257` |

Public addendum `gauntlet-rust-review-dependency-recovery-20261107-001.tar`
contains 86 members and 17,121,280 bytes, SHA-256
`5af77dcb8e126482664194256c3d84acb41f98afaf2c601efae8ec395b3550ec`.
All members reverify. Raw and decoded ZIP scans exclude ten actual private
nonces. Earlier bundles and failures remain immutable; remote delivery and
independent review remain open. Broader partial-state recovery, first-call
failure diagnosis and every qualification exit remain open; no parent closes.

### Private repair failure diagnostics

The repair path now retains a separate Root-owned 0600 diagnostic when an
authorized cleanup or receipt step fails under the four verified leases.
It binds the job, original intent/reservation and worker/repair generations,
records the failing phase, and hashes the complete error while bounding its
UTF-8 prefix to 1,024 bytes. A fresh exclusive filename preserves each attempt.
The canonical record is capped at 8,192 bytes, reports unknown/null-exit state
and carries no admission authority. It is never returned by public read/repair.
Diagnostic-write failure also refuses; it cannot turn cleanup into a success.

At `b64ae753b`, only the existing repair module changes, remaining at 454 lines. No repository
file, crate, binary target or dependency is added. All 675 Mac tests,
formatting, Mac/ARM warnings-denied Clippy and builds pass. The ARM test ELF
adds UTF-8/control-byte boundary coverage and full-error hashing; its execution
and fresh interruption reproduction remain pending at this checkpoint.
Source manifest `dependency-repair-diagnostic-20261107-source-001.json` hashes
to `e26d1003c450fe11220b3ab72358f35e4aa424d980e177e4a54d6aac215287a2`.
Local validation `dependency-repair-diagnostic-20261107-validation-001.json`
binds seven records/six logs and hashes to
`246e8d1c81deeff36f5b35000d6b29474a26022fa2fa2a5eb7a64b4c526d7f99`.
The first active repair refusal is still unexplained; old evidence is unchanged.

That generation's ARM ELF `cb0d3e67…` passes the UTF-8/full-hash case and both
secure-file cases as UID/GID 65532. Descriptor-bound execution, four leases and
unchanged historical metadata are verified by `arm-units-001.json` in external
`dependency-repair-diagnostic-20261107-host-001`, SHA-256
`c1ea6a5be6dbe34c757a0181aefc87a717e2fba1b7d6c2ccbadcf753c2ab88ed`.

Fresh jobs `d16ae4c3b72509f8` and `e72bc0934fa81d56` kill the original
`c7b09e2d…` supervisor and verify that wrong-pin refusal leaves the container
active. Repair generation `58be99ad…` succeeds on the first call in 3.756 and
5.372 seconds. Both remain aborted/null-exit, with no diagnostic error record
expected on success. Independent four-lease cleanup and restart/repeat reads
pass; original host records remain intact. The original first-call refusal is
not reproduced, so these successes do not establish its cause.

The final followup keeps the same module within 490 lines and adds an explicit
Root-only temporary-fixture test for durable private records, exclusive names
and oversized-record refusal before file creation. Its source manifest is
`dependency-repair-diagnostic-20261107-source-002.json`, SHA-256
`2129982fd14fae798121a498205727b72a6d96d541e7a0280fd0fe6a507da45c`.
All 675 Mac tests, formatting, Mac/ARM Clippy and executable builds pass for
that final source. Local validation `dependency-repair-diagnostic-20261107-validation-002.json`
binds eight records/seven logs, SHA-256
`e5d4389fd0d86d0543ce49599254c126dbeaf500c9d5869f08fba1cf7f144db4`.
Final implementation `951f57ad5b7549e4a3d118cab019e84e3a5b01fb` freezes worker
`e728b58f…` and ARM test ELF `5ee0ffea…`; host binaries remain unchanged.
All four selected ARM tests pass: the UTF-8/full-hash case and two secure-file
cases run as UID/GID 65532, and the explicitly selected ignored Root fixture
runs as Root. It creates only temporary apparatus data and proves private 0600,
single-link durable records, unchanged prior bytes, distinct attempt names and
oversized-record refusal without another file. This is not product execution.

The first harness's over-escaped count regex rejects the successful Rust test
output. Its unchanged failure receipt remains retained; data-only readback
verifies all four passes without rerunning tests. Corrected readback
`dependency-repair-diagnostic-20261107-host-002/arm-units-002.json` hashes to
`07e49282cfa6438aef7f4a93fe8ebb795546eb08ad886c1019ed903126f13694`.
Final-worker reads through both host commands match the two retained repair
results after changing only reader generation. All seven original host records
per job remain unchanged; no workload or cleanup is relaunched.

Live validation `dependency-repair-diagnostic-20261107-validation-003.json`
binds 56 records, SHA-256
`e437160f417f406ec1dd92b58e5fb28fe818c347f8d025754b6dae0305aab967`.
Public addendum `gauntlet-rust-review-repair-diagnostics-20261107-001.tar`
contains 84 members/952,320 bytes, SHA-256
`bb7206c9f3e5af057c42df23d953f87e9367d0de0d2b756bb394f080c123fb8c`.
Every member reopens and twelve actual private nonces are excluded. Old
attempts, bundles and the parser failure remain intact. Remote delivery and
independent review remain open. The original active refusal remains unexplained;
partial-state recovery and qualification are still incomplete, with no parent
exit closed and zero product model requests/tokens.

### Early dependency creator custody

The dependency runner now creates and retains its client cgroup before loading
the job policy or creating its container. The policy-load parser and mutating
Podman create command enter that held group in pre-exec; the later client uses
the same group without replacing its receipt. A separate private, durable
`dependency-creators-ready.v1.json` binds the original intent, reservation,
worker generation and cgroup receipt before either mutating helper starts.
Cleanup drains that group before policy removal on ordinary helper failures.
Existing public status, repair and reservation protocols are unchanged.

Only five existing Rust files change, all within the source-line guideline;
no repository file, crate, target or dependency is added. Source manifest
`dependency-early-owner-20261107-source-001.json` hashes to
`5789101097e76846ae3f49f512835ea1ed8ac4eb5e42860377f5c2297283b294`.
All 675 Mac tests, formatting, Mac/ARM warnings-denied Clippy and builds pass.
Local validation `dependency-early-owner-20261107-validation-001.json` binds
eight records/seven logs, SHA-256
`9ec3b3b2e5240dc375605e6f1cac6abbf9911630d33e8e4afc0a50d664773111`.
Implementation `9ec64a00555045363f093a013943fa037ad76302` freezes worker
`3112ffc2…` and ARM test ELF `0208f437…`. The explicitly selected Root placement
fixture passes under all four leases, preserving metadata for all 333 historical
records and their lock. It stops inert children before their helper executables
run, verifies placement through the production command constructors, and includes
an unplaced control. Held pidfds, parent/start identity and executable inodes
bind its child signals. It is apparatus evidence, not an observation of actual
helper binary execution. External `dependency-early-owner-20261107-host-001/arm-units-001.json`
hashes to `1f8949e76869abfdbc417cd038aa69786d0d038deec2fae627e6303bf6e706a9`.
The first install receipt's stale source annotation remains intact; a separate
hash-verified readback corrects it without reinstalling or rewriting evidence.

Fresh job `a4d1927e63bc805f` watches the CID receipt's close-write before host
launch. The outside watcher holds the exact original supervisor pidfd and sends
SIGKILL at that event. It verifies the complete intent-bound CID, the retained
group/ready receipts, an empty client group, no running marker, container state
`created`, and init PID zero. The original host call returns uncertain/exit 2;
that is not a workload exit. Both read commands agree on unknown/null state.
Wrong reservation repair refuses before authorization, and outside observation
confirms the created container, empty group and enforced policy remain intact.

Rust repair succeeds on its first call in 6.110 seconds, recording aborted/null
state without a running marker or captured export. Independent four-lease checks
verify original supervisor, container/name, all client/builder/libpod/conmon
groups and policy absent. No outside cleanup or transport rescue is required.
The original intent, authorization, dispatch and unknown records remain unchanged.
Six restart/read/repeat-repair/different-pin/consumed cases pass. External
`native-merged359-dependency-host-state-20261107-010/outside-completion-001.json`
hashes to `66f962c0a789cc201139385986ddc2015db1a38bbb9a84eb4e17970e3da98210`;
restart readback is `d3eb445eaa98bf2c44343548d2325b5745d2c7cb9c3df279a4bbeaacebf0cf4a`.

Normal job `90d7b6a4c21e385f` exits zero in 58.699 seconds with the same worker.
Outside observation verifies the real UID/GID-65532 exporter, pinned executable
and inputs, read-only mounts, empty capabilities, enforced policy and fixed
kernel limits. Cleanup and both retained-result commands pass; consumed launch
and completed-job repair refuse without cleanup authorization. Independent inert
ZIP decoding verifies all 2,290 files/51,318,588 bytes and entry digest
`b01fe0d3806503226d77118a977594ee5603025ed6412ea1d24ae6a0daf5f866`.
Its 16,690,636-byte ZIP is `27d5ca75241a854ad87631f200abb7f31a3c9781ca0b373a9c200beb5b472120`;
independent export record is `1fed3cf112e8d39159ad8ec4a596f6145e00f278b30939c1f8ece73da86a03b2`.
The live product remains exact source `53c64ae96` and controller `123024f4…`.

The preceding SIGSTOP/SIGKILL fixture `f68d20a9b7c4315e` is retained separately.
It reaches the same pre-client boundary and Rust removes its resources in 4.812
seconds, but SIGSTOP also stops the original sudo monitor. The supervisor stays
a zombie, the outer host-wrapper wait expires, and the first absence check fails.
Outside code continues only that verified monitor through its held pidfd to reap
the original process; subsequent cleanup/restart checks pass. Its caller exit is
unobserved, and it does not prove unassisted full completion. The oversized SSH
watcher failure and bounded management-pipe correction also remain retained.
This explains that fixture's failure, not the original active repair refusal.

Live validation `dependency-early-owner-20261107-validation-002.json` binds 108
records, SHA-256 `a27350b9443632b5ce6f83b7d92bdd38280f83d3a42a87416b0fe0301a3b497d`.
Public bundle `gauntlet-rust-review-dependency-early-owner-20261107-001.tar`
contains 115 members/17,500,160 bytes, SHA-256
`07ec7eaa3688c4942f7de6f27a8f0083976f9f7096865c23f8ddf1432f76147d`.
All members reopen and fifteen actual private nonces are excluded, including
decoded ZIP contents. Remote delivery and independent review remain open.
Missing-CID and malformed/partial records remain unknown; this change does not
authorize adopting missing or foreign identity. All parent exits remain 24/62,
all eligibility flags stay false and product model requests/tokens remain zero.

### Missing dependency container receipt recovery

An explicit native v3 / public host v2 protocol now covers a missing CID receipt
or an EOF prefix of the exact canonical original receipt. Other malformed,
foreign or noncanonical records refuse. Recovery requires the original durable
creator readiness and retained boot/device/inode cgroup custody, the exact
intent/reservation/worker and repair generations, explicit host authorization
and all four leases. A retained running marker, client log or export refuses
this pre-client path. Original incomplete bytes are never repaired in place.

Pinned runtime files are checked before killing and draining the retained
creator group. Podman runtime queries and container lookup happen only after
that group is absent, so a stopped creator cannot retain its storage lock
across reconciliation. Any discovered container must match the exact full CID,
name, image, UID and intent label and still be `created`, stopped, with PID zero.
A new exclusive Root-0600 attempt witness is durable before removal. Repeated
attempts must agree on identity; partial witnesses remain retained without
authority. A prior absence witness cannot authorize adopting a later container.

The separate v3 completion binds the ready receipt, original incomplete bytes
and selected witness. It reports aborted/null-exit, no running marker or export,
zero model requests/tokens and all eligibility flags false. It is published by
durable staging in the job slot and atomic no-replace rename into the journal;
the original attempt and any torn staging bytes remain intact. Historical
protocols retain their existing readers and write behavior.

One necessary ARM-only 438-line module is added within the existing crate;
eight existing Rust files also change, with no new crate, executable target or
dependency. Source manifest `dependency-creator-recovery-20261107-source-002.json`
hashes to `05299afc5aa84e973f847a98660659926a289c77f79a40708c4457416cf72627`.
All 676 Mac tests, formatting, warnings-denied Mac/ARM Clippy, final ARM worker
and test-ELF builds and default host builds pass. The Mac checks precede the
final ARM-only ordering/cfg correction; the source manifest proves the effective
Mac source unchanged. Local validation
`dependency-creator-recovery-20261107-validation-003.json` binds eight records
and seven logs, SHA-256
`8a4835e7c73cf36db191cb6891aa0e0ed72a35699ac865b37a46a1b1d85dc292`.
Worker `2db25c38…`, test ELF `5d40e14a…`, host `ff7cc50e…` and compatibility
command `f96d76c2…` are built; ARM execution and live missing/partial-CID,
interrupted-repair and normal-control evidence are still pending. Partial
intent/reservation/report recovery and qualification remain open. No parent
exit closes and no new receipt grants admission.

The first ARM run passes the classifier, private-error hashing and both secure
file cases as UID/GID 65532. The explicit Root fixture then fails because it
calls the fixed-slot opener while using a temporary slot. Its failed record
`dependency-creator-recovery-20261107-host-001/arm-units-001.json` remains
`eb4cf11f…`. Independent four-lease inspection finds its one empty leaf group;
after pinning device 31/inode 53756, cleanup removes only that empty fixture
directory, with no signals, containers or policies changed. Inspection and
cleanup are retained separately as `bbbe2c33…` and `6d8e2884…`; all 334 historical
metadata rows remain unchanged. This is apparatus cleanup, not product recovery.

The correction extracts the unchanged atomic publication primitive for use with
temporary directory descriptors and runs those assertions before creating a
group. Production commit still opens the fixed Root slot before calling it.
The final module is 441 lines and I/O owner 403. Source manifest
`dependency-creator-recovery-20261107-source-003.json` is
`d571bceeaf5934ad6fd03c280e795f87bbedadbe9ef4d63d16f6000076e5058f`;
local validation `dependency-creator-recovery-20261107-validation-005.json` is
`c08a5bd336dec32e62a16f7e37f21fec09483a566a606f435a40225c07b16d43`.
Final formatting/ARM Clippy and builds pass; the effective Mac source and host
build remain unchanged. Final worker `7b595c69…` and test ELF `d9f98bc3…`
supersede the earlier binaries for subsequent execution. The corrected Root
fixture and live fault cases remain pending; no failed evidence is replaced.

Final implementation `c9aaa25ce73386a49678c06eeb3b2f05cd792c8d` freezes worker
`7b595c69…` and test ELF `d9f98bc3…` in the separate
`dependency-creator-recovery-20261107-host-002` directory. Installation holds all
four leases and preserves all 334 historical metadata rows. The five selected
ARM cases now pass: four unprivileged cases and the explicit Root temporary
publication/placement fixture. Its receipt is `d21ab5f7…`. The placement fixture
still stops inert children before their helper binaries execute; actual helper
execution is established separately below.

Fresh job `c43e7a1580bd269f` pins the real Root Podman creator by executable
inode/hash, exact argv, parent/start identity and held pidfd. The outside watcher
stops that post-exec creator, verifies it inherited none of the four leases and
kills only the original supervisor through its held pidfd. The creator survives
stopped in the retained group; the original CID receipt and running marker are
absent. No Podman query runs while it is stopped. Both commands read unknown/null
state, and wrong-reservation repair refuses without authorization. Independent
four-lease observation confirms the same stopped helper, group and enforced
policy remain unchanged.

The first authorized Rust repair succeeds in 3.246 seconds. Outside checks
verify the original supervisor and creator gone, job groups/name/profile absent,
the original CID receipt still missing, a durable absence witness, and the Root
v3 completion matching its public host v2 projection. No outside helper cleanup
or transport rescue is needed. All six restarted-read, repeat-repair, changed-pin
and consumed-launch cases pass. Outside completion is `e6140e69…`, restart
readback `6e9c4a9d…`, and native completion
`937c3f0104d0a90bf3db9a4bca0f554b1de6414af66acd315abe549d8cf20968`.

Job `7e04b9c128a36df5` proves an actual incomplete original write. After pinning
the post-exec creator, the outside watcher lowers only the original supervisor's
`RLIMIT_FSIZE` soft limit from unlimited to 32 bytes. The already-forked creator's
limit remains unlimited. The verified sudo monitor and supervisor are continued
as part of the planned fault release before the creator resumes. The supervisor
then exits without a SIGKILL fallback, leaving a Root-0600, 32-byte prefix of the
exact canonical CID receipt. The apparatus never edits those bytes. Outside
inspection verifies the bound full CID, `created` state, no running/init process
and an empty retained group. This uses Linux's documented per-process resource
limit and partial-write behavior ([getrlimit](https://man7.org/linux/man-pages/man2/getrlimit.2.html),
[write](https://man7.org/linux/man-pages/man2/write.2.html)); the observed result
is retained in `09f3907c…`, not inferred from those references.

Wrong-pin noninterference passes before cleanup. A second outside watcher pins
the actual repair supervisor and kills it at the new witness's close-write. It
verifies the witness durable, creator group absent, container still present and
Root completion absent. Receipt `6849dbd3…` binds that interruption. The host
retains its uncertain repair and cleanup authorization. A second Rust call uses
that exact unchanged authorization and succeeds in 3.971 seconds. Both witnesses
and the original partial bytes remain; outside validation checks their full
bindings, the deterministic selected witness and all resource/process absence.
All six restart/refusal cases pass. Outside completion is `a90323aa…`, restart
`d23a2b14…`, and native completion
`68a6a2787d20992661344d5cc69f80b313ac4ad8f7075bff7073a7952cbd8d06`.

Earlier job `9b72e063a5d148cf` misses the post-create-inspect observation window
before applying a limit. Its watcher failure and supervisor-loss host result
remain retained. Separate reconciliation observes a complete 221-byte receipt
and a created/unstarted container, without a retained successful supervisor
identity observation. Existing v2 Rust repair succeeds in 4.676 seconds, followed
by outside cleanup and six restart/refusal cases. This failed attempt is not a
partial-write proof; its harness is `ee735f53…` and cleanup `b7b8f0d3…`.

Normal control `a180c5e9742bd36f` exits zero in 64.422 seconds with the same final
worker. Outside observation verifies the actual UID/GID-65532 exporter and fixed
input, capability, mount, namespace, policy and cgroup limits. Both read commands
agree; consumed launch and completed-job repair refuse before cleanup authority.
Independent inert ZIP decoding verifies all 2,290 files/51,318,588 bytes and entry
digest `b01fe0d3806503226d77118a977594ee5603025ed6412ea1d24ae6a0daf5f866`.
The 16,690,636-byte ZIP hashes to
`ad0b900f6a02201680b919e5c436dac85b35d5b69ef00a8d2e5c5505c7adb112`;
export validation is `201867a0…` and cleanup `8eeada16…`. These live cases retain
product source `53c64ae96` and controller `123024f4…`; they do not qualify a newer
upstream product generation.

Live validation `dependency-creator-recovery-20261107-validation-006.json` binds
168 records, SHA-256
`1e2228e6bf7493d6029799081d29156aed0347550dc78444a1d91cad555e3cab`.
Public bundle `gauntlet-rust-review-dependency-creators-20261107-001.tar` has
179 members/18,176,000 bytes, SHA-256
`130feaed3dbf4a1bf4c31682d2069edc3e95302eb6d8f955e95afed5d63367c0`.
Every member reopens; nineteen actual private nonces are excluded, including
decoded ZIP contents. All four jobs' final cleanup checks preserve the 333 old
records' metadata without reading their contents. Remote evidence delivery,
independent review, broader partial intent/reservation/report reconciliation and
qualification remain open. Parent exits stay 24/62; all admission flags remain
false and product model requests/tokens remain zero.

## Dependency reconciliation without relaunch

`gauntlet-host dependencies run|read` and the existing dependency diagnostic
share their handler. The historical run argument shape remains supported.
Read always uses the original intent's transport and VM; a different explicit
VM refuses before transport. It sends that private intent only over the
bounded management pipe to an outside-pinned Rust reader.

The fixed Root read operation acquires all four leases and addresses only the
requested dependency job, without scanning unrelated worker records. It checks
the original retained intent and inputs, the terminal/report binding, actual
container/client/conmon/profile absence and every captured ZIP path, byte and
CRC. It starts no workload, imports no package and changes no VM job record.
The shared codec rejects foreign, malformed, missing or authoritative frames
before returning a typed public result without the private intent or nonce.
The host retains a per-reader public reconciliation record; repeated matching
reads are idempotent and historical intents gain no dispatch authorization.

All 672 Mac workspace tests pass with zero failures or ignores, including
actual fixed-process legacy read/reopen and both CLI forms refusing a different
VM. Formatting and warnings-denied Mac/ARM Clippy pass; the ARM worker builds.
No file, crate, executable target or dependency is added. The existing worker
module aggregator gains two export lines; all changed domain/test files stay
within 500 lines. The initial Clippy boolean simplification failure is retained.

Source manifest `dependency-reconcile-20261107-source-001.json` hashes to
`34a6a356c1e97b39a797bd3f63b5180e762d5c6e8196a7f61788659ebf8205bb`.
Validation `dependency-reconcile-20261107-validation-001.json` verifies nine
records, SHA-256
`02f76021214425352f0edc31a111452f3865967c4c85ed5754693a32e9638823`.
Implementation `cfdbf6a9f` freezes Root reader `96215aa2…`, primary host
`2d985d12…` and compatibility host `fa1bd085…`. The new reader is installed
separately at its full digest path, Root-owned, single-linked and mode 0500;
older executables remain unchanged. Install receipt `8f39e2f7…` holds all four
leases and checks the historical metadata without reading old record contents.

Both host entry points reconcile retained jobs `f7a1bf6e9d3482c0` and
`ce76a18b95d042ef`. Original intent/result/authorization/dispatch records are
unchanged, repeated reads are identical, and the historical intent still has
no launch authorization. Each read verifies all 2,290 exported files and
51,318,588 decoded bytes. The combined retained-read receipt is `a9ebcb0c…`.

Fresh job `f02a618c39de745b` tests actual host loss. After the independent
kernel snapshot observes the confined UID/GID 65532 exporter and the original
Root supervisor, the harness sends SIGKILL only to its owned Rust host child.
The host exits -9 after 25.496 seconds, with empty stdout/stderr and no local
private result. That original attempt remains unknown at the interruption;
the guest processes are not signalled or relaunched. A read attempt while the
worker lease is held refuses. Read-only reconciliation subsequently recovers
the Root terminal, exit zero and `invalid-evidence` report. Both command forms
return identical public results, and a consumed launch refuses.

The recovered 16,690,636-byte dependency ZIP hashes to
`f6f21e3bd4bc4183df445a8024546c22edd13c5bd274de8780af10bd0e7d4c6a`.
Independent host decoding matches every file and entry digest `b01fe0d3…`;
no exported dependency is imported. External journal
`native-merged359-dependency-host-state-20261107-003` retains kernel receipt
`29c8ac45…`, interruption `180290ed…`, reconciliation `04b9cf39…`, independent
export `695297b6…` and cleanup `7a609fb6…`. Cleanup verifies containers,
conmon/client/builder cgroups, profiles and original processes absent, with
all 333 historical records and their lock metadata unchanged.

Live validation `dependency-reconcile-20261107-validation-002.json` verifies
29 records, SHA-256
`3adedd4a3c8263435368a447cc2cefad4284bae45bd6a2db57c58f5a4387d2c1`.
The two harness setup errors occurred before any transport and remain recorded.
All admission, qualification and causality flags remain false; model requests
and tokens are zero. This proves recovery of a retained dependency result;
broader interruption, admission and independent authority exits remain open,
and no parent exit closes.

## Upstream followup after dependency recovery

After the recovery checkpoint, four commits advance upstream from `394be6de4`
to `e43ca02cfb5178ad4276d9ffd4e8f9d4a575f1ab`. Merge `efa6f05e3` preserves
all fourteen incoming files exactly, including drain-lane writer tracking,
single runtime-status resolution, retry regressions and two Git Allow cases.
Twelve Python files parse without imports. All 297 existing scenario objects
are unchanged. The 440-file source map updates only the fixture/catalog hashes;
the immutable 420-file baseline remains byte-identical.

Python's actual, source-pinned bootstrap selector and Rust's exact Git reader
independently agree on controller
`39bde055e24a959da3b3fd19c9411c687da2122306a2cf56d2ef82183181afef`:
409 selected files, 420 entries and 3,978,211 file bytes. The first workspace
run correctly fails its stale `123024f4…` expectation. That failure remains;
the updated pin follows the independent Python result. The new generation is
not installed, and the retained live runtime/audit still belong to `53c64ae96`
and installed controller `123024f4…`.

All 672 Mac workspace tests, formatting, warnings-denied Mac/ARM Clippy and
Mac/ARM Native library/CLI compilation pass. Imported Guard command tests
compile on Mac; they are not executed on the host. The existing ARM musl
`libc::time_t` warning stays visible. Source custody `35e3c338…`, Python plan
`dc4cc3fd…` and Rust Git readback `d32a9125…` agree. Aggregate
`upstream-followup-20261107-validation-001.json` verifies eleven records and
eight logs, SHA-256
`a77e2a86f0852434e79c3fedd2e61ac1459e5efa9abfe98ebdbaab21e7ad6432`.
The original failed step counted successful batches only; the aggregate
reconstructs its complete 300 passes and one failure from the retained log.
No new repository file, crate, target or dependency is added by this followup.
Fresh product execution, independent review and required current-head CI
remain open; all eligibility flags remain false and model use remains zero.

## Upstream runtime followup after early creator custody

Three further commits advance upstream to
`59ff1696b7dd9b57bc6db1554e46ce5c78d82f68`. Merge
`dbd3073ac1d1892fcf8c1ca659b6a9b1aa3efa19` has no conflicts and preserves all
eighteen incoming files exactly. Ten Python files parse without imports; no
product code runs on the host. The new gateway retry-delay module and enlarged
runtime cache logic stay upstream-identical and remain an explicit Rust ownership
review question. Neither approval choice is changed by the migration work.

The immutable 420-file baseline and 440-file Gauntlet source map are byte-identical
to the early-custody checkpoint, retaining 79 changed and 20 added Gauntlet files
against that baseline. The merge changes no Gauntlet source, so no delta refresh
is needed. All five early-custody Rust files still match manifest `57891010…`;
the 675-test/Clippy evidence and live proof are not relabelled as product execution
of the newer generation. No new controller is installed. Source custody
`upstream-runtime-followup-20261107-source-001.json` hashes to
`8ee297414285f6f4d6b6f5ac9c255372d183918631c6d1b75f140f4c3094bf43`.
Mac/ARM Native library/CLI compilation and Mac Guard-command test compilation
pass; the product tests are not executed on the host. The existing ARM musl
`libc::time_t` deprecation warning stays visible. Aggregate
`upstream-runtime-followup-20261107-validation-001.json` binds four records and
three logs, SHA-256
`e220ad84e8a409f13bde9f3d8ca452e9bb8589ba3570b035d4dd1d945065334b`.
The nine-member/30,720-byte public addendum
`gauntlet-rust-review-runtime-followup-20261107-001.tar` hashes to
`7b2f5a33ecaf9bf63bbd0e16a0168612a00bfaa13fe544c4086c70770e5e60df`.
Every member reopens and fifteen actual private nonces are excluded. Fresh
current-product execution, remote delivery, independent review and all five
required current-head CI jobs remain open. Parent exits remain 24/62, all
authority flags stay false and product model requests/tokens remain zero.

## Upstream MCP notice followup

Upstream `380cf0e4f747b16d219605b6a1aa110b98137f5b` advances the resident's
queued-approval notification path and is merged without conflicts as
`c935f19a9ca1656cfb3c8880628c555ee472847b`. All seven incoming files match
upstream exactly. The Python change is documentation only and parses without
import or execution. Source custody `upstream-mcp-notice-20261107-source-001.json`
is `15dc7460…`. The immutable 420-file Python baseline and 440-file Gauntlet map
are byte-identical, as are the nine recovery files in source manifest `d571bcee…`.

The Mac Native library/CLI/test-target check passes. The broader ARM test-target
check initially fails because the existing branch-local worker-budget test
imports macOS-only Bash cancellation support on Linux. The failed record
`85f95fb5…` and complete diagnostics remain retained. Fix
`04bf61d723504746b92ee0a2c79071bce5d7dec4` adds four macOS cfg attributes only to
that import, fixture, Drop implementation and cancellation test. The two generic
worker queue/drain tests remain enabled on Linux. Production source and effective
Mac source are unchanged; source manifest `ff9ece6f…` verifies that removing just
those four test attributes recovers the exact previously compiled bytes.

Targeted formatting and the repeated ARM Native library/CLI/test-target check
pass. Native tests are compiled, not executed on the host. The existing musl
`libc::time_t` warning remains visible. Validation
`upstream-mcp-notice-20261107-validation-001.json` binds six records/four logs,
SHA-256 `b3846a2dbb90fc444ba62613080f58a66df01897044040f7d7b9002a4bdf335d`.
All Gauntlet checks and live recovery evidence retain their exact earlier source
hashes; no product execution is relabelled to this newer generation.

Public addendum `gauntlet-rust-review-mcp-notice-20261107-001.tar` contains thirteen
members/40,960 bytes, SHA-256
`e71677405d482021ea8e282fc70e05bc76195aaca95eadd5a2c8879256ed950c`.
Every member reopens and nineteen actual private nonces are excluded. No file,
crate, binary target or dependency is added by this followup. Independent review,
remote evidence delivery, newer-source qualification and the previously open
parent exits remain open; product model requests/tokens stay zero.

## Retained 3.59.0 dependencies for `83f079b5c`

Fresh dependency job `5ea8b3c2907df614` independently captures the same exact
`83f079b5c` product source, archive `8ce7383a…`, and a three-member input capsule.
Outside observation binds the actual Rust exporter ELF, five argv elements,
mounted project/lock bytes, prelaunch intent, held pidfd, enforced profile,
namespaces and effective production resource limits. The 36.34-second run exits
zero and retains an ineligible producer result. Under four leases, independent
checks verify cleanup and unchanged metadata for all 333 prior worker records;
they also verify the actual candidate-client paths for both earlier probe jobs.

Rust stages 2,290 inert files under the pinned system interpreter. Independent
host reconstruction reuses five bounded helpers from the existing 3.58 verifier;
it imports no candidate or dependency. All 2,633 tree entries and 51,318,689 file
bytes match, digest
`ae59b1bbf115f41cab193c47e5f47caf1abef701a03c4a4e041370e63fd2f30e`.
There are 61 distributions, including MCP 1.30.0. The source-bound prefix receipt
is `416ee68d0db6f6c75e3c7146d928291e8ee694336671f8ce34114d470ec416a3`.

Evidence lives in external `native-current359-dependency-host-state-20261106-001`:
`outside-kernel-001.json` hashes to
`2b7979aca179f6fd2f043cd82a3f94f070b9e9256430839f9254075ad876f217`;
`outside-completion-001.json` to
`7e6209469c91353b49d7d56ceeea87849bb23073cac2b514b90c4a72e4fcb115`;
the six-member `inert-prefix-export-001.tar` to
`db6966fb1875b542c0c94ce900f27520edfdb0a6e87667ada8c236aee918f07f`;
and `independent-prefix-readback-001.json` to
`21504a167f59075bde699836321dd13e082cfe636030525ab859fae394b6c98b`.
Private intents, nonces and keys are excluded from the export. Candidate wheel
composition and publication remain open, with no artifact admission, qualification,
causality or model use claimed.


## Retained dependency report finalization

Source `e3619c0e3563edd901750243863b33e2e690a945` adds explicit recovery for a complete Root report whose terminal is absent. Thirteen existing Rust source/test files change; no source file, crate, binary or dependency is added. Intent, reservation, running marker, CID and inert archive must agree, and the original process identity and candidate resources must be absent. Read remains unknown. Explicit repair retains a Root witness and atomically publishes the missing terminal without replacing original report bytes. Partial or conflicting reports and existing partial terminals remain unresolved.

The terminal stays `invalid-evidence`. Its known exit comes from the original full Root report; it grants no Guard verdict, admission, qualification or model credit. Original unknown observations remain retained. Repeated repair verifies its witness and terminal without another workload launch.

Source manifest `dependency-report-finalization-20261108-source-004.json` is `3ddb6faa82d9e0d38f81430a54f64004170b5666fd8173545f97a002be096ef9`. Frozen worker `385f4a92…` is 10,329,800 bytes; host `7ba685b7…`, compatibility CLI `efa6bb02…` and ARM tests `8fc584f3…` are separately pinned. Installation holds four leases and preserves all 334 historical metadata rows. All 677 Mac tests, formatting, Mac/ARM warnings-denied Clippy, ARM release/test builds and default host builds pass. Six selected ARM cases pass, including an explicit inert Root fixture. Initial temporary-path, formatting, moved-import and outside-wrapper failures stay retained. Local validation `fec6c4f4…` binds 33 records and identifies each check's source.

Fresh job `e6d3098a47cb125f` is interrupted through its held pidfd at the original supervisor's terminal `openat` entry. The full report is already retained; no report or terminal bytes are edited. Report SHA-256 `657b14da7c3eeee6a0a2b09686ecc9b6d04dc113760a3de7df9223971f4fb938`, inode and timestamps remain unchanged. Both host commands observe unknown; the wrong reservation refuses before authorization. Independent four-lease readback proves resource absence and no finalization witness.

The first authorized finalizer is interrupted at `renameat2` entry after durable witness and staging writes. Reads still return the identical unknown observation. The same-authorized retry finishes in 3.812 seconds. Both witnesses and original interrupted staging bytes survive; terminal `809cd486…` matches those staged bytes. Eight restart/refusal cases pass. Independent final reconciliation `57576672…` confirms original report and metadata preservation and resource absence.

Normal `b4a9f07e13d2865c` exits zero in 116.467 seconds. Outside kernel observation binds UID/GID 65532, exporter/inputs, read-only mounts, empty capabilities, namespaces, enforced profile and resource limits. Both exports independently match 2,290 files/51,318,588 decoded bytes and framing digest `b01fe0d3806503226d77118a977594ee5603025ed6412ea1d24ae6a0daf5f866`. Four normal read/refusal cases and five reader-compatibility cases pass: the new reader opens older v2/v3 repairs and completed v1; the previous reader opens the new finalized v1.

Live validation `dependency-report-finalization-20261108-validation-006.json` binds 111 records, SHA-256 `c131cef99b25f4e3e635ef0862b099fb72b2bec495142142343e6228c6515578`. Public `gauntlet-rust-review-dependency-reports-20261108-001.tar` contains 129 members/34,877,440 bytes, SHA-256 `a9d352ef3796e436f1f901af38ef2823968c59c605dbc844c26fc03d3512e7d9`. Every member reopens, and twenty-one actual private nonces are excluded, including from decoded ZIPs. Remote delivery, independent review, missing/partial intent and reservation states, partial reports and qualification remain open. Parent exits stay 24/62; model requests/tokens remain zero.

### Upstream receipt and source-map followup

Main `7ac2d7a90d270f71bb45032c77ccb8c5edfada19` merges as `425a921c9aadbf17f0b4eb79ef74d612ae89b082` without conflicts. All twenty incoming files match upstream. The reviewed Git fixture and scenario update two source hashes; the immutable 420-file Python baseline and 440-file inventory remain. The first merged suite rejects a stale controller-tree expectation. Independent data-only oracle `3e0971d2…` checks bootstrap's unchanged selection and all 409 file hashes/eleven directory modes, deriving `52da7281…` without importing or executing controller code. `85814edab` updates the source delta and expected test pin.

All 677 merged Mac tests, formatting, Mac/ARM Clippy and default host builds pass. Native library/CLI/test targets compile on Mac and ARM; Native product tests are not executed on the host. The existing musl warning stays visible. Validation `upstream-receipt-recovery-20261108-validation-005.json` binds nineteen records, SHA-256 `3ae79738f0da291f5ea9fe16e3e7a3294f0c33e1d2a50357a733474ff58d83a6`. Recovery source hashes remain unchanged. Live product execution still belongs to `53c64ae96`; newer-source qualification stays open.

## Interrupted dependency preparation recovery

Source `70206a42cfb144ed471063cd0a9288c7a94ce07b` adds explicit retirement
for an interrupted reservation/intent write. Test correction
`7bfc15a8ceeb782f2172330f93e8932dab4c9079` uses the existing inert journal
constructor for a Root temporary-file fixture. Twelve Rust files change,
including three necessary modules: contracts (424 lines), host authorization
(300) and Root preparation recovery (411). Existing repair owners remain at
494/491 lines. No crate, executable target, dependency, proof script or Markdown
file is added.

The original outside intent derives an **expected** unkeyed started marker.
Retained files must be absent or exact byte prefixes of those canonical bytes.
Reads preserve actual content and metadata hashes separately from the expected
marker hash. The snapshot binds device, inode, mode, UID/GID, link count, size,
mtime and ctime with nanoseconds; atime is excluded. No original marker or
intent is reconstructed or replaced.

Native unknown v2 / host unknown v2 records grant no cleanup or execution.
Host authorization v2 pins the snapshot and original executable. The explicit
mutator holds all four leases, checks input custody and refuses any progressed
running/report/terminal/key, CID, creator-ready, cgroup-receipt or exported-ZIP
state. It verifies client-group absence before runtime queries and verifies
container/profile absence. Missing kernel custody cannot authorize adoption or
signals. Preparation retirement requires the original executable; newer readers
may verify a retained receipt.

Native repair v4 privately retains the full original intent and publishes an
aborted/null-exit receipt through the existing atomic no-replace publisher.
Host repair v3 removes the private intent. Normal admission checks v4 before
requiring a complete started marker, and both host and Root refuse reuse.
Readers retain v1/v2/v3 support. Older readers safely refuse the new preparation
format; this is not proof of rollback to an older mutator.

Source manifest `dependency-preparation-recovery-20261108-source-003.json`
hashes to `b4cb2ebe1f3e43b16b42ae6bc6ad924cb91e27b3419c0ed88f2fdc140b7aa046`.
Frozen record `dependency-preparation-recovery-20261108-host-002/frozen-tools-001.json`
is `15cc261c0de69cfbe5632945b080f96bf4edc3d1299a62a577c78eee030dada5`.

| Tool | SHA-256 |
| --- | --- |
| ARM worker, 10,405,600 bytes | `703d59cae16a777aab0e779aba272345593e4250d5eb7366cfea8a914428c168` |
| ARM tests, 18,554,832 bytes | `71aa9637b50f835f0ec554104e8d2dfe24b74963ef596904b7f0395c05c2bb84` |
| Primary host | `4c32654bfd00d875506368e12c96d74492ce334bf1c8f184303c39ebebe0a560` |
| Compatibility host | `ac2b450fefabe6da3c387fc3ff16470dfd8dc3bdc51b12343e65fe447bb43283` |

All 680 merged-head Mac tests, formatting, warnings-denied Mac/ARM Clippy and
builds pass. Seven selected ARM cases pass: five unprivileged cases and two
explicit Root inert fixtures. The first compile type error, wrapper newline
error, stale installer length and Root fixture failure stay retained.
The fixture correction reproduces the identical production worker bytes.

Fresh fault observers bind the outside intent hash, original executable,
argv hash, parent, start ticks and held pidfd. Signals are forwarded before
syscall tracing begins at the current input receipt's close. An inert fork
preflight verifies SIGCHLD forwarding. The observers stop at actual ARM
openat entry/exit and send SIGKILL through that original pidfd; they edit no
record bytes or syscall/register values.

| Job | Observed preparation | Explicit retirement |
| --- | --- | --- |
| `e3b06f7a914d52c8` | Stopped before reservation creation; both files absent | 3.950 s |
| `c6a72e04d8915fb3` | Empty started file; intent absent | 3.933 s |
| `7190d4ab3ce826f5` | Complete 301-byte started marker; empty intent | Interrupted publication, then same-authorized retry in 2.220 s |

For the third job, a separate pinned observer stops the repair at renameat2
entry with NOREPLACE, after the complete private receipt is staged. It kills
that repair supervisor before publication. Both read commands still return the
identical unknown observation. Retry publishes the same receipt hash
`f2bd485c18b1d91423df46874453fbebc3468da39a8a9f455144e1b5b490985e`
and preserves the interrupted staging file's bytes and metadata. Final outside
completion is `bb67b43b32d97a65665a9fb8d9cfed0f7afa7d5e23d310b0ccf8feebcd869eb4`.

Two earlier observers failed: `83e5a9c2b71640df` compared mutable process
state as identity; `6d12a8e47bc0935f` stalled on a child-exit signal. Their
bounded cleanup and unknown host attempts remain retained as failed fixtures.
Separate four-lease observations verify original invocation/resource absence
and missing preparation, followed by explicit retirement in 3.910/4.117 seconds.
Those observations do not replace the missing successful pidfd/target proofs.

All five retirements pass fifty restarted repair/read/refusal cases. Wrong
reservation, mutator, VM and consumed host dispatch refuse; older host/Root
readers refuse v4 safely. A direct verified-FD Root invocation of the retired
missing-reservation job refuses with the consumed-job error in 42.709 seconds.
Six historical compatibility reads pass: the new reader opens old native v2/v3,
completed and finalized v1 records, while an older reader opens the new normal
v1 completion. Original host records and metadata remain intact.

Normal control `f2058c9d17b64e30` exits zero in 84.004 seconds after all
five v4 retirements. Independent observation verifies the UID/GID-65532 exporter
and existing isolation controls. Its 16,690,636-byte archive is
`a335f43a82198291e53851d06fcd0d8fefaabd788c1de564b2238b2450b0659e`.
Inert independent decoding matches all 2,290 files/51,318,588 bytes and entry
digest `b01fe0d3806503226d77118a977594ee5603025ed6412ea1d24ae6a0daf5f866`.
Final cleanup/readback repeats preserve its completion and all five recovery
receipts. Every final four-lease observation preserves the 333 historical
records and their lock metadata; no historical private bytes or keys are read.

Live validation `dependency-preparation-recovery-20261108-validation-006.json`
binds 227 records, SHA-256
`6431c9668fec3de3e71af59497c1376ecc8ca0e0d4fd672364f945553a5eea24`.
Public `gauntlet-rust-review-dependency-preparation-20261108-001.tar` has
277 members/18,708,480 bytes, SHA-256
`b0b82810781b4b7c140c674882adcd0f89562150fe5ec67595dcfb3d720c4bed`.
Manifest SHA-256 is
`16ad00623d894789c7f1f6eeeb980e12924c4ac9e8fe1c841714f34c618c4eeb`.
Every member reopens and twenty-seven actual nonces are excluded from raw
and decoded ZIP bytes. The archive remains outside Git in the existing
`gauntlet-rust-pr-ready-evidence-20261026` directory; remote delivery and
independent review remain open.

Live prefix faults cover absent/empty files. Every exact nonempty byte prefix
is exercised by the codec, with separate inert Root file-custody evidence;
there is no claim of a live nonempty short write. Partial report/terminal
reconciliation, missing-custody gaps, authority, qualification, required CI and
cutover remain open. Parent exits stay 24/62. Model requests/tokens are zero,
and all artifact/admission/qualification/causality flags remain false.

### Upstream cloud-action, warm-client and package-receipt followups

Main `968f88d24ccdfed3607d4a015426bbba305771c2` merges cleanly as
`e8b6130e961f3844ace67dd997fc16cbb6636dae`; all eighteen incoming files match.
Newer `0b8fa932d975f6e6eefa027e3355905d2acf2858` merges as
`65989a1951baab7525fbd09415f181e4d36bcdd3`, preserving all 47 incoming
files exactly. Changed Python sources parse without imports. Mac/ARM Native
library/CLI/test-target checks pass for both generations; product tests are not
executed on the host. The existing musl warning remains visible.

The twelve recovery-source hashes, immutable 420-file baseline and 440-file
map (79 changed/20 added) remain unchanged. Independent AST/data-only oracle
`92979c1c62ab084c1d2633698ac0f333f5ed83c7df655ef4dc7b1571fb8e564a`
reproduces controller digest
`52da7281d075c8d323a2a00c97d1dd080ca09bd71b73fc80c95a86aab489322e`.
All 680 merged-head Gauntlet tests and Mac/ARM checks pass. Latest source
reconciliation is `629cd780f98d15006427ba177f9d0edcd599627e0d50a34cc360b4bee980a8b1`.
Live product evidence remains pinned to `53c64ae96`; neither newer
product generation is qualified by these compilation checks.

## Interrupted dependency completion retirement

Source `792a64ab544cdd83012d596c861a6f3e22fa58a4` adds conservative
retirement of a partial Root report or terminal. Thirteen Rust files change;
two necessary modules separate shared protocol from privileged recovery.
Existing commands and publication helpers are reused. No crate, executable,
dependency, proof script or document is added.

Unknown v3 binds the original unkeyed reservation, running identity, retained
CID/cgroup custody, captured archive, and content/metadata hashes of both
completion files. Host authorization v3 freezes that outside snapshot before
transport. A terminal fragment must match the exact prefix derived from an
independently verified full report. A partial report permits no terminal.
Complete historical terminals retain their existing validation path.

Explicit retirement holds four leases, verifies original intent and input
custody, and requires process, container, cgroup and profile absence. It adopts
or signals no resource. It fsyncs the preserved originals, rechecks the snapshot,
then uses the existing durable staging and no-replace rename. Native repair v5
projects to host repair v4: `aborted`, unknown exit, all eligibility flags false,
zero model requests/tokens. It reconstructs neither file nor terminal. Full-report
finalization with an absent terminal remains a separate supported path.

### Source and validation

| Artifact | Pin |
| --- | --- |
| Source manifest, thirteen files | `aa1988986939c9949dcbc8e5099b31a923e3c9fd8ef563a2662a17766576aa49` |
| ARM worker, 10,435,704 bytes | `d71ca8b295d5a40d0d0240ea9e4df48bcb2d65c6df069af13e52fb6f2d202f59` |
| Primary host | `fde7281c444ce3bcad43136f5a32f13f2a2f38b229500037822749a6d49ca8a5` |
| Compatibility host | `ea4024ac8ea5724225d9455487f0bbb0dbe983088a3638e45c45030ff1bf9f4f` |
| ARM test executable | `5ca51afc04c4446a263c7dc2d23f0269b11778c8cb592524696bd4baaa710c97` |
| Frozen tool record | `4305227a6ea6dba1065e084c0dd16f1cf42969c65b49d7cefc584ea75aedf6fa` |
| Validation, 145 records | `bfa7c27803e2eaaa3f4012039632b1ac001fea54ad2caaeabff5c2b1af2c5fd6` |

All 682 Mac workspace tests, formatting, warnings-denied Mac/ARM Clippy and
final builds pass. Nine selected ARM tests pass, including three explicit Root
fixtures for helper placement, preserved preparation metadata and completion
fsync. Other selected tests run as UID/GID 65532 with groups cleared. The first
unused-import failure and initial Cargo-invocation error remain retained.

### Live partial writes and normal control

The observer binds the original supervisor's executable, exact invocation,
parent and held pidfd. At the original journal-file open, it limits only that
supervisor's file size; the actual writer performs a short write. The observer
then kills the held supervisor without editing records or registers.

| Job | Preserved completion | Retirement |
| --- | --- | --- |
| `6147ab2733bb774d` | 64-byte report; terminal absent | 7.022 seconds; native receipt `aa62b279…` |
| `f44a167f33be73b5` | Full 3,017-byte report; 32-byte terminal | 12.598 seconds; native receipt `0d9bdaa0…` |

Both commands first return identical unknown observations. Wrong reservation,
VM and Root snapshot pins refuse. Twenty restart/refusal cases preserve original
host bytes and metadata. Direct Root reuse refuses in 36.750 seconds. Seven
historical-reader cases pass across prior v2/v3/v4 repairs and completed/finalized
v1 reports; the prior worker reads the new normal v1 result. Older unsupported
readers safely refuse the new receipt. Older mutator admission and rollback
remain unqualified.

Normal `84267ae7556a6101` exits zero in 65.823 seconds after both retirements.
Independent kernel observations verify UID/GID 65532, empty capabilities,
separate namespaces, read-only inputs, seccomp, no-new-privileges and the job
profile. Its public ZIP has 16,690,637 bytes, SHA-256
`778a86de0e4cc67eb0df11c8b1a2955628551da6caa4468fb988ead56f5af8d5`.
Independent decoding matches all 2,290 files/51,318,588 bytes and entry digest
`b01fe0d3806503226d77118a977594ee5603025ed6412ea1d24ae6a0daf5f866`.
Both host read routes and consumed-run refusal pass. Final four-lease snapshots
match earlier snapshots byte-for-byte for both repairs and the normal control;
all resources are absent and 333 historical records plus their lock metadata
are unchanged. Custom proof wrappers read no historical worker record bytes.

Failed prelaunch control `de145dd6f485a69f` remains a failed fixture: its wrapper
compared fresh inputs with the preceding job's hash before invoking the CLI.
Independent inspection confirms no intent, dispatch, runtime reservation,
creator receipt or resource. Its inert prepared slot remains; the ID is never
replayed. Two export-wrapper failures (syntax and a changed comparison path)
also remain retained; the corrected read-only export succeeds without workload
replay.

This is process-loss recovery and point-in-time custody. It proves no power-loss
qualification, VM attestation or Guard causality. Live product execution remains
at `53c64ae96`; newer product sources need fresh qualification. Missing-custody
gaps and the original unexplained active refusal remain open. So do independent
authority, real workflows, legacy qualification, review, remote evidence delivery,
required CI and cutover. Parent exits stay **24/62**.

The final public completion bundle `gauntlet-rust-review-dependency-completion-20261108-002.tar`
has 177 members/18,503,680 bytes, SHA-256
`1e58a24a4386671f16586c46ee403955b957c15e4c397005be88c7a2c6b19625`.
Its external manifest SHA-256 is
`5415f91ea3a242649697d4660222aabd4f68992f661b56cf30afbc76951ab044`.
It includes the upstream follow-up below; the earlier 001 bundle is retained.
Every member reopens and all thirty actual nonces are excluded from raw and
decoded ZIP bytes. It remains local in the existing evidence directory.

### Upstream direct-evidence drain follow-up

Main `84ba6e4daa9d2e11ced491fa046c42690b06b4da` merges cleanly as
`ddc21cd6cea8f7c156d2062d55371ec3bbe72fbd`. All six incoming files match
upstream, including its empty-page cursor behavior; changed Python sources parse
without imports. The thirteen recovery-source hashes, immutable baseline,
440-file map and controller plan remain unchanged. Matching Native library/CLI/test-target compilation passes on Mac
(114.832 seconds) and ARM (103.017 seconds). All 682 merged-head Mac Gauntlet
tests pass in 72.387 seconds. Independent AST/data-only controller oracle
`9c8fb8882177e1b530c037b9bed4f2510e5484622d52e54297591dff5fea6869`
reproduces the unchanged `52da7281…` plan. Follow-up validation SHA-256 is
`03ccfb7af35b5fb8bbdd2ba5dfcaba5882b960e3bdefe5c0e3e9d583934ba4a0`.
No product tests run on the host, and this newer product source remains
unqualified by the retained live execution.

## Fresh current-source build and runtime through the primary commands

Product source `74d8d00814bfb281e4cf8a8823b083b3656db9bb` contains upstream
`84ba6e4daa9d2e11ced491fa046c42690b06b4da`. Its separately installed controller
has 409 selected files, 420 entries and tree `52da7281…`; Rust and an independent
byte/metadata walk agree while preserving prior controller generations.

Primary `gauntlet-host build source` captures job `c2e80b4915f76a3d`, archive
`bc170b35…` (63,248,018 bytes). The first setup attempt lacked the required
preexisting private state directory and refused before capture or VM work;
its failed record and unused ID remain retained. The fresh job runs through
primary `build run`, host `fde7281c…` and Root runner `6b769fa4…`, exiting zero
in 1,856.538 seconds. Four selected checks and all 185 contained contracts pass.
Independent observation binds the actual supervisor/client, pidfds, source
mount, UID/GID 65532, empty capabilities, namespaces, AppArmor, seccomp and
limits. Final inspection under four leases proves original process/resource
absence and unchanged metadata for the 333 historical records and their lock.

Trusted capture retains the 29,438,334-byte ZIP `a9003a02…`. Inert wheel
inspection reads all 1,638 entries, verifies wheel `7c5807a4…` and the actual
47,696,360-byte Native ELF `1d37eae8…`, with no missing capabilities. Two
restarted primary reads through host `5c8b6801…`, source `76a5604fe`, return
identical results and leave the original host pin/dispatch unchanged.

The [primary Rust source transfer](gauntlet-rust-vm-source-transfer-proof.md#primary-rust-transfer-into-the-build-slot)
feeds separate dependency job `c8a491e0d27bf653`. Its exact Git archive
`23c93580…` differs from the build archive but resolves to the same commit;
project and lock bytes match the retained capsule exactly. Primary dependency
execution under worker `d71ca8b2…` exits zero in 82.381 seconds. Independent
kernel/input and cleanup checks pass. Rust stages all 2,290 dependency files,
composes 4,328 prefix entries/124,462,108 bytes and six launchers, then publishes
the immutable source path with tree `060803ad…`. No package is imported by Root.

Independent host reconstruction reopens the 19-member public export, verifies
every wheel/dependency byte and reproduces all four inventories. It finds 62
distributions and MCP 1.30.0. Rust's 21 requirements, including 11 active,
all pass. All 62 METADATA files and the exact staging requirement code match
the prior Python oracle byte for byte, with the same VM boot, builder image
and prefix interpreter. Input-identity readback verifies that reused outcome;
it explicitly records that no fresh Python requirement execution occurred.

Evidence is outside Git in `current-source359-build-host-state-20261108-002`
and `current-source359-dependency-host-state-20261108-001` under the existing
evidence root:

| Record | SHA-256 |
| --- | --- |
| Outside build completion | `af4599a7290ebf6815a876717da9be9cb40afec2dd58fee5b62a4e2c205b44e1` |
| Inert wheel readback | `56cd2a15728491527a1cc8614a0b8c9b2c0c606fdfe06d422cf1abfa81bbdc24` |
| Immutable runtime publication | `29ff984936f46cdb4f947e59c57120e361e4e491836f08af0a70ee60427cc528` |
| Public runtime TAR, 48,240,640 bytes | `09e771311f78cfbab6ef37af44bb694111202e1f1ab9c1b7c5cde6d572d94989` |
| Independent four-tree reconstruction | `042d3f095f6c24f0f0205f46fab0587345b79c00949c583b1f0b7d2ea27248cc` |
| Python requirement input equivalence | `93ee2155b768c4dd59de9a2676ad0ed877cdd63dc02b0ddde25b7fe60f08d810` |

At export time, all 32 actual private nonces are excluded from raw bytes,
ASCII hex and recursively decoded ZIP contents. Independent review, retrievable
remote evidence, required CI, signed conformance, deterministic authority and
operational admission remain open. All eligibility/causality flags stay false,
model usage is zero and no parent exit closes.

After this live proof, upstream main `4220e765b3a9f4d7883d53f95cd7568837c8c563`
merges cleanly as `9adf112e9773c488439eb0fd354d19241eac1aca`. All six incoming
Native/Python files match upstream exactly; Gauntlet source and the 440-file
controller map are unchanged. Matching Native library, CLI and test targets
compile on Mac and ARM without executing a product test binary on the Host.
The compile records are `source-transfer-upstream-20261108-native-mac-001.json`
(`1d34ea03fa239748ac6513914ca70451031acf88e5e2d8892256f86dcd0e444c`)
and `source-transfer-upstream-20261108-native-arm-001.json`
(`645a0b5c1d8e968807d257a6b9e56c0fc3dbe88d7a5c4ee13643f6b2ca7dec89`).
The live build/audit above covers product `74d8d0081` only; the newer product
still needs live qualification.

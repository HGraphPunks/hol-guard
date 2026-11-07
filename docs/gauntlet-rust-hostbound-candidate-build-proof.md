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
`a38df7e1b26c4905` is running against the new controller; its terminal outcome,
broader recovery, independent authority and qualification remain open. All
admission/qualification/causality flags remain false, with zero model requests
or tokens and no parent-exit credit.

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

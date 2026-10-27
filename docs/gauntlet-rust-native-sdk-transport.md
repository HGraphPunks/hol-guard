# Rust Native SDK transport components

The current Native hook diagnostic passes on the owned ARM VM; see the
[retained transport proof](gauntlet-rust-native-hook-vm-proof-20261027.md).
The Rust worker now owns SDK request state, dependency publication, gate and
hook listeners, fixed Podman launch and cleanup, and the Native Bash route.
The latest owned-VM attempt completes an actual SDK session and delivers
the exact Native-captured Bash output. The benign test still fails because
npm aborts, so the complete diagnostic remains failed and ineligible.
MCP, conformance and Guard scoring remain open. The parent checklist remains
24/62 complete.

`NativeSdkRequest` accepts the explicitly bounded Bash-only SDK hook profile
and the separate contained-execution request. It preserves complete original
Bash arguments and the exact sender-byte digest, rejects duplicate/unknown
JSON fields and validates fixed workspace, session, call and text-output
types. The ledger binds one session and budget before product forwarding,
consumes each opaque route before execution, requires completed capture before
Post, and refuses replay or changed input/context. A route is transport state;
it cannot grant a Guard approval. The normal Native route remains responsible
for authorization. Historical SDK adapters are unchanged.

The Linux ARM peer observer holds pidfds, namespace descriptors and the actual
Bun executable inode. It checks every saved UID/GID, group and capability set,
NNP, seccomp, exact fresh named SDK template label, exact cgroup, namespace init, fixed SDK argv and
the externally pinned Bun bytes. The SDK must occupy the measured agent's
namespaces, separate from Root and the product cell. Hook peers must be that
exact Bun PID. Execution peers also require the existing twice-observed
ancestry relation. All held identities are rechecked. This observer alone
does not establish the entrypoint bytes, SDK tree or pre-import ordering;
those fields remain explicitly false until the Rust launcher/gate binds them.

## Public dependency custody

The retained public SDK is 18.4.12, with 42,321 entries and 1,053,309,967
ordinary file bytes. Its outside tree digest is
`4b12e74045c56e5f387c2a82312e38a97d665a88cc52bb698e55bf52747bf0b1`.
The Bun file is 91,801,560 bytes with SHA-256
`37141662ebed915a2ab89313156e455e2a1374395f5f6760d06407f49406f086`.
These are the existing retained public runner inputs. No package code runs
during transfer or publication.

A bounded courier exported the unchanged bytes and original owner metadata
from the retained VM. Its first canonical-order assertion refused before
writing payload bytes; the zero-byte attempt remains retained. The corrected
archive `native-sdk-public-source-024b.tar` has 42,324 logical members and
1,200,394,240 bytes, SHA-256
`fb658d14d25a8a7c7906edd723b2d9dad54ef063661bbb773419de3a0c6df4fc`.
Host readback checks every member and the original SDK/Bun pins.

The private external-dependency bootstrap copy changes UID/GID to Root and
removes ordinary group/other write bits. Symlink metadata and every file byte
are preserved. This explicit custody transformation produces the distinct
SDK tree digest
`ad4d62276c7f7d4026411ceedc56bbd257b06cd6ffd0c9933a6ef3b91d901a3e`.
It does not replace the original tree or pretend the metadata is unchanged.
The source declaration is
`1f4b60186253171767bf4784145095385ea362c6af9017730cd5027b7e45bc1a`.

`gauntlet-native-sdk-publish JOB DECLARATION_SHA256 OWN_GENERATION` reads only
that job's fixed private `sdk-source` directory and closed source declaration.
Under both permanent worker leases, it requires no unknown Native jobs,
re-inventories the normalized SDK, verifies Bun's ordinary Root custody,
actual Linux ARM64 ELF and exact digest, and reads the SDK package identity
as inert JSON. It clones through the existing descriptor-relative Rust
copier, checks complete source/copy readback, publishes without replacement
under `/opt/hol-gauntlet/sdk-assets/<normalized-sdk-digest>-<bun-digest>`, and writes
identical canonical receipts in that directory and the original job.
The composite identity permits a later Bun version to retain the same SDK
without aliasing an earlier publication. Wrong pins and consumed slots refuse;
partial state remains for reconciliation.
Publication remains unadmitted, with SDK/Bun execution flags false.

The complete Mac workspace passes 440 tests across 218 targets, with zero
failures or ignores. Retained log `rust-workspace-native-sdk-components-024b.log`
has SHA-256 `d751567121ca8799b1bcbe487974df423768d5998c73d72ef5c613159825b392`.
The five focused SDK tests, Mac/ARM warnings-denied Clippy and ARM publisher
compilation pass. The earlier sandboxed workspace attempt failed at local
Unix socket binding before either unchanged interop peer started; its log
`rust-workspace-native-sdk-components-024.log` remains retained as
`4868f9a736930f4de4df5c077f7004812f3cc834bcf87ee439023f78bc7cc474`.
The publisher now passes its first owned-VM execution and replay/lease/pin
refusals; see the [SDK publication proof](gauntlet-rust-native-sdk-publication-vm-proof-20261027.md).
The peer observer still requires actual live SDK verification. No model or
provider request occurred.

The next closed worker declaration is v3, `native-sdk-transport-v1`. Rust owns
the Root gate and hook sockets, fixed agent create/start/remove lifecycle,
retained bounded helper processes, readonly public helpers, actual Bun binding,
same-UID peer negative, complete original Bash input, one-use contained route,
captured-output delivery and replay refusal. It uses the unchanged SDK v1
synthetic-stream adapter, with Bash only and no MCP or provider connection.
Its first live execution refused before agent creation, as recorded below.
The profile always returns
`invalid-evidence`; independent Guard scoring, host signing-key admission,
MCP and fresh six-role staging/installed conformance remain open.

The SDK launcher compiles for Linux ARM64. The complete Mac workspace passes
446 tests across 218 targets, with zero failures or ignores; log
`rust-workspace-native-sdk-transport-025b.log` has SHA-256
`81f23baf078d46aa30f557c00ed6e0892ab04c296763bc8996127bf75e3d53fd`.
Warnings-denied Mac and ARM64 Clippy pass. After the controller exits, the
outer Rust worker independently requires no container metadata for that
job's SDK label and no scoped SDK AppArmor profile before writing a terminal.
An uncertain cleanup stays an unknown job rather than gaining a terminal
from the controller's claim alone. Historical v1/v2 report shapes remain
unchanged.

The first live job, `e2c701baf1472501` at source `c62ca717`, retained
`unsafe SDK Root helper`: the new 16 MiB helper bound excluded the existing
35,455,464-byte pinned Podman binary. Native cleanup and full prefix/SDK
readback completed, but the independent worker postcheck hit the same bound
and correctly left no terminal. The failed archive retains all 44 members,
245,760 bytes, SHA-256
`d3825a288cd282ca7e5882bb2b15ded274ff0551340ba3a5c0a042aa72df14ac`.
All 54 prior worker files are unchanged. No SDK agent or SDK import occurred.

The follow-up reader uses the existing image-operation reader's 128 MiB
Podman bound, preserving the exact outside executable digest and custody
requirements; the AppArmor parser retains its 16 MiB bound. Read-only SDK
absence checks use bounded anonymous non-executable memory files so repeated
repair verification creates no disk slot. A distinct v2 repair receipt
requires outside SDK container/profile absence in addition to the original
Native quiescence checks. It keeps the job consumed with `status: aborted`,
unknown exit status and no eligibility/model credit. Original v1 repair
semantics remain unchanged. Actual SDK repair and the corrected fresh control
remain pending. The corrected source passes all 446 Mac tests and Mac/ARM64
warnings-denied Clippy; log `rust-workspace-native-sdk-transport-026.log`
has SHA-256 `01f1a95f9e2ee3ba404a9f5f0bc7ea4cdf1f87c9b95e0a8f962f05096848d417`.

The first repair attempt at `f243516e` passes SDK absence checks, then
correctly refuses the older recovery path's four-row pending-image history:
this job already has the complete six-row image release and successful
Native cleanup. Its refusal is retained, with no repair receipt or original
evidence mutation. SDK v2 repair now selects a separate read-only closed
history verifier. It requires the exact owned release, both final supervisor
cleanup records, unchanged prefix and current process/cgroup/mount/profile/
image-lease absence; it never adopts or unmounts a lease. The historical
pending-image repair remains unchanged.

Helper output now flows through nonblocking pipes into strictly bounded
retained files. The limit does not alter Podman's storage/database file-size
limits. A native test preserves binary bytes and refuses overflow before
writing it. The Mac workspace passes 447 tests across 218 targets with zero
failures or ignores; log `rust-workspace-native-sdk-transport-027b.log`
has SHA-256 `e73e61367a9515f03a118c6ff5df0e80ae77c8ad88028591805cf1fa9c5f5019`.
Mac/ARM64 Clippy and ARM compilation pass. The preceding constructor borrow
error remains in `rust-native-sdk-transport-arm-clippy-027.log`; no VM
execution used that failed compile. The live closed-history repair is next.

The closed-history repair now passes on the owned VM at `3415db61`.
Receipt `618f53fbe80328d268bcd37f5e8a153f11b25286301ad6b7e00950160643e30e`
reopens byte-for-byte; all four original failed-job files remain unchanged.
Wrong generation/started pins and both competing leases refuse. The native
suites pass 148 worker tests with 24 existing fixture ignores, plus 30 rootfs
tests and its subprocess check. A wrong SDK publication digest refuses before
any product or SDK launch, with a consumed invalid-evidence terminal.

Fresh SDK job `e2c701baf1472701` stops before agent creation with
`SDK enforcing profile not observed` and fully cleans up. The inherited
`developer_browser.apparmor` template explicitly declares
`flags=(unconfined)`. The SDK label check now requires that exact named mode
and job/nonce identity, rather than claiming the SDK has an enforcing profile.
The template bytes, DAC, capability drop, NNP, seccomp, namespace and resource
limits are unchanged. The product cell's separate enforcing profile remains
required. AppArmor documents the distinct modes in its
[4.0 profile reference](https://www.apparmor.net/man/4.0/apparmor.d/).
This SDK diagnostic remains ineligible.

The second immutable export has 83 members and 348,160 bytes, SHA-256
`4000f12ed0e911013559eb2fc07e8865f22071e65874d8e8ec1e1bb665b92a0b`.
It retains both SDK attempts, the repair and earlier repair refusal,
pin/lease/replay/readback results, and preservation of all 71 worker files.
The mode-corrected source passes 448 Mac tests across 218 targets with zero
failures or ignores; log `rust-workspace-native-sdk-transport-028.log`
has SHA-256 `f386816d554f24c10283e927037c4e2b963dfb7ca67120db9e500b91f0ba55a7`.
Mac/ARM64 Clippy and ARM compilation pass. A fresh corrected SDK run remains
next; no SDK, MCP, Guard-causality or model result is claimed yet.

Job `e2c701baf1472801` reaches Podman create, then refuses the capability
inspection before starting the container. Podman 4.9 expands the requested
`--cap-drop=ALL` into its eleven default capability names; its effective and
bounding sets are empty (serialized as null). The reader now accepts that
exact expanded representation with empty reported sets and no added caps;
the actual post-start kernel checks still require all five sets to be zero.
See Podman's [inspection fields](https://docs.podman.io/en/v4.9.3/markdown/podman-container-inspect.1.html).

The failed constructor had dropped its partial owner before returning its
cleanup error, so the controller's agent-cleanup boolean was not reliable.
The outer worker correctly refused a terminal because metadata remained.
Preparation and launch are now separate: the controller holds the owner
through every startup attempt and cleanup, retaining its CID and inspection.

The explicit `--repair-sdk-created` route is restricted to an outside-pinned
unknown job's original started marker, exact CID and creation/inspection
captures. It verifies the full fixed image/mount/label/resource/capability
configuration, never-started state, exact nonce/template bytes, absent
controller/product resources and already-absent SDK profile. Under both
leases it records a one-use intent, removes only that CID without force or
signals, checks independent absence and writes a strict ineligible receipt.
It does not write a terminal or infer an exit. The existing closed-history
repair remains a separate step to mark the original job consumed/aborted.

The immutable pre-repair archive has 63 members and 337,920 bytes, SHA-256
`ee7646a50e47859d550f1ee831d34c12155fd7b3c381c82c7fd8ac07ad6aa002`.
Host readback verifies all 63 members, five binary-input members, 75 preserved
worker files, and the exact CID/creation/inspection/start pins. The created
container has never run; SDK/model/Guard credit remains false. The complete
Mac workspace passes 448 tests across 218 targets with zero failures or
ignores; log `rust-workspace-native-sdk-transport-029b.log` has SHA-256
`6049040e4beff250c1eef64010d3048d30c907a8e9329096cd78b366496beef4`.
Mac/ARM64 Clippy and ARM builds pass. Live metadata repair and a fresh SDK
attempt remain next.

The exact created-container repair now passes at `a506de2e`, with receipt
`080760c7cc9dbd504194e2fba57deb6a26cf27cfe3a729cd9e116c6b888a6433`
and intent `b7ae2e005e8b02f05ee183c0ef31d30accfef59434c3763554577cc95ada0297`.
It reopens exactly and preserves all 75 original worker files. The separate
closed-history repair records job `e2c701baf1472801` consumed/aborted with
unknown exit; receipt
`9cc45ffc6492a61c357487b24bd32771b99a88e4dc35f5fa3ac141a5bff9b433`
also reopens exactly. Wrong pins and both leases refuse in both routes.
Root passes 150 worker tests with 24 existing fixture ignores, plus 30 rootfs
tests and its subprocess check.

Fresh job `e2c701baf1472901` creates, starts and removes its SDK container
successfully, but the boundary reader refuses its payload cgroup relation
before Bun/SDK launch. The reader had assumed the payload occupied the libpod
scope directly. Podman/crun can place it in the fixed `container` leaf.
The corrected reader binds the exact job from the fresh named label, full
outside CID and either that exact scope or its single fixed leaf. Sibling
jobs/CIDs and arbitrary descendants refuse. Early cgroup/limit observations
are retained even when later startup checks fail. No scope, limit, namespace,
capability or label requirement is removed.

The immutable repair/cgroup-refusal export has 101 members and 471,040 bytes,
SHA-256 `6e2ac9913c65c68a31d1afc45eccca2f41069c1b6357800bf3f459f030572d14`.
It retains both repair receipts, original failures, replay/readback results,
helper captures and preservation of all 82 worker files. The first export
courier had a syntax error before executing any action; its corrected export
does not replace an earlier archive or worker record.
The cgroup-bound source passes 449 Mac tests across 218 targets with zero
failures or ignores; log `rust-workspace-native-sdk-transport-030.log`
has SHA-256 `ac87dad58cf780b3512244cf31ba95c2aeb06e1628a1fa047a2017c43f47e28f`.
Mac/ARM64 Clippy and ARM builds pass. The next fresh SDK control is pending.

Job `e2c701baf1473001` at `2213e73f` verifies the actual delegated cgroup
`/holgauntletruste2c701baf1473001.slice/libpod-<exact-CID>.scope/container`
with the expected 2 GiB memory, 256 PID and two-CPU limits. It then refuses
`SDK named unconfined template label differs`, before Bun/SDK launch. The
ordinary terminal remains `invalid-evidence`, exit 2; the SDK container,
profile, product cell, job slice and image lease are absent after cleanup.
The original process label was not retained by that generation. New source
retains the observed and declared labels before validating them and includes
both in any mismatch error. A fresh diagnostic reuses the pinned worker to
capture the init label independently without widening acceptance.

The generation-030 immutable export has 84 members and 440,320 bytes,
SHA-256 `7ac9557ca0a4082d621269efad32db1ff39cc26430f20b13ed6b17324925e3c2`.
Its host prelaunch pin is
`1ffc2339f4df604a3a72045c291118b9f782c09d69a2f840d8d2a02ae57bbf16`;
all 82 prior worker files are preserved, with 88 files now retained.
Root passes 151 worker tests with 24 existing fixture ignores, 30 rootfs
tests and one subprocess check.

The committed inert
[`verify_native_sdk_transport_recovery_20261027.py`](../ci/gauntlet-rs/proofs/verify_native_sdk_transport_recovery_20261027.py)
and its adjacent fixed-attempt reader independently verify exports 025,
027, 028, 029 and 030, their input binaries and host pins, original failed
bytes, both scoped repairs, canonical replay/readback relations, and exact
retained state. Run it with the evidence-directory argument; `--output`
creates a new report exclusively. The full reader and Ruff pass. This is
failure/recovery and boundary evidence, with no SDK, MCP, model or Guard pass.

Fresh label diagnostic `e2c701baf1473101` reuses the exact generation-030
worker and input rather than claiming another build. A held pidfd sample
matches the agent's PID/start/cgroup tuple, zero capabilities, NNP, seccomp,
limits and the actual `/usr/bin/sleep` ELF. Its complete process label is
`crun//&hol-gauntlet-sdk-e2c701baf1473101-833b4fbe9db5c62edae8011b4a5ec99d (unconfined)`.
The named SDK profile is present in the runtime's stack. AppArmor describes
these composed labels and restrictions in its [stacking reference](https://apparmor.net/advanced/AppArmorStacking/).

The new reader permits only the declared SDK label or that exact label
stacked with `crun`. Once measured, the complete label must remain identical
for the init, Bun and later rechecks; it cannot lose the runtime component.
Other profiles, changed jobs/nonces, additional stacks and different modes
refuse. The unchanged template's loaded mode is still verified separately.
The ordinary failure, cleanup and all 94 worker files are retained. The
80-member, 409,600-byte export has SHA-256
`8085e7a61b57da58723571061772dc213a36c87e785d61ec5c5bdd6936f08e61`;
host prelaunch pin
`43b9f0714660880c464bc9ccf2219cf93167a3d664b0cd698934967837deac5f`.
The adjacent `verify_native_sdk_transport_label_20261027.py` verifies that
diagnostic independently and passes Ruff. The new source passes 450 Mac tests
across 218 targets with zero failures or ignores, both warnings-denied
Clippy targets and ARM64 worker/test compilation. Workspace log
`rust-workspace-native-sdk-transport-032.log` has SHA-256
`32e4dd2355c2497a055b4c5b908caeec883ab952a9934c1846e754bb3da6b9f3`.
A fresh run of the stack-aware source is next; no actual SDK result is
credited by these diagnostics.

Job `e2c701baf1473201` at `426c7d93` now completes the actual pinned SDK
18.4.12 session. The Root gate binds the held Bun executable and process
before SDK import, and independently refuses a different same-UID peer.
The real SDK emits one Bash Pre, one consumed execution route and one Post;
normal Native containment authorizes the route, and Native reviews the actual
captured output. Both SDK context projections retain the original command.
The SDK receives the exact captured bytes and error flag, exits 0 and uses
two synthetic stream calls with zero provider requests.

The benign command fails: `npm --version` aborts with SIGABRT inside the
standard-library fixture, while the expected private workspace effect exists.
The controller's former combined predicate reports
`SDK did not receive the exact benign Native-reviewed captured output`;
host readback proves delivery was exact and the fixture outcome failed.
New source distinguishes these conditions and retains the failure as a
failure. The explicit v2 unprivileged fixture retains stdout/stderr for
Node/npm failures and preserves every success, boundary and version assertion;
v1 bytes and earlier evidence remain unchanged.

The 98-member, 573,440-byte immutable export has SHA-256
`3ff026ef1ca0389ea5d33ae3c8856768ea8d3dd2ea2bdd9961c992044e974695`;
the host prelaunch pin is
`18b4b6558806ad2d82c8a6a87249ab0bb239314036d42db3c57eba8c045fbc73`.
The inert `verify_native_sdk_bash_20261027.py` verifies all members, binary
inputs, 100 retained worker files, independent Bun PID/start/executable
samples, pre-import and same-UID controls, the complete SDK/Native output
relation, physical effect and cleanup. It returns `benign_control_passed:
false`. Root passes 152 worker tests with 24 existing fixture ignores, 30
rootfs tests and one subprocess check.

The improved result classification and v2 fixture pass 453 Mac tests across
218 targets with zero failures or ignores, both warnings-denied Clippy targets
and ARM64 compilation. Workspace log
`rust-workspace-native-sdk-transport-033.log` has SHA-256
`dce286ce774a2cb09c3f47f679324e8dff5ec0492a0ea1ec40fc01e793b13474`.
The fresh stderr-retaining diagnostic is next. None of these results grants
Guard-causality, benchmark qualification or model-inference credit.

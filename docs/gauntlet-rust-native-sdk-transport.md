# Rust Native SDK transport components

The current Native hook diagnostic passes on the owned ARM VM; see the
[retained transport proof](gauntlet-rust-native-hook-vm-proof-20261027.md).
This next implementation adds SDK request state, a kernel peer observer and
inert public dependency publication. The SDK listener/launcher is still being
connected. These components do not supply an SDK run, conformance or Guard
verdict. The parent checklist remains 24/62 complete.

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

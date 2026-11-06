# Rust Root feature worker

Updated 2026-11-06. The development worker and fixed host caller complete
`run/read/repair` in the owned ARM VM. A fresh 28-group audit independently
retains real product failures, and a separate supervisor-crash test completes
through the pinned Rust repair command. The earlier XML and signal failures
remain retained. Current-source qualification, the broader interruption matrix
and operator integration remain open. Parent acceptance stays 24/62.

## Ownership and fixed inputs

The Root executable is `gauntlet-feature-worker`; the Mac caller is
`gauntlet-host-feature-audit`. A closed host intent binds the existing
11-field executor spec, exact completed build result, complete controller
tree, builder/base images, rendered audit policy, four VM helper hashes and
the actual Root worker executable. It admits no arbitrary command, selector,
candidate path or resource override.

Root independently opens the successful build result and source/archive,
checks the nested wheel and actual Native bytes as data, verifies the full
controller tree and immutable local image, and repeats those checks after
execution. It never imports or executes a candidate package as Root. The
executor and fixed Node are separately captured as inert, content-addressed
ARM ELFs. Partial asset slots remain consumed.

The feature profile remains two CPUs, 12 GiB, 2048 tasks and a four-hour
deadline. The Root Podman client has its own fixed cgroup and bounded
128-KiB stdout/stderr. Existing candidate/dependency limits remain unchanged.
The unprivileged PID-1 executor still owns the complete fixed 28-group,
52-selector schedule and the source/installed context boundary.

## Durable lifecycle

Initialization v4 creates the private `feature-state` and `feature-jobs`
namespaces and `feature-assets` directory. Existing directories and locks
must already have safe custody; initialization never repairs their modes or
adopts existing job IDs. Historical initialization receipts remain intact.

Under the shared Rust and Python worker leases, the Root owner commits the
complete canonical intent as the one-use reservation before creating its
audit directory, loading a policy or creating a container. An incomplete
intent write consumes the ID and blocks admission. The separate feature
lease covers all feature journal writes.

Container ownership requires a full 64-character CID, exact intent label,
fixed unprivileged user, immutable image and exact security/resource settings.
The CID receipt precedes start. A separate fsynced client-cgroup receipt binds
the intent, kernel boot ID, device and inode before spawning the client. The
running marker binds its actual PID/start ticks and feature cgroup. Cleanup
targets those identities and keeps confinement enforced when teardown cannot
be proved. Shared cgroup custody now lives in `owned_cgroup.rs`; the existing
probe API and fixed limits remain unchanged.

After exact container/client/profile cleanup, Root compares its captured
stdout with the exported report, independently recomputes every XML/log
digest, count and status, and retains immutable Root copies. A closed result
binds those artifacts to the original outside intent. A complete result
always has terminal status `invalid-evidence`; `audit_status` separately
preserves `passed`, `failed`, `incomplete` or `invalid-evidence`.
Qualification, artifact admission and Guard causality remain false; model
requests and tokens remain zero.

New native, candidate and dependency dispatch checks reject unresolved feature
state. Orphan files, unknown sidecars, partial JSON and conflicting completion
records block further admission. Reading a completed result repeats custody,
artifact verification and present cleanup checks.

## Restart and recovery boundary

The host durably records dispatch before opening the VM connection. An
uncertain transport consumes the attempt. A second invocation refuses instead
of replaying the work. Restart opens the retained guest result using the
audit ID and original complete intent digest.

The host's `read` action requires the exact durable intent and dispatch bytes
before calling the pinned worker. It sends no run intent and commits or
compares a canonical private terminal copy. Its `repair` action additionally
requires an outside repair-binary SHA-256 and durably pins that authorization
before contacting the guest. Later reads use that authorized executable and
accept an aborted receipt only with matching original intent and repair pins.
The authorization is immutable; repeated cleanup reconciles the same binary
and never resubmits the workload. A completed host result cannot be repaired.

Local process tests cover completed readback, aborted repair/readback across
restart, transport failure, changed dispatch, partial or changed authorization,
substituted receipts and consumed-run refusal. The host journal tests have one
dedicated test module to keep the implementation below 500 lines. Historical
host-read evidence remains in
`gauntlet-rust-pr-ready-evidence-20261026/feature-host-read-proof-001.json`;
that earlier proof does not establish a new guest execution.

Under all three leases, recovery validates the original container receipt,
full CID/intent label and fixed resource/security settings. An active client
cgroup can be reopened only with its retained boot/device/inode identity.
Cleanup uses its held descriptor, never a historical PID. A name replacement,
missing ownership receipt, changed helper or policy pin, or uncertain custody
refuses before destructive cleanup. The create/receipt gap can retain a CID
only after an exact intent-bound inspect, before removing that container.

The worker keeps AppArmor loaded until the exact container and client cgroups
are absent and the original client has gone. It then removes the pinned policy,
rechecks actual cleanup and appends an exclusive `aborted` receipt with unknown
exit and zero model usage. Reading that receipt rechecks present cleanup.
Existing results and partial records remain immutable; unresolved uncertainty
continues to block dispatch. At `22d29e6e`, eleven feature cases and the explicit
Root cgroup-recovery case pass in the owned VM. The latter observes child and
descendant tasks, the parent's SIGKILL exit, complete drain/removal, forged/partial
receipt refusals and refusal of a replacement group with the same name.
Metadata for all 333 retained worker records is unchanged; no owned container
or cgroup remains. See the execution checklist for exact binary and log pins.
The fresh runs below subsequently exercise the complete live worker flow.

## Live attempts and fixes

All four attempts below used product `dc3b9336` (3.58.0) and build
`e2c701baf1475501`. The first two used Root worker SHA-256
`8baf4a30f4507f454639f07c312f2dbf5efc581a1266ff0164dff6dea02bc4ef`;
the last two used worker
`534c1ed1cada4f80de9147b2865a71f2084955793c6bfcf2b0cada32a75f6fee`
and executor `750c1643f18a76ade2d405aaf84f707c05e381362428aedaef209ac164c6dffb`.
They do not qualify the newer 3.59.0 candidate. The current-source build at
`83f079b5c` reports identical hashes for all eight trusted ARM release tools.

| Audit | Retained result |
| --- | --- |
| `98d0cdb912f50ef8` | Produced all 28 XML files, then Root returned `invalid-evidence`: pytest wrote mode 0644 while the strict export reader requires 0600. Real host readback preserves that result; consumed run and completed repair refuse. |
| `47f1bc9d804a6e25` | Supervisor SIGKILL left the client and container active. Repair drained the owned client group, but kernel audit logs show AppArmor denying `crun`'s TERM/KILL. After an operator-assisted, fresh full-CID/intent/start-tick/cgroup/pidfd-bound stop under all three leases, the pinned worker recorded `aborted`, unknown exit and quiescence. This is not automatic-recovery acceptance. |
| `6fb9d42a017c83e5` | Completes all 28 groups and 52 selectors in 2,019 seconds. Root verifies all XML/log digests, independently recomputes counts and retains 56 artifacts. There are 1,286 passing tests, two Cline assertion failures and one skip: 26 groups pass, one fails and one is incomplete. Audit status stays `failed`, outer status `invalid-evidence`, and eligibility false. Fresh read matches; replay and completed repair refuse. |
| `c42a9e3b701fd865` | A fresh pidfd-bound supervisor SIGKILL leaves the client and container active, with unknown readback refused. The pinned Rust repair finishes in 13.64 seconds and retains `aborted` with unknown exit. Fresh read and repeat repair match; replay refuses and all four host records remain byte-identical. No workload signal or resource rescue is supplied outside Rust repair. |

The complete audit uses controller `0a7c949b9` at digest `409fe095…`;
the crash/recovery test uses the newly installed `83f079b5c` controller at
`e81a214c…`. Outside observations bind the actual UID-65532 executor and
resource/confinement tuple, then verify container/cgroup/profile and original
process absence under all three leases. Metadata for all 333 older worker
records remains unchanged; their private byte contents are not read by that
metadata comparison.

The two Cline failures compare different withholding messages; the captured
output remains withheld. The skipped Pi test is explicitly marked as retired
Python composition behavior: the live hook now reviews that external-source
search shape. Its unchanged XML digest is
`11de5984ab328db8fbad56a2e62e53f1fe9b4d7ae96154585a8701a5619a33d8`;
the outside skip diagnostic receipt hashes to
`87b406647d0ae422f8856ef111645574c37e754d285c50491b5cf8056b650f88`.
That expected skip still leaves its group incomplete.
Neither outcome is rewritten as a pass. The Root report is SHA-256
`c9587c7ce2b5d909744565245c4f0b5b8b394122ff7a6f2a2848de47673a2dcf`;
its independent readback is
`65755213874d5e8491cc53741222951119da4436b3f2c106663f59488da652b1`.

On November 6, fresh host processes read and repeat-repair the identical aborted
receipt, and another `run` refuses. All four host intent/dispatch/authorization/
result byte hashes stay unchanged across these checks.

The executor now publishes pytest XML as 0600 through its held descriptor
after draining the child tree. It checks owner, single link, size and exact
0600/0644 source mode, preserves the bytes, fsyncs and rechecks identity/path.
Root keeps its strict reader and independent artifact recomputation. Two
actual ARM tests pass, including links, unsafe modes, wrong owner and bounds;
the test executable is `a2d8316e9d5bdc5982e9a956514d3cefd2cd5158a75f7fec0403d883d1885108`.

The shared builder policy adds receive-only access from the host's bare
`crun` profile. Outbound signals and ptrace remain scoped to the job. Fresh
probe `5e8b2a71c09f643d` runs a confined UID-65532 system sleep process and
proves that Podman stops/removes it while enforcement remains loaded. No
operator signal is used in that probe; its container/cgroup and profile are
then absent. Its rendered policy is
`f7313b4dc1e6172b50efec837fcce95636e96668bbc1db76d2c5eb7fc2efc66d`.

At `0a7c949b9`, the source map has 437 files, 78 changed and 17 added against the unchanged
420-file baseline. Actual Python bootstrap selection and Rust agree on 406
files, 417 entries and controller digest
`409fe095fe10627e4c2ab7a14fe73e9d1b6177bbc3471364ca430cf4ddfb35f0`.
The upstream import at `83f079b5c` has 440 files, 78 changed and 20 added;
actual Python, Rust Git-blob verification and the installed Root tree agree on
409 files, 420 entries and digest
`e81a214c9771095da22f2897aa5c25600d2016f416cd6562d4fd5511f6321e9a`.
All 656 Mac workspace tests, 28 focused Python tests and seven subtests pass.
Rustfmt, Mac workspace Clippy and ARM worker Clippy pass with warnings denied;
the touched Python test passes Ruff.
Supporting independent review found no blocking safety concern; the formal
immutable security scan still has its tool inventory gap.

Evidence remains outside Git in `gauntlet-rust-pr-ready-evidence-20261026`:
`feature-publication-policy-20261105-mac-all-001.log`
(`18bf84038f6db57d587a87a8366da381dfef23fc73a0c56f40f03168b758ea82`),
`feature-xml-publication-20261105-arm-tests-001.log`
(`907398dabac6f9355d41c2129d6fb865bce60cc87809dab50ba0b91a5aa55ed7`),
`feature-policy-20261105-crun-stop-001.json`
(`4a662b7e47829498e65e583fe42a6cfffd3fce6701ad366ad939ae0fb9c8245e`),
and the private `feature-worker-live-host-20261105-001` intent/result/attempt
journal. Metadata for all 333 older worker records remains identical;
`feature-live-20261106-worker-metadata-after-001.json` has SHA-256
`53760220746ed9bfa2a8256a954d5ff510fb49067935f4b53aae945c7c6edeae`.
The external evidence directory now contains
`feature-audit-6fb9d42a017c83e5-public-artifacts-20261106-001.tar`
(296,960 bytes), SHA-256
`a78fc9715147258ea019a94a416e49b8c0d3a4a9c9bbce012053c001543df672`.
Host readback verifies all 59 members: the unchanged report, readback,
56 XML/log artifacts and a source-pinned manifest. Private intents, nonces,
keys and dispatch records are excluded. This local package is ready for review;
remote delivery and a recovery-evidence handoff remain open. Current-source
qualification, operator wiring, broader interruption coverage,
cutover and required cloud CI remain open.

Fresh completion and recovery evidence in the same private journal:
`6fb9d42a017c83e5.outside-completion-001.json` has SHA-256
`6a18284ed7fc6f6fa61e3ff4023c2563583b6e7773a6372ae19d579d540582f2`;
`c42a9e3b701fd865.repair-command-001.json` has SHA-256
`26cb52e174f4eac49bacbf60472e0bad2a46bbccc80e806f476b7cf1e011115d`;
`c42a9e3b701fd865.outside-recovery-completion-001.json` has SHA-256
`711c0d08f97bdcda02a5a9edd62ab8397bee5d3136428c61a722de5863f54fa5`.
These establish the observed development flow and resource recovery, with
zero model use and false qualification/causality throughout.

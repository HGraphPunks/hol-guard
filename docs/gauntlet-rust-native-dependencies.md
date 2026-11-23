# Native dependency preparation

The current candidate requires MCP >=1.30.0. The retained dependency prefix
has 1.28.1, so it cannot supply the new installed-prefix proof unchanged.

`gauntlet-dependency-exporter` is the new fixed **unprivileged** adapter for
creating compatible data. It requires Linux ARM64, UID/GID 65532 throughout,
zero permitted/effective capabilities, no-new-privileges, seccomp mode 2 and
the expected job AppArmor attachment. It refuses host/VM Root. Its fixed
inputs are Root-owned mode-0444 `pyproject.toml` and `uv.lock` under `/input`,
each bounded at 4 MiB and checked against outside SHA-256 pins before use.

Rust creates one-use `/work/home` and `/work/project`, then invokes the pinned
image's UV with frozen locking, no dev/project install, no builds, its existing
Python executable and no Python download. Explicit copy mode avoids mutable
cache hardlinks. The child has a 300-second deadline and bounded reap; the
outer Root owner must still own and drain the entire container.

Rust then writes only ordinary site-package bytes and a versioned manifest to
exclusive mode-0600 `/output/dependencies.zip`. The ZIP writer uses held
descriptors, rejects links/special objects, unsafe ownership/modes and changing
files/directories, and bounds 100,000 visited objects, depth 128, 512 MiB decoded
bytes and 256 MiB of compressed output. It fsyncs the file/directory and hashes
the actual ZIP. The manifest binds job, source, both input hashes and a framed
digest over all exported file bytes. No dependency is imported or executed by
the archiver. Every report remains unadmitted and execution-ineligible with
zero model requests.

Three Mac tests verify binary ZIP readback, preservation on replay refusal,
no execution of `.pth` content, linked-file/root refusal, and byte/seek bounds
without allocating a 256-MiB test file. ARM64 compilation and warnings-denied
Mac/ARM64 worker Clippy pass. Its live container execution and independent
kernel observation now pass in the [dependency run proof](gauntlet-rust-native-dependency-run-vm-proof-20261026.md).

The Rust host command `gauntlet-host-prepare-dependency-inputs` now creates a
closed three-file capsule under an existing one-use local source slot. It
reverifies that archive/ref/Git graph, reads the two exact committed ordinary
blobs without checkout, and accepts only an outside-pinned owned static ARM64
ELF adapter. It writes and reads back the private capsule, rechecks the graph
and commits a separate canonical receipt. Real Git tests cover an advanced
worktree, immutable source/replay, linked project files and wrong/dynamic
exporter formats. The ZIP dependency adds only a locked graph edge; no package
version changes.

The native worker's explicit `--capture-dependency-inputs` operation receives
that capsule through its existing bounded cancellable stdin copier. Both
permanent leases, the actual worker generation, captured source hash and
strict native source receipt are required. Root validates exactly the three
ordinary members and outside hashes, writes 0444 project/lock files and a 0555
adapter under a private partial tree, independently reads them back, and
publishes without replacement. The archive and receipt stay source/job-bound;
failed partials remain consumed. No adapter or installer executes during this
operation. The [source-sized live VM capture proof](gauntlet-rust-native-dependency-input-vm-proof-20261026.md)
now passes, including both competing leases, wrong generation/source/hash,
truncation, overflow, member-hash mismatch and replay preservation. Independent
host readback verifies all 36 retained evidence members. The current Mac
workspace passes 413 tests across 213 targets with no failures or ignores;
the actual Root ARM64 library passes 126 tests with 24 preexisting fixture
ignores. The first ARM run exposed a stale current-context test expectation;
its failed log is retained alongside the corrected, independently recomputed
oracle. That input-capture proof did not execute the exporter; the later
dependency run proof below supplies its first live executions.

`gauntlet-host-run-dependencies` now has a distinct one-use prelaunch intent
journal binding the exact VM/transport, source/capsule/capture receipt, exporter,
controller, image, policy, runtime and runner, plus a fresh host nonce. The
shared closed contract rejects arbitrary command/path/resource fields. Private
descriptor custody, durable readback, restart, replay, linked-record and replaced
directory tests pass. Existing candidate pin schemas remain separate.

The native worker's `--prepare-native-dependencies` composition validates that
intent and its actual executable, takes both permanent worker leases and a
separate durable dependency reservation, and repeats image/input/policy/runtime
preflight. It creates one exact-ID container with a pinned intent label and
fixed UID, capabilities, AppArmor, seccomp, memory, CPU, PID and slirp controls.
The attached client has bounded logs, deadline, cancellation and disk checks.
Cleanup rechecks container identity before stopping it, then verifies the
container, systemd cgroup, client cgroup and policy are absent. Successful
exports are copied once into Root-owned 0444 data with independent readback.
The terminal stays `invalid-evidence`. Unresolved dependency state blocks later
dependency, native worker and candidate runs; it is never automatically retried.
The v3 inert initializer adds only the separate private dependency journal.
ARM64 compilation and warnings-denied Mac/ARM64 Clippy pass. The first composed
VM attempt is retained as unresolved job `e2c701baf1471301`: the actual
unprivileged exporter installs all 62 frozen packages, including MCP 1.30.0,
and creates a 17,489,481-byte archive, SHA-256
`a6a25abbbead6dbf5510534474c0da9bc36c423ff374b21ce7dad3917a75f642`.
Rust captures that data and removes the container, cgroups and enforced
profile, then refuses terminal publication because the journal lacks its
mandatory running-process marker. The initial job remains consumed, with no
report or terminal; its archive is unadmitted. The host retains an uncertain
execution result rather than a package/environment pass.

The follow-up connects the actual observed Podman client's PID, start ticks
and cgroup to `mark_running_under_lease` before collecting its result. It also
adds explicit `--repair-native-dependencies` for quiescent, externally pinned
jobs. Repair takes both permanent leases and the dependency lease, verifies
the exact original intent/reservation, all captured inputs, retained CID and
absence of client/container/cgroups/profile, then writes a separate `aborted`
receipt with null exit code and no execution credit. Missing running evidence
stays null; no marker or terminal is invented. The original files are preserved,
and later admission independently rechecks this separate receipt. The live
repair, replay and five pin/lease refusal cases now pass. Two fresh jobs then
complete from exact current source `62aa7ba7`; both retain running/report/terminal
identities and independently verified cleanup. Job `e2c701baf1471402` also has a
successful outside kernel observation. See the [complete proof](gauntlet-rust-native-dependency-run-vm-proof-20261026.md).

The independent observer of the first run is retained as unavailable: it read
the container's parent systemd scope without calculating effective limits
along the observed process's complete cgroup ancestry. A second observer also
refused absent limit files at the cgroup root. Both unavailable records remain.
The final observer reads every non-root ancestor and verifies the actual
effective 12-GiB, zero-swap, 512-PID and two-CPU limits without a probe error.
The first worker initialization also refused an installer-created 0555 file;
the recorded correction restricts that new file to the existing required 0500
mode. The source-matched actual Root library then passes 126 tests, with 24
preexisting fixture ignores, log SHA-256
`6f86cdf26ae4afd6cabe935f04f85ab00aebeb5f428ecc1c72eae4124c221fa2`.

The complete Mac workspace passes 416 tests across 215 targets with zero
failures/ignores. Log `rust-workspace-native-dependency-run-009.log` has SHA-256
`2745c680bde743e5741016ad9c56a504acc6263e935fc7606a807442f4546a63`.
The earlier sandboxed run is retained as `008.log`, SHA-256
`4863f5598c2cc66d75df2a10798cbf29c0280b5daed8298852328d66c1fb2ccc`:
both bridge interop fixtures refused local Unix socket creation. The complete
run used the approved local socket capability without changing those tests.

The new Rust ZIP reader validates the complete outside archive hash, closed
manifest, exact ordinary UTF-8 paths/modes, CRCs, object/path/decoded byte limits
and independently recomputed framed file digest. The prefix writer creates a
one-use private partial tree, writes and reads back every ordinary file, and
adds only fixed system-Python links and inert venv configuration. A real-export
test preserves binary/`.pth` bytes without executing them and refuses wrong
hash/replay before changing the existing tree. CRC corruption and oversized
declared entries refuse without a large allocation.

The native `--stage-native-dependency-prefix` operation binds a successful
retained dependency terminal to outside intent/result/archive/interpreter and
actual stager pins under both permanent leases. Repaired failed output cannot
supply a prefix. It independently verifies both partial and published Root tree
inventories, preserves partials on failure, publishes without replacement and
commits a separate source/byte/interpreter-bound receipt. Root imports no
package or candidate code. Mac refusal/data tests and ARM64 warnings-denied
Clippy pass. The full Mac workspace passes 419 tests across 215 targets with
zero failures or ignores; log `rust-workspace-native-dependency-prefix-014.log`
has SHA-256 `9000f9e65aec9ebc2726dd46308f9e23650c1dc31447dbad2698fbc78676860e`.
The [first live prefix operation](gauntlet-rust-native-dependency-prefix-vm-proof-20261026.md)
now passes: all 2,302 dependency files match the ZIP, nine refusals/replay cases
preserve the original inputs, the actual Root library passes 129 tests with
24 preexisting fixture ignores, and the host independently reconstructs the
complete 2,649-entry prefix from all 29 retained export members.

The remaining composition and verification are explicit:

- Extend recovery beyond the proven quiescent profile, with actual dependency
  timeout, cancellation and transport-interruption cases.
- Publish the verified composed prefix as one-use source-bound runtime data,
  then complete independent controls and fresh conformance before admission.

`gauntlet-vm-worker --clone-native-candidate-prefix` now composes a separately
published dependency prefix and candidate wheel under both worker leases. Its
closed arguments bind the candidate job/source/archive/version, dependency
job/receipt/tree, staged wheel tree and actual worker generation. The dependency
receipt must name the same source; current interpreter, run, input and complete
archive/tree custody are reverified before and after copying. Unknown jobs,
cancellation and insufficient disk refuse. A private consumed target remains
on uncertain failure, with a separate canonical receipt only after readback.

The historical `/opt/hol-gauntlet/candidates/<source>/prefix` clone and its
shadow-v1 schema keep their original entrypoint. Shared descriptor copying and
its tests were split into smaller files. Only the explicit native path adds
the six console scripts declared by the exact wheel, including the three
legacy aliases. Unknown, missing, duplicate or changed declarations refuse.
Fixed shell/Python launchers locate the sibling interpreter, preserve arguments
and use isolated mode without writing bytecode. No launcher runs during Root
staging. Tests check all six declarations, exclusive write/replay preservation,
Python parsing as inert data and actual shell relocation through paths with
spaces/quotes using a fixture interpreter. The full Mac workspace passes 423
tests across 215 targets, with no failures/ignores; retained log SHA-256 is
`7a84f6377cce1ca068e134b4b91c036b034cc72162d520f69a86e698d79b815c`.
The first live composed-prefix attempt at `5fa3f5f3` passes eleven pin/lease
refusals, then refuses the new launcher's wrong 0644 expectation: published
inert-wheel metadata is 0444. Its complete partial stays Root-private mode
0700, with 4,405 entries and 117,017,632 bytes, no launcher, no publication
receipt and no candidate execution. All 4,041 original files/links remain
unchanged. The first independent snapshot courier also refused two retained
unprivileged export files before any Rust operation; its separate correction
pins their publisher UID/GID, exact modes and outside hashes while retaining
the Root input reader. Both failures remain recorded.
Independent host verification checks all 27 members of the 2,007,040-byte
failed-attempt export, SHA-256
`821afdc60c204c4cc09351f2716d39b15e77ff075d408fd73693b93f04245ad9`,
and reconstructs the private partial from the earlier verified wheel and
dependency data. The partial digest is
`8c0d3a91bc60ce364c27c0eac5bcd0e21f47463bc766b391d38a15b380a08f1a`.
The source-matched Root library passes 133 tests with 24 preexisting fixture
ignores; the historical clone fixture also passes when run explicitly.

The follow-up requires exact 0444 metadata, tests refusal of 0644, and validates
the complete declaration before creating a prefix. It adds the version to the
new native receipt; the historical schema is unchanged. The corrected complete
Mac workspace again passes 423 tests, log SHA-256
`895fe5ca7b5d97d6f2c7ee74fe6d214a464f4b526f61dd6550b90cac9271a449`.
The consumed attempt is preserved; fresh candidate job `e2c701baf1471601`
uses the same exact product source for the next proof. The
[successful complete proof](gauntlet-rust-native-candidate-prefix-vm-proof-20261026.md)
now verifies the entire 4,411-entry prefix, all six CLI aliases, 14 refusal
cases and all 23 requirements over 63 distributions. Thirteen requirements
are active and satisfied, including MCP 1.30.0. Host readback verifies all 46
members, independently reconstructs every prefix file/hash and matches the
exact source-pinned Python staging loop with explicit Linux marker values.

The next explicit native operation, `--publish-native-runtime`, is implemented
as a one-use inert data publication under
`/opt/hol-gauntlet/candidates/<source>/prefix`. It verifies the closed outside-
hashed clone receipt, computes the complete typed requirement proof, takes
both leases, rechecks source/dependency/candidate/interpreter/tree custody,
copies through held descriptors into a private source/job partial and verifies
the exact copied tree before rename without replacement. Two canonical
receipts bind the published source path and original job. Existing/partial
slots refuse; no final deployment or eligibility is written and no package
executes as Root. The full Mac workspace passes 425 tests, with no failures
or ignores, log SHA-256
`e72f6ca366cd47e71e86cada08b545116fcea10a3ebfb5d46a9ffea9f2563d8a`.
Mac/ARM64 warnings-denied Clippy pass. The
[live publication proof](gauntlet-rust-native-runtime-publication-vm-proof-20261026.md)
now passes: ten pin/lease/replay refusals preserve 8,059 original files/links,
the published 4,411-entry tree matches exactly, both receipts agree, and host
readback verifies all 23 export members. The actual Root library passes 135
tests with 24 preexisting fixture ignores. Independent controls and fresh
conformance remain open; the runtime is unadmitted.

The [current Native worker lifecycle proof](gauntlet-rust-native-current-worker-vm-proof-20261026.md)
now passes success, timeout and cancellation on that runtime through Rust.
The earlier static-musl actor failure is retained; GNU ABI preflight and a
separate release build correct it without changing the library or isolation
pins. All prefix bytes remain unchanged, and host readback verifies 117 export
members. This is apparatus evidence; independent Guard controls and fresh
conformance remain next.

The inner attachment check does not establish the kernel policy's enforcement
mode by itself; the Root owner must observe that independently. An adapter
report or successful package installation supplies no Guard verdict, artifact
admission, conformance or inference authorization.

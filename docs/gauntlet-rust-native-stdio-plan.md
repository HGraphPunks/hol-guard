# Outside Native client pipe capture

Status: syscall metadata, transfer accounting and the initial outside pipe
snapshot producer are implemented after
verifier checkpoint `98a544f3` and published evidence checkpoint `5ddb5d52`.
The live ARM syscall ABI and pipe fixtures pass in the owned VM. Independent
Rust snapshot replay, framing and signed launch-v4 integration are implemented
and pass 615 macOS workspace tests and Mac/ARM Clippy. A fresh
[launch-v4 Native control](gauntlet-rust-native-stdio-live-proof-20261028.md)
passes with 12 streams and 497 complete frames, reproduced independently on
Mac and ARM. Atomic wire observation and request semantics remain open.
The existing image-lineage proof
does not observe internal Native request bytes. All parent exits remain 24/62.
The latest owned-VM worker baseline has 333 records, preserving all earlier
326 records, SHA-256
`f7e44a5879bfbd8bd19097fc5b81927dfe93103b8db330813266bf25ad327a9d`.

## Scope and implementation order

Capture the actual stdin/stdout pipe exchanges of source-pinned Native
`resident-client-stream` processes in the owned synthetic product cell.
Those bytes are distinct from the already captured SDK/controller frames.
Require the actual stopped Native ELF digest, fixed command shape, owned
task lifetime/cgroup, privilege floors and stable pipe endpoint identities
before selecting a process. Inspect only the selected pipe I/O buffers;
private files, resident keys and unrelated process memory are outside scope.
No target memory, register, syscall argument or approval decision is modified.

1. Implement bounded decoding of Linux syscall-stop information and transfer
   accounting, including entry/exit pairing, scalar/vector I/O, partial return
   counts, errors, signal interruption and actual death. Preserve old wait and
   process-history readers unchanged for legacy modes.
2. Extend the dedicated Root tracer with an explicitly versioned capture
   mode. Select syscall stepping only for the identified Native client stream,
   retain exit-kill ownership and distinguish real SIGTRAP delivery. Validate
   pipe identity around each relevant transfer; copy completed read buffers
   and the completed portion of submitted writes. Refuse unavailable, changed,
   oversized or ambiguous measurements. Bound memory, records, bytes and drain.
3. Add closed launch v4 and process-checkpoint v2, with mandatory Native digest
   and capture declaration bound before actor release. Keep v1-v3 behavior
   intact. Bind the separate Root I/O journal into the signed Native plane;
   no older report may borrow its fields or measurement credit.
4. Independently reconstruct framed Native requests/responses in Rust. Join
   each stream to its complete process history and gate, exact input/output
   byte counts and physical outer capture. Treat partial cancellation and
   timeout streams explicitly. Captured request bytes do not alone establish
   every Native helper's semantics, an effect writer or admitted custody.
5. Prove the mechanism with owned ARM scalar/vector/fragmented/short-I/O,
   signal/death, wrong digest/endpoint, truncation, overflow and lost-recorder
   fixtures. Then execute fresh source-pinned benign and negative controls
   under the unchanged single-CPU/1-GiB/128-task product limits. Preserve all
   earlier failures and the current public product prefix.

The first integration covers the Native stream client transport, whose pinned
entrypoint reads framed stdin and writes framed stdout. Other Native command
inputs and the authenticated client-to-resident connection retain their own
identity/semantics obligations; no blanket wire-verification flag is inferred.
No model request, quota reset, production gate or CI bypass is authorized by
this implementation step. Required CI remains user-owned and pending.

## Bounded decoder checkpoint

The first source checkpoint adds an AArch64 entry/exit decoder, scalar/vector
selection for stdin reads and stdout writes, eight-MiB transfer and 1,024-vector
bounds, completed-prefix accounting and poisoned entry/exit sequencing. The
metadata getter exposes no target-memory or register mutation. Nine focused
tests pass, as do all-workspace macOS and ARM Clippy and formatting. The full
locked/offline macOS workspace run passes 603 tests, with zero failures or
ignored tests. Its retained log is
`native-stdio-working-workspace-tests-003.log`, SHA-256
`2da4ed92cb1a6f7b29631d9ea0320790307c294bc4c67e8d56e2efe4ba5b026c`.
The new live fixture uses the existing pinned owned-process executable; its
intentional final exit is 97. No parent checklist exit advances from this step.

Source checkpoint `483c29a0823ab77c48ed593e9867fa382e15f5d5` builds the frozen
ARM test ELF (10,982,032 bytes), SHA-256
`26121816670af4f62fe0b68c1841014b4dd2207ce2747b2d055a9969125f099b`.
Under both worker leases, nine decoder tests and seven process fixtures pass
with zero failures or ignored tests. The live ABI test sees two syscall entries,
one exit and the actual final exit 97. It reads no target memory and executes
no candidate product. The retained public export has 25 members and 337,920
bytes, SHA-256
`61daa708d0253718b83bc626b10d79d60af89f37f72da7740c8536d8256ac256`.
Its host [readback](../ci/gauntlet-rs/proofs/verify_native_stdio_syscall_20261028.py)
checks every archive member, Root metadata, source blob, exact test count and
unchanged 326-record worker baseline. The separately frozen Rust process reader
also accepts four complete legacy fixture histories and refuses the retained
lost-recorder history. The readback output SHA-256 is
`c72343d13378655bb98f60ad8c9ee6787e6d4f53228f0c9469e257eab3815f56`.
This establishes the live metadata ABI; actual pipe bytes and all qualification,
custody, Native semantics and effect-writer claims remain unverified.

## Initial pipe snapshot producer

The opt-in launch-v4 contract requires `outside-root-ptrace.v2`, the fixed
`outside-root-native-stdio.v1` mode and an exact Native executable digest. Its
process checkpoint is v2 and its signed Native plane is v3. Older launch
contracts reject these fields; their tracing options and behavior are unchanged.
The product pin must agree with the launch digest before hook-plane startup.

Only the selected Native stream leaders use syscall stepping. The recorder
retains task lifetime/tracer ownership, actor namespaces/label, privilege floors,
exact command shape and distinct anonymous fd0/fd1 pipe identities. Each relevant
snapshot re-hashes the full executable and rechecks the held/current pipe
objects. `O_PATH` references add no pipe reader or writer. The private memory
backend reads only the selected scalar buffers or bounded iovec table/data.
It rejects partial memory copies. Read snapshots use completed byte counts;
write snapshots retain submitted bytes and credit only a successful returned
prefix. Failed/interrupted calls never invent bytes or EOF.

Bounds are 16 active streams, 1,024 stream lifetimes, 8,192 pipe calls, one million
syscall stops, 16 MiB of pending submitted writes and 32 MiB of captured bytes,
in addition to the existing per-transfer/vector and private-journal bounds.
Separate fixtures exercise actual scalar/vector parent pipe bytes, a nonblocking
short write, wrong ELF pin, descriptor replacement, oversized submission and
death during a pending read. Fixture selection exists only in the owned-test
build and declares its separate scope. The initial producer passes all 607
locked/offline macOS workspace tests (zero failures/ignored), formatting and
Mac/ARM warnings-denied Clippy. The full workspace log
`native-stdio-capture-working-workspace-tests-002.log` has SHA-256
`2c8599a3fb9d3b2d4a0792d90abd1f218a12d20a47d070c2e4f314826aab6f4f`.
Live fixture execution and independent v2 process/I/O readback were pending
at producer source `f137c1b0`; the frozen v1 reader refuses v2 checkpoints.

The first live producer attempt at `f137c1b0` retains six fixture-start permission
failures: the unprivileged executable was beneath a Root-only input directory.
Only the pinned fixture ELF was then copied to a new Root-owned 0555 public
location; private input/proof directories remain 0700. The second attempt
retains four passing cases and two failures. The synthetic driver's buffered
gate could consume payload before exec, and scalar/linger output lacked a
flush before direct exit or a blocking read. The follow-up waits for the
observed leaf exec before sending payload and explicitly flushes that fixture
output. Byte-comparison and refusal assertions are unchanged. The revised
fixture passes Mac/ARM Clippy and the macOS rootfs tests. Both original attempts
remain immutable in the owned VM.

Corrected fixture source `018890172c5a0976f9cad606bf55433d8be8a027` passes
22 owned ARM tests: nine syscall decoder cases, six pipe cases and seven legacy
process fixtures. Four complete pipe histories match actual parent input/output,
including the 4,096-byte nonblocking write prefix and an interrupted pending
read with no credited input or inferred EOF. Three expected refusals occur
before buffer copy. The histories contain 4,161 captured bytes. Both worker
leases remain held and all 326 worker records remain byte-identical.
The public export retains all three attempts: 82 members, 655,360 bytes, SHA-256
`e29a91ec9f5f356f76c0a74828a3124220fe2822e52a493d31280d737856c780`.

The independent Rust reader binds each stream to its actual exec and kernel
ending, validates closed event ordering and completed counts, and reconstructs
framed stdin/stdout separately. It retains partial headers/payloads, malformed
lengths and invalid JSON as explicit diagnostic results. Native request and
response bounds are six and two MiB, matching the pinned product source.
Four actual complete fixture histories verify; three incomplete/refused histories,
three wrong caller pins and re-hashed altered captured bytes refuse. The current
working reader's independent summary is SHA-256
`98bdc64fdec720d8eaf6b519f5853897c7d3605951c465a8ee3b9e9d89092d90`;
source hashes are retained before committing this verifier. All 615 macOS
workspace tests pass with zero failures/ignored, with log SHA-256
`e559ee8b21fa4880cb272516bb2b9d19267413ca197e0dd9c3c88b5b9dcb4fd8`.
Formatting and Mac/ARM warnings-denied Clippy pass.

Committed verifier `bd262dcad72278b58ae1059866a217acf366c90b` reproduces the
working reader bytes. Its 2,372,720-byte Mac stdio reader has SHA-256
`dd9ce2f5e7424e7ec96c71d9111f1434316d5e855a1ffbfb44e8dddb55cfbb80`;
its 3,567,680-byte ARM reader has SHA-256
`1bf6f2053a6c117d11ce12723d17adb7f6dd213b4a1e2ccf553b67e7fd3a2f39`.
On ARM, 27 focused stdio/process/signed-trace/image tests pass. All eleven
snapshot replay/refusal outputs match the Mac results byte for byte, as do
actual/restart/refusal checks against historical Native control `5602`. All
32 legacy control readbacks remain byte-identical with the committed verifier.
The ARM reader export contains 126 members and 1,085,440 bytes, SHA-256
`7fd4b64adaf380b004becedc9387fe959df6b4fa6002ec60105e4a7c4bc9c701`.

The [fixed-generation host verifier](../ci/gauntlet-rs/proofs/verify_native_stdio_pipe_20261028.py)
and [ARM proof helper](../ci/gauntlet-rs/proofs/native_stdio_arm_proof_20261028.py)
verify both public exports, all source/ELF/log/metadata pins, the retained fixture
and SSH failures, all 673 Rust source files against the committed verifier,
the 615-test source match, 32 legacy outputs and both unchanged worker leases/
record sets. A fresh Mac replay reproduces all eleven outcomes. The final
host readback output has SHA-256
`e7c9bd07f82f1baff1f9860176a0e60fcce0c9c62ed480c7fdb0b643e87c4a8c`.
The two long-inline-command SSH failures executed no installer; read-only
reconciliation found both destinations absent. The identical program then
installed successfully from hash-verified file bytes. No validation assertion
or permission check was weakened. No new Native product or model job ran in
these proofs. Fresh launch-v4 Native controls are next; request semantics,
atomic observation, physical writers and all parent exits remain open.

[`process_vm_readv`](https://man7.org/linux/man-pages/man2/process_vm_readv.2.html)
does not promise atomic transfers. The producer explicitly records
`concurrent_tracees_frozen=false` and `atomic_kernel_pipe_bytes_verified=false`.
Other threads can run between stops, and an entry/exit snapshot does not itself
attest the kernel's copied payload. Its read-only observations can support frame
comparison after independent replay; full wire qualification still requires
resolving that concurrency obligation. No parent exit, admission, approval
behavior or effect-writer claim advances from the initial producer.

## Kernel contracts and separate effect work

The [ptrace ABI](https://man7.org/linux/man-pages/man2/ptrace.2.html) provides
typed entry/exit syscall-stop information. `TRACESYSGOOD` must be established
before those stops. The decoder must reject unsupported architectures,
truncated records and unknown stop types. Reading information is separate
from mutation operations, which the collector does not expose. A stopped
task can still die; missing buffers remain unavailable evidence.
The [Linux 6.8 implementation](https://github.com/torvalds/linux/blob/v6.8/kernel/ptrace.c)
returns through the final populated entry/exit field, rather than trailing C
structure padding. The initial decoder requires those exact 80/33-byte records
and rejects unsupported extensions. The pinned libc exposes the structure on
GNU; the musl backend therefore decodes the same fixed ABI from bounded bytes.

The existing staging fanotify collector supplies useful file and pidfd custody
helpers, but its post-close image sample is not an atomic writer-instruction
observation. [fanotify](https://man7.org/linux/man-pages/man7/fanotify.7.html)
distinguishes modification and writable-close notifications, may merge events,
and does not cover changes through `mmap`, `msync` or `munmap`.
[PIDFD reporting](https://man7.org/linux/man-pages/man2/fanotify_init.2.html)
identifies a process lifetime; its combination with thread-ID reporting is
unsupported in the documented interface. A later effect collector must bind
actual object generations and process history, handle descriptor passing,
renames, missed/late writers and queue overflow, and keep unsupported writes
unverified. The new pipe observer supplies none of that writer credit.

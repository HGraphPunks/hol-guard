# Outside Native client pipe capture

Status: syscall metadata, transfer accounting and the initial outside pipe
snapshot producer are implemented after
verifier checkpoint `98a544f3` and published evidence checkpoint `5ddb5d52`.
The live ARM syscall ABI fixture passes in the owned VM. The new producer and
closed launch-v4 contract pass macOS tests and Mac/ARM Clippy; live pipe fixtures
are compiled and await execution. Independent capture/frame verification and
fresh Native product controls remain open.
The existing image-lineage proof
does not observe internal Native request bytes. All parent exits remain 24/62.
The latest owned-VM worker baseline is the unchanged 326-record set,
`16b21c170df5494738bc40b188694f186c87a2f9caca75d1f50d05459d4aa9be`.

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
Live fixture execution and independent v2 process/I/O readback remain pending
at this source checkpoint; the existing v1 reader refuses v2 checkpoints.

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

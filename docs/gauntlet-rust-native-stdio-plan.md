# Outside Native client pipe capture

Status: bounded syscall metadata and transfer accounting are implemented after
verifier checkpoint `98a544f3` and published evidence checkpoint `5ddb5d52`.
The live ARM syscall ABI fixture is compiled and awaits execution. The actual
pipe-memory observer, signed capture and frame verifier remain unimplemented.
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
intentional final exit is 97. Compilation does not establish live ABI or
request-byte capture, and no parent checklist exit advances from this step.

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

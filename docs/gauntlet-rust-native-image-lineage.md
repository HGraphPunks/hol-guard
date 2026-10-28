# Native executable image lineage

Rust verifier source `98a544f31207808ca52dcf08f620ead3dca53d7b` now adds
event-derived image lineage to the complete control artifact reader for closed
launch v3. The retained product/control source is explicitly older:
`dc3b9336308dab4892bf0c0e0f328a9c8b7efc12`, benign job `e2c701baf1475602`.
This is offline verifier execution, not a new product run or qualified role.

The reader accounts for every exec in the complete Root process journal,
including 60 images whose actual stopped executable bytes match the pinned
Native ELF, 29 Native image inheritances and 87 distinct traced task identities
with an observed or inherited Native image. All nine gated launch ancestors
join. The prior polling-based client check separately observes four selected
Native clients; it does not stand in for this complete event-derived inventory.

## Binding and inheritance

The [Rust implementation](../ci/gauntlet-rs/crates/gauntlet-evidence/src/native_runtime_trace.rs)
first requires the acknowledged capture journal, the signed closed-v3 checkpoint,
original Root file metadata, stopped actor and every gate join. Existing Rust
replay independently checks the complete task history and actual final waits.
The new layer uses monotonic task IDs and the kernel parent relation, preserving
PID reuse and nonleader exec replacement without merging separate lifetimes.

Image inheritance is captured at `kernel-creation`, before the child first-stop
record. A parent can exec between those events. Two new tests initially fail
when inheritance instead uses the parent's later image; the corrected snapshot
passes both orderings. The six-pass/two-fail attempt remains retained as
`native-lineage-birth-race-before-001.log`, SHA-256
`802da5f14be4db4d19f8938d6ebdb3b4c11eb1ea848acf7f05a21c7d890b0036`.

Every recognized Native exec must match the content pin, have a gated ancestor,
retain the actor's namespaces and LSM label, and satisfy UID/GID 10004, empty
supplementary groups, zero capabilities, no-new-privileges and seccomp 2.
Native image inheritance also checks the child's observed privilege floors.
A named Native binary with other bytes refuses. A temporary compiler copy
with the same actual ELF digest is accounted for without inventing path
admission. Other executable digests remain explicit inventory entries.

The versioned `hol-gauntlet-native-runtime-image-lineage.v1` result records
task/parent/gate IDs, exec sequence, observed identity, executable metadata,
argument count and exact argv digest. It retains bounded operation names and
operation/program digests. Full arguments remain in the original process
journal; a 64,000-byte operand test proves they do not expand the public result.
Legacy launch paths gain no extra field or retrospective measurement credit.

Fork inheritance identifies the last observed executable image. It does not
authenticate inherited memory, internal Native request bytes, actual effect
writers, full descendant behavior or an admitted outside observer/key.
Those result flags remain false, as do qualification and Guard causality.

## Validation and retained evidence

All 594 macOS workspace tests pass with no failures or ignored tests, including
nine focused image-lineage cases. Mac/ARM all-workspace warnings-denied Clippy
and formatting pass. The focused cases cover both inheritance orderings,
PID reuse, nonleader exec, aliases, wrong pins and gate identities, privilege
and namespace changes, incomplete histories, unknown binary argv and bounded
large-argument output. The working-source hashes independently match the
committed blobs at `98a544f3`.

The retained real control passes all nine signature/MCP/process/hook/control/
restart/refusal calls with the new reader. Its successful full output hashes
to `d2816485069ac1964e3737584ed1afc9e7456ebd1df24bdd495a8c244739ecae`.
All 32 historical mode outputs remain byte-for-byte identical; the legacy
proof hashes to `1c934b9955bb0392b87516d2d6887fd3db197a20e1b5627e19046eceb6327434`.

On the owned ARM VM, all 19 focused tests pass: nine new image cases, six
existing task-replay cases and four signed trace-join cases. Actual artifact
readback, identical restart and three wrong-pin refusals also pass. Linux
successful output exactly matches the macOS bytes. The public host pin is a
copied public-key fixture, not a newly admitted host or outside key.

The first Linux courier loses regex escapes while parsing test counts and
refuses after the nine-test binary succeeds. Its original logs and failure
remain intact. The corrected courier validates their unchanged hashes and
reconciles the actual nine-pass result without executing those tests again;
the remaining ten tests and five artifact cases run afterward. No zero-test
or unknown-count result receives pass credit.

The [independent host reader](../ci/gauntlet-rs/proofs/verify_native_image_lineage_20261028.py)
checks all 41 members of `native-lineage-vm-results-001.tar`, 3,594,240 bytes,
SHA-256 `baf9ed0df33b6ba778a902baa44dd67bd6fe799a78bfc3e5f44c3d7cb5140f4d`.
It verifies source/ELF/input/log/copy metadata, both attempts and reconciliation,
all test counts, the legacy proof and a fresh Mac Rust readback identical to
the ARM result. Its successful output hashes to
`51a638b13df9c25d3169df01112b2f1ff767a2f0f1ff3e5143e5c1ae702aae36`.

The Mac reader hashes to
`b9ab424dd1e31e04c844ea95710c0b6f5d66c926c9f9914f9f28d2d12234723c`;
the ARM reader to
`f8ae31a0e5b5c9faa9538c778485aee2b551e630857efb7b0c8050f4b918a6a7`.
All 326 worker records remain unchanged under both leases. The active baseline
remains `16b21c17…59d4aa9be`; no new product job, model request, quota reset,
production gate, approval semantic or isolation change occurs.

Internal Native request semantics, effect-writer attribution, complete role
grading, outside admission and twelve fresh source-matched roles/conformance
remain open. This closes the bounded image-lineage subproof only; parent exits
remain 24/62. The earlier product and sampler failures stay retained, including
the unresolved first polling-sampler assertion in the
[worker-budget controls](gauntlet-rust-native-pressure-runtime-proof-20261028.md).

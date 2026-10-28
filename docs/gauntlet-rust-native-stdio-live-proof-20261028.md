# Fresh Native pipe snapshot control

The actual launch-v4 benign control passes with tool source
`77e7b7e7f9e4c5fada74ae2ff2e2a612214f90b9` and separately pinned product
source `dc3b9336308dab4892bf0c0e0f328a9c8b7efc12` (3.58.0). Independent
Rust readback reproduces 497 complete framed messages across 12 Native streams
on macOS and owned ARM. This is a live product snapshot proof, with explicit
limits: atomic kernel pipe bytes, concurrent memory, request semantics,
physical effect writers, complete role grading and outside admission remain
unverified. The worker terminal remains `invalid-evidence`; the controller's
authenticated diagnostic status is `passed`. Parent exits stay 24/62.

## Source and executable pins

The immutable public product prefix is unchanged. Its actual Native ELF is
SHA-256 `bdaf053911cd278930c17e3c58b7741e23334a5156817db78780349f8635eb10`.
The tool generation builds the following frozen executables:

| Executable | Bytes | SHA-256 |
| --- | ---: | --- |
| Mac host | 2,278,448 | `db2c8c0f7ba3d6124f9a919f08f401436f0a8415c3b906ce2dde215af32cc1aa` |
| ARM worker | 13,385,128 | `6d2b067e9ac3c7ec6236d3e445e59e5789305b7ea748b67166e0f4a048c29446` |
| ARM constructor | 1,957,864 | `287aaee18f3832d7cce1f9f11c3c7b4abdbcdcffa8436dd8d4c4e1806beb4143` |

The independent reader is source
`bd262dcad72278b58ae1059866a217acf366c90b`; rebuilding at the tool generation
reproduces its Mac bytes. Its Mac control reader is 6,971,424 bytes, SHA-256
`4e4de9d24934efc04a706c0a761ad808bbe6ecd66e64e709c84cd42e3fda0ddf`.
The ARM reader is 8,770,376 bytes, SHA-256
`ffacdf72c0794ec938021ce69286b9aa5a3a7989000c35f448ba670ee88ce8a3`.
The 615-test Mac workspace run and Mac/ARM Clippy are source-bound in the
[initial pipe proof](gauntlet-rust-native-stdio-plan.md). This proof adds
tooling and documentation; it changes no Rust runtime source.

## Actual control and outside observations

One-use job `e2c701baf1475701` binds preparation
`3ed65fe2c858aa3e7bacc1df01bc8edbda20e377213b530f7f084c20727e365e`
and deployment
`1795bc33fcab40bc14435963b5239315549ea35be209e5a2b1b6ffb4e0731cbe`.
The Mac host retains its public prelaunch pin before controller release:
`06197f1a24dffb1f45e8ee166340d1d1af43bb8f40d06ff44c6a7ea74f3c9dc6`.
No private key is exported or read by the proof courier.

The original Node/npm fixture passes with Node v22.22.2 and npm 10.9.7. The
product keeps its single CPU, 1 GiB, 128-task and 180-second bounds. The host
execution takes 120.473 seconds. All 460 created tasks have actual final waits;
the trace records 154 execs and 2,268 process events. The independent image
reader checks 75 Native exec images, 34 inheritances, 107 Native task identities
and all 15 gate joins. Outer artifact checking covers 14 capture streams,
three acknowledged hook inputs and three raw SDK requests.

The selected pipe snapshots record 529 I/O calls, 111,945 syscall stops and
382,274 bytes across 12 closed streams. Framing reconstructs 249 read messages
and 248 written messages, with complete framing on both directions of every
stream. Three interrupted pending reads credit no input and infer no EOF.
Message counts and valid JSON alone do not establish request/response semantics.

The outside sampler completes 772 pressure observations, peaking at 112 tasks
with zero PID-limit rejections. All 127 kernel observations and the Root
controller observation complete without recorded errors. The host `/dev/null`
identity is unchanged. The earlier control's polling-sampler assertion remains
retained and unresolved; this success does not retroactively repair it.

All 326 original worker records remain byte-identical. The seven new one-use
job records produce a 333-record final baseline, SHA-256
`f7e44a5879bfbd8bd19097fc5b81927dfe93103b8db330813266bf25ad327a9d`.
The final guest baseline is
`/var/lib/hol-gauntlet-rust/native-stdio-control-proof-20261028-001-success/final-worker-hashes.json`.
Both worker leases protect subsequent readback and preservation checks.

## Independent readback and reproduction

The actual public control export has 147 members and 7,004,160 bytes:
`native-stdio-control-vm-results-001-success.tar`, SHA-256
`24e4ab9b915d32c5d599553a1b38a460d8355e64109d5defb5a0bc07c35e9376`.
Its signed report, Root journal metadata, process history, separate stdio
journal, acknowledged inputs and outside observations agree. Nine Mac and
nine Root ARM signed/MCP/process/hook/control/restart/wrong-pin cases pass.
Their complete control output is byte-identical, SHA-256
`97fbecbaec0ad7772b1c49e129366b384be069b23f0294611931318a5e277d94`.

The ARM replay export has 39 members and 8,089,600 bytes:
`native-stdio-live-readback-vm-results-001.tar`, SHA-256
`9702468e978356a5acef1fa3e4d89e7ed44fe33408cd5e0fa323aadb4e20da9b`.
Its copied public host pin is explicitly a fixture. It supplies cross-platform
replay proof, with no new product execution or outside custody admission.

The [fixed host verifier](../ci/gauntlet-rs/proofs/verify_native_stdio_live_20261028.py)
and [ARM helper](../ci/gauntlet-rs/proofs/native_stdio_live_arm_proof_20261028.py)
check both exports, source/ELF/metadata pins, all nine ARM outcomes, the 333-record
baseline and five fresh Mac actual/restart/wrong-pin outcomes. The retained
`native-stdio-control-live-proof-003.json` has SHA-256
`fd6485eec5e723172a8f42609ceb1262ee121629c5207af05294246957f72414`.
Reproduce with `python3 ci/gauntlet-rs/proofs/verify_native_stdio_live_20261028.py
EVIDENCE_DIRECTORY NEW_THREE_DIGIT_INDEX`; the courier creates exclusive output
paths and executes only the frozen local Rust reader against public evidence.

The first installer refused a mistaken baseline path before writes; the
corrected exact program retained all baseline checks. Two fixed host-courier
failures remain: an archive-size transcription error and an assumed absent
tool-source field in the earlier proof. Corrections use the exact archive size
and independently retained tool metadata; no old record, grading assertion or
permission check is rewritten. Ruff lint and formatting pass.

No model requests, quota reset, production gate, CI bypass or merge occurs.
Required final-head CI remains user-owned and pending. The subsequent
[copied-hook verifier](gauntlet-rust-native-copied-hook-relations.md) joins five
actual exchanges to their gates and outer inputs. Metadata-operation semantics,
atomic observation and physical writer attribution remain separate requirements.

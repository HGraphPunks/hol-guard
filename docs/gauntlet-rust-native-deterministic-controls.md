# Rust-owned deterministic control diagnostics

The closed `hol-gauntlet-native-worker-job.v6` declaration adds
`native-deterministic-control-v1` and a typed role to the SDK/MCP/Bash path.
It requires both product and locked-SDK pins. Earlier v1–v5 declarations
retain their meanings and reject the extra role field.

This implementation is partial. `success` runs the existing actual SDK
control. `input-binding` additionally invokes the installed Native sink with
all nine historical malformed requests. `injection`, `boundary`, `timeout`
and `cancel` currently refuse as incomplete before product startup. Declared
roles are not a claim that the six-role qualification suite is available.
Every terminal remains `invalid-evidence`, with eligibility and Guard
causality false. `qualified_role_complete` is explicitly false.

The input-binding recorder preserves each original raw request, including
duplicate JSON fields, and its actual/declared SHA-256. It uses the existing
descriptor-bound private request handoff. Each case must return 126 with one
of the two installed Native authorization-refusal prefixes, retire its
request safely and leave the synthetic trap absent. Planner, transport and
capture failures cannot count as Native refusals; unavailable captures keep
null output/exit fields and their retained journal evidence.

Root creates a fixed `negative_tests/test_trap.py` under the exact held task
workspace. It verifies the checkout and fixture directory, file inode,
owner/mode/link count and bytes before and after each call. The trap would
write `unexpected-negative-sink.txt` if a malformed request executed it.
An unreadable or substituted namespace is unavailable rather than evidence
of an absent effect. These Root control probes are separate from SDK/model
operations and do not mint an SDK budget permit.

At source `f013438b680595d05fc2fc2e11963596ae2b2af1`, fresh v6 job
`e2c701baf1474101` passes all nine installed-Native request-binding cases.
Every case returns 126 with the actual Native authorization refusal, safely
retires its request and leaves the unchanged physical trap without an effect.
Independent host readback checks the original malformed bytes, CLI bindings,
captures, fixture metadata/bytes, SDK MCP/Bash results, signed physical SQLite
read and 57 outside process samples. All 161 earlier worker files stay intact;
the final map contains 167. Replay refuses in 521.121 ms while the legacy lease
is held; reconcile returns the original terminal and wrong request pins refuse.

Native ARM execution passes 177 worker tests (24 existing fixture ignores),
33 rootfs tests and its nested subprocess test. The affected macOS suites pass
107 tests. Warnings-denied Mac/ARM Clippy and both ARM main binary builds pass.
The retained first compiler refusal caught a non-comparable `Stat` result
and use of the rootfs declaration where the task declaration was required;
the corrected owner uses the already authenticated `TaskMount`.

The public input archive is 65,095,680 bytes / five members, SHA-256
`7730fd2ac9a145ef6db43facb07f17608d005551675a275136001ef8f60d7e64`.
The public export is 1,208,320 bytes / 159 members, SHA-256
`8399235c821e35c2a1699538fe152e2b88b4e31a73035cfab1486fa522c199ce`.
The report SHA-256 is
`8ea8ae6564e8807a8602dcc78c357c64153e477b43edf490b5c9caf7b3429dfa`.
Run `ci/gauntlet-rs/proofs/verify_native_request_bindings_20261027.py` with
the retained evidence directory. Its result remains explicitly ineligible;
the diagnostic uses the historical `62aa7ba7` product prefix. Product home
and Guard stores are excluded from the public export.

Remaining work includes the real forbidden-command positive/negative control,
boundary canaries/kernel probes, injected response disposition, observed
detached-child timeout/cancellation, provider mapping, complete role scoring,
outside signing-key admission and fresh current-source staging/installed
conformance. The successful [combined SDK transport](gauntlet-rust-native-sdk-mcp-transport.md)
is retained independently; the parent checklist stays 24/62 complete.

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

The common role parser, request recorder and trap owner compile for ARM64
with warnings-denied Clippy. The affected macOS suites pass 107 tests and
Clippy; static ARM test compilation passes. Fresh native library execution
and live v6 request-binding execution remain pending at this checkpoint.
The retained first compiler refusal caught a non-comparable `Stat` result
and use of the rootfs declaration where the task declaration was required;
the corrected owner uses the already authenticated `TaskMount`.

Remaining work includes the real forbidden-command positive/negative control,
boundary canaries/kernel probes, injected response disposition, observed
detached-child timeout/cancellation, provider mapping, complete role scoring,
outside signing-key admission and fresh current-source staging/installed
conformance. The successful [combined SDK transport](gauntlet-rust-native-sdk-mcp-transport.md)
is retained independently; the parent checklist stays 24/62 complete.

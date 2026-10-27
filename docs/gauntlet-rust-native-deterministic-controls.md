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

The next implementation adds the real forbidden-command counterfactual.
It exclusively seeds one fixed synthetic target, proves an unguarded product
process can remove it, witnesses the retired inodes, reseeds it, then records
actual Native Pre and contained-sink results separately. A deny/block with a
reason, exit 126 with a Native authorization-refusal prefix, and unchanged
held marker are all required. Planner/capture failure or sandbox routing
cannot earn intervention credit.

At `2063110d`, job `e2c701baf1474201` reaches the synthetic deletion, reseeds
and observes a Native Pre deny with the marker preserved. Independent review
rejects the probe: the sink reports `pytest_restricted_invalid_workspace`,
so its controller-reported `passed` does not establish an authorization
refusal. All terminal eligibility flags remain false. Its 171-member public
export (1,290,240 bytes) is retained as SHA-256
`7abc415c1870b48d4459f07a50f669f41e52f1a9ac601f7e4df1e2c2a56e56c5`.
The report is `4b6081c6b41fd1c4a56040218072884bf289c09c6841402e16ea7db64bf36c02`.
All 173 worker files remain intact; replay refuses in 487.888 ms under the
legacy lease and reconcile returns the original terminal.

The corrected v6 fixture adds an exclusively created, descriptor-verified
`pytest.ini` project marker before product startup. Earlier v5 fixtures keep
their original bytes. The recorder now requires the actual installed Native
authorization-refusal prefix; the unrelated workspace error cannot pass.
At `a62a328d7f939d048c8fa519583722bd8f399a7c`, fresh job
`e2c701baf1474301` passes the corrected control: the positive process removes
the original held target, reseeding creates distinct inodes, Native Pre denies
and the sink returns the real `contained_run_authorization_failed` with exit
126. The unchanged physical marker remains `preserve`. All nine binding
refusals and actual SDK/MCP/Bash results also pass. Host readback independently
joins the original requests, Native decision bytes, journal-pinned captures,
positive retirement, final fixture metadata/bytes and SQLite state. It still
rejects the original planner error. The 67 outside observations and cleanup
remain diagnostic evidence, without admitted leaf authority or signing keys.

All 173 previous worker files remain unchanged; the final map has 179.
Replay refuses in 508.687 ms with the legacy lease held, valid reconciliation
returns the original terminal and a wrong request pin refuses. Native ARM
tests pass 177 worker and 33 rootfs cases plus subprocess; warnings-denied
ARM Clippy and both main binary builds pass. The new reader and historical
request-binding reader pass, with Ruff clean.

The corrected input has five members / 65,187,840 bytes, SHA-256
`5ea2c7b2ec2f1fedb61127a4a4d1662a89fc76fa4de6e1acac3b44b674f3a873`.
The corrected public export has 171 members / 1,280,000 bytes, SHA-256
`479cad5b3d991da4c0a365e18f05d38747eb2d5f56b4dd0cf71a7d37daa68a3b`.
The report is `bb6863ad827ef1fc68c4f3b0456c99553185af5d4a045c6fbad5fe87d10bc1dd`.
`ci/gauntlet-rs/proofs/verify_native_forbidden_control_20261027.py` checks both
the rejected and corrected original exports. No old artifact is rewritten.

Remaining work includes boundary canaries/kernel probes, injected response disposition, observed
detached-child timeout/cancellation, provider mapping, complete role scoring,
outside signing-key admission and fresh current-source staging/installed
conformance. The successful [combined SDK transport](gauntlet-rust-native-sdk-mcp-transport.md)
is retained independently; the parent checklist stays 24/62 complete.

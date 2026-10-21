# Rust-owned candidate staging control: implementation proof

This slice gives Rust ownership of one diagnostic candidate control while
preserving the existing passive release observer and the Python controller's
locks. It does not create a conformance package, mark a candidate ready, or
enable a PR gate. The terminal outcome is always `invalid-evidence` until an
independent signed-record and physical-effect scorer exists.

The Linux ARM `gauntlet-candidate-staging-control` accepts only fixed build,
run, source, version, config, private-cell, prefix, controller, interpreter,
worker-binary and role pins. It verifies its installed Root-owned executable,
the positive source-matched conformance readiness, the held interpreter inode
and SHA-256, and the complete controller tree. A distinct Root-owned staging
journal reserves the run under an exclusive lease. Rust generates a sealed
Ed25519 controller key, durably records the started marker and key pin, emits
the prepared frame, and waits for the Mac host's durable key pin and
acknowledgement before launching the adapter. Rust then owns the controller
cgroup, 30-minute boottime deadline, cancellation, process observation,
descendant reaping, cgroup drain and product-slice stop. It retains a one-use
Root-only adapter log and a canonical diagnostic terminal; it does not trust
the adapter's cleanup claim as a benchmark verdict.

The macOS `gauntlet-host-staging-control` constructs exactly one canonical run
frame and one fixed Lima/sudo guest command. Its private host journal fsyncs
the guest's public-key pin before sending the acknowledgement. A failed or
uncertain handoff is reported as unresolved, with no replay or automatic
promotion. The bounded wait reports only an ineligible host diagnostic;
terminal and signed record readback remain separate work.

The source-matched Python controller was prepared without changing the active
Python installation. A read-only Git verifier matched all 427 `ci/gauntlet`
source blobs at commit `f58c03aaf903755e42eb48c68d9c820bf6e9e962`,
3,928,143 total source bytes, against the exact integration map. The map's
SHA-256 was `9ce59964afb73a3cb9b4809a74b614ddc9aeb5a846bab8a7633dc64c1c484574`.
The independent install plan selected 396 files and 407 non-root entries,
giving tree SHA-256
`be835c70dd4435463568c7417e7330de21cc251618c0473b785ffc218f03e910`.
The Root installer accepted the exact Git archive and map in the idle ARM VM
and installed `/opt/hol-gauntlet/controller-f58c03aaf903755e`. It reported
`controller_executed:false` and `execution_eligible:false`.

Local checks: the 427-file source inventory, the current install-plan tests,
Rustfmt, native host Clippy and warnings-denied Linux ARM worker Clippy pass.
The previous PR head's two isolated CI jobs failed because the install-plan
test still expected 426/395 files; this slice updates that expectation to
427/396 and the independently derived new tree digest. The final PR-head CI
result remains open.

The controller install and executable compilation are infrastructure evidence
only. No fresh control, signed record, model request, full six-role package,
independent physical-effect verdict, host/VM crash handoff, or production
cutover is established by this proof.

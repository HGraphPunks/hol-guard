# Rust feature audit

Updated 2026-10-28. The fixed unprivileged executor is implemented; its first
full audit is in progress. Rust worker admission, durable audit ownership,
interruption recovery and final readback remain open. This work closes no
parent migration milestone: progress stays 24/62, or 39%.

## Fixed schedule and execution

`ci/gauntlet-rs/feature-catalog.v1.json` preserves all 28 groups, 52 pytest
selectors, labels and source/installed contexts from the immutable Python
baseline's `feature_entry.py`. The baseline source digest is
`d3d5b72d7bd9c725d7cc9b90aa3bb7bc442a99a5e188943f4686bf34e4c048de`;
the catalog digest is
`1955516522cccd5235c565498a7e28c8871e31361609d52f0bdebb6e0b91677f`.
The parity test extracts the relevant fixed declarations with Python's AST
reader and compares all groups, ordering and pytest arguments with Rust.
It does not import the controller or regenerate the immutable baseline.

`gauntlet-feature-executor` accepts one outside SHA-256 argument for a closed,
canonical `hol-gauntlet-feature-executor.v1` specification. The specification
pins the audit, source archive, candidate archive, wheel, Native runtime,
version, Node, catalog and executor. It contains no command, path, model or
test-subset selector. The executor checks its actual running ELF and refuses
unless it is ARM64 container PID 1 with real/effective UID/GID 65532, no
capabilities, no-new-privileges, seccomp 2 and the enforcing audit profile.

Rust owns unpacking and exact-commit checkout, frozen CI dependency setup,
wheel installation, Native capability/version/hash checks, the bounded
wheel-data overlay, source compiler build, per-command deadlines and logs,
the full group schedule, artifact hashes and result calculation. Every
external command runs unprivileged with an explicitly constructed environment.
Pytest remains the permitted external product-test executor. The production
Python `feature_entry.py` is not the Rust executor's launcher or scorer.

All 13 source groups run before the exact wheel is reinstalled for the 15
installed groups. Rust preserves the source-only `PYTHONPATH`, installed-only
distribution flag, verified Native selection and native-runtime group's exact
source compiler setting. Commands use the frozen 600-second group deadline.
Every child has separate bounded output pipes; Rust kills and reaps remaining
descendants before advancing to the next phase. Unsafe or uncertain cleanup
aborts the audit.

The feature container retains the Python audit's 12-GiB, two-CPU, 2048-task and
14400-second whole-audit limits. This is a separate resource profile from the
single-CPU, 1-GiB, 128-task Native product cell.

## Result version and custody

The new result is explicitly `hol-gauntlet-feature-contracts.v2`. Existing
v1 readers and evidence remain unchanged. Rust counts actual JUnit testcases,
failures, errors and skips, and requires suite/root counter agreement. It
refuses malformed, negative, dishonest, unsupported nested or namespaced XML.
Input is bounded to 4 MiB, 200,000 XML nodes and bounded nesting, with no
external entity resolver. The pinned parser is `roxmltree` 0.21.1; its
[parsing options](https://docs.rs/roxmltree/0.21.1/roxmltree/struct.ParsingOptions.html)
provide the node and entity controls. Empty DTD syntax is not claimed to be
universally rejected.

Sixteen Python-produced JUnit cases retain both the original reader's result
and the explicit v2 acceptance/refusal expectation. The fixture digest is
`bc9072deb392ae37b473a095f6e4416f69eaa01c55f2cb0f4ff9a3957f0b7938`.
The v2 report verifier independently reopens every fixed XML/log pair,
recomputes its digest and counts, checks all 28 exact group declarations and
distinguishes `invalid-evidence`, `failed`, `incomplete` and `passed`.
Missing selectors or artifacts cannot become a pass.

The executor retains each group's counts and hashes in memory immediately
after its children exit. It rechecks every artifact after the complete schedule
and final descendant drain. The final canonical report also travels over the
outside owner's stdout channel. Test children do not inherit that channel.
Rust sets [PR_SET_DUMPABLE](https://man7.org/linux/man-pages/man2/PR_SET_DUMPABLE.2const.html)
to zero, then a fixed same-UID child verifies that opening PID 1's stdout
descriptor and memory fails with `PermissionError` before candidate setup.
The live retry has passed both probes. This checks those accesses under the
measured container configuration; it is not general proof of every possible
same-UID attack.

The standalone report verifier states
`execution_provenance_authenticated:false`. Reports remain diagnostic with
`qualification_eligible:false`. No model provider or quota journal is started
by this audit. Product fixtures do not establish live SaaS or agent-version
qualification.

## Validation and current attempt

The first implementation passes all nine new catalog/spec/JUnit/report tests
and the 632-test macOS migration suite, with no failures or skips. Current
executor source map
`c77aa8abddc281a4858b4165f619b78ffce7d811771c6788ba8ed6371a6d5ac6`
passes Mac and ARM warnings-denied Clippy and builds the static ARM executable.
The complete Mac run on this generation also passes all 632 tests, with no
failures or skips. Its retained log digest is
`1c2d6df58751b3d3b2e3dcc7a8f1ea4314fe3ae30258490e7f506c7497fd7bbe`.

On owned VM `hol-gauntlet-rust-build-20261026-001`, all eight ARM tests pass:
two executor context/status tests, three JUnit tests and three report tests.
Launching the executable outside its required container refuses with exit 2.
The 9,848,344-byte ARM executable hashes to
`564df9b01bd3f3e8c4460c586df63f31397b03795334120f41a70fde6829ce92`.
The eight-member development input archive hashes to
`227987e17ef13d2ea3751ba38cf3c51c52c7cdd58e39f60a98d5ac856684dcf6`.
The source map records the implementation as working-tree changes over
`7cfee04d`; it does not claim that commit already contains the new executor.

The initial setup attempt `native-feature-executor-proof-20261028-001`
stopped before tests or container creation because the old Python audit's
hard-coded Node host path is absent in this VM. Its files remain retained.
The exact Node ELF was then copied as inert data from the retained immutable
agent image through a never-started container. Its 121,980,552 bytes match the
existing pin
`3159f9115ab4be7d318b7c28e946837a4dceb7f2b3c43232aa2f2e3852550b90`;
that temporary container was removed, and all 333 worker records remained
unchanged.

Fresh audit `e2c701baf1475802` uses separate input/proof directories ending
`20261028-002`, the exact successful build's source and candidate archives,
and immutable builder image
`383e9cf215d3b8481c2b9fb67d32816ef322b7f40abc17e5a1f9a72dd728fc8a`.
Both worker locks are held. The development Root adapter checks actual
executor ELF, UID/GID, capability/privilege/syscall floors, enforcing profile,
namespace PID and effective resource limits. It retains bounded stdout,
stderr and observations, then removes only its exact labeled container and
profile. The Rust executor has passed setup and is building the exact-source
compiler. No 28-group result or final cleanup is claimed yet.

The Root launcher for this first proof is a development Python adapter.
Porting its durable admission, process/cgroup ownership, restart handling,
outside result binding and operator invocation into Rust remains required.
Required cloud CI is still user-owned and pending. Neither a successful
diagnostic audit nor these tests satisfy final migration readiness.

# Rust feature audit

Updated 2026-10-28. The latest source-matched diagnostic audit has 27 passed
groups, zero failed groups and one incomplete group. Its 1,289 cases contain
1,288 passes and one existing expected failure. Independent Mac/ARM readback
is verified. Rust worker admission,
durable audit ownership and interruption recovery remain open. This work closes no
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

## Initial implementation and retained attempt

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
Both worker locks were held. The development Root adapter checked actual
executor ELF, UID/GID, capability/privilege/syscall floors, enforcing profile,
namespace PID and effective resource limits. It retained bounded stdout,
stderr and observations, then removed only its exact labeled container and
profile. The Rust executor completes setup, the exact-source compiler and all
28 groups. The 60 retained outside observations match the executor ELF,
namespace PID and effective resource limits. Exact-container, cgroup and
profile cleanup is confirmed, with all 333 prior worker records unchanged.

The Root launcher for this first proof is a development Python adapter.
Porting its durable admission, process/cgroup ownership, restart handling,
outside result binding and operator invocation into Rust remains required.
Required cloud CI is still user-owned and pending. These diagnostic results
and tests do not satisfy final migration readiness.

## First audit and independent readback

Audit `e2c701baf1475802` reports 1,289 testcases: 1,287 passed, one failed and
one expected failure. All groups were attempted. Its overall status is
`failed`, and the executor exits 1 with empty stderr.

- The installed `codex_claude` group fails
  `test_native_pretool_keeps_ordinary_safe_command_prompt_free`: the actual
  Native hook answers `deny` for `git status --short`, where the test requires
  `allow`. The original assertion, failed report and log remain unchanged.
- The `grok_pi_zcode_devin` group remains `incomplete` because
  `test_pi_post_tool_use_allows_medium_matches_from_external_source_search`
  is an existing expected failure. Its reason says the live hook reviews
  this shape and only the retired Python composition allowed it. The Rust
  verifier retains the skipped/expected-failure count; it grants no pass.

The source compiler hashes to
`f379f3347d9b527330cb216da0067a8b586ad1b3033f2d780c9c301c8da0b1c5`.
The exact canonical report hashes to
`c3af621accac096ee61cdc77c95a0ac156fb117ed4ec4565c1b1b84525b123e0`.

The standalone `gauntlet-feature-report-verify` reopens the outside-pinned
specification/report and every fixed XML/log artifact through no-symlink
ancestry and stable single-link descriptors. It returns exit 1 for this valid
non-passing report and exit 2 for unavailable or inconsistent evidence.
Changed pins, hardlinks, symlinks, directory inputs and changed artifacts
are covered by meaningful file-custody tests.

The current reader source map is
`94276f2ab2cb823065fd22fe5f9aac58c355f94ea63beba60b5dcfa0af6106ad`.
The full Mac workspace passes 634 tests, with no failures or skips; its log
hash is `d9e391a3c1d1848b338cfd4f188a059b9d1570f444e3af74664926af6a28ef94`.
Mac/ARM warnings-denied Clippy, Rustfmt and the fixed host proof's Ruff checks
also pass on this generation.
Eight reader tests also pass natively on ARM. Five ARM artifact readbacks
and six fresh Mac outcomes check the actual report, identical restart,
wrong pins, symlink ancestry and a forged report hiding the real failure.
The Mac and ARM actual/restart stdout bytes agree, hashing to
`8e0d02d00b8d48f53287f51d3a4975eb3f95873a67c3f843d461d9885a6caa86`.

| Retained public export | Bytes / members | SHA-256 |
| --- | --- | --- |
| `native-feature-executor-vm-results-002.tar` | 10,455,040 / 104 | `aba4afcb915915ce4fe95408183501d2cefba1cd9267eec186def1aa2fb3f8aa` |
| `native-feature-readback-vm-results-001.tar` | 30,720 / 16 | `c019759cea2aa9b4d80abadb9ff75ef2a3f0685a61a6a1e26dbafd868c776ec3` |

The [fixed-generation host proof](../ci/gauntlet-rs/proofs/verify_feature_executor_20261028.py)
checks both exports, all 706 producer source-map Git blobs at `1711967d`,
the executable and producer program, every artifact digest, all 1,289 actual
case outcomes, 60 resource observations, ARM fixtures and six fresh Mac
outcomes. The immutable Python baseline's actual `junit()` function agrees
on all 28 groups. No new product or model job runs during readback.

Its four local inputs are the two exports above, the frozen
`native-feature-readback-mac-reader-001` executable and this checkout's Git
history. It creates an exclusive `native-feature-executor-host-readback-001`
directory and `native-feature-executor-fixed-host-proof-001.json` in the
supplied evidence directory. Reproduce in a fresh copy of those public inputs:

```sh
python ci/gauntlet-rs/proofs/verify_feature_executor_20261028.py /path/to/public-evidence
```

The metadata pack's duplicate-path error and two prewrite ARM bootstrap
errors remain retained. The corrected bounded read helper was tested locally
with both string and Path inputs before the successful ARM run. No failed
attempt was overwritten or represented as completed execution.

## Corrected environment and repeat audit

The Codex failure came from the Rust executor's preparation Git variables
leaking into pytest. Against the same frozen source-matched Mac Native build,
the unchanged assertion fails with `GIT_CONFIG_GLOBAL`, `GIT_CONFIG_NOSYSTEM`
and `GIT_TERMINAL_PROMPT` and passes without them. The Native environment
trust check conservatively refuses Git configuration whose value did not
travel with the request. Product policy and test assertions are unchanged.

Fix `cb9ea66e7848ef113735f69bf4658c6ea8024fb3` removes the three setup-only
variables from every product-test context and keeps them for preparation.
The context test checks that boundary for all 28 groups. The fixed ARM
executor has 9,878,128 bytes and digest
`2f5b02b29451f5c94fbb0df430bbea24138d269c3ae8051fea73ae0843e96f9c`;
its 708-entry source map hashes to
`ebc283be6f4c0ea8205d0ea44c4d2fa0b03eab14f1c5af7322d0167292e33096`.
Every entry matches its Git blob at `cb9ea66e`.

Fresh audit `e2c701baf1475803` retains the exact original product, source
archive, candidate, wheel, Native ELF, Node and 28-group/52-selector catalog.
Ten ARM tests and both same-UID probes pass before the complete schedule.
All 59 Codex/Claude cases now pass. Only that group's outcome changes:
27 groups pass and the pre-existing Pi expected failure keeps one group and
the aggregate `incomplete`. Counts are 1,289 total, zero failures, zero errors
and one skipped/expected failure. The compiler digest remains byte-identical
at `f379f334…b1c5`.

All 70 outside observations match the actual executor ELF, PID-1 namespace
and 12-GiB/two-CPU/2048-task limits. Exact container/cgroup/profile cleanup
is confirmed and all 333 prior worker records remain unchanged. The corrected
report hashes to
`28353f575d031eddfe933d7bf866af20455d35f7c84029880f80c9631527e9f7`.
Mac and ARM actual/restart readbacks are byte-identical at
`d5ad2b5ea991400ed470490a32d0af9ecb14c06f7d12838496c49b4437b1d2cb`.

| Retained corrected export | Bytes / members | SHA-256 |
| --- | --- | --- |
| `native-feature-executor-vm-results-003.tar` | 10,485,760 / 104 | `7de5dcb693cd466930a3a8f420da0ede4035111126a7640ca7f85454e37ceb8c` |
| `native-feature-env-readback-vm-results-001.tar` | 20,480 / 5 | `34c5661d9eb7cb8c4888540310016c521569cb172bfb03d71282242b31992192` |

The [fixed comparison proof](../ci/gauntlet-rs/proofs/verify_feature_environment_20261028.py)
checks the original and corrected complete exports, all source-map blobs,
unchanged product inputs and assertions, each XML/log digest, Python baseline
and actual testcase counts, 70 observations and exact Mac/ARM readback.
It uses the preserved original proof helpers and frozen standalone reader;
it starts no product or model job. Its output is
`native-feature-environment-fixed-host-proof-001.json`. The earlier failure
and expected failure keep their original classifications. Rust durable Root
worker integration and final qualification remain open.

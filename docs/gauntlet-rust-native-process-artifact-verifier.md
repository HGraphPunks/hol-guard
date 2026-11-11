# Rust SDK and MCP process artifact verification

Implementation `70c0d1d929be4b04c12d82cf32372eda3928ae03` adds completion mode
`--process-artifacts PUBLIC_USTAR SHA256 INTERPRETER_SHA256 OBSERVER_SHA256`.
It composes the [MCP/provider verifier](gauntlet-rust-native-mcp-artifact-verifier.md)
with separate public kernel observations and explicit readback digests. The
existing envelope and three artifact modes remain byte-compatible.

For every role, Rust matches eight SDK/MCP processes: Bun, its contained-exec
relay, two SDK service relays, two normal Native proxies and two upstream
relays. It checks PID/start time, held pidfd, actual executable digest, exact
arguments, all seven namespaces, namespace PIDs, job/container cgroups, exact
SDK/MCP profile, all UID/GID slots and groups, zero capabilities, seccomp,
no-new-privileges and effective resource limits. Every matching sample must
agree; one contradictory duplicate refuses. SDK relays must have the actual
Bun process as direct parent, matching their Root-observed ancestry.

All eight public SDK helpers must match the compiled fixed bytes or exact
episode configuration and their Root file metadata. SDK asset/publication/Bun
pins must agree with the host-authenticated declaration. SDK Pre/Post peers
must be the bound Bun identity; the execution peer must be its measured relay.
Cancellation retains an accepted execution request without a response or Post.
The two same-UID negative controls remain distinct from the bound SDK.

The historical SDK executable marker hashes its fixed argv without the final
NUL, while the separate sampler hashes raw `/proc` bytes including that NUL.
The verifier independently checks both versioned encodings. Historical request
hashes describe raw SDK JSON, whose field order was lost in the parsed public
record. It does not substitute a canonical-value digest for those missing bytes.

Future Rust executions now retain explicit
`hol-gauntlet-native-sdk-request-capture.v2` rows with original request bytes
and actual response bytes. The reader checks raw hashes and parsed values;
pending cancellation must still omit the response. Tests cover reordered JSON,
changed responses, old missing bytes and missing cancellation responses. This
new producer format has not yet had a fresh actual SDK execution.

## Actual historical evidence and limits

The six retained v7 jobs `e2c701baf1475102` through `5107` use runtime
`f53bc490` and product `62aa7ba7` / 3.57.0. Their 420 separate samples match
48 primary process tuples. Eight of twelve negative probes were captured:
success 2, input binding 2, injection 0, boundary 1, timeout 2, cancellation 1.
Four missing samples remain explicitly unverified. All six archives lack raw
SDK request bytes and receive zero raw-request-capture credit.

The interpreter readback digest is
`c86f21d0da9290ece2d7d49a3f7ed52aed59cb029abdf0ea25c79634f6cbe960`;
the separate observer digest is
`dba8f56bcbac3610e18f77c292dea957f61c744dabba989a9bd36b89c9041c0a`.
These are explicit readback inputs. V7 did not pin the interpreter before
execution. The verifier keeps `interpreter_prelaunch_pinned:false`,
`raw_sdk_request_bytes_checked:false`, observer/key admission false and
`independent_process_custody_checked:false`. Native hook/Bash processes and
effects, full lifecycle grading, admitted observer custody and fresh controls
remain separate requirements. No Guard causality or qualification is inferred.

The frozen committed-source Mac verifier is 5,498,048 bytes, SHA-256
`47274c5283c534be79757dbfffc68d50a114b63d1c42682a036048e34592da43`.
Its build log hashes to
`a11a1de8037a032bda7e33f88e31dc898d0129cfe94956add639cd289d2ce985`.
The [inert archive courier](../ci/gauntlet-rs/proofs/verify_native_process_artifacts_20261027.py)
passes 50 cases: six actual readbacks and six restarts, six envelope regressions,
six byte-identical MCP regressions, both older artifact regressions, 23
refusals and a separate missing-probe case that correctly stays unverified.
Mutation archives recompute their inventory and outer hash. Changed executable,
arguments, identity slots, groups, privileges, namespace, limits, label, parent,
observer claim, contradictory sample, missing Bun and missing helper refuse.
All refusals exit 2 with empty stdout. Original archives and host pins are intact.
The 11,977-byte proof index hashes to
`96244f19ed22058152295fd2716a2a2aff6ea3c945d12d5bb02f27e4e970a175`.

## Mac and native ARM validation

The workspace development run passes 537 tests with zero failures or ignores,
log SHA-256 `2cd3bb76e5ceea2a73e6d3079fd97f64318d56b20ca2ed362072ff2f8e9bd3e3`.
After the final test-style and container-ID checks, all eight focused tests
pass (`6de614453b33dc75faf6f3b6c3a22631d6bd833ab3fe1498d0d280e0e3e2f633`).
Warnings-denied all-workspace/all-target/all-feature Clippy passes on Mac
(`7f6c7793e428d469470fed592a0b642ae0204bf47eb2dea0276256a5c5d884b1`)
and ARM (`a312bbb6186f8c7e676cb0840f0e39edfa2ad113be6689b94af4bde45f95c48e`).
The initial boolean-assert style failure and earlier reader prototypes remain
retained; no archive is changed to make a prototype pass.

All eight process tests and both archive tests pass natively under Root on
owned VM `hol-gauntlet-rust-build-20261026-001`, with both worker leases held,
all 284 prior worker records unchanged and owned product cgroups absent.
These ten focused tests are not a full native workspace run. Their ELF pins are
`1e6540ab052503d9bb71a0ca9a1dff2c1b4cc0b5ab91c44af312c49b2ef7819a`
and `db34810761e07a8865306514133b9736484072dc6a425b7bf2bc7fefc45b0a05`.
Their logs hash to
`3301656f53ec1085f1f54ef528b463f54e92603fee91a5b2878be5a0a36f60f9`
and `68b0e1d88b930dbe43b7262bb8d69b7940bbb23309caae50fae43bd86abeae81`.

The 32,163,840-byte three-member input hashes to
`a9cf67b16e1fbdcd50adcb0c554d207ee114bf02b73cfa989564225d0f3afd25`.
Root hashes the held output before public handoff. The 20,480-byte eight-member
export hashes to
`dd1251ecfcb486ffd6edc7fd28f53bb3570c6b3a5039aa139f37468992ed508f`.
The [fixed-generation host reader](../ci/gauntlet-rs/proofs/verify_native_process_arm_20261027.py)
checks every public member and source/ELF/log/metadata pin; its successful
stdout hashes to
`fd2a3451b3384d108f89f5175fb2583d6a559640d8463989eaf5e4f12df8f0fa`.
Both proof helpers pass Ruff formatting and lint. No model requests ran.

Parent exits remain 24/62. Complete Native role grading, fresh prelaunch pins
and wire captures, twelve current-source staging/installed roles, conformance
and the other migration phases remain open. Required CI is user-owned and pending.

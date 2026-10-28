# Rust deterministic control and lifecycle artifact verification

Implementation `575c83a918a04aadb8d57676ced0a3721065cf0a` adds completion mode
`--control-artifacts PUBLIC_USTAR SHA256 INTERPRETER_SHA256 OBSERVER_SHA256`.
It composes the [hook verifier](gauntlet-rust-native-hook-artifact-verifier.md)
with the fixed six roles, actual product launch observations, reconstructed
capture streams, physical fixture/effect relations and detached lifecycle.
Earlier envelope and artifact modes retain their exact output bytes.

The reader matches the product actor and 66 prefix-Python launches, including
each measured gate and actual post-exec interpreter. It checks exact arguments,
PID/start tuples, namespaces, UID/GID slots, groups, zero capabilities, seccomp,
no-new-privileges, enforcing profile, job cgroup, direct parent and resource
limits. It also checks 43 actual installed Native runtime clients below their
measured CLIs against the declared Native executable digest and fixed argv.
A matching good sample cannot hide a contradictory executable or kernel tuple.

All 67 output captures are reconstructed from their released handles' actual
base64 stream chunks. Cumulative byte counts, EOF state, terminal code and
retirement must agree with the captured files. Cancellation retains its one
partial capture. The fixed fixture and project-marker bytes/metadata, actual
benign effect and retained Node result are checked. Input binding, forbidden
command/injection counterfactual and boundary reuse their existing Rust checks.
One-use route tokens, exact serial request counts and cancellation's absent
completed sink/Post are checked separately.

For timeout and cancellation, Rust reconstructs the compiled job/role fixture,
joins the detached child's pidfd/start/argv/executable/kernel observations to
the Native CLI ancestry, and matches its real overlay directory and ready-file
generation. It checks exact detached session/process-group identity, held
bytes, permitted unlink state and the absence of a delayed write in the sampled
view. The request-file handoff, actual timeout 124 or cancellation error,
closed-effect relation and exact version-one lower-directory absence record
must agree. Missing cancellation result/Post remains missing.

## Historical evidence and explicit gaps

These are the original six v7 jobs at runtime `f53bc490` and product
`62aa7ba7` / 3.57.0. Nine malformed-input probes lack sampled internal
resident clients; seven non-prefix helper launches remain ungraded. Internal
Native request bytes, all Native descendants, actual effect-writer attribution,
outside observation of child death, admitted observer/key custody and fresh
prelaunch interpreter pins remain open. The held child death is a checked
Root report, not a newly supplied outside death observation.

The old captures retain zero input-receipt/checkpoint credit. The new raw SDK
wire and input-receipt producers still need fresh product execution. Full
qualification, execution eligibility and Guard causality remain false. This
artifact composition does not qualify the historical controls or current 3.58
runtime, and it does not test actual model resistance.

The frozen Mac verifier is 5,961,984 bytes, SHA-256
`2055cbccac1650be2f23deced43e49c11a3314781a11252c1b07bd730859ce28`.
Its committed-source build log hashes to
`13d8923b3c3d7a77b4d8d029c808923c0127373813f3f18a8f4c8ab5594eb615`.
The [inert archive courier](../ci/gauntlet-rs/proofs/verify_native_control_artifacts_20261027.py)
passes 81 cases: six actual readbacks and six restarts, 26 earlier-mode
regressions and 43 refusals. Rehashed mutation archives change process
executable/parent/start/privileges, stream counts/bytes/EOF/exit, release or
retirement, effect/fixture ownership and bytes, ready generation, delayed
effect, child parent, missing readiness and lower-directory absence. Every
refusal exits 2 with empty stdout. Original archives and host pin records are
unchanged. The 18,455-byte proof index hashes to
`72242b0d6a4120677fb5de5bcd3eb8c57d838cb5cb868d5435c34fbe343f7f18`.

## Mac and native ARM validation

The complete Mac workspace passes 554 tests with zero failures or ignores,
log SHA-256 `4164896a68b14d379e5ee619ff03e288926284f3cd12e40e1f7ae784ddf84f52`.
All-workspace/all-target/all-feature warnings-denied Clippy passes on Mac
(`e2ffa74dbfeb08771fb0b693e850eeef8929e1e723a498b85b4feee0d2963608`)
and ARM
(`5577e63860963ef3794c20717af26d2e31c2a2b3dcc4a744e133fe12dffe2af1`).

On owned VM `hol-gauntlet-rust-build-20261026-001`, eleven focused tests pass
under Root: seven new evidence tests, two Native request tests and the two
dependency/launcher fixture regressions. The actual ARM verifier also passes
six archive readbacks, six restarts and five refusals. All twelve successful
outputs match the Mac grader byte for byte. Both worker leases are held,
all 284 original worker records and every proof input remain unchanged, and
owned product cgroups are absent. This is not a full native workspace run.

| ARM program | Bytes | SHA-256 |
| --- | ---: | --- |
| Evidence tests | 21,918,040 | `88355e46041e0a19ce85050661ee6b275103a20111cfc031e8455638d5602778` |
| Rootfs tests | 9,698,104 | `d1a4e4ed407413dea6869448882b8dce0fd662fd6f64266ed35980d732e3fc47` |
| Worker tests | 27,960,840 | `203bd4b99e10dcdadfb427505176dcec56d0620ddd461d486fe197d079330a88` |
| Actual verifier | 7,751,792 | `108c8f1361be7ff6109f83756b3135d7bb87710ea8b3e3c9d13433f02dc8ba7b` |

The VM uses byte-for-byte copies of public historical completions, archives
and public-key pin records as fixtures. Those copies do not create another
host prelaunch event or admit the VM as an outside key custodian. No fresh
product job or model request runs in this proof.

The 77,967,360-byte 24-member input hashes to
`70e94155d3b1210db4108ca8f68cf7a6c7cf8e2b9c942909c9f29980975c67b1`.
Root hashes the held export before public handoff. The 256,000-byte 69-member
export hashes to
`01ca467cf85dbed6391bbe92d5645078fad2cb07b19978999452cb02268fefd2`.
The [fixed-generation host reader](../ci/gauntlet-rs/proofs/verify_native_control_arm_20261027.py)
checks all members, source/program/log/metadata pins, test counts, original
fixture hashes and cross-platform outputs. Its stdout hashes to
`6c32dc7aa0e3c5208fb0be63927f04d256a093c20fb5698171d8b611dc0a6004`.
Both proof helpers pass Ruff formatting and lint.

Retained failures include a sandbox compiler temporary-file refusal, the
development reader's incorrect expectation of an extra field in the old v1
absence record, two full-suite attempts exposing inherited Mac fixture GIDs,
and the VM installer's refusal of a mode-0644 transfer before installation.
Synthetic fixtures now explicitly set their declared group; production custody
checks retain their requirements. A new mode-0600 transfer uses fresh names;
the original refused input remains untouched.

Parent exits remain 24/62. Complete independent role/effect/process authority,
fresh producer execution, twelve current-source staging/installed controls,
conformance and the other migration phases remain open. CI remains user-owned
and pending; no required check is bypassed.

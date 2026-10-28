# Native task pressure in the Rust Gauntlet cell

The product cell keeps its existing single-CPU, 1-GiB, 128-task limits. The
benign fixture still requires the real Node and npm version checks to pass.
An npm abort is a failed control; a source change must not hide that failure
by changing the fixture or increasing its resource budget.

Fresh traced control `e2c701baf1475404` at Rust worker source `8adf90cc` uses
the explicitly older product source `9f42d9dd` (3.58.0). Its outside sampler
records 88 observations without errors, and the SDK receives the exact
Native-reviewed original output. The unittest fails because `npm --version`
aborts with SIGABRT. Outside pressure records `pids.peak=128` and
`pids.events: max 1`; a separate bounded kernel read confirms a fork rejection
in this exact job's product cgroup. The recorder closes 460 tasks with 460
actual final waits. Independent Rust replay succeeds, but the control stays
`failed` with an `invalid-evidence` terminal.

The pressure record observes the Python daemon with 61 threads and a Native
resident with 29, alongside its supervisor, stream client and product actor.
Source inspection finds that even a known single-CPU allocation creates at
least sixteen Native evaluation and four authentication workers. This fixed
twenty-worker floor contributes to the cell's task use. It does not by itself
prove the complete cause of every historical abort or rendering failure.

The public export is `native-kernel-v2-vm-results-001-success.tar`, SHA-256
`222e982e883e3d0dbbf94db486699a9b73dc4ccaec9ea024b7d5fff9a23406fd`.
The separate kernel read is retained as
`native-kernel-v2-pressure-kernel-001.stdout`. After cleanup, its public
process scan finds no UID 10004 process anywhere in the owned VM. All 305
prior worker records survive; the current 312-record baseline has SHA-256
`5530c850da1b4dd4d43052c3189e568dd26a14dc4ddff8db148e3f2d2a7b5383`.
See [the process-event proof](gauntlet-rust-native-process-event-plan.md) for
the exact sources, pins, failed attempts and all qualification limits.

## Worker sizing implementation

Rust now derives the resident worker counts from known available CPU capacity.
The evaluation floor consists of one reserved metadata worker, the unchanged
two-active-launch limit and two interactive evaluation workers: five in
total. Authentication keeps at least two workers. Evaluation scales up to
32 workers; authentication scales at one worker per four CPUs, capped at
eight. Sixteen CPUs and larger keep their previous counts. An unavailable CPU
count keeps the historical sixteen/four fallback. Existing queue limits stay
between 32 and 64; metadata keeps its dedicated lane.

The active-launch limit and metadata-worker count have one shared Rust
definition, so a later capacity change cannot silently outgrow the evaluation
floor. The new concurrency regression fills both actual launch registrations
and requires policy reads, the reserved metadata lane and cancellation to
complete. It then requires both launches to release their ownership. No
approval token, saved decision, containment rule or execution binding changes.

All seventeen focused Native tests pass: two worker-budget cases, thirteen
transport cases including the actual two-launch cancellation/policy/metadata
regression, and two existing launch-ownership/cancellation cases. Native
all-target warnings-denied Clippy and formatting pass. The first compile
attempt's incorrect test module path remains retained; the corrected test
uses the existing launch owner without changing its registration rules.

The budget, transport, launch-cancellation and Clippy log SHA-256 values are
`7aff57614dfa3e07cee27ed6efc7917217c76fdb0bdbb24a6a16efe457047bb7`,
`00e64ab232d111f972c3266f8b62ee4a04fd7d45cd2e225ba1a35b53c8f66168`,
`a12f43e65c5338231acbc2e5b96cce95394dd943af064b00d186e007787d34e1`
and `a7c8a57bacb92ed24fe268d6915f47e1162a42c4a60e0b49c37a536418c00c38`.
The successful format log is empty. The working-source file pins are retained
in `native-worker-budget-working-source-002.json` beside those logs.

The implementation is committed as `dad35522` and preserved through upstream
merge `dc3b9336`. The [fresh runtime proof](gauntlet-rust-native-pressure-runtime-proof-20261028.md)
records its exact-source ARM build, locked dependencies, immutable publication
and two traced controls against that actual Native ELF. Both controls pass
the real Node/npm fixture, peak at 108 tasks and record `pids.events: max 0`,
with the original single-CPU/1-GiB/128-task limits. This is evidence that the
new budget improves the reproduced pressure case; it does not establish that
every historical abort had that cause or that wider workload pressure is solved.

The first control's polling sampler records an assertion after 57 observations;
its failed observation stays retained. The second retains every assertion,
adds bounded error tracebacks and completes 70 observations without errors.
The failure did not recur and its precise cause remains unknown. Pressure
sampling separately completes 200 and 213 snapshots without errors. Root
tracing closes 393/393 and 392/392 actual tasks/final waits respectively.
The second control's complete Rust artifact reader passes, including all nine
launches, four observed Native clients, three acknowledged hook inputs, three
raw SDK frames and eight reconstructed output captures.

The old `9f42d9dd` prefix, npm failures, first sampler failure and all prior
records remain immutable. The new 326-record worker baseline hashes to
`16b21c170df5494738bc40b188694f186c87a2f9caca75d1f50d05459d4aa9be`.
The pressure checklist stays open for broader complete-role conformance.
Outside admission, complete Native grading and all final-source roles remain
open. Parent exits stay at 24/62. No model request or quota reset occurs.

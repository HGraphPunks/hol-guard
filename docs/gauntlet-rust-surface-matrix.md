# Gauntlet command and state ownership matrix

This inventories Python Gauntlet PR #5263 at `b4efd8171b06d0e13cbe12a077c376ecdc891fd1` and its explicit Rust successors. Command availability, historical evidence and fresh execution acceptance are separate. The [execution checklist](gauntlet-rust-execution-checklist.md) remains the acceptance ledger: **24/62 parent exits complete, 38 open**. All external source and asset pins must arrive from outside the candidate build. No Python entrypoint or reader has been removed.

## CLI surfaces

| Current entrypoint and commands | Current effect | Rust owner / evidence boundary |
| --- | --- | --- |
| `scripts/gauntlet up`, `down`, `doctor`, `status`, `agent`, `hold`, `resume` | Own the passive dashboard/observer lifecycle, VM readiness and admission hold. | Host controller, Phase 3. |
| `gauntlet-vm-worker` fixed `inspect`, `progress`, `reconcile`, `run` | Rust-owned native dispatch with both leases, durable reservation/running/terminal state and fixed job/source/deployment/generation pins. No command or path selector. | `gauntlet-worker-state`, Phase 2. [Apparatus lifecycle evidence](gauntlet-rust-native-current-worker-vm-proof-20261026.md) and [captured hook relations](gauntlet-rust-native-copied-hook-relations.md) are retained. Signed read-only job `015` binds 162 pipe exchanges and five hook identities; eight client execs have checked outer floors and seventy other Native exec images remain ungraded. Terminals stay invalid-evidence; current-source admission, independent policy/effect grading and qualification remain open. |
| `gauntlet-host build`: source/transfer, transfer-bounded/transfer-bounded-read, run-bounded/read-bounded, capture/wheel-stage, prefix-clone/prefix-clone-read, runtime-publish/runtime-publish-read; retained run/read/repair routes | Source-bound dispatch, bounded build, inert capture, candidate prefix cloning and immutable runtime publication. Downstream bounded routes require completed Source.v2 context, original VM/host identity and private authority. Keep original source/dependency volumes while later verification or Native preparation needs them. | Host-state and worker-state, Phase 2. [Primary transfer](gauntlet-rust-vm-source-transfer-proof.md#primary-rust-transfer-into-the-build-slot) and [build/read/recovery evidence](gauntlet-rust-hostbound-candidate-build-proof.md) retain their historical scope. Genuine `bb69ca40` build and runtime publication passed on historical v1 storage, ineligible. New storage.v2 normal flow and completed-read recovery remain unproved; see the [current checkpoint](gauntlet-rust-pr-readiness-plan.md#resume-from-this-checkpoint). |
| `gauntlet-host dependencies`: inputs/transfer/transfer-read, run-bounded/read-bounded/repair-bounded, prefix-stage/prefix-stage-read; retained run/read/repair and compatibility `gauntlet-host-run-dependencies` | One-use dependency dispatch and inert staging under the original bounded source capsule. Reads and repair retain original private intent, consumed dispatch and outside authority; uncertain completion never permits replay or inferred exit. | Host-state and worker-state, Phase 2. Genuine `bb69ca40` dependency resolution/staging passed on historical v1 storage, ineligible. [Completion retirement](gauntlet-rust-hostbound-candidate-build-proof.md#interrupted-dependency-completion-retirement) preserves earlier versioned evidence. New bounded recovery still needs actual validation. |
| `gauntlet-host artifacts`: record/download/download-read, ack/ack-read, retire/retire-read | Retain actual private archive bytes before acknowledgement; recheck file custody before retirement. New routes require the completed Source.v2 context and original authority. Public hashes cannot reconstruct missing private state. | Host-state and worker-state. Implemented custody/recovery interfaces and focused fixtures do not prove a fresh bounded build-to-retirement run. |
| `gauntlet-host deterministic` and `live`: initialize/initialize-read, record, prepare/prepare-read, run/read/report/repair; live provision/provision-read/pair | Explicit Native job lifecycle, outside preparation pins, authenticated readback and independent report reduction. Live provisioning binds the two-cell World/cleanup observers before dispatch. | Worker-state, cell-rootfs, host-state and evidence. The actual pinned SDK passed MCP-only inventory and four formatter cases with zero inference. The model pair, beta campaign and ordinary allowed-Bash/legacy execution remain open; source/reducer tests do not establish those runs. |
| `gauntlet-host provider` prepare/start/read/stop | Source/job-bound owner lifecycle and serial authenticated Unix model relay with retained quota cap and history-prefix checks. No quota reset. | Host-state and evidence. Implementation and temporary-ledger fixtures exist; model/source authorization, sufficient quota and operational approvals remain pending. |
| `gauntlet-host features` and compatibility `gauntlet-host-feature-audit`, fixed `record`, `run`, `read`, `repair`; `gauntlet-feature-worker` fixed initialize/capture/run/read/repair | Share one host command implementation, durably bind the private intent, return public recording pins, consume dispatch once, run the unprivileged 28-group executor and independently verify retained artifacts. Repair pins its executable before contacting the VM. | `gauntlet-host-state`, `gauntlet-worker-state` and `gauntlet-evidence`, Phases 2–3. [Fresh primary audit](gauntlet-rust-feature-worker.md#fresh-primary-audit-at-the-current-build-generation): `52b9d314e8a670cf` at product `74d8d0081`/controller `52da7281…` retains 1,304 passes, zero failures/errors and one deliberate retired-Pi skip. Rust/Python replay agrees on all 28 groups/52 selectors and 56 artifacts; restart readback, consumed refusal and independent cleanup match. Status stays incomplete. Earlier failed audits remain preserved; broader recovery, authority, qualification and observer admission remain open. |
| `gauntlet-native-actor-verify ACTOR OUTSIDE_SHA256` | Bounded inert ELF64/ARM64/glibc-loader and outside byte-hash inspection. No code execution or admission. | `gauntlet-evidence`; the factory repeats preflight before artifact creation and ARM CI checks its release artifact. |
| `gauntlet-product-cell actor`, `exec-gate` (Rust preparation) | Run the UID/GID-10004 PID1 actor, eight private RPC operations, bounded child I/O and measured release gate with the pinned syscall floor. | [Native product-cell proof](gauntlet-rust-product-cell-native-proof.md), Phase 2 subset. Real ARM64 process interoperability passed; versioned VM artifacts, AppArmor/rootfs/supervisor integration and qualified effects remain open. |
| `gauntlet-host init`, `configure`, `up`, `status`, `doctor`, `hold`, `resume`, `agent`, `down`, `enqueue-release` (isolated Rust preparation) | Own `rust-host-v1`, an immutable configuration, exact two-release discovery/queue, independent cancellable telemetry and public publication; `up` owns its loopback dashboard in the same process. Never dispatch VM work. | [Native observer proof](gauntlet-rust-observer-native-proof.md), Phase 3 subset, live port 8794. Python history import, repair, receipt reconciliation and production admission/cutover remain open. |
| `scripts/gauntlet dashboard-rust-up`, `dashboard-rust-restore` (combined migration branch) | Switch only the loopback dashboard HTTP server between a state-keyed Rust container and the existing Python server. | Dashboard lifecycle handoff is exercised on port 8791; Python still owns the observer and jobs, Phase 3. |
| `scripts/gauntlet repair`, `diagnose`, `reconcile`, `retry-staging`, `probe-runtime`, `audit-staging` | Repair an idle deployment, inspect retained failures, reconcile exact receipts, reuse a verified build, run bounded diagnostics. | Host controller plus fixed VM worker, Phases 2–3. Recovery must not replay an uncertain job. |
| `scripts/gauntlet test-local`, `features-local` | Queue a clean exact-commit candidate and run source-bound product feature audit. | Host admission plus VM builder/stager, Phases 2–3. |
| `scripts/gauntlet live-local`, `feature-ai-local`, `refresh-live-candidate`, `live-reconcile` | Run 12-cell or two-cell local Qwen E2E, refresh exact deployment, reconcile model/VM outcome. | Host model supervisor and campaign controller, Phases 3–4. |
| `scripts/gauntlet gate enable\|disable` | Print a ruleset plan; `--apply` changes the Gauntlet-owned GitHub ruleset. | Separately reviewed publication controller, Phase 5. Keep inactive throughout migration. |
| `python -m ci.gauntlet.benchmark profile`, `preview`, `deterministic`, `pilot` | Export beta selection, compile inventory, run zero-model controls, or one diagnostic live episode. | Campaign catalog and VM executor, Phases 2–4. |
| `python -m ci.gauntlet.benchmark freeze`, `run`, `status`, `gate` | Freeze selected local campaign, execute, audit retained attempts, compute local verdict. | Campaign controller and verifier, Phase 4. |
| `python -m ci.gauntlet.benchmark ci preflight\|freeze\|run\|resume\|report\|check` | Versioned portable CI path. `check` creates a fresh freeze, executes the complete selected profile and writes a local-integrity report. | Trusted CI runner and evidence verifier, Phases 4–5. Preserve exit/status semantics or version a successor. |
| `python -m ci.gauntlet.benchmark approval`, `developer` | Two-session approval and developer diagnostics. | Campaign controller, Phase 4. |
| `python -m ci.gauntlet list`, `run`, `installed`, `verify`, `pack`, `qualify` | Fixed legacy catalog, real-agent run, installed acceptance, independent evidence verification/export and trusted qualification driver. | Legacy controller/verifier/publisher, Phase 5; retain Python readers for unsupported historical formats. |

The `ci check` profile values are `deterministic`, `beta-e2e`, `feature-ai`, and `feature-ai-protocol`. The legacy `run` profiles are `core`, `contained-bun-vitest`, `full-tasks`, `approval-retry`, and `connector-setup`; only its pinned OMP core path makes the existing qualification claim. The legacy harness values are `omp`, `claude-code`, `codex`, and `cursor`; non-OMP harnesses remain diagnostic. A Rust CLI must not silently collapse these scopes into one green result.

The immutable baseline core has **128 rows**, catalog SHA-256 `6195060f…`
at `b4efd817…`. The current source has **308 core rows**, plus separate
16-row approval-retry, 11-row connector-setup and 15-row full-task catalogs.
The contracts library's `legacy_catalog::fixed_legacy_catalog` pins these
four existing current files. All eleven normalized row fields, defaults,
declaration order and the legacy list projection match Python reader
`1acb014b…`. Its versioned inventory always reports execution and qualification
ineligible. The contained Bun/Vitest profile has no corresponding data catalog
and is refused by this selector. This library subset does not implement the
legacy CLI, fixture workers, candidate-catalog admission or historical parity.

The November 10 static inventory verifies all 440 mapped source hashes and
finds 304 Python files, 282 parser calls across 24 files, 44 main guards and
268 possible process calls. These are lexical counts: a method named run is
not necessarily an external process. The retained external evidence
`budget-limits-20261110-001/static-surface-inventory-001.json`
(`04a9bec0…`) records each location, phase and proposed owners. Its derived
`process-surface-inventory-001.json` (`962e0e98…`) separates 194 literal
process API calls from 74 other possible calls. Dynamic
dispatch, exact argv and per-file authority still require semantic review;
the exhaustive inventory parent exit remains open.

In addition to the three public CLIs, the following parser families require
explicit boundary ownership:

| Current parser family under ci/gauntlet | Proposed Rust owner / retained dependency |
| --- | --- |
| benchmark native builtin/product/pytest, Linux browser/executor and Root initializer controls | Worker-state, product-cell, cell-rootfs and evidence; pytest remains an external executor. |
| benchmark contained-exec/service relays and MCP server | MCP-service and World; worker-state owns process lifetime and evidence owns grading. |
| benchmark approval pilot/elapsed control and developer pilot/worker probe | Agent-bridge, worker-state and evidence; OMP/Bun stays a bounded external adapter. |
| benchmark developer model/provider relays; control-plane live provider | Host-state and evidence own supervision and quota; MLX stays the external model process. |
| control-plane dashboard server | Host-state owns the public projection and loopback HTTP lifecycle. |
| full-task argument extension/gateway and GitHub CI helper | Host-state and evidence own scheduling, verification and publication; external service actions retain their separate authorization. |
| benchmark wrong-temperature fixture parser | Product test asset, executed only inside the unprivileged fixture boundary. |

## Versioned inputs and executable boundaries

| Input or external process | Current contract | Rust owner / outstanding proof |
| --- | --- | --- |
| Runner declarations `gauntlet-ci-runner.v1`–`.v7`, 22 Draft 2020-12 schemas | Caller-pinned canonical config, campaign/policy, selected cells, shard and budget checks. | `gauntlet-contracts` and `gauntlet-evidence` have partial read-only parity. Full asset custody and installed identity remain Phase 1. |
| File roles `bun`, `node`, `wheel`, `native`, `policy`, `compiler`, `model_manifest`, `provider_manifest`, optional `conformance` | Exact SHA-256, canonical relative path; executable roles require access to run. | Phase 1 reader has hashes and execute bits; OS access and execution custody remain open. |
| Tree roles `sdk`, optional `zod_cache`, `guard_prefix`; `private_cell` artifact set | Inert tree/manifest digests, ownership, modes, controller source binding, installed runtime metadata. | Phase 1 tree prototype; Root-owned prefix and private-cell parity remain open. |
| Linux ARM `limactl` guest, Podman builder, `slirp4netns`, AppArmor/seccomp, Bubblewrap and native runtime | VM executes candidate build and product cells under restricted identities, not in the Mac host or as Root. | Fixed Rust worker and negative isolation matrix, Phase 2. |
| Bun/Node/OMP SDK and local Qwen/MLX provider | Actual agent/tool traffic, host-owned model process and lifetime quota. | Bounded external adapters supervised by Rust, Phase 4; no scripted inference substitute. |
| Product pytest feature audit | 28 fixed contract groups on the exact wheel/source/native pairing. | Keep pytest as the external executor; Rust must verify its report provenance, Phase 2. |
| Native job/report v1 and v2, `hol-gauntlet-native-hook-product-pins.v1` | Separate fixed apparatus and controller-generated hook-transport profiles; exact source/version/runtime/backend pins. | `gauntlet-worker-state` and `gauntlet-cell-rootfs`. No authenticated SDK or qualified verdict is inferred from these declarations. |
| Historical storage v1 and bounded storage.v2 | V2 requires finite byte/inode limits and the live original, outside-pinned mount-namespace owner. An owner restart or disappearance cannot be repaired by adopting another process. | Host-state, worker-state and cell-rootfs. Genuine v1 publications remain ineligible and cannot acquire new v2 retirement authority. Worker ENOSPC and the complete bounded normal flow remain unproved. |
| Supervisor v5 and v6 | Both retain `outside-root-ptrace.v1` / `outside-root-native-pipes.v1`. V5 has exactly five pinned helpers; v6 has exactly those five plus `/usr/bin/nsenter`, with the same closed fields. V1–v5 keep their original contracts. | Cell-rootfs and evidence enforce version/helper-map separation. An actual private-namespace/full-journal cleanup test passed with cleanup credit unknown; helper declarations alone do not prove namespace entry or qualification. |
| `adapters/native_guard_identity_v1.py`, `native_workspace_readiness_v1.py`, frozen success-test bytes | Explicit product-test adapters inside UID/GID-10004 isolation; one normal-client call or metadata probe. Rust owns orchestration, budgets and response checks. | Versioned external product-test dependency permitted by the migration contract. Adapter hashes are reported; no Root Python service/oracle or scoring authority is introduced. |

The VM worker accepts only `inspect`, `progress`, `reconcile`, and identity/deployment-bound one-time `run`. The bounded syntax in [the worker boundary](gauntlet-rust-worker-protocol.md) remains separate from execution authority. The Rust native apparatus worker now dispatches and drains real owned-VM jobs under its fixed versioned profile; its receipts remain invalid-evidence. Full qualified deployment, SDK/Guard scoring, host authentication and operational cutover remain separate open exits.

The baseline disposition retain_external_model_runtime on `provider.py` is a
proposal to audit, not permission to retain trusted Python orchestration after
cutover. Its InferenceRelay also owns endpoint/credential handling, fixed-model
forwarding, canary interception, round limits and response observations. Those
functions need Rust host-state/agent-bridge/evidence owners in Phases 4–5;
the model process alone remains external. Likewise, retained TypeScript SDK
observers provide bounded input observations, not independent grading or
publication authority. Keep the immutable baseline tags and track this scope
correction in the exhaustive audit.

## State, public status and receipts

The Python observer stores private job records under `private/jobs/<job-id>.json`. Its operational states include `queued`, `waiting`, `waiting-candidate`, `preparing`, `running`, `unknown`, `passed`, `diagnostic-passed`, `failed`, `build-failed`, `conformance-failed`, `invalid-evidence`, `superseded`, and `archived`. A restart changes `preparing` or `running` to `unknown`; this blocks admission until exact remote receipt reconciliation. Rust must use a new state namespace and prove the same no-replay behavior before cutover.

The public snapshot is `hol-gauntlet-dashboard.v1` with observer `hol-gauntlet-observer.v2`. It exposes only an allowlist of up to 200 unarchived jobs, including identity, state, reason, timestamps, phase/events, bounded progress, selected build/stage summaries and public resource/headroom telemetry. Private logs, credentials, config, candidate runtime state and signing material stay outside this snapshot. Rust dashboard tests must show stale or absent telemetry as unavailable.

Python Agent.publish and Rust host-state public_jobs share these 29 job keys:

| Group | Keys |
| --- | --- |
| Identity | id, pr, title, url, sha, base_sha, kind, tag |
| Lifecycle | state, reason, created_at, started_at, finished_at, updated_at |
| Publication | status_error, result, posted_state |
| Progress | phase, phase_started_at, events, vm_progress, progress_error |
| Build and staging | build_run, build_dispatch, source_error, local_build, stage_error, stage_result, diagnostic_result |

The nested local_build allowlist is source_sha, job_id, tag, status,
builder_image, error, failure_phase, exit_code, log_path and version. The
projection excludes archived jobs, sorts newest first and caps the result at
200; Rust also bounds the complete projection to 8 MiB. Its publication
eligibility stays false until observer ownership and a coherent snapshot
are independently established. Other top-level telemetry/server annotations
and nested public result formats still need the exhaustive audit.

The VM uses a Root-owned worker lease and a one-time `<job>.started.json` marker before candidate execution, followed by `<job>.json` terminal receipt. The build/stage paths have their own retained receipts and progress files. The workflow controller uses `ci-controller.lock`, per-shard attempt ledgers and immutable frozen inputs. The host model provider uses `events.jsonl` and `quota.lock`; unsettled or unknown usage halts admission. A new Rust writer must not share Python's live lock/journal namespace, and a reader cannot turn absence of a terminal receipt into permission to retry.

Normal Rust recovery requires the original private intents and consumed dispatches,
the original Lima/SSH homes and instance identity, and outside authority. Lost
replies require authenticated original readback; public summaries cannot recreate
launch authority. Raw archives, model frames and Host pins remain private. New
Host completed-read/recovery work is under validation, with no staging or export
credit inferred from a missing or unauthenticated terminal.

The following source inventory separates process success from report meaning.
These rows have not all been exercised as differential Rust CLI cases:

| Python surface | Existing exit semantics | Proposed Rust owner |
| --- | --- | --- |
| Control-plane commands | 0 success; 2 caught operational error. Worker rejects also exit 2. | Host-state and worker-state |
| Legacy list, verify, pack | 0 after successful operation; 2 for caught ValueError, RuntimeError or OSError. | Contracts and evidence |
| Legacy run, including non-OMP harnesses | 0 for report pass; 1 otherwise; caught validation/operational errors 2. Non-OMP results remain diagnostic. | Worker-state and evidence |
| Legacy installed | 0 accepted, 1 rejected; report-only returns 0 regardless of acceptance. Caught operational errors return 2. | Worker-state and evidence |
| Legacy qualify | 0 qualified, or successfully prepared with prepare-only; otherwise 1. Pre-dispatch errors caught by the outer CLI return 2. | Host-state and evidence |
| Benchmark profile, preview, freeze, run, status | 0 after returning a result. Uncaught exceptions retain the interpreter's failure; parser errors exit 2. | Contracts, host-state and worker-state |
| Benchmark pilot | 0 execution_valid, 1 otherwise. This is a diagnostic claim. | Worker-state and evidence |
| Benchmark approval and developer | Return None after printing the report, so normal process exit is 0 regardless of its score. | Agent-bridge and evidence; retain diagnostic limits |
| Benchmark gate | 0 accepted local gate; 1 computed failed gate; 2 invalid evidence; 3 invalid policy. | Evidence |
| Benchmark ci and deterministic | Return the result exit_code; boundary-caught exceptions are 2 and KeyboardInterrupt is 130. CI-check uses 0/1 for accepted/failed local gates. | Host-state, worker-state and evidence |

Legacy argparse failures exit 2 before dispatch. The native OMP route installs
SIGTERM/SIGHUP handlers that unwind through SystemExit(128 + signal); a
successor must preserve cleanup as well as the numeric status. The portable
CI reports remain qualification_eligible false, trust_status local-integrity-only
and production_ci_activated false. Historical-reader errors, every signal
interleaving and final report/JUnit reason classes still require differential
vectors; no zero exit alone establishes qualification.

## Open inventory work

The November 6 upstream import adds `approval_retry_persistent.py`,
`docker_stub_fixtures.py` and `extension_allow_fixtures.py`. Their explicit
disposition is Phase 5 `port_to_rust`: catalog/selection belongs to
`gauntlet-contracts`, fixture execution to `gauntlet-worker-state` under the
unprivileged product boundary, and approval/effect grading to
`gauntlet-evidence`. Rust now has source-derived current/frozen reducers, with
kind-specific full-task and Connector handling. Python execution paths and
readers remain available; reducer parity does not establish fresh legacy,
installed or qualification acceptance. Ordinary allowed Bash still lacks the
execution/binding path for the SDK's genuine persistent brush process.

The subsequent import through `2b811b610` expands those existing Phase 5
owners with persistent offline package approval under `NODE_OPTIONS`, an exact
GitHub merge/read sequence after `cd`, Git-config key-pattern reads and a
sibling Jest command filtered through `sed`. The ten changed Gauntlet files
match upstream exactly. The source map remains 440 files, 78 changed and 20
added; the fresh 409-file/420-entry controller plan hashes to `24926e43…`.
It is not installed over the retained `e81a214c…` generation. These source
pins do not establish Rust legacy execution, approval or effect parity.

The next import through `394be6de4` updates approval-retry, linked-worktree,
extension-allow and benign-scenario coverage. The map is now 440 files, 79
changed and 20 added. Its separate `123024f4…` controller is installed and
independently verified while preserving `e81a214c…`. The fresh runtime has
independent byte/requirement replay; its completed feature audit retains one
deliberate retired-Pi skip. These checks
do not establish the outstanding Rust legacy catalog or approval/effect parity.

This table covers the named entrypoints and primary durable state boundaries. The 420-file [parity manifest](../ci/gauntlet-rs/parity-manifest.v1.json) still needs disposition-by-disposition review. In particular, enumerate every historical evidence schema, provider and controller journal format, public status field, external executable argument contract, and legacy exit code against a trusted Rust owner or retained Python reader. The checklist leaves that audit open until the matrix is exhaustive and its accept/refuse cases are frozen.

The [readiness checkpoint](gauntlet-rust-pr-readiness-plan.md#resume-from-this-checkpoint)
separates actual tests from implemented paths. Bounded normal flow, Worker ENOSPC,
new Host recovery, the model pair, beta and full legacy execution remain unproved.
Model source authorization, retained-quota capacity, required CI and independent
approval gates remain open. Parent completion stays **24/62**; Python is removed
nowhere by this update.

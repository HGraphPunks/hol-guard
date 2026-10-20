# Rust Gauntlet VM worker protocol boundary

This is the fixed request boundary for the proposed Root-owned Linux ARM worker. The implemented parser is [`worker_request.rs`](../ci/gauntlet-rs/crates/gauntlet-contracts/src/worker_request.rs). It performs data validation only; no Rust VM worker is installed or allowed to act on a parsed request yet. The [execution checklist](gauntlet-rust-execution-checklist.md) tracks response receipts, leases, process identity, conformance and cutover separately.

The request is at most 1,024 bytes of bounded JSON. It has schema `hol-gauntlet-worker-request.v1` and exactly one of these shapes:

| Action | Required fields | Allowed effect |
| --- | --- | --- |
| `inspect` | `schema`, `action`, `source_sha`, `job_id` | Read a fixed Root-owned deployment declaration and report whether the exact source is staged. |
| `progress` | Same four fields | Read fixed progress/receipt paths without acquiring the active lease. Missing measurements are unavailable. |
| `reconcile` | Same four fields | Read the terminal receipt for the same job; missing or inconsistent evidence is unknown, never a replay instruction. |
| `run` | Those four fields plus `deployment_digest` | Attempt one source/deployment/job-bound execution only after Root-owned custody, lease and one-time started-marker checks. |

`source_sha` is 40 lowercase hexadecimal characters, `job_id` is 16, and the run-only `deployment_digest` is 64. Unknown fields, arbitrary command/path/profile selectors, duplicate JSON keys, missing pins and noncanonical identifiers fail before state access. The future host must obtain the deployment digest from an independent trusted channel. A digest carried in a candidate manifest or the request itself cannot pin the worker.

The future response protocol must preserve the existing Python worker's source/job binding and explicit `ready`, `unknown`, `running` or terminal distinctions. It needs a versioned receipt with worker generation, action, source SHA, job ID, deployment digest when applicable, process start identity, and a signed or independently pinned terminal result. The Rust worker must durably write the started marker before launching candidate execution, keep a single exclusive lease, reject repeats even after restart, and refuse an uncertain receipt. These response and execution rules are **not implemented** by the request parser.

Only a separately reviewed worker artifact may interpret the request. Candidate source is inert input to the unprivileged builder; the worker must never import a candidate as Root. The existing passive release observer and optional PR gate remain unchanged during this protocol work.

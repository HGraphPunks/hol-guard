# Rust-owned SDK, MCP and Bash transport

The closed `hol-gauntlet-native-worker-job.v5` profile,
`native-sdk-mcp-transport-v1`, composes the locked SDK 18.4.12 with normal
Native MCP proxies, Rust MCP dispatch/SQLite services and the Native Bash
hook plane. The existing v1–v4 job profiles keep their original meaning.

The Root controller binds the actual Bun process before SDK import. Both
hook and MCP same-UID negative controls must refuse unrelated processes
before the controller acknowledges the SDK gate. Each MCP relay must be a
descendant of that Bun process, execute the held image interpreter with the
fixed relay argv and retain its measured namespaces, IDs and cgroup. Root
rechecks those facts for every forwarded frame. The SDK, MCP and product
planes have distinct private namespaces.

One Root-owned four-operation ledger covers MCP ingress and Bash Pre calls.
An MCP operation consumes its budget before forwarding to Native. The
provider requires an exact, one-use canonical request permit for the family,
ID and arguments. Changed requests, cross-family calls and replay cannot
mint a provider operation. A Guard refusal still consumes ingress budget.
Metadata requests retain separate bounded transport/session limits.

The synthetic SDK stream reads `developer-spec` through actual `docs.read`,
then runs the fixed benign Bash control. Result checks require the actual
tool mapping, exact delivered MCP content, unchanged physical provider
records, one signed read receipt and exact captured Bash output. They also
require the original reviewed command in provider context while execution
keeps its contained transport. No model request is made.

The worker separately checks SDK and MCP container/profile absence after
controller cleanup. Unknown or interrupted jobs retain their original
reservation. Earlier recovery profiles explicitly refuse this combined
profile; they cannot invent a successful exit or reinterpret its evidence.

At source `dde4cb736f44091cdffc9c514dc8e1b7c64a426c`, fresh job
`e2c701baf1473901` passes the composed execution. The actual SDK returns both
the delegated `docs.read` result and exact successful Bash capture. Host
readback verifies 24 frontend and 24 upstream frames, both normal CLI proxies
and resident relays, actual SDK descendant peers, one Ed25519 read receipt,
the physical unchanged SQLite records, the contained effect and 50 outside
process samples. Both pre-import same-UID negative controls refuse access.
The shared ledger records one MCP and one builtin operation, with no pending
permit. The SDK, MCP and product resources drain and the prefix stays intact.

Fresh reference job `e2c701baf1473902` also passes the existing v4 Native MCP
profile using the same worker: two reads, 14 upstream frames, two receipts and
24 outside samples. The two jobs preserve all 143 prior worker artifacts;
the final map contains 155 unchanged/new worker files. Both terminals remain
`invalid-evidence` despite successful diagnostic execution.

Validation includes 80 macOS worker tests, warnings-denied Mac/ARM Clippy,
177 native ARM worker tests (24 existing ignores), 31 rootfs tests and its
nested subprocess test. The initial Clippy boolean-simplification refusal
and corrected pass remain in retained logs.

The first replay courier correctly received the one-use refusal for the
reference job, but incorrectly supplied run-only `deployment_digest` to its
read-only reconcile request. The strict parser refused it. The corrected
reconcile requests return the original terminals. The original SDK replay
courier then timed out at 30 seconds during prior-job preflight; its unknown
return code is retained, both leases were subsequently reacquired, and all
155 worker files still match their hashes. The next source rejects consumed
identities under the active lease before unrelated host preflight, while
retaining exact pin checks and the final atomic reservation. Its ARM Clippy
and build pass; its fresh VM execution/replay proof is pending.

Public evidence, excluding product homes and Guard stores:

| Artifact | SHA-256 |
| --- | --- |
| Input archive, 64,931,840 bytes / 5 members | `331ffceb7c555fec33c7aa5fe030d3e7d06b7c9bf3216a1c916a171593f12a21` |
| Export, 1,495,040 bytes / 208 members | `242e75a36de417c1e3fa6f97b986aac5ce6552ee4030118a397074aa3778b885` |
| Combined report | `fde34916d2dc1ef22bb8cd6793136ad8e7f42305b40738e7296232217537c96e` |
| Reference report | `a4f0c2758c0943231f162c305ef2bb6f053765633a3c9a57abf7de9d5580313b` |

Run `ci/gauntlet-rs/proofs/verify_native_sdk_mcp_transport_20261027.py` with
the retained evidence directory. It independently checks the public archive,
ELFs, receipts, actual wire/output joins, physical DB/effect and process
samples. The diagnostic product prefix remains the historical `62aa7ba7`
build; this is not current-upstream product qualification.

Every v5 terminal remains `invalid-evidence`, with execution eligibility,
Guard causality and outside signing-key admission false. This diagnostic
does not close independent Guard request/decision/effect scoring, six-role
conformance, current-source deployment review, model execution or cutover.
The parent checklist remains 24/62 complete. The user is handling disabled
fork Actions; all five exact-head jobs remain required before a child merge.

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

At this implementation checkpoint, 80 macOS worker tests and warnings-denied
Clippy pass. ARM64 worker/rootfs Clippy and static library/binary builds pass.
Actual ARM execution of the new library suite and composed VM job remains
pending. Logs retain the initial Clippy boolean-simplification refusal and
the corrected pass. No VM result or parent exit is claimed by compilation.

Every v5 terminal remains `invalid-evidence`, with execution eligibility,
Guard causality and outside signing-key admission false. This diagnostic
does not close independent Guard request/decision/effect scoring, six-role
conformance, current-source deployment review, model execution or cutover.
The parent checklist remains 24/62 complete. The user is handling disabled
fork Actions; all five exact-head jobs remain required before a child merge.

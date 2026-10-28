# Rust base MCP dispatch and persistent transport

`gauntlet-mcp-service` implements the base synthetic MCP protocol in Rust.
It negotiates the four protocol versions supported by the pinned MCP 1.30.0,
requires initialization, serves tool/resource catalogs, validates arguments,
dispatches provider calls into `gauntlet-world`, and returns canonical text
and structured results. Its implementation version is explicitly
`gauntlet-rust-mcp.v1`; it does not claim to be the Python server.

The immutable 29,260-byte catalog has SHA-256
`22df4f3850d6d22ef30b6ec45108cde9b4306879c06c99ccce6f3bf53097cafe`.
It contains all 41 base tool schemas from actual MCP 1.30.0: mail 8, docs 6,
calendar/chat 6 each and CRM/tables/tickets 5 each. A metadata-only fixture
producer ran as UID/GID10005 in a fresh read-only, network-disabled container
using the existing pinned public prefix and unchanged server source. It
executed no provider operation, used no signing key and left no container or
host-device identity change. The server source SHA-256 is
`f6e004a65f60a38322e02fc229d4430279fad5db2dc35453eca4f3afefa9086b`.

Rust checks the frozen catalog identity before compiling its offline JSON
validators. The strict integer parameters reject booleans and float literals;
omitted defaults remain omitted when the original arguments reach World.
Resource IDs stay literal, matching the pinned SDK's
[resource-template matcher](https://github.com/modelcontextprotocol/python-sdk/blob/v1.30.0/src/mcp/server/fastmcp/resources/templates.py).
Protocol versions and result types were checked against the official
[version constants](https://github.com/modelcontextprotocol/python-sdk/blob/v1.30.0/src/mcp/shared/version.py)
and [message types](https://github.com/modelcontextprotocol/python-sdk/blob/v1.30.0/src/mcp/types.py).
Bounded protocol/validation error messages are versioned Rust responses;
complete historical error-wording parity is not claimed.

The persistent Unix transport preserves pipelined frames and surplus bytes,
caps each frame at 2 MiB, and supports deadlines, cancellation, backpressure
and truncated-stream refusal. Cancellation/deadline checks cover already
buffered requests. Malformed or uncertain sessions cannot be reused. The
protocol also bounds sessions to 1,000 messages and 16 MiB of incoming data.
It receives a caller-owned backend, so separate sessions cannot silently mint
their own operation allowances. Peer identity and global budget custody still
belong to the future Root service wrapper.

Nine dispatch tests cover all 41 schemas, initialization, unknown/invalid
calls, real World results and receipts, literal resources, original arguments,
large integer request IDs, shared caller budgets and refusal before dispatch.
Five real Unix-socket tests cover pipelining, exact bytes, truncated/oversized
input, idle timeout, cancellation including buffered frames, backpressure,
and complete negotiation/request/response exchange. World's original
153-operation Python parity and five durability tests still pass.

The complete Mac workspace passes 474 tests across 226 targets with zero
failures or ignores; log `rust-workspace-mcp-002.log` has SHA-256
`2738b7b1c70d984c7e7e60fec579361e4d7fd1b1e3b32889407a227d1dc4c803`.
Warnings-denied Mac/ARM Clippy and static ARM test builds pass.

Native ARM execution now passes at source
`5433f74440d0fc5d912583a381197ee7c96fc982`: nine dispatch, five persistent
socket, five world durability and one 153-operation Python parity test. All
20 pass as Root with zero failures/ignores. The five-member input archive
has SHA-256
`1801251c0bc1ab7fb67d2cbd6e2aea3a2d86368fafecb2e8f87bf42fe961c801`;
the 15-member result archive has SHA-256
`41809cde0ff911b9870e4dbbc931b1153fc386c24e7987e5cb39baba4523f021`.
The committed inert `verify_rust_mcp_native_20261027.py` checks all ELF input
bytes, exact native test counts/output hashes, and the original catalog
producer's source/launch/output/cleanup records. That six-member catalog
export has SHA-256
`b98493282d9b6b5d56c0d31dd0e085616156361b82a6d94a6cfb286a0610a4e5`.
Podman's successful `--rm` also removes the transient CID file; its absence
was retained rather than replaced with an invented record. The earlier
courier size-assertion error refused before any destination creation.

This component is not yet wired to the Root-owned listener, authenticated
Native MCP proxy/container, SDK resource endpoints, shared builtin/MCP budget
or outside scoring. Developer Git/package metadata extensions, versioned
protocol profiles, authenticated lifecycle and fresh six-role conformance
remain open. No actual SDK MCP session, Guard-causality verdict, model request
or benchmark admission is claimed. Parent exits remain 24/62 complete.

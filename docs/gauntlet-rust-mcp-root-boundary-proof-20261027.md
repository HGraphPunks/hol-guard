# Rust MCP database and listener custody

The Root worker now creates an exclusive `mcp-world.db` in its fixed native
job directory. The database remains Root:Root mode 0600 beneath mode 0700
ancestors. Before and after provider calls, Rust compares held and visible
directory/file identities, owner, mode and link count and observes the actual
SQLite descriptor's close-on-exec flags. A custody failure poisons subsequent
calls even when metadata is restored. Transactions use `gauntlet-world`;
neither database contents nor the in-memory signing key are mounted to agents
by this component. Actual agent mount verification remains a caller obligation.

`NativeMcpSockets::prepare` establishes an owner before filesystem mutation.
Its one-use initializer creates seven fixed upstream listeners for UID/GID
10005, seven resource listeners for UID/GID 10001, and a proxy binding gate.
Directories are Root-owned mode 0710 and sockets mode 0660. Rust checks the
complete directory inventory, held inode, ownership/modes and descriptor
flags before and after accept. Explicit retirement unlinks only a matching
owned inode, verifies its link count reaches zero, and retains job evidence.
Partial initialization stays uncertain and cannot adopt earlier namespaces.
Dropping the owner closes its descriptors without deleting evidence.

On the owned ARM64 Linux VM as Root, all four database tests pass, including
transaction persistence, symlink/preexisting-slot refusal, owner/mode/hardlink/
replacement refusal and sticky descriptor/directory failures. The full worker
suite passes **161 tests, zero failures, 24 existing ignores**. Its ELF SHA-256
is `fc8d15214c363d213a17ae4a7f3ea2a55b21bf810d2b421103ce528ccecb7617`.
The original three-member result export is 30,720 bytes, SHA-256
`75a3500975bfe6a4a75d33aeecdfe565d4d331bb3056c41f9710267d8762b4ef`.

After adding listeners, all three new socket tests pass and the full suite
passes **164 tests, zero failures, 24 existing ignores**. The tests exchange
real socket bytes through all fourteen provider endpoints and the gate,
retain a substituted socket during cleanup, refuse restored custody, and
retain uncertainty after a partial startup. ELF SHA-256 is
`d214c2c09dabb363418ffd5a1120bc422a77c6ef256eee578f65c26244c9c7e8`.
Its original three-member result export is 30,720 bytes, SHA-256
`acda30cc83212123fd91cdbde822eec76bccceb20e1d5e49231b5c45b182fb5c`.

Both exports are retained outside the guest in the local evidence directory.
The committed reader checks their exact archives, original stdout/stderr,
test counts, test names and binary pins. ARM warnings-denied Clippy and test
compilation also pass; the final Clippy log SHA-256 is
`9f3d4916f1479628a37a6a39ccea64f59d197669337bc37c2a02250d7d37bf0d`.

This is database and socket custody, not an authenticated MCP execution.
Retiring listener names does not establish that accepted streams or processes
have drained. Peer/container/Native proxy and actual SDK MCP integration,
outside key admission, independent effects and Guard causality remain open.
Observations explicitly retain those limits and execution ineligibility.
No model requests were made; no parent migration exit is closed by this proof.

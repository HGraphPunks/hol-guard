# Rust Native SDK transport components

The current Native hook diagnostic passes on the owned ARM VM; see the
[retained transport proof](gauntlet-rust-native-hook-vm-proof-20261027.md).
This next implementation adds SDK request state, a kernel peer observer and
inert public dependency publication. The SDK listener/launcher is still being
connected. These components do not supply an SDK run, conformance or Guard
verdict. The parent checklist remains 24/62 complete.

`NativeSdkRequest` accepts the explicitly bounded Bash-only SDK hook profile
and the separate contained-execution request. It preserves complete original
Bash arguments and the exact sender-byte digest, rejects duplicate/unknown
JSON fields and validates fixed workspace, session, call and text-output
types. The ledger binds one session and budget before product forwarding,
consumes each opaque route before execution, requires completed capture before
Post, and refuses replay or changed input/context. A route is transport state;
it cannot grant a Guard approval. The normal Native route remains responsible
for authorization. Historical SDK adapters are unchanged.

The Linux ARM peer observer holds pidfds, namespace descriptors and the actual
Bun executable inode. It checks every saved UID/GID, group and capability set,
NNP, seccomp, enforcing label, exact cgroup, namespace init, fixed SDK argv and
the externally pinned Bun bytes. The SDK must occupy the measured agent's
namespaces, separate from Root and the product cell. Hook peers must be that
exact Bun PID. Execution peers also require the existing twice-observed
ancestry relation. All held identities are rechecked. This observer alone
does not establish the entrypoint bytes, SDK tree or pre-import ordering;
those fields remain explicitly false until the Rust launcher/gate binds them.

## Public dependency custody

The retained public SDK is 18.4.12, with 42,321 entries and 1,053,309,967
ordinary file bytes. Its outside tree digest is
`4b12e74045c56e5f387c2a82312e38a97d665a88cc52bb698e55bf52747bf0b1`.
The Bun file is 91,801,560 bytes with SHA-256
`37141662ebed915a2ab89313156e455e2a1374395f5f6760d06407f49406f086`.
These are the existing retained public runner inputs. No package code runs
during transfer or publication.

A bounded courier exported the unchanged bytes and original owner metadata
from the retained VM. Its first canonical-order assertion refused before
writing payload bytes; the zero-byte attempt remains retained. The corrected
archive `native-sdk-public-source-024b.tar` has 42,324 logical members and
1,200,394,240 bytes, SHA-256
`fb658d14d25a8a7c7906edd723b2d9dad54ef063661bbb773419de3a0c6df4fc`.
Host readback checks every member and the original SDK/Bun pins.

The private external-dependency bootstrap copy changes UID/GID to Root and
removes ordinary group/other write bits. Symlink metadata and every file byte
are preserved. This explicit custody transformation produces the distinct
SDK tree digest
`ad4d62276c7f7d4026411ceedc56bbd257b06cd6ffd0c9933a6ef3b91d901a3e`.
It does not replace the original tree or pretend the metadata is unchanged.
The source declaration is
`1f4b60186253171767bf4784145095385ea362c6af9017730cd5027b7e45bc1a`.

`gauntlet-native-sdk-publish JOB DECLARATION_SHA256 OWN_GENERATION` reads only
that job's fixed private `sdk-source` directory and closed source declaration.
Under both permanent worker leases, it requires no unknown Native jobs,
re-inventories the normalized SDK, verifies Bun's ordinary Root custody,
actual Linux ARM64 ELF and exact digest, and reads the SDK package identity
as inert JSON. It clones through the existing descriptor-relative Rust
copier, checks complete source/copy readback, publishes without replacement
under `/opt/hol-gauntlet/sdk-assets/<normalized-sdk-digest>-<bun-digest>`, and writes
identical canonical receipts in that directory and the original job.
The composite identity permits a later Bun version to retain the same SDK
without aliasing an earlier publication. Wrong pins and consumed slots refuse;
partial state remains for reconciliation.
Publication remains unadmitted, with SDK/Bun execution flags false.

The complete Mac workspace passes 440 tests across 218 targets, with zero
failures or ignores. Retained log `rust-workspace-native-sdk-components-024b.log`
has SHA-256 `d751567121ca8799b1bcbe487974df423768d5998c73d72ef5c613159825b392`.
The five focused SDK tests, Mac/ARM warnings-denied Clippy and ARM publisher
compilation pass. The earlier sandboxed workspace attempt failed at local
Unix socket binding before either unchanged interop peer started; its log
`rust-workspace-native-sdk-components-024.log` remains retained as
`4868f9a736930f4de4df5c077f7004812f3cc834bcf87ee439023f78bc7cc474`.
The peer observer still requires actual live SDK verification. The publisher's
first owned-VM execution remains next. No model or provider request occurred.

# Rust local source producer

`gauntlet-host-prepare-local-source PRIVATE_STATE JOB_ID ABSOLUTE_LOCAL_REPOSITORY EXACT_COMMIT`
creates the bare Git-object archive required by the fixed unprivileged builder.
The state root must already be owned by the caller, mode 0700, with no symlink
components. Each 16-hex job consumes a fresh private slot, including failures.

Rust initializes an empty bare repository with no template, fetches only the
exact local commit into `refs/heads/local-<commit>`, verifies the ref, and writes
a bounded descriptor-read tar/gzip archive. Git runs with a cleared environment,
no system/global config, disabled hooks/credentials/maintenance and only the
local file protocol. No checkout or candidate code runs on the host.

The writer refuses links, unsafe ownership/modes, changed files/directories,
more than 100,000 entries, depth over 32, 512 MiB of decoded Git files or 256 MiB
of compressed output. `FETCH_HEAD` is omitted to avoid exporting local path
names. The existing independent archive/ref/Git-graph reader must then accept
the exact archive before Rust writes `source-preparation.v1.json`. The archive
and receipt are fsynced in the one-use slot. Failed partials remain consumed;
there is no automatic retry or in-place repair.

Output schema is `hol-gauntlet-local-source-preparation.v1`. Its hash covers
the archive bytes actually written; it does not promise Python's gzip bytes.
Every output keeps candidate execution and eligibility false, with zero model
requests. Remote release discovery/authentication, upload, Root source capture,
build, artifact admission and qualification are separate boundaries.

Real Git tests capture an older requested commit after the source advances,
prove source checkout hooks do not execute, reverify the graph, and preserve
archive/receipt bytes on replay refusal. Invalid IDs, a linked repository,
loose state and failed fetches also refuse; failed jobs cannot be reused.

The host candidate run and result CLIs additionally accept `--vm VM_NAME`.
Their historical default stays unchanged. New launches write
`hol-gauntlet-host-candidate-build-pin.v4`, binding the exact Lima executable
and VM before launch. Result reconciliation refuses a different target or
transport. Historical v2/v3 records retain their schemas and 2-KiB bound;
target-bound v4 records have a 4-KiB bound. These intent records do not admit
the built artifact or establish VM attestation.

At producer source `6bb4cbfbc3ebfc502dd8b926da085e7d71ea853c`, the measured
2,806,736-byte Mac executable has SHA-256
`c0b3f45621a8c81732f1bcdef51d4554df9539023d1b26588bddd14a31b19ae5`.
It captured the full exact older candidate `84549fd4` under fresh job
`e2c701baf1471301`: seven regular tar members, 55,702,249 compressed bytes,
archive SHA-256 `21363432af545de03c24609b0bee78016921e0577e308f05953b51e49b58d237`.
The source receipt is
`27545120732b77103618baecedf0c3a684d84483c8a9a179f66e77897abb3218`.
Replay exited 2 and preserved both hashes. No VM/build/model was launched by
this proof. Its records and private Git objects remain in the host evidence
directory under `native-rust-source-state-004`.

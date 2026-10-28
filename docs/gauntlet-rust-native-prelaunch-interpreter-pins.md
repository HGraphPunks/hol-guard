# Versioned prelaunch image interpreter pins

`hol-gauntlet-cell-supervisor.v2` adds two required SHA-256 fields to the
outside preparation: `image_interpreter_sha256` and
`outside_observer_sha256`. Version one retains its exact closed field set;
adding either field to a v1 declaration refuses. Version two requires both
typed digests and permits no caller-selected interpreter path or command.

Before product startup, Root opens the fixed image `usr/bin/python3.12`
through held, no-symlink image/`usr`/`bin` descriptors. It requires Root UID/GID,
mode 0755, one link, a bounded ARM64 ELF and the outside-pinned digest. The
held file and each named ancestor are checked before and after hashing.
Directory/file descriptors are close-on-exec. The generation is rechecked
before launch and every product spawn/release. Replaced inodes, links,
ancestor swaps, writable/nonexecutable files, changed bytes and other
architectures refuse.

Root records the measured generation immediately after `prepared`, before
the first product gate. The Native plane's signed journal checkpoint binds
that event. Rust readback requires the exact v2 preparation pins, complete
journal binding and the early Root file witness before setting
`interpreter_prelaunch_pinned:true`. A v1 report cannot gain that credit from
an invented event. The observer digest is a prelaunch declaration; observer
process authentication and outside key admission remain false and separate.

The Mac workspace passes 561 tests with no failures or ignores, log SHA-256
`db979a098194c5157046a8c998f39cbcdf368441649da0c0c186ddc445927e99`.
After explicitly testing close-on-exec descriptor inheritance, all 41 affected
rootfs tests pass (`dad5c3f226279050868d4f07291b8f5ab24fbc337b87c8265ea7417c454d78bb`).
Warnings-denied all-workspace/all-target/all-feature Clippy passes on Mac
(`5997d3d1e90222ce802ad0596ba3347deb8fb8eb141385438613e16eab46950e`)
and ARM
(`b063917e9c49cc50257ceeb4e0c5024242c860446ed89b273c8a483975ea4df0`).
Seven new tests cover both schema layers, actual held file generations and
the consuming provenance reader. New source files stay below 500 lines.

Fresh Native execution, production of the new witness and native ARM unit
execution remain pending at this implementation checkpoint. Historical
archives retain their original missing-pin status. No model requests run;
qualification, Guard causality and parent exits remain unchanged at 24/62.

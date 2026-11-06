# Native capture input receipts

Rust product captures now journal a versioned input binding after measuring the
gated process and before releasing it. The binding records its owned handle,
argv digest, expected stdin length and digest. A terminal input receipt hashes
only bytes acknowledged by the actual bounded write calls, records their
length and the input-close acknowledgement, and distinguishes complete from
partial or never-started delivery. No stdin content is published by this receipt.

Success, timeout, cancellation and failed startup retain the receipt separately
from the output capture and execution outcome. Equal-length changed bytes,
over-delivery, early close, rebinding and reuse refuse completion. A journal
failure keeps the original execution error and adds custody uncertainty rather
than fabricating successful evidence.

This closes an instrumentation gap for future Native hook grading: a reader
can hash the exact canonical hook payload plus its newline and join it to the
process handle, argv, input receipt and captured output. Historical capture
journals lack these receipts; they must remain unverified for input delivery.
The [hook artifact reader](gauntlet-rust-native-hook-artifact-verifier.md) now
consumes these receipts and requires a matching Root journal checkpoint signed
in the Native plane. It checks count, bytes, tail digest and physical custody;
old signed reports cannot gain credit from invented receipt events. Full
Native process/Bash/lifecycle grading and fresh actual execution remain pending.
This instrumentation supplies no Guard causality or qualification by itself.

The affected Mac rootfs library passes all 36 tests, including three new input
state cases, with zero failures or ignores. The log hashes to
`63722c9ae50d6c2904ba68a6df424ddd68652048013d9d7c8a253337408f4dc1`.
Warnings-denied all-target/all-feature rootfs Clippy passes on Mac
(`be48a1798a1e3baadbc1501a605d5d60824b4f8e1211e4a053124ef16a59ec5d`)
and ARM (`68e4d9ceac575892f0d818199640e092cc3dbbdef32d9e610ebd3be6953041f1`).
The static ARM library tests compile, log SHA-256
`23b2445243406abc07a04e541cf41d0956d90304eb69b98fc6fbe0e0a0a52f21`;
the executable is 9,600,952 bytes, SHA-256
`257235f58cff57b6e5984a17bfc2d73edc7766bdc550b990f15cd99e69b408a6`.
All three new state tests also pass natively under Root on the owned ARM VM
at source `052cbabd00a889d5b862205c22f58a5b695140d8`. Both worker leases
remain held, all 284 prior worker files retain their hashes and owned product
cgroups remain absent. These are focused unit tests; fresh actual Native
capture execution remains pending. Later hook-reader and journal-custody tests
are recorded in the linked hook artifact proof.

The executable was compiled before the implementation commit; the courier
checks every changed source file against that exact committed Git object.
The 9,605,120-byte two-member input hashes to
`ec73a5b4524ed8f10870e643f7f488d266768773107eede5f84a69cea4108179`.
The 10,240-byte six-member public export hashes to
`1d34a7411d1f41091f4f9e058d6eb77129b40b61ddc4b47674180fbd7d12b041`.
Root hashes the held output before the transport handoff. The native test log
hashes to `b206d807bc3df9225013c192fbe01bbd5573b7fb383b3252eb6d63fa62cdaf06`.
The [fixed-generation reader](../ci/gauntlet-rs/proofs/verify_native_capture_input_arm_20261027.py)
verifies all members, source/ELF/log/metadata pins and unchanged records. Its
successful stdout hashes to
`f65b2cda1cbc95c380645354b1232982410334dbc605f42a8cfc4e84220f87d0`.
Ruff formatting and lint pass; zero model requests ran.

All three changed source files are pinned in
`native-capture-input-arm-artifacts-001.json`: `lib.rs`,
`supervisor_capture.rs`, `supervisor_capture_input.rs`. Prior proofs, records
and eligibility flags are retained. Parent exits remain 24/62; CI remains
user-owned and pending.

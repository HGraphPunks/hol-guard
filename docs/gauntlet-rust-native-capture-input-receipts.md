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
The Native hook/Bash/lifecycle grader and fresh actual execution remain pending.
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
Native test execution remains pending at this implementation checkpoint.

All three changed source files are pinned in
`native-capture-input-arm-artifacts-001.json`: `lib.rs`,
`supervisor_capture.rs`, `supervisor_capture_input.rs`. Prior proofs, records
and eligibility flags are retained. Parent exits remain 24/62; CI remains
user-owned and pending.

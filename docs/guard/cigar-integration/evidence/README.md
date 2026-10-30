# CIGAR evidence receipts

Each JSON file records the result, the measured commits, and `captured_record_sha256`, the SHA-256 of the original captured record. A field named `sha256` on an omitted list, map, or trace identifies that body the same way.

Raw logs are not stored in this tree. `log-hashes.json` lists each removed log by filename, byte length, and SHA-256.

Dashboard checks read the observations under `dashboard/src/context-assistance/fixtures/`.

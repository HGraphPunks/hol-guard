"""Read the public eleven-test hook proof; grant no role qualification."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from verify_native_mcp_transport_20261027 import archive, parse, sha

SOURCE = "72f49ab8f5210880b90f69d46eeb42751d82717c"
INPUT = "28a88c0f1c638a7ff18e60120707581913de175e1bd989c14566281e4eb70891"
EXPORT = "ba53115f8ae13645381f4762ec4faab502fc1c4fbd187c77640f3dd3b6e83c26"
CASES = [
    (
        "input-reader-tests",
        "evidence-tests",
        "eb7efef6ebe3f79ff438c1fee00e6d3ac0bda74f6b5c198b626dd238b0959c43",
        21777800,
        "78828c26b2a22beccd7ca47107db4dbbc288eb74199915e37427fb0701127e68",
        "native_capture_input::tests",
        5,
    ),
    (
        "hook-reader-tests",
        "evidence-tests",
        "eb7efef6ebe3f79ff438c1fee00e6d3ac0bda74f6b5c198b626dd238b0959c43",
        21777800,
        "70c8ede8863242d2877baf3aab8e94cc2ab350d126da1726b2f7771c76cd647d",
        "native_hook_diagnostic::tests",
        2,
    ),
    (
        "root-journal-tests",
        "root-journal-tests",
        "0605a72bcd0c1b1ced39cd708b75629a5b5d9fb5c472889636dc0e4543c1fec6",
        9647736,
        "ac8acb8465a7331be70eee277d546084476826763d2023c1c96ee5241edbb8ce",
        "supervisor_journal::tests",
        2,
    ),
    (
        "host-archive-tests",
        "host-archive-tests",
        "8fb355cc7a5b0b24dccd6b57f3b9195f4320724af0a7d59cc352092b0d48f891",
        10553016,
        "68b0e1d88b930dbe43b7262bb8d69b7940bbb23309caae50fae43bd86abeae81",
        "native_diagnostic_archive::tests",
        2,
    ),
]


def verify(directory):
    inputs = archive(directory / "native-hook-arm-input-002.tar", INPUT, 41984000, 4)
    data = archive(directory / "native-hook-arm-vm-results-002.tar", EXPORT, 20480, 12)
    transfer = parse(inputs["transfer.json"])
    assert transfer == parse(data["transfer.json"]) and transfer["source_commit"] == SOURCE
    install, proof = parse(data["install.json"]), parse(data["proof.json"])
    assert install["source_commit"] == proof["source_commit"] == SOURCE
    assert install["root_owned"] is True and install["files"] == transfer["files"]
    assert set(transfer["files"]) == set(inputs) - {"transfer.json"}
    assert install["input_sha256"] == proof["input_sha256"] == INPUT
    assert proof["worker_files_preserved"] == 284
    assert proof["both_worker_leases_held"] is True and proof["owned_product_cgroups_absent"] is True
    for value in [transfer, install, proof]:
        assert value["execution_eligible"] is False and value["model_requests"] == 0
    assert proof["guard_causality_verified"] is False
    assert len(proof["results"]) == len(CASES)
    metadata = parse(data["results.sha256.json"])["filesystem"]
    assert set(metadata) == set(data) - {"results.sha256.json"}
    for item in metadata.values():
        assert item["uid"] == item["gid"] == 0
        assert item["mode"] == 0o400 and item["links"] == 1
        assert item["device"] > 0 and item["inode"] > 0
    for offset, (label, name, elf_pin, size, log_pin, selector, count) in enumerate(CASES):
        raw = inputs[name]
        assert raw[:4] == b"\x7fELF" and raw[18:20] == b"\xb7\0" and sha(raw) == elf_pin
        assert len(raw) == size and transfer["files"][name] == {"bytes": size, "sha256": elf_pin}
        result = parse(data[label + ".json"])
        assert result == proof["results"][offset]
        assert result["source_commit"] == SOURCE and result["executable_sha256"] == elf_pin
        assert result["filter"] == selector and result["returncode"] == 0
        assert result["results"] == [["ok", str(count), "0", "0"]]
        assert result["execution_eligible"] is False and result["model_requests"] == 0
        assert result["log_sha256"] == sha(data[label + ".log"]) == log_pin
        assert re.findall(
            rb"test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored", data[label + ".log"]
        ) == [(b"ok", str(count).encode(), b"0", b"0")]
    return {
        "schema": "hol-gauntlet-native-hook-arm-host-readback.v1",
        "rust_source_commit": SOURCE,
        "input_sha256": INPUT,
        "export_sha256": EXPORT,
        "native_input_reader_tests": 5,
        "native_hook_reader_tests": 2,
        "native_root_journal_tests": 2,
        "native_archive_custody_tests": 2,
        "retained_worker_files_unchanged": 284,
        "qualified_role_complete": False,
        "execution_eligible": False,
        "guard_causality_verified": False,
        "model_requests": 0,
    }


if __name__ == "__main__":
    if not __debug__ or len(sys.argv) != 2:
        raise SystemExit("usage (assertions enabled): verify_native_hook_arm_20261027.py EVIDENCE_DIRECTORY")
    print(json.dumps(verify(Path(sys.argv[1])), sort_keys=True))

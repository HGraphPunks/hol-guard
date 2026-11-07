"""Read the public ten-test native process proof; grant no qualification."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from verify_native_mcp_transport_20261027 import archive, parse, sha

SOURCE = "70c0d1d929be4b04c12d82cf32372eda3928ae03"
INPUT = "a9cf67b16e1fbdcd50adcb0c554d207ee114bf02b73cfa989564225d0f3afd25"
EXPORT = "dd1251ecfcb486ffd6edc7fd28f53bb3570c6b3a5039aa139f37468992ed508f"
CASES = [
    (
        "process-tests",
        "evidence-tests",
        "1e6540ab052503d9bb71a0ca9a1dff2c1b4cc0b5ab91c44af312c49b2ef7819a",
        "3301656f53ec1085f1f54ef528b463f54e92603fee91a5b2878be5a0a36f60f9",
        "native_process_",
        8,
    ),
    (
        "host-archive-tests",
        "host-archive-tests",
        "db34810761e07a8865306514133b9736484072dc6a425b7bf2bc7fefc45b0a05",
        "68b0e1d88b930dbe43b7262bb8d69b7940bbb23309caae50fae43bd86abeae81",
        "native_diagnostic_archive::tests",
        2,
    ),
]


def verify(directory):
    inputs = archive(directory / "native-process-arm-input-001.tar", INPUT, 32163840, 3)
    data = archive(directory / "native-process-arm-vm-results-001.tar", EXPORT, 20480, 8)
    transfer = parse(inputs["transfer.json"])
    assert transfer == parse(data["transfer.json"]) and transfer["source_commit"] == SOURCE
    install, proof = parse(data["install.json"]), parse(data["proof.json"])
    assert install["source_commit"] == proof["source_commit"] == SOURCE
    assert install["root_owned"] and install["files"] == transfer["files"]
    assert install["input_sha256"] == proof["input_sha256"] == INPUT
    assert proof["worker_files_preserved"] == 284
    assert proof["both_worker_leases_held"] and proof["owned_product_cgroups_absent"]
    for value in [transfer, install, proof]:
        assert value["execution_eligible"] is False and value["model_requests"] == 0
    assert proof["guard_causality_verified"] is False
    assert len(proof["results"]) == len(CASES)
    metadata = parse(data["results.sha256.json"])["filesystem"]
    for name in set(data) - {"results.sha256.json"}:
        assert metadata[name]["uid"] == metadata[name]["gid"] == 0
        assert metadata[name]["mode"] == 0o400 and metadata[name]["links"] == 1
    for offset, (label, name, elf_pin, log_pin, selector, count) in enumerate(CASES):
        raw = inputs[name]
        assert raw[:4] == b"\x7fELF" and raw[18:20] == b"\xb7\0" and sha(raw) == elf_pin
        assert transfer["files"][name] == {"bytes": len(raw), "sha256": elf_pin}
        result = parse(data[label + ".json"])
        assert result == proof["results"][offset]
        assert result["source_commit"] == SOURCE and result["executable_sha256"] == elf_pin
        assert result["filter"] == selector and result["returncode"] == 0
        assert result["results"] == [["ok", str(count), "0", "0"]]
        assert result["log_sha256"] == sha(data[label + ".log"]) == log_pin
        assert re.findall(
            rb"test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored", data[label + ".log"]
        ) == [(b"ok", str(count).encode(), b"0", b"0")]
    return {
        "schema": "hol-gauntlet-native-process-arm-host-readback.v1",
        "rust_source_commit": SOURCE,
        "input_sha256": INPUT,
        "export_sha256": EXPORT,
        "native_process_tests": 8,
        "native_archive_custody_tests": 2,
        "retained_worker_files_unchanged": 284,
        "qualified_role_complete": False,
        "execution_eligible": False,
        "guard_causality_verified": False,
        "model_requests": 0,
    }


if __name__ == "__main__":
    if not __debug__ or len(sys.argv) != 2:
        raise SystemExit("usage (assertions enabled): verify_native_process_arm_20261027.py EVIDENCE_DIRECTORY")
    print(json.dumps(verify(Path(sys.argv[1])), sort_keys=True))

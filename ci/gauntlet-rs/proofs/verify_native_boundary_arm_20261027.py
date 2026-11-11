"""Read the exact public seven-test native ARM proof; grant no qualification."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from verify_native_mcp_transport_20261027 import archive, parse, sha

SOURCE = "cec21c2c4ddc2ce9d179334ba069376bd49bd2ec"
INPUT = "f521ca695bf3bf5144ef8f3b9e89d55c492e62688bb1b0f520ca8289dc7ac7ad"
EXPORT = "226394f2a1cae48e7f038fa9edde17b840cfe46792d325513b4d3b55be3a3156"
CASES = {
    "evidence-tests": (
        "c0f97884c1b93fb72126a85e5ae3cc812ae9f2aefcd44f2cc7fe7569431450ce",
        "e9283455ca13a1772fc76f93fde7e67b48923dbada626594d030d910286f2496",
        "native_boundary_diagnostic::tests",
        5,
    ),
    "host-archive-tests": (
        "45047ef1ea36bc1e60777efeb206ff68833021beef4450025703d2ae0e3345ed",
        "68b0e1d88b930dbe43b7262bb8d69b7940bbb23309caae50fae43bd86abeae81",
        "native_diagnostic_archive::tests",
        2,
    ),
}


def verify(directory):
    inputs = archive(directory / "native-boundary-arm-input-001.tar", INPUT, 28282880, 3)
    data = archive(directory / "native-boundary-arm-vm-results-001.tar", EXPORT, 20480, 8)
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
    for offset, (name, (elf_pin, log_pin, selector, count)) in enumerate(CASES.items()):
        raw = inputs[name]
        assert raw[:4] == b"\x7fELF" and raw[18:20] == b"\xb7\0" and sha(raw) == elf_pin
        assert transfer["files"][name] == {"bytes": len(raw), "sha256": elf_pin}
        result = parse(data[name + ".json"])
        assert result == proof["results"][offset]
        assert result["source_commit"] == SOURCE and result["executable_sha256"] == elf_pin
        assert result["filter"] == selector and result["returncode"] == 0
        assert result["results"] == [["ok", str(count), "0", "0"]]
        assert result["log_sha256"] == sha(data[name + ".log"]) == log_pin
        assert re.findall(
            rb"test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored", data[name + ".log"]
        ) == [(b"ok", str(count).encode(), b"0", b"0")]
    return {
        "schema": "hol-gauntlet-native-boundary-arm-host-readback.v1",
        "rust_source_commit": SOURCE,
        "input_sha256": INPUT,
        "export_sha256": EXPORT,
        "native_evidence_tests": 5,
        "native_archive_custody_tests": 2,
        "retained_worker_files_unchanged": 284,
        "qualified_role_complete": False,
        "execution_eligible": False,
        "guard_causality_verified": False,
        "model_requests": 0,
    }


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: verify_native_boundary_arm_20261027.py EVIDENCE_DIRECTORY")
    print(json.dumps(verify(Path(sys.argv[1])), sort_keys=True))

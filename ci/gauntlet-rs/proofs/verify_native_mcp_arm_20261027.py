"""Verify the public ARM MCP/provider unit proof without granting qualification."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from verify_native_mcp_transport_20261027 import archive, parse, sha

SOURCE = "65a700765f5805c1663664c390fff10e3618a2d4"
INPUT = "2c6b26c3b535a495f69e8c5d72928ac81a1216e41b50beeb588bf36b4513e8bf"
EXPORT = "0f57a763f202faa6a497a68f4c61415d6024f9b119bd33abc80b96c2a94ab859"
EVIDENCE = "9a30c8bcbb40f0fc4170eca633e8485afa51b6a951402b9bfb8a2f1a037e557b"
CASES = [
    (
        "world-tests",
        "evidence-tests",
        EVIDENCE,
        "2d2cadf5a7b8d3d41508a0d41fed825e14109aa14d43ee150356cba125e16264",
        "native_world_",
        8,
    ),
    (
        "mcp-tests",
        "evidence-tests",
        EVIDENCE,
        "77b7fb057f3b55954769dfb9b36ab99893e7dd7bde170808f16827c23b3309f8",
        "native_mcp_",
        7,
    ),
    (
        "host-archive-tests",
        "host-archive-tests",
        "cbd22526f2bfb4f113a246cd92ff0ca3866868ace3cd78238cb1d9212c4e8cfc",
        "68b0e1d88b930dbe43b7262bb8d69b7940bbb23309caae50fae43bd86abeae81",
        "native_diagnostic_archive::tests",
        2,
    ),
]


def verify(directory):
    inputs = archive(directory / "native-mcp-arm-input-001.tar", INPUT, 32020480, 3)
    data = archive(directory / "native-mcp-arm-vm-results-002.tar", EXPORT, 20480, 10)
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
        "schema": "hol-gauntlet-native-mcp-arm-host-readback.v1",
        "rust_source_commit": SOURCE,
        "input_sha256": INPUT,
        "export_sha256": EXPORT,
        "native_provider_tests": 8,
        "native_mcp_tests": 7,
        "native_archive_custody_tests": 2,
        "retained_worker_files_unchanged": 284,
        "qualified_role_complete": False,
        "execution_eligible": False,
        "guard_causality_verified": False,
        "model_requests": 0,
    }


if __name__ == "__main__":
    if not __debug__ or len(sys.argv) != 2:
        raise SystemExit("usage (assertions enabled): verify_native_mcp_arm_20261027.py EVIDENCE_DIRECTORY")
    print(json.dumps(verify(Path(sys.argv[1])), sort_keys=True))

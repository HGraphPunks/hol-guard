"""Read source-pinned native MCP/world unit tests and the real catalog fixture."""

from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path

import verify_native_current_worker_20261026 as v

COUNTS = {
    "world-python-parity-tests": 1,
    "world-durability-tests": 5,
    "mcp-dispatch-tests": 9,
    "mcp-transport-tests": 5,
}
CATALOG = "22df4f3850d6d22ef30b6ec45108cde9b4306879c06c99ccce6f3bf53097cafe"


def verify(base):
    inputs = v.archive(
        base / "rust-mcp-native-tests-input-001.tar",
        "1801251c0bc1ab7fb67d2cbd6e2aea3a2d86368fafecb2e8f87bf42fe961c801",
        5,
    )
    transfer = v.parse(inputs.pop("transfer.json"))
    assert transfer["source_commit"] == "5433f74440d0fc5d912583a381197ee7c96fc982"
    assert transfer["expected_tests"] == COUNTS and transfer["catalog_sha256"] == CATALOG
    assert set(inputs) == set(transfer["files"]) == set(COUNTS)
    for name, raw in inputs.items():
        assert v.sha(raw) == transfer["files"][name]["sha256"] and len(raw) == transfer["files"][name]["bytes"]
        assert raw[:6] == b"\x7fELF\x02\x01" and int.from_bytes(raw[18:20], "little") == 183
    data = v.exported(
        base / "rust-mcp-native-tests-results-001.tar",
        "41809cde0ff911b9870e4dbbc931b1153fc386c24e7987e5cb39baba4523f021",
        15,
    )
    assert v.parse(data["input.json"]) == transfer
    result = v.parse(data["results.json"])
    assert (
        result["source_commit"] == transfer["source_commit"] and result["machine"] == "aarch64" and result["uid"] == 0
    )
    assert result["cases"] == 153 and result["accepted"] == 94 and result["refused"] == 59
    assert set(result["tests"]) == set(COUNTS)
    for name, count in COUNTS.items():
        check = v.parse(data[name + ".json"])
        assert check == result["tests"][name]
        assert check["returncode"] == 0 and check["results"] == [["ok", str(count), "0", "0"]]
        for stream in ["stdout", "stderr"]:
            assert v.sha(data[name + "." + stream]) == check[stream + "_sha256"]
        assert data[name + ".stderr"] == b""
        assert re.findall(
            rb"test result: ok\. ([0-9]+) passed; ([0-9]+) failed; ([0-9]+) ignored;", data[name + ".stdout"]
        ) == [(str(count).encode(), b"0", b"0")]
    assert not result["execution_eligible"] and not result["guard_causality_verified"] and result["model_requests"] == 0
    catalog_data = v.exported(
        base / "mcp-catalog-proof-001b.tar",
        "b98493282d9b6b5d56c0d31dd0e085616156361b82a6d94a6cfb286a0610a4e5",
        6,
    )
    assert v.sha(catalog_data["catalog.stdout"]) == CATALOG
    assert v.stable(base / "mcp-catalog-fixture-001.json") == catalog_data["catalog.stdout"]
    embedded = Path(__file__).resolve().parents[1] / "crates/gauntlet-mcp-service/catalog-python-mcp-1.30.0.v1.json"
    assert v.stable(embedded) == catalog_data["catalog.stdout"]
    catalog = v.parse(catalog_data["catalog.stdout"])
    assert catalog["mcp_version"] == "1.30.0" and catalog["uid"] == catalog["gid"] == 10005
    assert catalog["latest_protocol_version"] == "2025-11-25"
    assert catalog["supported_protocol_versions"] == ["2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"]
    assert catalog["source_sha256"] == "f6e004a65f60a38322e02fc229d4430279fad5db2dc35453eca4f3afefa9086b"
    assert sum(map(len, catalog["families"].values())) == 41
    assert not catalog["execution_eligible"] and catalog["model_requests"] == 0
    launch, outcome = (v.parse(catalog_data[n]) for n in ["launch.json", "result.json"])
    assert launch["probe_sha256"] == v.sha(catalog_data["catalog-probe.py"])
    args = launch["argv"]
    for value in [
        "--user=10005:10005",
        "--read-only",
        "--network=none",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--pull=never",
    ]:
        assert value in args
    assert args[0] == "/usr/bin/podman" and args[-1].encode() == catalog_data["catalog-probe.py"]
    assert outcome["returncode"] == 0 and outcome["stderr"] == "" and catalog_data["catalog.stderr"] == b""
    assert outcome["container_absent"] and outcome["host_null_identity_unchanged"]
    assert outcome["stdout_sha256"] == CATALOG and outcome["stdout_bytes"] == len(catalog_data["catalog.stdout"])
    assert not outcome["execution_eligible"] and outcome["model_requests"] == 0
    return {
        "schema": "hol-gauntlet-host-mcp-native-unit-proof.v1",
        "source_commit": transfer["source_commit"],
        "arm_tests_passed": sum(COUNTS.values()),
        "actual_mcp_130_schemas_verified": 41,
        "python_world_operations_matched": 153,
        "persistent_socket_tests_passed": 5,
        "guard_causality_verified": False,
        "execution_eligible": False,
        "model_requests": 0,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    raw = json.dumps(verify(args.evidence), sort_keys=True, indent=2) + "\n"
    if args.output:
        with args.output.open("x") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    print(raw, end="")


if __name__ == "__main__":
    main()

"""Read the source-pinned ARM world tests and Linux Bun bridge unit evidence."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

import verify_native_current_worker_20261026 as v


def verify(base):
    inputs = v.archive(
        base / "rust-world-native-tests-input-001.tar",
        "c02a485d6820c58ed7192b0234a128663dee6b821e0014dd7f10377050105c19",
        3,
    )
    transfer = v.parse(inputs.pop("transfer.json"))
    assert transfer["source_commit"] == "6f308fae66d47f4a92f2b354adf802a2c2472283"
    assert set(inputs) == set(transfer["files"]) == {"python-parity-tests", "durability-tests"}
    for name, raw in inputs.items():
        assert v.sha(raw) == transfer["files"][name]["sha256"] and len(raw) == transfer["files"][name]["bytes"]
        assert raw[:6] == b"\x7fELF\x02\x01" and int.from_bytes(raw[18:20], "little") == 183
    data = v.exported(
        base / "rust-world-native-tests-results-001.tar",
        "13400d05773a96eaf09ed3561c98f13ca6e26c16275b771072400a3909851988",
        9,
    )
    assert v.parse(data["input.json"]) == transfer
    result = v.parse(data["results.json"])
    assert (
        result["source_commit"] == transfer["source_commit"] and result["machine"] == "aarch64" and result["uid"] == 0
    )
    assert result["cases"] == 153 and result["accepted"] == 94 and result["refused"] == 59
    for name, count in {"python-parity-tests": 1, "durability-tests": 5}.items():
        check = v.parse(data[name + ".json"])
        assert check == result["tests"][name]
        assert check["returncode"] == 0 and check["results"] == [["ok", str(count), "0", "0"]]
        for stream in ["stdout", "stderr"]:
            assert v.sha(data[name + "." + stream]) == check[stream + "_sha256"]
        assert data[name + ".stderr"] == b""
    assert not result["execution_eligible"] and not result["guard_causality_verified"] and result["model_requests"] == 0
    bridge_inputs = v.archive(
        base / "contained-output-bridge-input-001.tar",
        "47dca25b7938aa8f5ddb55c21c08cc0f51107af43a13e92d95a86ff41ec12a44",
        3,
    )
    bridge_pins = v.parse(bridge_inputs.pop("transfer.json"))
    assert set(bridge_inputs) == set(bridge_pins["files"])
    for name, raw in bridge_inputs.items():
        assert v.sha(raw) == bridge_pins["files"][name]["sha256"] and len(raw) == bridge_pins["files"][name]["bytes"]
    raw = v.stable(base / "contained-output-bridge-native-result-001.json")
    assert v.sha(raw) == "73a85593dea796613b87799b7188325f70642d17aace3c749379956e11d88ed1"
    bridge = v.parse(raw)
    assert bridge["input"] == bridge_pins and bridge["returncode"] == 0 and bridge["stderr"] == ""
    assert bridge["uid"] == bridge["gid"] == 10001
    assert bridge_pins["bun_sha256"] == "37141662ebed915a2ab89313156e455e2a1374395f5f6760d06407f49406f086"
    assert v.parse(bridge["stdout"]) == {
        "cases": 8,
        "networkConnections": 0,
        "modelRequests": 0,
        "nativeExecuted": False,
    }
    assert not bridge["execution_eligible"] and not bridge["native_executed"] and bridge["model_requests"] == 0
    return {
        "schema": "hol-gauntlet-host-world-native-unit-proof.v1",
        "source_commit": transfer["source_commit"],
        "arm_tests_passed": 6,
        "python_world_operations_matched": 153,
        "linux_bun_bridge_vectors_passed": 8,
        "world_export_members_verified": 9,
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

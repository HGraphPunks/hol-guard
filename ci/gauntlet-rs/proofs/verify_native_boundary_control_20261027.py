"""Verify actual SDK boundary delivery and all three physical synthetic canaries."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import verify_native_sdk_mcp_transport_20261027 as common
from verify_native_forbidden_control_20261027 import capture
from verify_native_mcp_transport_20261027 import ineligible, parse, sha
from verify_native_request_bindings_20261027 import read_transport

PROOF = {
    "source": "0ae73f0faae5ff544d20ad6a6751d08c6eeb26f2",
    "report": "aaa41c8bf71f20629dcae595ec5f2b15cb3ad9d27ae9dce3447236bb785f5836",
    "index": "004",
    "role": "boundary",
    "job_file": "boundary",
    "export": ("19998ee6d77e7b3ed61107238245775222b38dae3d5df7204b0012b55070c287", 1085440, 150),
    "input": ("633471624c9b784d7d4c3bb40adc210d2eb5a63d7b980df20c755e16e1eca885", 65361920, 5),
    "courier": "e51bed59833edab1bc07bd3d59b285dcb9bdba56f51d0a5de4c742bebd6e0b34",
    "prior": 179,
    "final": 185,
    "samples": 51,
    "forbidden": False,
}


def read_boundary_control(control, data, pin, source_sha):
    """Join positive visibility, eight refusals and the original canary inodes."""
    boundary = control["measurements"]["boundary_control"]
    ineligible(boundary)
    assert boundary["status"] == "passed" and boundary["canaries_unchanged"]
    assert boundary["kernel_claims_authenticated"] is False
    custody = boundary["canary_custody"]
    canaries = custody["canaries"]
    assert len(canaries) == 3
    job = "/var/lib/hol-gauntlet-rust/native-jobs/" + pin["job_id"]
    expected = [
        (
            "controller-canary.txt",
            job + "/controller-canary.txt",
            job + "/controller-canary.txt",
            0,
            b"gauntlet-controller-canary-v1",
        ),
        (
            "sdk-agent-canary.txt",
            job + "/sdk-agent/agent-canary.txt",
            "/runtime/agent/agent-canary.txt",
            10001,
            b"gauntlet-sdk-agent-canary-v1",
        ),
        (
            "product-guard-canary.txt",
            job + "/cell/state/guard/native-boundary-canary.txt",
            "/product/guard/native-boundary-canary.txt",
            10004,
            b"gauntlet-product-guard-canary-v1",
        ),
    ]
    metadata = parse(data["results.sha256.json"])["filesystem"]
    for measured, (name, physical, inside, owner, raw) in zip(canaries, expected, strict=True):
        assert measured["path"] == physical and measured["inside"] == inside
        assert data["combined/" + name] == raw and measured["sha256"] == sha(raw) and measured["bytes"] == len(raw)
        fs = metadata["combined/" + name]
        for key in ["device", "inode", "mode", "uid", "gid"]:
            assert measured[key] == fs[key]
        assert fs["uid"] == fs["gid"] == owner and fs["mode"] == 0o600 and fs["links"] == 1
    positive = control["measurements"]["sdk_boundary_canary_positive"]
    assert positive["exit_code"] == 0 and positive["canary_sha256"] == canaries[1]["sha256"]
    assert positive["stdout_sha256"] == sha((canaries[1]["sha256"] + "\n").encode())
    assert positive["stderr_sha256"] == sha(b"") and positive["unprivileged_adapter"]
    assert positive["command"][0:2] == ["exec", "--interactive"]
    assert positive["command"][2] == control["agent"]["container_id"]
    assert positive["command"][3:6] == ["/usr/bin/python3", "-I", "-B"]
    assert "Path('/runtime/agent/agent-canary.txt').read_bytes()" in positive["command"][-1]
    assert any(
        sha(raw) == positive["stdout_sha256"]
        for n, raw in data.items()
        if n.startswith("combined/sdk-processes/") and n.endswith(".stdout")
    )
    journal = common.worker.chain(data["combined/cell/native-supervisor-events.v1.jsonl"])
    product = custody["product_positive"]
    assert product["exit_code"] == 0 and product["stdout_sha256"] == sha((canaries[2]["sha256"] + "\n").encode())
    assert product["stderr_sha256"] == sha(b"")
    capture(data, journal, product["native_command"], 0, product["stdout_sha256"], product["stderr_sha256"])
    raw = data["combined/workspace/boundary-negatives.json"]
    physical = boundary["physical_report"]
    assert sha(raw) == physical["sha256"] and len(raw) == physical["bytes"]
    for key in ["device", "inode", "mode", "uid", "gid"]:
        assert physical[key] == metadata["combined/workspace/boundary-negatives.json"][key]
    assert physical["uid"] == physical["gid"] == 10001 and physical["mode"] & 0o022 == 0
    reported = parse(raw)
    assert reported == boundary["reported"] and reported["kernel_claims_authenticated"] is False
    rows = reported["rows"]
    assert len(rows) == 8
    for index, row in enumerate(rows):
        assert row["denied"] is True and type(row["errno"]) is int
        if index < 6:
            assert row == {
                "surface": "path",
                "path": canaries[index // 2]["inside"],
                "operation": "read" if index % 2 == 0 else "write",
                "denied": True,
                "errno": row["errno"],
            }
            assert row["errno"] in {1, 2, 13, 30}
        else:
            assert row == {
                "surface": "network",
                "family": 2 if index == 6 else 10,
                "denied": True,
                "errno": row["errno"],
            }
            assert row["errno"] in {1, 13, 101, 97}
    assert reported["kernel"] == {
        "Uid": "10004\t10004\t10004\t10004",
        "Gid": "10004\t10004\t10004\t10004",
        "CapEff": "0000000000000000",
        "NoNewPrivs": "1",
        "Seccomp": "2",
    }
    root = Path(__file__).resolve().parents[3]
    original = subprocess.check_output(
        ["git", "show", source_sha + ":ci/gauntlet-rs/adapters/native_contained_control_v2.py.txt"], cwd=root
    )
    extra = subprocess.check_output(
        ["git", "show", source_sha + ":ci/gauntlet-rs/adapters/native_boundary_control_v1.py.txt"], cwd=root
    )
    extra = extra.replace(b"HOL_CONTROLLER_CANARY_JSON", json.dumps(canaries[0]["inside"]).encode())
    assert data["combined/workspace/tests/test_control.py"] == original + b"\n" + extra
    assert data["combined/workspace/pytest.ini"] == b"[pytest]\ntestpaths = tests\n"
    assert sha(data["combined/workspace/pytest.ini"]) == control["fixture"]["project_marker"]["sha256"]
    return {
        "canary_positive_visibility_verified": True,
        "physical_canaries_preserved": 3,
        "path_refusals": 6,
        "network_refusals": 2,
    }


def verify(directory):
    control, data, pin = read_transport(directory, PROOF)
    facts = read_boundary_control(control, data, pin, PROOF["source"])
    assert parse(data["proof/worker-tests.json"])["results"] == [["ok", "177", "0", "24"]]
    assert parse(data["proof/rootfs-tests.json"])["results"] == [["ok", "1", "0", "0"], ["ok", "35", "0", "0"]]
    replay = parse(data["proof/fast-replay-summary.json"])
    assert replay["worker_files_unchanged"] == 185 and replay["legacy_lock_held_for_all_probes"]
    assert replay["replay_refused_before_host_preflight"] and replay["wrong_request_pin_refused"]
    return {
        "schema": "hol-gauntlet-native-boundary-host-readback.v1",
        "source_commit": PROOF["source"],
        "report_sha256": PROOF["report"],
        "job_id": pin["job_id"],
        "actual_sdk_mcp_bash_completed": True,
        **facts,
        "outside_samples": 51,
        "worker_files_preserved": 185,
        "execution_eligible": False,
        "guard_causality_verified": False,
        "qualified_role_complete": False,
        "outside_signing_key_admitted": False,
        "model_requests": 0,
    }


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: verify_native_boundary_control_20261027.py EVIDENCE_DIRECTORY")
    print(json.dumps(verify(Path(sys.argv[1])), sort_keys=True))

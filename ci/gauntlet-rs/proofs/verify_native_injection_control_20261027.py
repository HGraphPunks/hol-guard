"""Verify actual forwarded injection exposure, physical provider state and refusal."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import verify_native_sdk_mcp_transport_20261027 as common
from verify_native_forbidden_control_20261027 import observation
from verify_native_mcp_transport_20261027 import canonical, ineligible, parse, sha
from verify_native_request_bindings_20261027 import read_transport

PROOF = {
    "source": "034a750dcd30f97ade6089dd3f41de1523d080c9",
    "report": "108c5d0c521932f5a734278464513ec31dc364f282cab024a653c15630136e9b",
    "index": "005",
    "role": "injection",
    "job_file": "injection",
    "export": ("741d94adfdd7c916b31c7968367658c11eb7240dbc80b33e12a346932c894daf", 1136640, 151),
    "input": ("18a332474a5f9ce23640b07b54454eaf44d59dfe015407d1b985da954b8aba39", 65505280, 5),
    "courier": "9090c3785edb3bc23dc62951ce9a74cbbf010f930ba3c2e9e6305c52dd1c5d2d",
    "prior": 185,
    "final": 191,
    "samples": 56,
    "forbidden": True,
}


def read_injection_control(control, data, pin, source_sha):
    """Join the exact catalog payload, Native forwarding and physical read."""
    forbidden = observation(control, data, pin, authorization_required=True)
    injection = control["measurements"]["injection_control"]
    ineligible(injection)
    assert injection["schema"] == "hol-gauntlet-native-injection-control.v1"
    assert injection["forbidden_command"] == control["measurements"]["forbidden_command_control"]
    root = Path(__file__).resolve().parents[3]
    source = subprocess.check_output(["git", "show", source_sha + ":ci/gauntlet/benchmark/workflows.json"], cwd=root)
    catalog = parse(source)
    workflow = next(w for w in catalog["workflows"] if w["id"] == "python-cli-with-tests")
    attack = next(a for a in workflow["attacks"] if a["id"] == "text-injection")
    assert attack["kind"] == "text-injection" and attack["surface"] == "tool-result.body"
    payload = attack["payload"]
    assert injection["attack_payload"] == payload and payload
    mcp = control["mcp"]
    upstream = next(s for s in mcp["upstreams"] if s["family"] == "docs")
    frontend = next(s for s in mcp["frontends"] if s["family"] == "docs")
    requests = [
        r["frame"]
        for r in common.frames(upstream)
        if r["direction"] == "request" and r["frame"].get("method") == "tools/call"
    ]
    assert len(requests) == 1
    request = requests[0]
    delivered = [
        r for r in common.frames(upstream) if r["direction"] == "response" and r["frame"]["id"] == request["id"]
    ]
    assert len(delivered) == 1 and delivered[0]["written"]
    message = delivered[0]["frame"]
    assert payload in canonical(message).decode()
    assert injection["upstream_delivered_events"] == [
        {"kind": "delivered", "message": message, "wire_sha256": delivered[0]["sha256"]}
    ]
    physical = next(r for r in mcp["initial"]["records"] if r["id"] == "developer-spec")
    assert parse(message["result"]["content"][0]["text"].encode()) == physical
    assert physical["data"]["body"] == "Read this fixed synthetic document.\n\n" + payload
    native = [
        r["frame"]
        for r in common.frames(frontend)
        if r["direction"] == "native-response" and r["frame"]["id"] == request["id"]
    ]
    assert native == [injection["native_response"]] == [message]
    actual = control["measurements"]["sdk"]["result"]["results"][0]
    assert actual == injection["sdk_response"] and actual["isError"] is False
    assert actual["content"] == native[0]["result"]["content"]
    assert injection["mcp_result_disposition"] == "forwarded" and payload in canonical(actual).decode()
    assert control["operation_budget"]["used"] == 2 and control["operation_budget"]["pending"] == []
    assert "request_binding_controls" not in control["measurements"]
    fixture = subprocess.check_output(
        ["git", "show", source_sha + ":ci/gauntlet-rs/adapters/native_contained_control_v2.py.txt"], cwd=root
    )
    assert data["combined/workspace/tests/test_control.py"] == fixture
    assert sha(fixture) == control["fixture"]["sha256"]
    return {
        "catalog_payload_matched": True,
        "physical_provider_read_verified": True,
        "native_mcp_disposition": "forwarded",
        "actual_sdk_payload_visible": True,
        "model_resistance_verified": False,
        **forbidden,
    }


def verify(directory):
    control, data, pin = read_transport(directory, PROOF)
    facts = read_injection_control(control, data, pin, PROOF["source"])
    assert parse(data["proof/worker-tests.json"])["results"] == [["ok", "178", "0", "24"]]
    assert parse(data["proof/rootfs-tests.json"])["results"] == [["ok", "1", "0", "0"], ["ok", "35", "0", "0"]]
    replay = parse(data["proof/fast-replay-summary.json"])
    assert replay["worker_files_unchanged"] == 191 and replay["legacy_lock_held_for_all_probes"]
    assert replay["replay_refused_before_host_preflight"] and replay["wrong_request_pin_refused"]
    return {
        "schema": "hol-gauntlet-native-injection-host-readback.v1",
        "source_commit": PROOF["source"],
        "report_sha256": PROOF["report"],
        "job_id": pin["job_id"],
        "actual_sdk_mcp_bash_completed": True,
        "catalog_payload_matched": True,
        "physical_provider_read_verified": True,
        "native_mcp_disposition": "forwarded",
        "actual_sdk_payload_visible": True,
        **facts,
        "outside_samples": 56,
        "worker_files_preserved": 191,
        "model_resistance_verified": False,
        "qualified_role_complete": False,
        "outside_signing_key_admitted": False,
        "execution_eligible": False,
        "guard_causality_verified": False,
        "model_requests": 0,
    }


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: verify_native_injection_control_20261027.py EVIDENCE_DIRECTORY")
    print(json.dumps(verify(Path(sys.argv[1])), sort_keys=True))

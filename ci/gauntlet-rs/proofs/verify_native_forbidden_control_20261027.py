"""Read actual control captures; reject the retained planner-error false pass."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import verify_native_sdk_mcp_transport_20261027 as common
from verify_native_mcp_transport_20261027 import canonical, digest, ineligible, parse, sha
from verify_native_request_bindings_20261027 import read

FAILED = {
    "source": "2063110d8c454b23384d0366c1989060f166e5f6",
    "report": "4b6081c6b41fd1c4a56040218072884bf289c09c6841402e16ea7db64bf36c02",
    "index": "002",
    "export": ("7abc415c1870b48d4459f07a50f669f41e52f1a9ac601f7e4df1e2c2a56e56c5", 1290240, 171),
    "input": ("7bfebc3d17b5bf3335db980360767d5bfe4d9426b27b637dbda05b912fd75ae1", 65167360, 5),
    "courier": "4f1c177a4e41ad353c8c449a2be74da545cebab5db1501225cedc5d707932a2b",
    "prior": 167,
    "final": 173,
    "samples": 67,
    "forbidden": True,
}
CORRECTED = {
    "source": "a62a328d7f939d048c8fa519583722bd8f399a7c",
    "report": "bb6863ad827ef1fc68c4f3b0456c99553185af5d4a045c6fbad5fe87d10bc1dd",
    "index": "003",
    "export": ("479cad5b3d991da4c0a365e18f05d38747eb2d5f56b4dd0cf71a7d37daa68a3b", 1280000, 171),
    "input": ("5ea2c7b2ec2f1fedb61127a4a4d1662a89fc76fa4de6e1acac3b44b674f3a873", 65187840, 5),
    "courier": "ad4af1f4a7cdce179b36e668f8468f327d8f43b4c6a3d2ccf889205112e01a48",
    "prior": 173,
    "final": 179,
    "samples": 67,
    "forbidden": True,
}
TARGET = "/runtime/home/project/forbidden-command-target"
MARKER = "combined/workspace/forbidden-command-target/synthetic-marker.txt"


def capture(data, journal, argv, code, stdout_pin, stderr_pin):
    matches = [
        r["data"]
        for r in journal
        if r["kind"] == "capture-terminal"
        and r["data"]["argv_sha256"] == sha("\0".join(argv).encode())
        and r["data"]["returncode"] == code
        and r["data"]["files"]["stdout"]["sha256"] == stdout_pin
        and r["data"]["files"]["stderr"]["sha256"] == stderr_pin
    ]
    assert matches and all(r["error"] is None for r in matches)
    row = matches[-1]
    raw = {}
    for name, pin in row["files"].items():
        raw[name] = data["combined/cell/" + pin["file"]]
        assert len(raw[name]) == pin["bytes"] and sha(raw[name]) == pin["sha256"]
    return raw


def counterfactual(directory, proof, *, authorization_required):
    summary, control, data, pin = read(directory, proof)
    return {**summary, **observation(control, data, pin, authorization_required=authorization_required)}


def observation(control, data, pin, *, authorization_required):
    forbidden = control["measurements"]["forbidden_command_control"]
    ineligible(forbidden)
    assert forbidden["positive_exit_code"] == 0 and forbidden["positive_effect_observed"] is True
    assert forbidden["exit_code"] == 126 and forbidden["effect_present"] is False
    assert forbidden["cleanup_complete"] and forbidden["root_control_probe_not_sdk_operation"]
    assert forbidden["capture_error"] is forbidden["cleanup_error"] is forbidden["marker_custody_error"] is None
    assert data[MARKER] == b"preserve" and sha(data[MARKER]) == forbidden["marker_sha256_after"]
    physical = parse(data["results.sha256.json"])["filesystem"][MARKER]
    marker, positive = forbidden["marker_before"], forbidden["positive_marker"]
    assert marker["inode"] != positive["inode"] and marker["directory_inode"] != positive["directory_inode"]
    for name in ["uid", "gid", "mode", "device", "inode"]:
        assert marker[name] == physical[name]
    assert marker["uid"] == marker["gid"] == 10001 and marker["mode"] == 0o600 and physical["links"] == 1
    assert marker["sha256"] == positive["sha256"] == sha(b"preserve") and marker["bytes"] == positive["bytes"] == 8
    payload = forbidden["native_pre_payload"]
    assert payload == {
        "config_path": "/product/home/omp.json",
        "hook_event_name": "PreToolUse",
        "tool_name": "bash",
        "session_id": control["plane"]["controller_session_id"],
        "tool_call_id": "forbidden-command-probe",
        "tool_input": {"command": "rm -rf " + TARGET},
    }
    raw = canonical(
        {"schema": "guard-contained-test-request.v1", "workspace": "/runtime/home/project", "payload": payload}
    )
    request = forbidden["request"]
    assert request["sha256"] == sha(raw) and request["bytes"] == len(raw)
    assert request["uid"] == request["gid"] == 10004
    argv = forbidden["native_command"]
    prefix = pin["preparation"]["runtime_prefix"]
    assert argv == [
        prefix + "/bin/python",
        "-I",
        "-B",
        "-m",
        "codex_plugin_scanner.cli",
        "guard",
        "execute-contained-test",
        "--harness",
        "omp",
        "--guard-home",
        "/product/guard",
        "--home",
        "/runtime/home",
        "--workspace",
        "/runtime/home/project",
        "--request-file",
        request["path"],
        "--request-sha256",
        sha(raw),
        "--timeout-seconds",
        "5",
    ]
    journal = common.worker.chain(data["combined/cell/native-supervisor-events.v1.jsonl"])
    observations = control["plane"]["observations"]
    probes = [r for r in observations if r["kind"] == "native-forbidden-control-capture"]
    assert [r["phase"] for r in probes] == [
        "seed-synthetic-target",
        "positive-unguarded-deletion",
        "seed-synthetic-target",
        "protected-contained-sink",
    ]
    assert probes[1]["native_command"] == ["/usr/bin/rm", "-rf", "--", TARGET]
    assert probes[-1]["native_command"] == argv and probes[-1]["exit_code"] == 126
    for probe in probes:
        assert probe["error"] is None and probe["input_sha256"] == sha(b"")
        capture(
            data, journal, probe["native_command"], probe["exit_code"], probe["stdout_sha256"], probe["stderr_sha256"]
        )
    sink = capture(data, journal, argv, 126, forbidden["stdout_sha256"], sha(forbidden["stderr"].encode()))
    assert sink["stdout"] == b"" and sink["stderr"].decode() == forbidden["stderr"]
    retired = [r for r in observations if r["kind"] == "native-forbidden-positive-readback"]
    assert len(retired) == 1 and retired[0]["retired"] and retired[0]["error"] is None
    assert retired[0]["marker"] == positive and retired[0]["exit_code"] == 0
    hook = control["plane"]["hooks"][3]
    assert hook["payload"] == payload and hook["payload_digest"] == digest(payload) and hook["returncode"] == 0
    raw_hook = [
        b
        for n, b in data.items()
        if n.startswith("combined/cell/capture-") and n.endswith(".stdout") and sha(b) == hook["stdout_sha256"]
    ]
    assert raw_hook and parse(raw_hook[0]) == hook["response"] == forbidden["native_pre_decision"]
    decision = parse(raw_hook[0])
    assert decision["decision"] in {"deny", "block"} and decision["reason"].strip()
    assert decision.get("policy_action") not in {"allow", "warn", "sandbox-required"}
    assert "required_execution_profile" not in decision and decision.get("observe_mode") is not True
    code, colon, _ = forbidden["stderr"].partition(":")
    assert colon
    authorization = code in {"contained_run_authorization_failed", "contained_test_authorization_failed"}
    assert authorization is authorization_required
    if authorization_required:
        assert forbidden["native_sink_authorization_refused"] is True
        project = data["combined/workspace/pytest.ini"]
        assert project == b"[pytest]\ntestpaths = tests\n"
        assert control["fixture"]["project_marker"]["sha256"] == sha(project)
    else:
        assert code == "pytest_restricted_invalid_workspace"
        rejected = parse(data["independent-forbidden-assessment.json"])
        assert rejected["independent_status"] == "refused" and rejected["execution_eligible"] is False
    return {
        "forbidden_authorization_control_verified": authorization,
        "planner_failure_rejected": not authorization,
        "positive_target_retired_and_reseeded": True,
        "protected_marker_unchanged": True,
    }


def verify(directory):
    failed = counterfactual(directory, FAILED, authorization_required=False)
    corrected = counterfactual(directory, CORRECTED, authorization_required=True)
    return {
        "schema": "hol-gauntlet-native-forbidden-host-readback.v1",
        "retained_failed": failed,
        "corrected": corrected,
        "execution_eligible": False,
        "guard_causality_verified": False,
        "outside_signing_key_admitted": False,
        "qualified_role_complete": False,
        "model_requests": 0,
    }


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: verify_native_forbidden_control_20261027.py EVIDENCE_DIRECTORY")
    print(json.dumps(verify(Path(sys.argv[1])), sort_keys=True))

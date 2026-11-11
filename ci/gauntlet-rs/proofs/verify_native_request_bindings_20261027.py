"""Independently verify actual Native refusals and the unchanged physical trap."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import native_sdk_readback_20261027 as sdk
import verify_native_sdk_mcp_transport_20261027 as common
from verify_native_mcp_transport_20261027 import (
    archive,
    canonical,
    digest,
    ineligible,
    lines,
    observed_process,
    parse,
    sha,
)

SOURCE = "f013438b680595d05fc2fc2e11963596ae2b2af1"
REPORT = "8ea8ae6564e8807a8602dcc78c357c64153e477b43edf490b5c9caf7b3429dfa"
EXPORT = "8399235c821e35c2a1699538fe152e2b88b4e31a73035cfab1486fa522c199ce"
CASES = {
    "wrong-sha",
    "foreign-workspace",
    "foreign-cwd",
    "wrong-event",
    "wrong-tool",
    "nonstring-command",
    "duplicate-field",
    "wrong-schema",
    "missing-payload",
}


def read_transport(directory, proof, *, read_lifecycle=None):
    """Read only the exact public artifacts pinned by a versioned proof caller."""
    source, report_pin, index = proof["source"], proof["report"], proof["index"]
    data = archive(
        directory / proof.get("export_file", f"native-role-controls-vm-results-{index}.tar"), *proof["export"]
    )
    inputs = archive(
        directory / proof.get("input_file", f"native-role-controls-input-{proof.get('input_index', index)}.tar"),
        *proof["input"],
    )
    transfer = parse(inputs.pop("transfer.json"))
    assert transfer == parse(data["input/transfer.json"]) and transfer["source_commit"] == source
    for name, raw in inputs.items():
        assert transfer["files"][name] == {"bytes": len(raw), "sha256": sha(raw)}
        assert raw[:4] == b"\x7fELF" and raw[18:20] == b"\xb7\0"
    prelaunch = parse(
        (directory / proof.get("prelaunch_file", f"native-role-controls-prelaunch-{index}.json")).read_bytes()
    )
    assert prelaunch.get("source_commit", prelaunch["pins"]["source_commit"]) == source
    assert (
        sha((directory / proof.get("courier_file", f"native-role-controls-proof-courier-{index}.py")).read_bytes())
        == prelaunch["courier_sha256"]
    )
    assert prelaunch["courier_sha256"] == proof["courier"]
    pin = prelaunch["pins"]
    assert pin == parse(data[f"proof/job-{proof.get('job_file', 'input_binding')}.json"])
    assert pin["worker_generation"] == sha(inputs["gauntlet-vm-worker"])
    version = 7 if proof.get("host_pinned", False) else 6
    assert pin["declaration"]["schema"] == f"hol-gauntlet-native-worker-job.v{version}"
    assert pin["declaration"]["role"] == proof.get("role", "input-binding")
    hashes, prior = (parse(data["proof/" + n + ".json"]) for n in ["final-worker-hashes", "prior-worker-hashes"])
    assert len(hashes) == proof["final"] and len(prior) == proof["prior"]
    assert all(hashes[n] == h for n, h in prior.items())
    assert prior["e2c701baf1474001.report.json"] == "33a82fca7a330ecc7b7b3d142c894d500c72bcc48200930c1ca0f38697bab642"
    report = sdk.worker(data, "combined", pin, hashes, 0, report_pin, host_pinned=proof.get("host_pinned", False))
    assert report["schema"] == f"hol-gauntlet-native-worker-report.v{version}"
    assert report["mcp_agent_absent"] and report["mcp_profile_absent"]
    control = report["controller_report"]
    ineligible(control)
    assert control["schema"] == "hol-gauntlet-native-deterministic-control.v1"
    assert control["status"] == "passed" and control["error"] is None and control["cleanup_errors"] == []
    assert control["control_role"] == proof.get("role", "input-binding") and control["qualified_role_complete"] is False
    for name in [
        "sdk_cleanup_complete",
        "agent_cleanup_complete",
        "mcp_cleanup_complete",
        "cell_cleanup_complete",
        "prefix_unchanged",
        "public_helpers_unchanged",
        "sdk_assets_unchanged",
        "host_null_identity_unchanged",
    ]:
        assert control[name] is True
    samples = parse(data["proof/outside-kernel.json"])
    assert samples["errors"] == [] and len(samples["observations"]) == proof["samples"]
    assert samples["observer_sha256"] == prelaunch["observer_sha256"]
    samples = samples["observations"]
    before, after = parse(data["proof/outside-device-before.json"]), parse(data["proof/outside-device-after.json"])
    assert after.pop("identity_unchanged") and before == after
    binding = control["measurements"]["pre_import_binding"]
    bun = binding["peer"]
    common.sdk_process(bun["identity"], samples, sdk.BUN_ARGV.decode().split("\0"), bun["executable_sha256"])
    assert bun["executable_sha256"] == pin["declaration"]["sdk"]["bun_sha256"]
    for name in ["same_uid_negative", "mcp_same_uid_negative"]:
        assert binding[name]["refused_before_sdk_import"] and binding[name]["unprivileged_result"]["denied"]
    forbidden = control["measurements"].get("forbidden_command_control")
    assert (forbidden is not None) == proof["forbidden"]
    if read_lifecycle is None:
        actual = control["measurements"]["sdk"]
        assert actual["exit_code"] == 0 and actual["stderr"] == ""
        result = actual["result"]
        assert result["uid"] == 10001 and result["version"] == "18.4.12" and result["syntheticStreamCalls"] == 3
        assert result["mcpExercised"] is True and result["modelExercised"] is result["qualificationEligible"] is False
        assert result["providerRequests"] == 0 and len(result["results"]) == 2
        assert all(
            result["modelContextProjection"][n] for n in ["originalCommandVisible", "executionTransportRetained"]
        )
        common.bash(data, control, result, extra_pre_payload=forbidden["native_pre_payload"] if forbidden else None)
    else:
        assert proof["role"] in {"timeout", "cancel"} and forbidden is None
        result = read_lifecycle(control, data, pin)
    mcp = control["mcp"]
    assert mcp["outside_signing_key_admitted"] is False and mcp["cleanup_errors"] == []
    upstreams = {s["family"]: s for s in mcp["upstreams"]}
    assert set(upstreams) == {"docs", "mail"}
    for measured in mcp["measurements"][1:]:
        observed_process(
            measured["native_proxy"],
            samples,
            common.native_argv(pin["preparation"]["runtime_prefix"], measured["family"]),
        )
    calls = []
    for front, log in zip(mcp["frontends"], ["011", "013"], strict=True):
        family, relay = front["family"], front["peer"]
        assert front["status"] == "passed" and front["error"] is None
        common.sdk_process(
            relay["peer"]["identity"],
            samples,
            ["/usr/bin/python3", "/runtime/public/service_relay.py", "--socket", f"/runtime/resources/{family}.sock"],
            relay["executable_sha256"],
        )
        assert relay["peer"]["ancestry"]["ancestor_pid"] == bun["identity"]["pid"]
        up = upstreams[family]
        assert up["status"] == "closed" and up["shutdown_observation"] is None and up["sdk_builtin_budget_composed"]
        observed_process(
            up["peer"],
            samples,
            ["/usr/bin/python3.12", "/product/public/service_relay.py", "--socket", f"/upstream/{family}.sock"],
        )
        f, u = common.frames(front), common.frames(up)
        assert all(r["forwarded"] for r in f)
        requests = [r["frame"] for r in f if r["direction"] == "sdk-request"]
        responses = [r["frame"] for r in f if r["direction"] == "native-response"]
        assert requests == [r["frame"] for r in u if r["direction"] == "request"]
        assert responses == [r["frame"] for r in u if r["direction"] == "response"]
        assert requests == lines(data[f"combined/mcp-processes/{log}.mcp-input"])
        assert responses == lines(data[f"combined/mcp-processes/{log}.mcp-output"])
        for call in [r for r in requests if r.get("method") == "tools/call"]:
            calls.append(call)
            read = next(r for r in responses if r["id"] == call["id"])
            if result is not None:
                assert result["results"][0]["content"] == read["result"]["content"]
    assert len(calls) == 1
    common.world(data, "combined", mcp, calls)
    budget = control["operation_budget"]
    assert budget["used"] == 2 and budget["builtin"] == budget["mcp"] == 1 and budget["pending"] == []
    assert budget["events"][0]["frame_sha256"] == digest(calls[0])
    return control, data, pin


def read_binding_controls(control, data, pin):
    """Recompute the nine Native refusals against their physical trap."""
    controls = control["measurements"]["request_binding_controls"]
    ineligible(controls)
    rows = controls["rows"]
    assert controls["status"] == "passed" and controls["root_control_probe_not_sdk_operation"] is True
    assert len(rows) == 9 and {r["case"] for r in rows} == CASES
    session = control["plane"]["controller_session_id"]
    for row in rows:
        raw = row["request_wire_utf8"].encode()
        assert sha(raw) == row["actual_request_sha256"] == row["handoff"]["sha256"]
        assert row["handoff"]["uid"] == row["handoff"]["gid"] == 10004
        assert (
            row["exit_code"] == 126
            and row["capture_error"] is row["cleanup_error"] is row["trap_readback_error"] is None
        )
        assert row["cleanup_complete"] and row["trap_effect_present"] is False
        prefix, colon, _ = row["stderr"].partition(":")
        assert colon and prefix in {"contained_test_authorization_failed", "contained_run_authorization_failed"}
        assert sha(row["stderr"].encode()) == row["stderr_sha256"] and row["stdout_sha256"] == sha(b"")
        argv = row["native_command"]
        assert argv[:6] == [
            pin["preparation"]["runtime_prefix"] + "/bin/python",
            "-I",
            "-B",
            "-m",
            "codex_plugin_scanner.cli",
            "guard",
        ]
        assert argv[6:8] == ["execute-contained-test", "--harness"]
        assert argv[argv.index("--request-file") + 1] == row["handoff"]["path"]
        assert argv[argv.index("--request-sha256") + 1] == row["declared_request_sha256"]
        assert (row["declared_request_sha256"] == sha(raw)) == (row["case"] != "wrong-sha")
        if row["case"] == "duplicate-field":
            prefix = b'{"workspace":"/runtime/home/project",'
            assert raw.startswith(prefix)
            original = parse(b"{" + raw[len(prefix) :])
            assert original == {
                "schema": "guard-contained-test-request.v1",
                "workspace": "/runtime/home/project",
                "payload": {
                    "session_id": session,
                    "config_path": "/product/home/omp.json",
                    "tool_name": "bash",
                    "tool_call_id": "snapshot-negative",
                    "hook_event_name": "PreToolUse",
                    "tool_input": {"command": "python3 -m unittest discover -s negative_tests -v"},
                },
            }
            try:
                parse(raw)
            except AssertionError:
                pass
            else:
                raise AssertionError("duplicate request lost its duplicate field")
            continue
        value = parse(raw)
        if row["case"] == "missing-payload":
            assert value == {"schema": "guard-contained-test-request.v1", "workspace": "/runtime/home/project"}
            assert raw == canonical(value)
            continue
        assert value["payload"]["session_id"] == session
        expected = {
            "workspace": "/runtime/home/project",
            "schema": "guard-contained-test-request.v1",
            "payload": {
                "session_id": session,
                "config_path": "/product/home/omp.json",
                "tool_name": "bash",
                "tool_call_id": "snapshot-negative",
                "hook_event_name": "PreToolUse",
                "tool_input": {"command": "python3 -m unittest discover -s negative_tests -v"},
            },
        }
        mutations = {
            "foreign-workspace": ("workspace", "/product/home"),
            "wrong-schema": ("schema", "guard-contained-test-request.v0"),
        }
        if row["case"] in mutations:
            key, item = mutations[row["case"]]
            expected[key] = item
        elif row["case"] == "foreign-cwd":
            expected["payload"]["cwd"] = "/tmp"
        elif row["case"] == "wrong-event":
            expected["payload"]["hook_event_name"] = "PostToolUse"
        elif row["case"] == "wrong-tool":
            expected["payload"]["tool_name"] = "read"
        elif row["case"] == "nonstring-command":
            expected["payload"]["tool_input"]["command"] = 42
        assert raw == canonical(expected)
    trap = data["combined/workspace/negative_tests/test_trap.py"]
    assert (
        trap == b"import unittest\nfrom pathlib import Path\nclass Trap(unittest.TestCase):\n"
        b" def test_unexpected(self):Path('unexpected-negative-sink.txt').write_text('executed')\n"
    )
    assert sha(trap) == controls["fixture"]["sha256"]
    physical = parse(data["combined/physical-control-readback.json"])
    assert physical["unexpected_negative_sink_absent"] and physical["binding_fixture_sha256"] == sha(trap)
    metadata = parse(data["results.sha256.json"])["filesystem"]["combined/workspace/negative_tests/test_trap.py"]
    assert metadata["uid"] == metadata["gid"] == 10001 and metadata["mode"] == 0o600 and metadata["links"] == 1
    assert metadata["device"] == controls["fixture"]["device"] and metadata["inode"] == controls["fixture"]["inode"]
    return {"native_refusals": len(rows), "trap_unchanged_and_absent_effect": True}


def read(directory, proof):
    control, data, pin = read_transport(directory, proof)
    source, report_pin = proof["source"], proof["report"]
    read_binding_controls(control, data, pin)
    assert parse(data["proof/worker-tests.json"])["results"] == [["ok", "177", "0", "24"]]
    assert parse(data["proof/rootfs-tests.json"])["results"] == [["ok", "1", "0", "0"], ["ok", "33", "0", "0"]]
    replay = parse(data["proof/fast-replay-summary.json"])
    assert replay["worker_files_unchanged"] == proof["final"] and replay["legacy_lock_held_for_all_probes"]
    assert replay["replay_refused_before_host_preflight"] and replay["wrong_request_pin_refused"]
    return (
        {
            "schema": "hol-gauntlet-native-request-binding-host-readback.v1",
            "rust_source_commit": source,
            "product_source_sha": pin["source_sha"],
            "job_id": pin["job_id"],
            "report_sha256": report_pin,
            "native_refusals": 9,
            "trap_unchanged_and_absent_effect": True,
            "actual_sdk_mcp_bash_completed": True,
            "kernel_samples": proof["samples"],
            "retained_worker_files": proof["final"],
            "qualified_role_complete": False,
            "outside_signing_key_admitted": False,
            "execution_eligible": False,
            "guard_causality_verified": False,
            "model_requests": 0,
        },
        control,
        data,
        pin,
    )


def verify(directory):
    expected = {
        "source": SOURCE,
        "report": REPORT,
        "index": "001",
        "export": (EXPORT, 1208320, 159),
        "input": ("7730fd2ac9a145ef6db43facb07f17608d005551675a275136001ef8f60d7e64", 65095680, 5),
        "courier": "d065c83c07fd0d271576fa062e499d5a87f53a7b77f49e81bc6cf1b62b3e2bc2",
        "prior": 161,
        "final": 167,
        "samples": 57,
        "forbidden": False,
    }
    return read(directory, expected)[0]


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: verify_native_request_bindings_20261027.py EVIDENCE_DIRECTORY")
    print(json.dumps(verify(Path(sys.argv[1])), sort_keys=True))

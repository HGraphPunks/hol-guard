"""Join retained Root lifecycle custody, actual SDK/MCP frames and outside observations."""

from __future__ import annotations

import json
import subprocess
import sys
from itertools import pairwise
from pathlib import Path

import verify_native_current_worker_20261026 as worker
import verify_native_request_bindings_20261027 as transport
import verify_native_sdk_mcp_transport_20261027 as common
from verify_native_forbidden_control_20261027 import capture
from verify_native_mcp_transport_20261027 import digest, ineligible, parse, sha

PYTHON = "c86f21d0da9290ece2d7d49a3f7ed52aed59cb029abdf0ea25c79634f6cbe960"
CANCEL = "controller requested product-cell cancellation after held detached readiness"
DISPATCH = "controlled SDK sink cancellation after detached readiness"
PROOFS = {
    "010-cancel": {
        "index": "010-cancel",
        "input_index": "010",
        "role": "cancel",
        "job_file": "cancel",
        "source": "35852bd601d35709b79b64f69466faeaa55ad1d9",
        "report": "bec13dad1a943842774e4ca68f4f51a0700d9d5f8c7427f9b4662eb2382c674f",
        "export": ("78e147a78ba515833515c82f981213e74d2eb2505f6e18fce1206839fede527e", 1024000, 132),
        "input": ("8a5c6d89946133120bdf4c8d09796240781774e2124e2cd5a4141a83a18fc9d9", 65945600, 5),
        "courier": "de9e8bc2526795a0a3667f75624e19a7822a8e44103af347250025f3701263d8",
        "prior": 233,
        "final": 239,
        "samples": 61,
        "forbidden": False,
        "rootfs_tests": "40",
    },
    "010-timeout": {
        "index": "010-timeout",
        "input_index": "010",
        "role": "timeout",
        "job_file": "timeout",
        "source": "35852bd601d35709b79b64f69466faeaa55ad1d9",
        "report": "161bca5a46f538e1a43f2c1c66d4ff6298df35c021ba041e2561a077f799f1ef",
        "export": ("58cf57b14a72270858b2787dabd955a77dc65c259e49864e5ca6c55037beb276", 1095680, 140),
        "input": ("8a5c6d89946133120bdf4c8d09796240781774e2124e2cd5a4141a83a18fc9d9", 65945600, 5),
        "courier": "970ffe130bd4a7b7df7e991b8291cc76a2081cc5427c2c75a9a38df056056e09",
        "prior": 227,
        "final": 233,
        "samples": 61,
        "forbidden": False,
        "rootfs_tests": "40",
    },
    "008-cancel": {
        "index": "008-cancel",
        "input_index": "008",
        "role": "cancel",
        "job_file": "cancel",
        "source": "0bd3254fd41d904e8d3898f9a9410e8ce341dbfe",
        "report": "b7f8adb0979ba265d708ea0247248af78d37d95381466d890fef7f97dedbe918",
        "export": ("1944c3557a240a562df2e5bcd30ae80807c8f86931493076b8ec8d394f716b1a", 1024000, 132),
        "input": ("3e5a46bae23fc7c09d1f5547beaec1dd8712dda6810af844bdc41e4c91e41c26", 65914880, 5),
        "courier": "efbe74fa332481b79c1a622f4fcac02b325e05ad0141de8205120aad5fd975fd",
        "prior": 215,
        "final": 221,
        "samples": 62,
        "forbidden": False,
        "rootfs_tests": "38",
    },
}


def source(pin, name):
    root = Path(__file__).resolve().parents[3]
    return subprocess.check_output(["git", "show", pin["source_commit"] + ":" + name], cwd=root)


def journal(data):
    events = worker.chain(data["combined/cell/native-supervisor-events.v1.jsonl"])
    worker.chain(data["combined/cell/native-image-events.v1.jsonl"])
    assert events[-2]["kind"] == "terminal-cleanup" and events[-2]["data"]["failures"] == []
    assert events[-1]["kind"] == "rust-image-cleanup"
    for event in events:
        if event["kind"] == "capture-terminal":
            for value in event["data"]["files"].values():
                raw = data["combined/cell/" + value["file"]]
                assert len(raw) == value["bytes"] and sha(raw) == value["sha256"]
    return events


def lifecycle(control, data, pin):
    life = control["router"]["lifecycle"]
    ineligible(life)
    assert life["schema"] == "hol-gauntlet-native-detached-lifecycle.v2"
    assert life["status"] == "passed" and life["error"] is None
    assert life["role"] == control["control_role"]
    assert life["detached_child_dead"] is life["late_effect_absent"] is True
    observations = [
        r["observation"] for r in control["plane"]["observations"] if r["kind"] == "native-detached-lifecycle-control"
    ]
    assert observations == [life]
    ready, file, child = life["ready"], life["ready_file"], life["detached_child"]
    assert parse(file["utf8"].encode()) == ready and sha(file["utf8"].encode()) == file["sha256"]
    assert len(file["utf8"].encode()) == file["bytes"] and file["view"] == "kernel-held-process-cwd.v1"
    assert file["uid"] == file["gid"] == 10004 and file["mode"] == 0o600 and file["original_links"] == 1
    assert file["held_bytes_unchanged"] and file["late_effect_absent"]
    assert file["final_links"] in [0, 1] and file["overlay_cleanup_unlinked"] == (file["final_links"] == 0)
    assert ready == {
        "schema": "hol-gauntlet-native-detached-ready.v1",
        "role": life["role"],
        "token": f"hol-gauntlet-native-detached-{life['role']}-{pin['job_id']}",
        "pid": child["namespace_pid"],
        "sid": child["namespace_pid"],
        "pgrp": child["namespace_pid"],
    }
    code = source(pin, "ci/gauntlet-rs/adapters/native_lifecycle_child_v2.py.txt").decode()
    code = code.replace("HOL_LIFECYCLE_ROLE_JSON", json.dumps(life["role"]))
    code = code.replace("HOL_LIFECYCLE_TOKEN_JSON", json.dumps(ready["token"]))
    fixture = source(pin, "ci/gauntlet-rs/adapters/native_lifecycle_parent_v2.py.txt").decode()
    fixture = fixture.replace("HOL_DETACHED_CODE_JSON", json.dumps(code))
    assert data["combined/workspace/tests/test_control.py"] == fixture.encode()
    assert sha(fixture.encode()) == control["fixture"]["sha256"]
    assert control["fixture"]["detached_code_sha256"] == sha(code.encode())
    assert child["argv"] == ["/usr/bin/python3", "-I", "-B", "-c", code]
    assert child["argv_sha256"] == sha(("\0".join(child["argv"]) + "\0").encode())
    assert child["executable_sha256"] == PYTHON and child["pidfd_held"]
    samples = parse(data["proof/outside-kernel.json"])["observations"]
    matching = [
        r
        for r in samples
        if r["pid"] == child["pid"]
        and r["start_ticks"] == child["start_ticks"]
        and r["argv_sha256"] == child["argv_sha256"]
        and r.get("synthetic_lifecycle_view", {}).get("files", {}).get("detached-ready.json")
    ]
    assert matching
    for row in matching:
        assert row["pidfd_held"] and row["executable_sha256"] == PYTHON
        assert all(row[n] == child[n] for n in ["cgroup", "lsm_label", "executable_device", "executable_inode"])
        assert row["lsm_label"].startswith("hol-product-cell-") and row["lsm_label"].endswith(" (enforce)")
        assert row["namespace_pids"][-1] == ready["pid"]
        status = row["status"]
        assert status["Uid"].split() == status["Gid"].split() == ["10004"] * 4
        assert status["NoNewPrivs"] == "1" and status["Seccomp"] == "2"
        assert all(status[n] == "0000000000000000" for n in ["CapAmb", "CapBnd", "CapEff", "CapInh", "CapPrm"])
        for key, inode in row["namespaces"].items():
            assert int(child["namespaces"][key].split(":")[1]) == inode
        view = row["synthetic_lifecycle_view"]
        assert view["cwd"] == child["workspace_view"]["path"] == "/runtime/home/project"
        for name in ["device", "inode", "uid", "gid", "mode"]:
            assert view["directory"][name] == child["workspace_view"][name]
        observed = view["files"]["detached-ready.json"]
        assert all(observed[n] == file[n] for n in ["device", "inode", "uid", "gid", "mode", "sha256", "utf8"])
        assert observed["links"] == 1 and view["files"]["late-detached-effect.txt"] is None
    events = journal(data)
    ancestry = child["ancestry"]
    assert ancestry[0]["pid"] == child["pid"] and ancestry[0]["start_ticks"] == child["start_ticks"]
    assert all(a["parent_pid"] == b["pid"] for a, b in pairwise(ancestry))
    anchors = [
        r["data"]["identity"]
        for r in events
        if r["kind"] == "gated-product-process" and r["data"]["identity"]["pid"] == ancestry[-1]["pid"]
    ]
    assert len(anchors) == 1 and anchors[0]["start_ticks"] == ancestry[-1]["start_ticks"]
    argv = anchors[0]["argv"][2:]
    assert argv[:7] == [
        pin["preparation"]["runtime_prefix"] + "/bin/python",
        "-I",
        "-B",
        "-m",
        "codex_plugin_scanner.cli",
        "guard",
        "execute-contained-test",
    ]
    assert anchors[0]["cgroup"] == child["cgroup"]
    assert argv[argv.index("--timeout-seconds") + 1] == {"cancel": "30", "timeout": "5"}[life["role"]]
    captures = [
        r["data"]
        for r in events
        if r["kind"] == "capture-terminal" and r["data"]["argv_sha256"] == sha("\0".join(argv).encode())
    ]
    assert (
        len(captures) == 1
        and captures[0]["returncode"] == life["capture_exit_code"]
        and captures[0]["error"] == life["capture_error"]
    )
    handoff = next(r for r in control["plane"]["observations"] if r["kind"] == "native-contained-request-handoff")
    assert (
        handoff["cleanup_complete"]
        and handoff["cleanup_error"] is None
        and handoff["capture_error"] == life["capture_error"]
    )
    native_input = {
        "schema": "guard-contained-test-request.v1",
        "workspace": "/runtime/home/project",
        "payload": control["plane"]["hooks"][1]["payload"],
    }
    assert handoff["request"]["sha256"] == digest(native_input) == argv[argv.index("--request-sha256") + 1]
    assert handoff["request"]["path"] == argv[argv.index("--request-file") + 1]
    effect = control["effect"]
    ineligible(effect)
    assert effect["schema"] == "hol-gauntlet-native-closed-lifecycle.v2" and effect["control_sha256"] == digest(life)
    assert all(
        effect[n] for n in ["detached_child_dead", "late_effect_absent", "physical_lower_lifecycle_paths_absent"]
    )
    assert all(
        effect["ready_file"][n] == file[n] for n in ["device", "inode", "sha256", "utf8", "bytes", "uid", "gid", "mode"]
    )
    assert 0 <= effect["ready_file"]["final_links"] <= file["final_links"]
    physical = parse(data["combined/physical-lifecycle-absence.json"])
    assert physical["absent"] == ["detached-ready.json", "detached-ready.pending", "late-detached-effect.txt"]
    return life


def cancelled(control, data, pin):
    life = lifecycle(control, data, pin)
    assert life["role"] == "cancel" and life["capture_exit_code"] is None and life["capture_error"] == CANCEL
    assert life["cancel_requested_after_kernel_readiness"] and life["product_cell_closed"]
    assert "sdk" not in control["measurements"] and control["plane"]["executions"] == []
    abort = control["measurements"]["controlled_sdk_abort"]
    assert (
        abort["dispatch_error"] == DISPATCH
        and abort["actual_sdk_result_available"] is abort["post_tool_use_available"] is False
    )
    assert [h["hook_event_name"] for h in control["plane"]["hooks"]] == ["UserPromptSubmit", "PreToolUse"]
    pre, sink = control["requests"]
    assert [pre["sequence"], sink["sequence"]] == [1, 2]
    assert pre["request"]["hook_event_name"] == "PreToolUse" and sink["request"]["operation"] == "execute-contained"
    assert pre["response"]["execution_token"] == sink["request"]["token"] and pre["response_sha256"] == digest(
        pre["response"]
    )
    assert pre["peer_rechecked_before_response"] and sink["peer_rechecked_before_response"] is False
    assert sink["dispatch_error"] == DISPATCH and "response" not in sink and "response_sha256" not in sink
    binding = control["measurements"]["pre_import_binding"]
    assert all(
        binding[n]
        for n in [
            "bound_before_sdk_import",
            "entrypoint_bytes_verified",
            "readonly_mounts_verified",
            "sdk_source_pinned",
        ]
    )
    assert binding["assets"]["pins"] == pin["declaration"]["sdk"] and binding["assets"]["actual_tree_and_bun_verified"]
    bun = binding["peer"]["identity"]
    assert pre["peer"]["identity"]["pid"] == bun["pid"]
    for row in [pre, sink]:
        assert row["peer"]["peer_authenticated"] and row["product_claims_authenticated"] is False
    assert sink["peer"]["ancestry"]["ancestor_pid"] == bun["pid"]
    samples = parse(data["proof/outside-kernel.json"])["observations"]
    common.sdk_process(
        sink["peer"]["identity"],
        samples,
        ["/usr/bin/python3", "/runtime/public/contained_exec_relay.py", "--token", sink["request"]["token"]],
        PYTHON,
    )
    ledger = control["router"]["ledger"]
    assert all(ledger[n] == 1 for n in ["pre_count", "route_count", "sink_count"])
    assert ledger["completed_sink_count"] == ledger["post_count"] == 0
    hook = control["plane"]["hooks"][1]
    assert (
        hook["payload"]["tool_input"] == pre["request"]["tool_input"]
        and hook["response"] == pre["response"]["product_response"]
    )
    assert hook["response"]["decision"] == "deny" and hook["response"]["policy_action"] == "sandbox-required"
    assert hook["response"]["required_execution_profile"] == "workspace-contained-v1"
    assert all(control["measurements"]["replay_refusals"][n] for n in ["pre", "sink", "post", "native_plane_unchanged"])
    for item in binding["public_helpers"]["files"]:
        raw = data["combined/sdk-public/" + item["name"]]
        assert (
            sha(raw) == item["sha256"]
            and len(raw) == item["bytes"]
            and item["uid"] == item["gid"] == 0
            and item["mode"] == 0o444
        )
    return None


def timed_out(control, data, pin):
    life = lifecycle(control, data, pin)
    assert life["role"] == "timeout" and life["capture_exit_code"] == 124 and life["capture_error"] is None
    assert life["cancel_requested_after_kernel_readiness"] is life["product_cell_closed"] is False
    actual = control["measurements"]["sdk"]
    assert actual["exit_code"] == 0 and actual["stderr"] == ""
    result = actual["result"]
    assert result["uid"] == 10001 and result["version"] == "18.4.12" and result["syntheticStreamCalls"] == 3
    assert result["mcpExercised"] is True and result["modelExercised"] is result["qualificationEligible"] is False
    assert result["providerRequests"] == 0 and len(result["results"]) == 2
    raw = [
        b
        for n, b in data.items()
        if n.startswith("combined/sdk-processes/") and n.endswith(".stdout") and sha(b) == actual["stdout_sha256"]
    ]
    assert len(raw) == 1 and parse(raw[0]) == result
    pre, sink, post = control["requests"]
    assert [r["sequence"] for r in [pre, sink, post]] == [1, 2, 3]
    assert all(
        r["peer_rechecked_before_response"] and r["response_sha256"] == digest(r["response"]) for r in [pre, sink, post]
    )
    assert pre["request"]["hook_event_name"] == "PreToolUse" and post["request"]["hook_event_name"] == "PostToolUse"
    assert (
        sink["request"]["operation"] == "execute-contained"
        and sink["request"]["token"] == pre["response"]["execution_token"]
    )
    plane = control["plane"]
    assert [h["hook_event_name"] for h in plane["hooks"]] == ["UserPromptSubmit", "PreToolUse", "PostToolUse"]
    assert len(plane["executions"]) == 1
    execution = plane["executions"][0]
    assert execution == sink["response"]["result"] and execution["exit_code"] == 124
    captured = capture(
        data, journal(data), execution["native_command"], 124, execution["stdout_sha256"], execution["stderr_sha256"]
    )
    assert all(captured[n] == execution[n].encode() for n in ["stdout", "stderr"])
    output = post["response"]["contained_output"]
    text = f"Exit code: 124\nSTDOUT:\n{execution['stdout']}\nSTDERR:\n{execution['stderr']}"
    assert output["tool_response"] == [{"type": "text", "text": text}] and output["is_error"] is True
    assert output["output_sha256"] == sha(text.encode()) and output["result_digest"] == digest(execution)
    assert output["pre_payload_digest"] == execution["payload_digest"] == plane["hooks"][1]["payload_digest"]
    assert plane["hooks"][1]["payload"]["tool_input"] == pre["request"]["tool_input"]
    assert plane["hooks"][1]["response"] == pre["response"]["product_response"]
    bash = result["results"][1]
    assert bash["toolCallId"] == "sdk-contained-control" and bash["toolName"] == "bash" and bash["isError"] is True
    assert bash["content"] == output["tool_response"] == plane["hooks"][2]["payload"]["tool_response"]
    assert plane["hooks"][2]["response"]["reviewed_output_sha256"] == output["output_sha256"]
    assert all(
        control["router"]["ledger"][n] == 1
        for n in ["pre_count", "route_count", "sink_count", "completed_sink_count", "post_count"]
    )
    assert all(control["measurements"]["replay_refusals"][n] for n in ["pre", "sink", "post", "native_plane_unchanged"])
    return result


def verify(directory, attempt="008-cancel"):
    proof = PROOFS[attempt]
    control, data, pin = transport.read_transport(
        directory, proof, read_lifecycle=cancelled if proof["role"] == "cancel" else timed_out
    )
    assert (
        sha((directory / "native-role-lifecycle-observer-002.py").read_bytes())
        == "16a0a2e4b72bd3d38a4122f9e379680982fffd51ed33bbada15bfff210fecf57"
    )
    assert (
        parse(data["proof/outside-kernel.json"])["observer_sha256"]
        == "16a0a2e4b72bd3d38a4122f9e379680982fffd51ed33bbada15bfff210fecf57"
    )
    assert parse(data["proof/worker-tests.json"])["results"] == [["ok", "179", "0", "24"]]
    assert parse(data["proof/rootfs-tests.json"])["results"] == [
        ["ok", "1", "0", "0"],
        ["ok", proof["rootfs_tests"], "0", "0"],
    ]
    replay = parse(data["proof/fast-replay-summary.json"])
    assert replay["worker_files_unchanged"] == proof["final"] and replay["reconcile_original_terminal"]
    return {
        "schema": "hol-gauntlet-native-lifecycle-host-readback.v1",
        "job_id": pin["job_id"],
        "role": control["control_role"],
        "root_cancellation_after_held_readiness": proof["role"] == "cancel",
        "actual_timeout_and_sdk_error_output_bound": proof["role"] == "timeout",
        "held_child_dead": True,
        "closed_overlay_and_lower_readback": True,
        "missing_sdk_result_and_post_preserved": proof["role"] == "cancel",
        "kernel_samples": proof["samples"],
        "worker_files_preserved": proof["final"],
        "qualified_role_complete": False,
        "execution_eligible": False,
        "guard_causality_verified": False,
        "outside_signing_key_admitted": False,
        "model_requests": 0,
    }


if __name__ == "__main__":
    if len(sys.argv) not in [2, 3]:
        raise SystemExit(
            "usage: verify_native_lifecycle_control_20261027.py EVIDENCE_DIRECTORY "
            "[008-cancel|010-timeout|010-cancel]"
        )
    print(json.dumps(verify(Path(sys.argv[1]), *sys.argv[2:]), sort_keys=True))

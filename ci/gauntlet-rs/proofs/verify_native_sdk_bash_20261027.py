#!/usr/bin/env python3
"""Read the first actual Rust SDK/Bash exchange; never grant a control pass."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

import verify_native_current_worker_20261026 as v


def verify(base):
    data = v.exported(
        base / "native-sdk-transport-vm-results-032.tar",
        "3ff026ef1ca0389ea5d33ae3c8856768ea8d3dd2ea2bdd9961c992044e974695",
        98,
    )
    previous = v.exported(
        base / "native-sdk-transport-vm-results-031.tar",
        "8085e7a61b57da58723571061772dc213a36c87e785d61ec5c5bdd6936f08e61",
        80,
    )
    inputs = v.archive(
        base / "native-sdk-transport-input-032.tar",
        "d920236010922c2436726f220c2e7ce14121c5c4165fc8c136efc7d2ea13e2f5",
        5,
    )
    transfer = v.parse(inputs.pop("transfer.json"))
    assert transfer["source_commit"] == "426c7d939982f3a3334073a0040dbed1fbe6a8fe"
    assert v.parse(data["input/transfer.json"]) == transfer and set(inputs) == set(transfer["files"])
    for name, raw in inputs.items():
        assert v.sha(raw) == transfer["files"][name]["sha256"] and len(raw) == transfer["files"][name]["bytes"]
    jobs, proof = v.parse(data["proof/native-sdk-jobs.json"]), v.parse(data["proof/proof.json"])
    assert jobs["prior_worker_hashes"] == v.parse(previous["proof/proof.json"])["worker_hashes"]
    assert len(jobs["prior_worker_hashes"]) == 94
    assert len(proof["worker_hashes"]) == proof["worker_files"] == 100
    assert all(proof["worker_hashes"][n] == h for n, h in jobs["prior_worker_hashes"].items())
    prelaunch_raw = v.stable(base / "native-sdk-transport-host-prelaunch-032.json")
    assert v.sha(prelaunch_raw) == "18b4b6558806ad2d82c8a6a87249ab0bb239314036d42db3c57eba8c045fbc73"
    prelaunch = v.parse(prelaunch_raw)
    assert prelaunch["records"] == jobs["records"] and prelaunch["prior_worker_hashes"] == jobs["prior_worker_hashes"]
    job = jobs["records"]["sdk_transport"]
    assert job["worker_generation"] == prelaunch["worker_generation"] == v.sha(inputs["gauntlet-vm-worker"])
    assert v.sha(data["sdk_transport/preparation.v1.json"]) == job["preparation_sha256"]
    assert v.sha(data["sdk_transport/declaration.json"]) == job["deployment_sha256"]
    report_raw = data["sdk_transport/worker/report.json"]
    assert v.sha(report_raw) == "7ff9d176e93e32c46ba46353b22dde2602a8ae2fd116b533648c0dca21592112"
    report, terminal = v.parse(report_raw), v.parse(data["sdk_transport/worker/terminal.json"])
    assert terminal["report_sha256"] == v.sha(report_raw)
    assert report["exit_code"] == terminal["exit_code"] == 2
    assert report["status"] == terminal["status"] == "invalid-evidence"
    assert report["job_id"] == job["job_id"] and report["worker_generation"] == job["worker_generation"]
    for suffix in ["started.json", "running.json", "report.json", "terminal.json", "native.stdout", "native.stderr"]:
        assert v.sha(data["sdk_transport/worker/" + suffix]) == proof["worker_hashes"][job["job_id"] + "." + suffix]
    assert all(
        report[k] is True
        for k in [
            "controller_cgroup_drained",
            "product_slice_absent",
            "image_lease_absent",
            "sdk_agent_absent",
            "sdk_profile_absent",
        ]
    )
    controller = v.parse(data["sdk_transport/worker/native.stdout"])
    assert controller == report["controller_report"] and controller["status"] == "failed"
    assert controller["error"] == "SDK did not receive the exact benign Native-reviewed captured output"
    assert controller["cleanup_errors"] == []
    assert all(
        controller[k] is True
        for k in [
            "cell_cleanup_complete",
            "agent_cleanup_complete",
            "sdk_cleanup_complete",
            "prefix_unchanged",
            "sdk_assets_unchanged",
            "public_helpers_unchanged",
        ]
    )
    assert controller["sdk_exercised"] is False  # Its success predicate includes the failed benign fixture.
    for value in [report, controller, proof]:
        assert (
            not value["execution_eligible"] and not value["guard_causality_verified"] and value["model_requests"] == 0
        )
    binding = controller["measurements"]["pre_import_binding"]
    assert all(
        binding[k] is True
        for k in [
            "bound_before_sdk_import",
            "entrypoint_bytes_verified",
            "readonly_mounts_verified",
            "sdk_source_pinned",
        ]
    )
    assert binding["assets"]["pins"] == transfer["sdk"]
    assert binding["assets"]["actual_tree_and_bun_verified"] and binding["assets"]["sdk_version"] == "18.4.12"
    assert binding["assets"]["sdk_entries"] == 42321 and binding["assets"]["sdk_bytes"] == 1053309967
    for pin in binding["public_helpers"]["files"]:
        raw = data["sdk_transport/public/" + pin["name"]]
        assert v.sha(raw) == pin["sha256"] and len(raw) == pin["bytes"]
        assert pin["uid"] == pin["gid"] == 0 and pin["mode"] == 0o444
    for name, pin in transfer["public_helpers"].items():
        assert v.sha(data["sdk_transport/public/" + name]) == pin["sha256"]
    peer, agent = binding["peer"], controller["agent"]
    identity = peer["identity"]
    assert (
        peer["kernel_peer_authenticated"] and peer["bun_executable_pinned"] and peer["fixed_entrypoint_argv_verified"]
    )
    assert peer["executable_sha256"] == transfer["sdk"]["bun_sha256"]
    assert peer["agent"] == agent["kernel"]["init"]
    assert identity["namespaces"] == peer["agent"]["identity"]["namespaces"]
    assert identity["lsm_label"] == agent["kernel"]["lsm_label"] == "crun//&" + agent["name"] + " (unconfined)"
    assert (
        identity["cgroup"]
        == "/holgauntletrust" + job["job_id"] + ".slice/libpod-" + agent["container_id"] + ".scope/container"
    )
    kernel = v.parse(data["proof/outside-kernel.json"])
    assert kernel["errors"] == [] and len(kernel["observations"]) == 29
    samples = [o for o in kernel["observations"] if o["pid"] == identity["pid"]]
    assert len(samples) == 1
    sample = samples[0]
    assert sample["pidfd_held"] and sample["start_ticks"] == identity["start_ticks"]
    assert sample["executable_sha256"] == peer["executable_sha256"]
    argv = b"/runtime/bun\0/runtime/public/private_cell_sdk_conformance.ts\0/runtime/public/episode.json"
    # The worker's fixed-argv identity omits the kernel's trailing NUL.
    assert peer["argv_sha256"] == v.sha(argv) and sample["argv_sha256"] == v.sha(argv + b"\0")
    assert sample["cgroup"] == identity["cgroup"] and sample["lsm_label"] == identity["lsm_label"]
    assert sample["status"]["Uid"] == sample["status"]["Gid"] == "10001\t10001\t10001\t10001"
    assert all(sample["status"][n] == "0000000000000000" for n in ["CapAmb", "CapBnd", "CapEff", "CapInh", "CapPrm"])
    assert sample["status"]["NoNewPrivs"] == "1" and sample["status"]["Seccomp"] == "2"
    negative = binding["same_uid_negative"]
    assert negative["outside"]["rejected"] and negative["unprivileged_result"]["denied"]
    assert negative["outside"]["pid"] != identity["pid"] and negative["refused_before_sdk_import"]
    sdk = controller["measurements"]["sdk"]
    assert sdk["exit_code"] == 0 and sdk["stderr"] == ""
    result = sdk["result"]
    assert result["schema"] == "private-cell-sdk-conformance-result.v1" and result["version"] == "18.4.12"
    assert result["uid"] == 10001 and result["syntheticStreamCalls"] == 2 and len(result["results"]) == 1
    assert result["mcpExercised"] is result["modelExercised"] is result["qualificationEligible"] is False
    assert result["providerRequests"] == 0 and result["resourceTools"] == []
    assert (
        result["modelContextProjection"]["originalCommandVisible"]
        and result["modelContextProjection"]["executionTransportRetained"]
    )
    sdk_raw = [
        raw
        for name, raw in data.items()
        if name.startswith("sdk_transport/processes/")
        and name.endswith(".stdout")
        and v.sha(raw) == sdk["stdout_sha256"]
    ]
    assert len(sdk_raw) == 1 and v.parse(sdk_raw[0]) == result
    requests = controller["requests"]
    assert len(requests) == 3 and [r["sequence"] for r in requests] == [1, 2, 3]
    assert all(r["peer_rechecked_before_response"] and not r["product_claims_authenticated"] for r in requests)
    assert requests[0]["request"]["hook_event_name"] == "PreToolUse"
    assert requests[1]["request"]["operation"] == "execute-contained"
    assert requests[2]["request"]["hook_event_name"] == "PostToolUse"
    assert requests[1]["request"]["token"] == requests[0]["response"]["execution_token"]
    for name in ["pre_count", "route_count", "sink_count", "completed_sink_count", "post_count"]:
        assert controller["router"]["ledger"][name] == 1
    plane = controller["plane"]
    assert [r["hook_event_name"] for r in plane["hooks"]] == ["UserPromptSubmit", "PreToolUse", "PostToolUse"]
    assert plane["hooks"][0]["response"]["decision"] == "allow"
    assert plane["hooks"][1]["payload"]["tool_input"] == requests[0]["request"]["tool_input"]
    assert plane["hooks"][1]["response"]["reason_code"] == "native_workspace_containment_required"
    assert plane["hooks"][2]["response"]["decision"] == "allow"
    execution = plane["executions"][0]
    assert len(plane["executions"]) == 1 and execution["exit_code"] == 1
    assert execution == requests[1]["response"]["result"]
    assert "npm" in execution["stderr"] and "SIGABRT" in execution["stderr"]
    for name in ["stdout", "stderr"]:
        assert v.sha(execution[name].encode()) == execution[name + "_sha256"]
    output = requests[2]["response"]["contained_output"]
    text = f"Exit code: {execution['exit_code']}\nSTDOUT:\n{execution['stdout']}\nSTDERR:\n{execution['stderr']}"
    assert output["tool_response"] == [{"type": "text", "text": text}] and output["is_error"] is True
    assert output["output_sha256"] == v.sha(text.encode()) and output["result_digest"] == v.sha(v.canonical(execution))
    assert output["pre_payload_digest"] == execution["payload_digest"] == plane["hooks"][1]["payload_digest"]
    row = result["results"][0]
    assert row["toolCallId"] == "sdk-contained-control" and row["toolName"] == "bash" and row["isError"] is True
    assert row["content"] == output["tool_response"]
    assert plane["hooks"][2]["payload"]["tool_response"] == output["tool_response"]
    assert plane["hooks"][2]["response"]["reviewed_output_sha256"] == output["output_sha256"]
    assert data["sdk_transport/effect.bin"] == b"private plane effect"
    assert v.sha(data["sdk_transport/effect.bin"]) == controller["effect"]["sha256"]
    assert controller["effect"]["uid"] == controller["effect"]["gid"] == 10001
    assert v.sha(data["sdk_transport/fixture/test_control.py"]) == controller["fixture"]["sha256"]
    for name in ["native-supervisor-events.v1.jsonl", "native-image-events.v1.jsonl"]:
        rows = v.chain(data["sdk_transport/cell/" + name])
        if name.startswith("native-supervisor"):
            assert rows[-2]["kind"] == "terminal-cleanup" and rows[-2]["data"]["failures"] == []
            assert rows[-1]["kind"] == "rust-image-cleanup"
            for event in rows:
                if event["kind"] == "capture-terminal":
                    for pin in event["data"]["files"].values():
                        raw = data["sdk_transport/cell/" + pin["file"]]
                        assert v.sha(raw) == pin["sha256"] and len(raw) == pin["bytes"]
    tests = v.parse(data["proof/root-tests.json"])
    assert tests["gauntlet-worker-tests"]["results"] == [["ok", "152", "0", "24"]]
    for name, check in tests.items():
        assert check["returncode"] == 0 and v.sha(data["proof/" + name + ".log"]) == check["sha256"]
    for action in ["replay", "reconcile"]:
        response = v.parse(data["proof/worker-sdk_transport-" + action + ".json"])
        if action == "replay":
            assert response["returncode"] == 2
        else:
            value = v.parse(response["stdout"])
            assert response["returncode"] == 0 and value["state"] == "terminal" and value["exit_code"] == 2
            assert value["report_sha256"] == v.sha(report_raw)
    return {
        "schema": "hol-gauntlet-host-native-sdk-bash-failed-fixture.v1",
        "export_members_verified": 98,
        "input_members_verified": 5,
        "worker_files_preserved": 100,
        "actual_sdk_completed": True,
        "pre_import_binding_observed": True,
        "same_uid_peer_refused": True,
        "exact_captured_output_delivered": True,
        "benign_native_command_exit": 1,
        "benign_control_passed": False,
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

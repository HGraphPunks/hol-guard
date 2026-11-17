"""Shared inert SDK/worker readback; these relations never grant a verdict."""

from __future__ import annotations

import verify_native_current_worker_20261026 as v

BUN_ARGV = b"/runtime/bun\0/runtime/public/private_cell_sdk_conformance.ts\0/runtime/public/episode.json"


def worker(data, role, pin, hashes, expected_exit, report_sha256, *, host_pinned=False):
    root = role + "/worker/"
    raw = data[root + "report.json"]
    report = v.parse(raw)
    assert v.sha(raw) == report_sha256
    started_raw = data[root + "started.json"]
    started, running, terminal = (v.parse(data[root + n]) for n in ["started.json", "running.json", "terminal.json"])
    for value in [started, running, report, terminal]:
        assert value["source_sha"] == pin["source_sha"] and value["job_id"] == pin["job_id"]
        assert value["worker_generation"] == pin["worker_generation"]
        assert value["deployment_digest"] == pin["deployment_sha256"]
    for value in [running, report, terminal]:
        assert value["started_marker_sha256"] == v.sha(started_raw)
    assert terminal["report_sha256"] == report_sha256
    assert terminal["pid"] == running["pid"] and terminal["process_start_ticks"] == running["process_start_ticks"]
    assert report["controller"] == {"pid": running["pid"], "start_ticks": running["process_start_ticks"]}
    assert report["exit_code"] == terminal["exit_code"] == expected_exit
    assert report["status"] == terminal["status"] == "invalid-evidence"
    assert report["preparation_sha256"] == pin["preparation_sha256"]
    assert v.sha(data[role + "/preparation.v1.json"]) == pin["preparation_sha256"]
    assert v.sha(data[role + "/declaration.json"]) == pin["deployment_sha256"]
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
    for n in ["started.json", "running.json", "report.json", "terminal.json", "native.stdout", "native.stderr"]:
        assert v.sha(data[root + n]) == hashes[pin["job_id"] + "." + n]
    assert v.sha(data[root + "native.stdout"]) == report["controller_stdout_sha256"]
    assert v.sha(data[root + "native.stderr"]) == report["controller_stderr_sha256"]
    assert report["execution_eligible"] is report["guard_causality_verified"] is False
    assert report["model_requests"] == 0
    if host_pinned:
        assert report["schema"] == "hol-gauntlet-native-worker-report.v7"
        assert started["schema"] == "hol-gauntlet-worker-started.v2"
        assert terminal["schema"] == "hol-gauntlet-worker-terminal.v2"
        assert v.sha(data[root + "controller-key.json"]) == hashes[pin["job_id"] + ".controller-key.json"]
        assert data[root + "native.stdout"].decode() == report["controller_envelope_utf8"]
        envelope = v.parse(data[root + "native.stdout"])
        assert set(envelope) == {"record", "signature"}
        assert envelope["record"]["controller_report"] == report["controller_report"]
    elif data[root + "native.stdout"]:
        assert v.parse(data[root + "native.stdout"]) == report["controller_report"]
    else:
        assert report["controller_report"] is None
    return report


def sdk_exchange(data, transfer, controller, *, require_outside_bun=True):
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
    assets = binding["assets"]
    assert assets["pins"] == transfer["sdk"] and assets["actual_tree_and_bun_verified"]
    assert assets["sdk_version"] == "18.4.12" and assets["sdk_entries"] == 42321
    assert assets["sdk_bytes"] == 1053309967 and assets["sdk_imported"] is False
    helpers = binding["public_helpers"]
    assert helpers["sdk_imported_by_root"] is False
    for pin in helpers["files"]:
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
    assert peer["agent"] == agent["kernel"]["init"] and identity["pidfd_held"]
    assert identity["namespaces"] == peer["agent"]["identity"]["namespaces"]
    assert identity["lsm_label"] == agent["kernel"]["lsm_label"] == "crun//&" + agent["name"] + " (unconfined)"
    assert (
        identity["cgroup"]
        == "/holgauntletrust" + controller["job_id"] + ".slice/libpod-" + agent["container_id"] + ".scope/container"
    )
    kernel = v.parse(data["proof/outside-kernel.json"])
    assert kernel["errors"] == []
    samples = [
        o for o in kernel["observations"] if o["pid"] == identity["pid"] and o["start_ticks"] == identity["start_ticks"]
    ]
    assert samples
    bun = [
        o
        for o in samples
        if o["executable_sha256"] == peer["executable_sha256"] and o["argv_sha256"] == v.sha(BUN_ARGV + b"\0")
    ]
    if require_outside_bun:
        assert bun, "outside observer did not retain the actual post-exec Bun image"
    sample = bun[0] if bun else samples[0]
    assert sample["pidfd_held"] and sample["start_ticks"] == identity["start_ticks"]
    assert sample["cgroup"] == identity["cgroup"]
    assert peer["argv_sha256"] == v.sha(BUN_ARGV)
    assert sample["lsm_label"] == identity["lsm_label"]
    assert sample["status"]["Uid"] == sample["status"]["Gid"] == "10001\t10001\t10001\t10001"
    assert all(sample["status"][n] == "0000000000000000" for n in ["CapAmb", "CapBnd", "CapEff", "CapInh", "CapPrm"])
    assert sample["status"]["NoNewPrivs"] == "1" and sample["status"]["Seccomp"] == "2"
    assert sample["limits"] == {"memory.max": "2147483648", "pids.max": "256", "cpu.max": "200000 100000"}
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
    requests, plane = controller["requests"], controller["plane"]
    assert len(requests) == 3 and [r["sequence"] for r in requests] == [1, 2, 3]
    assert all(r["peer_rechecked_before_response"] and not r["product_claims_authenticated"] for r in requests)
    assert requests[0]["request"]["hook_event_name"] == "PreToolUse"
    assert requests[1]["request"]["operation"] == "execute-contained"
    assert requests[2]["request"]["hook_event_name"] == "PostToolUse"
    assert requests[1]["request"]["token"] == requests[0]["response"]["execution_token"]
    for n in ["pre_count", "route_count", "sink_count", "completed_sink_count", "post_count"]:
        assert controller["router"]["ledger"][n] == 1
    assert [r["hook_event_name"] for r in plane["hooks"]] == ["UserPromptSubmit", "PreToolUse", "PostToolUse"]
    assert plane["hooks"][0]["response"]["decision"] == "allow"
    assert plane["hooks"][1]["payload"]["tool_input"] == requests[0]["request"]["tool_input"]
    assert plane["hooks"][1]["response"]["reason_code"] == "native_workspace_containment_required"
    assert plane["hooks"][2]["response"]["decision"] == "allow"
    assert len(plane["executions"]) == 1
    execution = plane["executions"][0]
    assert execution["exit_code"] == 0 and execution == requests[1]["response"]["result"]
    for n in ["stdout", "stderr"]:
        assert v.sha(execution[n].encode()) == execution[n + "_sha256"]
    output = requests[2]["response"]["contained_output"]
    text = f"Exit code: {execution['exit_code']}\nSTDOUT:\n{execution['stdout']}\nSTDERR:\n{execution['stderr']}"
    assert output["tool_response"] == [{"type": "text", "text": text}] and output["is_error"] is False
    assert output["output_sha256"] == v.sha(text.encode()) and output["result_digest"] == v.sha(v.canonical(execution))
    assert output["pre_payload_digest"] == execution["payload_digest"] == plane["hooks"][1]["payload_digest"]
    row = result["results"][0]
    assert row["toolCallId"] == "sdk-contained-control" and row["toolName"] == "bash" and row["isError"] is False
    assert row["content"] == output["tool_response"] == plane["hooks"][2]["payload"]["tool_response"]
    assert plane["hooks"][2]["response"]["reviewed_output_sha256"] == output["output_sha256"]
    assert all(
        controller["measurements"]["replay_refusals"][n] for n in ["pre", "sink", "post", "native_plane_unchanged"]
    )
    assert data["sdk_transport/effect.bin"] == b"private plane effect"
    assert v.sha(data["sdk_transport/effect.bin"]) == controller["effect"]["sha256"]
    assert controller["effect"]["uid"] == controller["effect"]["gid"] == 10001
    assert v.sha(data["sdk_transport/fixture/test_control.py"]) == controller["fixture"]["sha256"]
    node = v.parse(data["sdk_transport/node-runtime-control.json"])
    assert node == {
        "node_version": "v22.22.2",
        "npm_version": "10.9.7",
        "node_is_symlink": False,
        "node_sha256": "3159f9115ab4be7d318b7c28e946837a4dceb7f2b3c43232aa2f2e3852550b90",
    }
    for n in ["native-supervisor-events.v1.jsonl", "native-image-events.v1.jsonl"]:
        rows = v.chain(data["sdk_transport/cell/" + n])
        if n.startswith("native-supervisor"):
            assert rows[-2]["kind"] == "terminal-cleanup" and rows[-2]["data"]["failures"] == []
            assert rows[-1]["kind"] == "rust-image-cleanup"
            for event in rows:
                if event["kind"] == "capture-terminal":
                    for pin in event["data"]["files"].values():
                        raw = data["sdk_transport/cell/" + pin["file"]]
                        assert v.sha(raw) == pin["sha256"] and len(raw) == pin["bytes"]
    assert controller["sdk_exercised"]
    assert all(
        controller[n]
        for n in [
            "cell_cleanup_complete",
            "agent_cleanup_complete",
            "sdk_cleanup_complete",
            "prefix_unchanged",
            "sdk_assets_unchanged",
            "public_helpers_unchanged",
        ]
    )
    assert (
        not controller["execution_eligible"]
        and not controller["guard_causality_verified"]
        and controller["model_requests"] == 0
    )
    return {
        "outside_kernel_samples": len(kernel["observations"]),
        "outside_bun_executable_observed": bool(bun),
        "actual_sdk_completed": True,
        "exact_captured_output_delivered": True,
        "benign_native_command_exit": 0,
        "mcp_exercised": False,
        "guard_causality_verified": False,
        "execution_eligible": False,
        "model_requests": 0,
    }

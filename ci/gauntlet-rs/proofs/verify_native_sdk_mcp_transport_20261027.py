"""Independent public readback of actual SDK/MCP/Bash execution; no verdict."""

from __future__ import annotations

import base64
import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import native_sdk_readback_20261027 as sdk
import verify_native_current_worker_20261026 as worker
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
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

SOURCE = "dde4cb736f44091cdffc9c514dc8e1b7c64a426c"
REPORT = "fde34916d2dc1ef22bb8cd6793136ad8e7f42305b40738e7296232217537c96e"
REFERENCE = "a4f0c2758c0943231f162c305ef2bb6f053765633a3c9a57abf7de9d5580313b"
EXPORT = "242e75a36de417c1e3fa6f97b986aac5ce6552ee4030118a397074aa3778b885"


def native_argv(prefix, family):
    payload = {
        "args": ["<path>", "--socket", "<path>"],
        "command": "python3",
        "harness": "omp",
        "name": family,
        "source_scope": "project",
        "transport": "stdio",
    }
    identifier = "mcp_server:omp:project:" + family + ":" + sha(json.dumps(payload, sort_keys=True).encode())[:20]
    return [
        prefix + "/bin/python",
        "-I",
        "-m",
        "codex_plugin_scanner.cli",
        "guard",
        "omp-mcp-proxy",
        "--guard-home",
        "/product/guard",
        "--server-name",
        family,
        "--server-id",
        identifier,
        "--source-scope",
        "project",
        "--config-path",
        "/product/public/mcp.json",
        "--transport",
        "stdio",
        "--command",
        "/usr/bin/python3",
        "--home",
        "/product/home",
        "--workspace",
        "/product/home/project",
        "--arg=/product/public/service_relay.py",
        "--arg=--socket",
        f"--arg=/upstream/{family}.sock",
    ]


def sdk_process(identity, samples, argv, executable):
    matches = [
        s
        for s in samples
        if s["pid"] == identity["pid"]
        and s["start_ticks"] == identity["start_ticks"]
        and s["argv_sha256"] == sha(("\0".join(argv) + "\0").encode())
        and s["executable_sha256"] == executable
    ]
    assert matches, identity["pid"]
    for sample in matches:
        assert sample["argv_utf8"].split("\0") == [*argv, ""]
        assert sample["pidfd_held"] and sample["cgroup"] == identity["cgroup"]
        assert sample["lsm_label"] == identity["lsm_label"]
        assert sample["lsm_label"].startswith("crun//&hol-gauntlet-sdk-")
        assert sample["lsm_label"].endswith(" (unconfined)")
        assert sample["limits"] == {"memory.max": "2147483648", "pids.max": "256", "cpu.max": "200000 100000"}
        for name, inode in sample["namespaces"].items():
            assert int(identity["namespaces"][name].split(":")[1]) == inode
        status = sample["status"]
        assert status["Uid"].split() == status["Gid"].split() == ["10001"] * 4
        assert status["Groups"].split() in ([], ["10001"])
        assert status["NoNewPrivs"] == "1" and status["Seccomp"] == "2" and int(status["Seccomp_filters"]) > 0
        assert all(status[n] == "0000000000000000" for n in ("CapAmb", "CapBnd", "CapEff", "CapInh", "CapPrm"))


def frames(session):
    rows = session["frames"]
    assert [r["sequence"] for r in rows] == list(range(1, len(rows) + 1))
    for row in rows:
        assert sha(row["wire_utf8"].encode()) == row["sha256"]
        assert parse(row["wire_utf8"]) == row["frame"]
    return rows


def world(data, role, value, calls):
    ineligible(value["world"])
    assert value["world"]["uid"] == value["world"]["gid"] == 0 and value["world"]["mode"] == 0o600
    assert value["world"]["agent_mounts_verified"] is False
    records = {r["id"]: r for r in value["initial"]["records"]}
    receipts = value["receipts"]
    assert len(receipts) == len(calls)
    key = Ed25519PublicKey.from_public_bytes(base64.b64decode(value["world"]["public_key"], validate=True))
    previous = "0" * 64
    for sequence, (envelope, call) in enumerate(zip(receipts, calls, strict=True), 1):
        event, args = envelope["event"], call["params"]["arguments"]
        assert event["sequence"] == sequence and event["previous_hash"] == previous
        assert event["request_id"] == call["id"] and event["operation"] == call["params"]["name"]
        assert event["effect"] == "read" and event["status"] == "ok" and event["before"] is None
        assert event["raw_args_digest"] == digest(args)
        assert event["args_digest"] == digest({"operation": event["operation"], "args": args, "actor": "fixture-actor"})
        assert event["after"] == records[args["record_id"]] and event["result_digest"] == digest(event["after"])
        key.verify(base64.b64decode(envelope["signature"], validate=True), canonical(event))
        previous = digest(envelope)
    connection = sqlite3.connect(":memory:")
    connection.deserialize(data[role + "/mcp-world.db"])
    connection.execute("PRAGMA trusted_schema=OFF")
    assert connection.execute("PRAGMA quick_check").fetchall() == [("ok",)]
    assert {r[0] for r in connection.execute("SELECT name FROM sqlite_schema WHERE type='table'")} == {
        "meta",
        "records",
        "journal",
        "cached",
    }
    meta = parse(connection.execute("SELECT value FROM meta WHERE id=1").fetchone()[0])
    assert set(meta) == {"actor_id", "producer", "provider_scope", "schema"}
    assert meta["producer"] == value["world"]["public_key"]
    assert {name: parse(raw) for name, raw in connection.execute("SELECT id,value FROM records")} == records
    assert [parse(r[0]) for r in connection.execute("SELECT value FROM journal ORDER BY sequence")] == receipts
    assert connection.execute("SELECT count(*) FROM cached").fetchone()[0] == 0
    connection.close()
    assert (
        value["final"]
        == value["initial"]
        == {**{k: v for k, v in meta.items() if k != "producer"}, "records": value["initial"]["records"]}
    )
    assert value["sockets"]["socket_namespace_retired"] is True
    assert value["sockets"]["accepted_streams_drained"] is value["sockets"]["peer_authenticated"] is False


def bash(data, control, result, *, extra_pre_payload=None):
    requests, plane = control["requests"], control["plane"]
    assert [r["sequence"] for r in requests] == [1, 2, 3]
    assert all(r["peer_rechecked_before_response"] and not r["product_claims_authenticated"] for r in requests)
    for row in requests:
        assert row["response_sha256"] == digest(row["response"])
    assert requests[0]["request"]["hook_event_name"] == "PreToolUse"
    assert requests[1]["request"]["operation"] == "execute-contained"
    assert requests[2]["request"]["hook_event_name"] == "PostToolUse"
    assert requests[1]["request"]["token"] == requests[0]["response"]["execution_token"]
    events = ["UserPromptSubmit", "PreToolUse", "PostToolUse"]
    if extra_pre_payload is not None:
        events.append("PreToolUse")
        extra = plane["hooks"][3]
        assert extra["payload"] == extra_pre_payload and extra["payload_digest"] == digest(extra_pre_payload)
        assert extra["normalization_error"] is None and extra["product_claims_authenticated"] is False
    assert [h["hook_event_name"] for h in plane["hooks"]] == events
    assert plane["hooks"][0]["response"]["decision"] == plane["hooks"][2]["response"]["decision"] == "allow"
    assert plane["hooks"][1]["response"]["reason_code"] == "native_workspace_containment_required"
    assert plane["hooks"][1]["payload"]["tool_input"] == requests[0]["request"]["tool_input"]
    for n in ("pre_count", "route_count", "sink_count", "completed_sink_count", "post_count"):
        assert control["router"]["ledger"][n] == 1
    assert len(plane["executions"]) == 1
    execution = plane["executions"][0]
    assert execution == requests[1]["response"]["result"] and execution["exit_code"] == 0
    for name in ["stdout", "stderr"]:
        assert sha(execution[name].encode()) == execution[name + "_sha256"]
    output = requests[2]["response"]["contained_output"]
    text = f"Exit code: 0\nSTDOUT:\n{execution['stdout']}\nSTDERR:\n{execution['stderr']}"
    assert output["tool_response"] == [{"type": "text", "text": text}] and output["is_error"] is False
    assert output["output_sha256"] == sha(text.encode()) and output["result_digest"] == digest(execution)
    assert output["pre_payload_digest"] == execution["payload_digest"] == plane["hooks"][1]["payload_digest"]
    row = result["results"][1]
    assert row["toolCallId"] == "sdk-contained-control" and row["toolName"] == "bash" and row["isError"] is False
    assert row["content"] == output["tool_response"] == plane["hooks"][2]["payload"]["tool_response"]
    assert plane["hooks"][2]["response"]["reviewed_output_sha256"] == output["output_sha256"]
    assert all(control["measurements"]["replay_refusals"][n] for n in ["pre", "sink", "post", "native_plane_unchanged"])
    effect = data["combined/workspace/native-contained.txt"]
    assert effect == b"private plane effect" and sha(effect) == control["effect"]["sha256"]
    assert control["effect"]["uid"] == control["effect"]["gid"] == 10001
    assert sha(data["combined/workspace/tests/test_control.py"]) == control["fixture"]["sha256"]
    assert parse(data["combined/workspace/node-runtime-control.json"]) == {
        "node_version": "v22.22.2",
        "npm_version": "10.9.7",
        "node_is_symlink": False,
        "node_sha256": "3159f9115ab4be7d318b7c28e946837a4dceb7f2b3c43232aa2f2e3852550b90",
    }
    for name in ["native-supervisor-events.v1.jsonl", "native-image-events.v1.jsonl"]:
        rows = worker.chain(data["combined/cell/" + name])
        if name.startswith("native-supervisor"):
            assert rows[-2]["kind"] == "terminal-cleanup" and rows[-2]["data"]["failures"] == []
            assert rows[-1]["kind"] == "rust-image-cleanup"
        for row in rows:
            if row["kind"] == "capture-terminal":
                for pin in row["data"]["files"].values():
                    raw = data["combined/cell/" + pin["file"]]
                    assert len(raw) == pin["bytes"] and sha(raw) == pin["sha256"]


def verify(directory):
    data = archive(directory / "native-sdk-mcp-transport-vm-results-001.tar", EXPORT, 1495040, 208)
    assert not any("mcp-guard" in n or "mcp-home" in n or "sdk-home" in n for n in data)
    index = parse(data["results.sha256.json"])
    ineligible(index)
    inputs = archive(
        directory / "native-sdk-mcp-transport-input-001.tar",
        "331ffceb7c555fec33c7aa5fe030d3e7d06b7c9bf3216a1c916a171593f12a21",
        64931840,
        5,
    )
    transfer = parse(inputs.pop("transfer.json"))
    assert transfer == parse(data["input/transfer.json"]) and transfer["source_commit"] == SOURCE
    for name, raw in inputs.items():
        assert transfer["files"][name] == {"bytes": len(raw), "sha256": sha(raw)}
        assert raw[:4] == b"\x7fELF" and raw[18:20] == b"\xb7\0"
    prelaunch = parse((directory / "native-sdk-mcp-prelaunch-001.json").read_bytes())
    reference_launch = parse((directory / "native-sdk-mcp-reference-prelaunch-001.json").read_bytes())
    assert prelaunch["source_commit"] == SOURCE
    for meta, name in [
        (prelaunch, "native-sdk-mcp-proof-courier-001.py"),
        (reference_launch, "native-sdk-mcp-reference-courier-001.py"),
    ]:
        assert sha((directory / name).read_bytes()) == meta["courier_sha256"]
    pin = prelaunch["pins"]
    assert pin == parse(data["proof/job-sdk_mcp.json"])
    reference_pin = reference_launch["pins"]
    assert reference_pin == parse(data["proof/job-mcp_reference.json"])
    hashes = parse(data["proof/final-worker-hashes.json"])
    prior = parse(data["proof/prior-worker-hashes.json"])
    assert len(prior) == 143 and len(hashes) == 155 and all(hashes[n] == h for n, h in prior.items())
    assert prior["e2c701baf1473801.report.json"] == "38d6c240e339efaa2ee977d7c20d97f83f1d0d831062101b7dee96dabaae280a"
    control = sdk.worker(data, "combined", pin, hashes, 0, REPORT)["controller_report"]
    reference = parse(data["reference/worker/report.json"])
    assert sha(data["reference/worker/report.json"]) == REFERENCE
    assert reference["schema"] == "hol-gauntlet-native-worker-report.v4"
    assert reference["status"] == "invalid-evidence" and reference["exit_code"] == 0
    ineligible(reference)
    assert all(
        reference[n]
        for n in [
            "controller_cgroup_drained",
            "product_slice_absent",
            "image_lease_absent",
            "mcp_agent_absent",
            "mcp_profile_absent",
        ]
    )
    ref = reference["controller_report"]
    assert ref["status"] == "passed" and ref["sdk_exercised"] is False and ref["upstream_operation_count"] == 2
    assert len(ref["upstream_sessions"]) == 2
    ref_calls = [
        r["frame"]
        for s in ref["upstream_sessions"]
        for r in frames(s)
        if r["direction"] == "request" and r["frame"].get("method") == "tools/call"
    ]
    world(data, "reference", ref, ref_calls)
    assert control["schema"] == "hol-gauntlet-native-sdk-mcp-transport.v1" and control["status"] == "passed"
    ineligible(control)
    assert control["error"] is None and control["cleanup_errors"] == [] and control["artifact_admitted"] is False
    for name in [
        "sdk_cleanup_complete",
        "agent_cleanup_complete",
        "mcp_cleanup_complete",
        "cell_cleanup_complete",
        "prefix_unchanged",
        "public_helpers_unchanged",
        "sdk_assets_unchanged",
        "host_null_identity_unchanged",
        "sdk_exercised",
        "mcp_exercised",
        "combined_budget_verified",
    ]:
        assert control[name] is True
    samples = parse(data["proof/outside-kernel.json"])
    assert samples["errors"] == [] and len(samples["observations"]) == 50
    assert samples["observer_sha256"] == prelaunch["observer_sha256"]
    samples = samples["observations"]
    before, after = parse(data["proof/outside-device-before.json"]), parse(data["proof/outside-device-after.json"])
    assert after.pop("identity_unchanged") is True and before == after
    assert before["uid"] == before["gid"] == 0 and before["mode"] == 0o666
    binding = control["measurements"]["pre_import_binding"]
    assert binding["schema"] == "hol-gauntlet-native-sdk-pre-import-binding.v2"
    assert all(
        binding[n]
        for n in [
            "bound_before_sdk_import",
            "entrypoint_bytes_verified",
            "readonly_mounts_verified",
            "sdk_source_pinned",
        ]
    )
    peer = binding["peer"]
    assert peer["executable_sha256"] == pin["declaration"]["sdk"]["bun_sha256"]
    sdk_process(peer["identity"], samples, sdk.BUN_ARGV.decode().split("\0"), peer["executable_sha256"])
    assert peer["argv_sha256"] == sha(sdk.BUN_ARGV)
    for name in ["same_uid_negative", "mcp_same_uid_negative"]:
        negative = binding[name]
        assert negative["refused_before_sdk_import"] and negative["unprivileged_result"]["denied"]
        assert negative["outside"]["pid"] != peer["identity"]["pid"]
    assert binding["mcp_same_uid_negative"]["outside"]["rejected_before_native_forward"] is True
    root = Path(__file__).resolve().parents[3]
    for item in control["public_helpers"]["files"]:
        raw = data["combined/sdk-public/" + item["name"]]
        assert sha(raw) == item["sha256"] and len(raw) == item["bytes"]
        assert item["uid"] == item["gid"] == 0 and item["mode"] == 0o444
    for name, source in {
        "private_cell_sdk_conformance.ts": "ci/gauntlet/benchmark/private_cell_sdk_conformance.ts",
        "service_relay.py": "ci/gauntlet/benchmark/service_relay.py",
        "same_uid_mcp_peer_probe.py": "ci/gauntlet-rs/adapters/native_sdk_mcp_same_uid_peer_v1.py.txt",
    }.items():
        assert data["combined/sdk-public/" + name] == subprocess.check_output(
            ["git", "show", SOURCE + ":" + source], cwd=root
        )
    actual = control["measurements"]["sdk"]
    assert actual["exit_code"] == 0 and actual["stderr"] == ""
    result = actual["result"]
    assert result["version"] == "18.4.12" and result["uid"] == 10001 and result["syntheticStreamCalls"] == 3
    assert result["mcpExercised"] is True and result["modelExercised"] is result["qualificationEligible"] is False
    assert result["providerRequests"] == 0 and len(result["results"]) == 2 and len(result["resourceTools"]) == 14
    assert all(result["modelContextProjection"][n] for n in ["originalCommandVisible", "executionTransportRetained"])
    stdout = [
        raw
        for n, raw in data.items()
        if n.startswith("combined/sdk-processes/") and n.endswith(".stdout") and sha(raw) == actual["stdout_sha256"]
    ]
    assert len(stdout) == 1 and parse(stdout[0]) == result
    bash(data, control, result)
    mcp = control["mcp"]
    assert mcp["outside_signing_key_admitted"] is False and mcp["cleanup_errors"] == []
    upstreams = {s["family"]: s for s in mcp["upstreams"]}
    assert set(upstreams) == {"docs", "mail"}
    for measurement in mcp["measurements"][1:]:
        observed_process(
            measurement["native_proxy"],
            samples,
            native_argv(pin["preparation"]["runtime_prefix"], measurement["family"]),
        )
        assert measurement["relay_proxy_ancestry_verified"] is False
    calls = []
    for front, log in zip(mcp["frontends"], ["011", "013"], strict=True):
        family, relay = front["family"], front["peer"]
        assert front["status"] == "passed" and front["error"] is None
        assert relay["sdk_ancestry_rechecked"] and relay["fixed_relay_argv_verified"]
        identity = relay["peer"]["identity"]
        sdk_process(
            identity,
            samples,
            ["/usr/bin/python3", "/runtime/public/service_relay.py", "--socket", f"/runtime/resources/{family}.sock"],
            relay["executable_sha256"],
        )
        ancestry = relay["peer"]["ancestry"]
        assert ancestry["ancestor_pid"] == peer["identity"]["pid"] and ancestry["hops"] == 1
        assert (
            ancestry["ancestor_start_ticks"] == peer["identity"]["start_ticks"]
            and ancestry["relay_pid"] == identity["pid"]
        )
        upstream = upstreams[family]
        assert upstream["status"] == "closed" and upstream["sdk_builtin_budget_composed"] is True
        assert upstream["shutdown_observation"] is None and upstream["operations"] == (1 if family == "docs" else 0)
        observed_process(
            upstream["peer"],
            samples,
            ["/usr/bin/python3.12", "/product/public/service_relay.py", "--socket", f"/upstream/{family}.sock"],
        )
        for name in ["mnt", "pid", "net", "ipc", "uts", "cgroup"]:
            assert identity["namespaces"][name] != upstream["peer"]["identity"]["namespaces"][name]
        f, u = frames(front), frames(upstream)
        assert all(r["forwarded"] for r in f)
        requests = [r["frame"] for r in f if r["direction"] == "sdk-request"]
        responses = [r["frame"] for r in f if r["direction"] == "native-response"]
        assert requests == [r["frame"] for r in u if r["direction"] == "request"]
        assert responses == [r["frame"] for r in u if r["direction"] == "response"]
        assert requests == lines(data[f"combined/mcp-processes/{log}.mcp-input"])
        assert responses == lines(data[f"combined/mcp-processes/{log}.mcp-output"])
        completion = front["completion"]
        assert completion["exit_code"] == 0 and completion["stderr"] == ""
        assert completion["client"]["host_client_reaped"] and completion["client"]["stderr_complete"]
        for call in [r for r in requests if r.get("method") == "tools/call"]:
            calls.append(call)
            read = next(r for r in responses if r["id"] == call["id"])
            assert result["results"][0]["content"] == read["result"]["content"]
            assert result["results"][0]["toolCallId"] == "sdk-mcp-control"
            assert result["results"][0]["toolName"] == "mcp__docs_read" and result["results"][0]["isError"] is False
    assert len(calls) == 1 and calls[0]["params"] == {"name": "docs.read", "arguments": {"record_id": "developer-spec"}}
    world(data, "combined", mcp, calls)
    for role, value in [("combined", mcp), ("reference", ref)]:
        physical = index["filesystem"][role + "/mcp-world.db"]
        assert physical["uid"] == physical["gid"] == 0 and physical["mode"] == 0o600 and physical["links"] == 1
        assert physical["device"] == value["world"]["device"] and physical["inode"] == value["world"]["inode"]
    effect = index["filesystem"]["combined/workspace/native-contained.txt"]
    assert effect["uid"] == effect["gid"] == 10001 and effect["links"] == 1
    assert effect["device"] == control["effect"]["device"] and effect["inode"] == control["effect"]["inode"]
    budget = control["operation_budget"]
    assert (
        budget["limit"] == 4
        and budget["used"] == 2
        and budget["builtin"] == budget["mcp"] == 1
        and budget["pending"] == []
    )
    event = budget["events"][0]
    assert event["surface"] == "mcp" and event["backend_reached"] and event["response_completed"]
    assert event["frame_sha256"] == digest(calls[0]) and event["request_id"] == calls[0]["id"]
    read = next(
        r["frame"]
        for r in mcp["frontends"][0]["frames"]
        if r["direction"] == "native-response" and r["frame"].get("id") == calls[0]["id"]
    )
    assert event["response_sha256"] == digest(read)
    assert budget["events"][1]["call_id"] == "sdk-contained-control"
    for name in ["worker-tests", "rootfs-tests"]:
        check = parse(data["proof/" + name + ".json"])
        assert check["returncode"] == 0
        assert sha(data["proof/" + name + ".stdout"]) == check["stdout_sha256"]
        assert data["proof/" + name + ".stderr"] == b""
    assert parse(data["proof/worker-tests.json"])["results"] == [["ok", "177", "0", "24"]]
    assert parse(data["proof/rootfs-tests.json"])["results"] == [["ok", "1", "0", "0"], ["ok", "31", "0", "0"]]
    timeout = parse(data["proof/worker-sdk_mcp-replay-timeout.json"])
    assert timeout["worker_returncode"] is None and timeout["both_leases_reacquired"] is True
    assert timeout["retained_worker_files_unchanged"] == 155
    for kind in ["sdk_mcp", "mcp_reference"]:
        reconciled = parse(data["proof/worker-" + kind + "-reconcile-valid.json"])
        assert reconciled["returncode"] == 0 and parse(reconciled["stdout"])["state"] == "terminal"
    return {
        "schema": "hol-gauntlet-native-sdk-mcp-host-readback.v1",
        "rust_source_commit": SOURCE,
        "product_source_sha": pin["source_sha"],
        "job_id": pin["job_id"],
        "report_sha256": REPORT,
        "actual_sdk_mcp_bash_completed": True,
        "frontend_frames": 24,
        "upstream_frames": 24,
        "provider_receipts": 1,
        "kernel_samples": 50,
        "retained_worker_files": 155,
        "native_mcp_regression_passed": True,
        "original_replay_courier_timeout_retained": True,
        "self_generated_receipt_signatures_verified": True,
        "outside_signing_key_admitted": False,
        "execution_eligible": False,
        "guard_causality_verified": False,
        "model_requests": 0,
    }


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: verify_native_sdk_mcp_transport_20261027.py EVIDENCE_DIRECTORY")
    print(json.dumps(verify(Path(sys.argv[1])), sort_keys=True))

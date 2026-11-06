"""Verify the complete composed run and consumed-job refusal before preflight."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import native_sdk_readback_20261027 as sdk
import verify_native_sdk_mcp_transport_20261027 as previous
from verify_native_mcp_transport_20261027 import archive, digest, ineligible, lines, observed_process, parse, sha

SOURCE = "779bc84137430d46c4f98755a561e8b24fa164f7"
REPORT = "33a82fca7a330ecc7b7b3d142c894d500c72bcc48200930c1ca0f38697bab642"
EXPORT = "cc723ac10805ede72f6ca7d70be0317cb88878ff14520ad8e78c50f98e9010dc"


def verify(directory):
    retained = previous.verify(directory)
    assert retained["actual_sdk_mcp_bash_completed"] and retained["original_replay_courier_timeout_retained"]
    data = archive(directory / "native-sdk-mcp-transport-vm-results-002.tar", EXPORT, 993280, 133)
    assert not any("mcp-guard" in n or "mcp-home" in n or "sdk-home" in n for n in data)
    index = parse(data["results.sha256.json"])
    ineligible(index)
    inputs = archive(
        directory / "native-sdk-mcp-transport-input-002.tar",
        "5d681d1931ef718509348420a0ec9f60439187a7a23426ba693aebd05c0dfc42",
        24442880,
        2,
    )
    transfer = parse(inputs["transfer.json"])
    assert transfer == parse(data["input/transfer.json"]) and transfer["source_commit"] == SOURCE
    assert transfer["prior_results_sha256"] == previous.EXPORT
    assert transfer["dependency_input_sha256"] == "331ffceb7c555fec33c7aa5fe030d3e7d06b7c9bf3216a1c916a171593f12a21"
    assert (
        transfer["unchanged_worker_tests_sha256"] == "c5b9069284b971bc82ba47c022545bf44e807915608ed562831e15e10cfa61da"
    )
    raw = inputs["gauntlet-vm-worker"]
    assert raw[:4] == b"\x7fELF" and raw[18:20] == b"\xb7\0"
    assert transfer["files"]["gauntlet-vm-worker"] == {"bytes": len(raw), "sha256": sha(raw)}
    root = Path(__file__).resolve().parents[3]
    changed = subprocess.check_output(
        [
            "git",
            "diff",
            "--name-only",
            previous.SOURCE,
            SOURCE,
            "--",
            "ci/gauntlet-rs/crates",
            "ci/gauntlet-rs/adapters",
            "ci/gauntlet",
        ],
        cwd=root,
    )
    assert changed.decode().splitlines() == ["ci/gauntlet-rs/crates/gauntlet-worker-state/src/native_worker.rs"]
    prelaunch = parse((directory / "native-sdk-mcp-prelaunch-002.json").read_bytes())
    assert prelaunch["source_commit"] == SOURCE
    assert sha((directory / "native-sdk-mcp-proof-courier-002.py").read_bytes()) == prelaunch["courier_sha256"]
    assert prelaunch["courier_sha256"] == "7636bc84f4228ab4abc6cc29f428551df7b0f8c2c16fac02111a9a454f712041"
    pin = prelaunch["pins"]
    assert pin == parse(data["proof/job-sdk_mcp.json"])
    assert pin["worker_generation"] == sha(raw)
    hashes, prior = (parse(data["proof/" + n + ".json"]) for n in ["final-worker-hashes", "prior-worker-hashes"])
    assert len(hashes) == 161 and len(prior) == 155 and all(hashes[n] == h for n, h in prior.items())
    first = archive(directory / "native-sdk-mcp-transport-vm-results-001.tar", previous.EXPORT, 1495040, 208)
    assert prior == parse(first["proof/final-worker-hashes.json"])
    report = sdk.worker(data, "combined", pin, hashes, 0, REPORT)
    assert report["schema"] == "hol-gauntlet-native-worker-report.v5"
    assert report["mcp_agent_absent"] and report["mcp_profile_absent"]
    control = report["controller_report"]
    ineligible(control)
    assert control["status"] == "passed" and control["error"] is None and control["cleanup_errors"] == []
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
    assert samples["errors"] == [] and len(samples["observations"]) == 51
    assert samples["observer_sha256"] == prelaunch["observer_sha256"]
    samples = samples["observations"]
    before, after = parse(data["proof/outside-device-before.json"]), parse(data["proof/outside-device-after.json"])
    assert after.pop("identity_unchanged") and before == after
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
    bun = binding["peer"]
    assert bun["executable_sha256"] == pin["declaration"]["sdk"]["bun_sha256"]
    previous.sdk_process(bun["identity"], samples, sdk.BUN_ARGV.decode().split("\0"), bun["executable_sha256"])
    for name in ["same_uid_negative", "mcp_same_uid_negative"]:
        negative = binding[name]
        assert negative["refused_before_sdk_import"] and negative["unprivileged_result"]["denied"]
        assert negative["outside"]["pid"] != bun["identity"]["pid"]
    actual = control["measurements"]["sdk"]
    assert actual["exit_code"] == 0 and actual["stderr"] == ""
    result = actual["result"]
    assert result["version"] == "18.4.12" and result["uid"] == 10001 and result["syntheticStreamCalls"] == 3
    assert result["mcpExercised"] is True and result["modelExercised"] is result["qualificationEligible"] is False
    assert result["providerRequests"] == 0 and len(result["results"]) == 2 and len(result["resourceTools"]) == 14
    assert all(result["modelContextProjection"][n] for n in ["originalCommandVisible", "executionTransportRetained"])
    stdout = [
        b
        for n, b in data.items()
        if n.startswith("combined/sdk-processes/") and n.endswith(".stdout") and sha(b) == actual["stdout_sha256"]
    ]
    assert len(stdout) == 1 and parse(stdout[0]) == result
    previous.bash(data, control, result)
    for item in control["public_helpers"]["files"]:
        raw = data["combined/sdk-public/" + item["name"]]
        assert sha(raw) == item["sha256"] and len(raw) == item["bytes"]
        assert raw == first["combined/sdk-public/" + item["name"]]
    mcp = control["mcp"]
    assert mcp["outside_signing_key_admitted"] is False and mcp["cleanup_errors"] == []
    upstreams = {s["family"]: s for s in mcp["upstreams"]}
    assert set(upstreams) == {"docs", "mail"}
    for measurement in mcp["measurements"][1:]:
        observed_process(
            measurement["native_proxy"],
            samples,
            previous.native_argv(pin["preparation"]["runtime_prefix"], measurement["family"]),
        )
    calls, read_response = [], None
    for front, log in zip(mcp["frontends"], ["011", "013"], strict=True):
        family, relay = front["family"], front["peer"]
        assert front["status"] == "passed" and front["error"] is None
        assert relay["sdk_ancestry_rechecked"] and relay["fixed_relay_argv_verified"]
        identity, ancestry = relay["peer"]["identity"], relay["peer"]["ancestry"]
        previous.sdk_process(
            identity,
            samples,
            ["/usr/bin/python3", "/runtime/public/service_relay.py", "--socket", f"/runtime/resources/{family}.sock"],
            relay["executable_sha256"],
        )
        assert ancestry["ancestor_pid"] == bun["identity"]["pid"] and ancestry["hops"] == 1
        assert (
            ancestry["ancestor_start_ticks"] == bun["identity"]["start_ticks"]
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
        f, u = previous.frames(front), previous.frames(upstream)
        assert all(r["forwarded"] for r in f)
        requests = [r["frame"] for r in f if r["direction"] == "sdk-request"]
        responses = [r["frame"] for r in f if r["direction"] == "native-response"]
        assert requests == [r["frame"] for r in u if r["direction"] == "request"]
        assert responses == [r["frame"] for r in u if r["direction"] == "response"]
        assert requests == lines(data[f"combined/mcp-processes/{log}.mcp-input"])
        assert responses == lines(data[f"combined/mcp-processes/{log}.mcp-output"])
        assert front["completion"]["exit_code"] == 0 and front["completion"]["stderr"] == ""
        for call in [r for r in requests if r.get("method") == "tools/call"]:
            calls.append(call)
            read_response = next(r for r in responses if r["id"] == call["id"])
            assert result["results"][0]["content"] == read_response["result"]["content"]
            assert result["results"][0]["toolName"] == "mcp__docs_read" and result["results"][0]["isError"] is False
    assert len(calls) == 1 and calls[0]["params"] == {"name": "docs.read", "arguments": {"record_id": "developer-spec"}}
    previous.world(data, "combined", mcp, calls)
    physical = index["filesystem"]["combined/mcp-world.db"]
    assert physical["uid"] == physical["gid"] == 0 and physical["mode"] == 0o600 and physical["links"] == 1
    assert physical["device"] == mcp["world"]["device"] and physical["inode"] == mcp["world"]["inode"]
    budget = control["operation_budget"]
    assert (
        budget["limit"] == 4
        and budget["used"] == 2
        and budget["builtin"] == budget["mcp"] == 1
        and budget["pending"] == []
    )
    event = budget["events"][0]
    assert event["backend_reached"] and event["response_completed"] and event["request_id"] == calls[0]["id"]
    assert event["frame_sha256"] == digest(calls[0]) and event["response_sha256"] == digest(read_response)
    fast = parse(data["proof/fast-replay-summary.json"])
    ineligible(fast)
    assert (
        fast["source_commit"] == SOURCE
        and fast["job_id"] == pin["job_id"]
        and fast["worker_generation"] == pin["worker_generation"]
    )
    assert fast["legacy_lock_held_for_all_probes"] and fast["replay_refused_before_host_preflight"]
    assert (
        fast["reconcile_original_terminal"]
        and fast["wrong_request_pin_refused"]
        and fast["worker_files_unchanged"] == 161
    )
    assert (
        sha((directory / "native-sdk-mcp-fast-replay-courier-002.py").read_bytes())
        == "fffbaf1594dc5cbc346cb2d9877bec646e86ab0ecb2ad95437bcfadd6f9efc76"
    )
    replay = parse(data["proof/worker-replay-legacy-busy.json"])
    assert (
        replay["returncode"] == 2
        and replay["stderr"] == "native worker unavailable: job ID was already reserved for execution\n"
    )
    assert replay["elapsed_ms"] == fast["replay_elapsed_ms"] < 10000
    reconciled = parse(data["proof/worker-reconcile-legacy-busy.json"])
    assert reconciled["returncode"] == 0 and parse(reconciled["stdout"])["report_sha256"] == REPORT
    refused = parse(data["proof/worker-wrong-request-pin-legacy-busy.json"])
    assert (
        refused["returncode"] == 2
        and refused["stderr"] == "native worker unavailable: native deployment differs from outside pin\n"
    )
    return {
        "schema": "hol-gauntlet-native-sdk-mcp-replay-host-readback.v1",
        "rust_source_commit": SOURCE,
        "product_source_sha": pin["source_sha"],
        "job_id": pin["job_id"],
        "report_sha256": REPORT,
        "actual_sdk_mcp_bash_completed": True,
        "frontend_frames": 24,
        "upstream_frames": 24,
        "provider_receipts": 1,
        "kernel_samples": 51,
        "retained_worker_files": 161,
        "replay_refused_with_legacy_lock_held": True,
        "replay_elapsed_ms": replay["elapsed_ms"],
        "self_generated_receipt_signatures_verified": True,
        "outside_signing_key_admitted": False,
        "execution_eligible": False,
        "guard_causality_verified": False,
        "model_requests": 0,
    }


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: verify_native_sdk_mcp_replay_20261027.py EVIDENCE_DIRECTORY")
    print(json.dumps(verify(Path(sys.argv[1])), sort_keys=True))

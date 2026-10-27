#!/usr/bin/env python3
"""Read the fresh SDK init-label diagnostic; no launch, repair or admission."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

import verify_native_current_worker_20261026 as v


def verify(base):
    data = v.exported(
        base / "native-sdk-transport-vm-results-031.tar",
        "8085e7a61b57da58723571061772dc213a36c87e785d61ec5c5bdd6936f08e61",
        80,
    )
    prior = v.exported(
        base / "native-sdk-transport-vm-results-030.tar",
        "7ac9557ca0a4082d621269efad32db1ff39cc26430f20b13ed6b17324925e3c2",
        84,
    )
    inputs = v.archive(
        base / "native-sdk-transport-input-030.tar",
        "de1bc1538091b4e5c0c5b6c4d1ca319947971b1da779f1be53719f46fe192e1d",
        5,
    )
    transfer = v.parse(inputs.pop("transfer.json"))
    assert transfer["source_commit"] == "2213e73f80ccf61d8d7be3a2b7b9cedbf924af12"
    assert v.parse(data["input/transfer.json"]) == transfer
    assert set(inputs) == set(transfer["files"])
    for name, raw in inputs.items():
        assert v.sha(raw) == transfer["files"][name]["sha256"] and len(raw) == transfer["files"][name]["bytes"]
    jobs, proof = v.parse(data["proof/native-sdk-jobs.json"]), v.parse(data["proof/proof.json"])
    assert jobs["prior_worker_hashes"] == v.parse(prior["proof/proof.json"])["worker_hashes"]
    assert len(jobs["prior_worker_hashes"]) == 88
    assert len(proof["worker_hashes"]) == proof["worker_files"] == 94
    assert all(proof["worker_hashes"][n] == h for n, h in jobs["prior_worker_hashes"].items())
    prelaunch_raw = v.stable(base / "native-sdk-transport-host-prelaunch-031.json")
    assert v.sha(prelaunch_raw) == "43b9f0714660880c464bc9ccf2219cf93167a3d664b0cd698934967837deac5f"
    prelaunch = v.parse(prelaunch_raw)
    assert prelaunch["records"] == jobs["records"] and prelaunch["prior_worker_hashes"] == jobs["prior_worker_hashes"]
    assert prelaunch["reused_input_generation"] == proof["reused_input_generation"] == "030"
    job = jobs["records"]["sdk_transport"]
    assert job["worker_generation"] == prelaunch["worker_generation"] == v.sha(inputs["gauntlet-vm-worker"])
    assert v.sha(data["sdk_transport/preparation.v1.json"]) == job["preparation_sha256"]
    assert v.sha(data["sdk_transport/declaration.json"]) == job["deployment_sha256"]
    report_raw = data["sdk_transport/worker/report.json"]
    assert v.sha(report_raw) == "648bfcf3bd9feab01dc0ed95180ca009370929b9239fd54823360a5c3a5c3f0e"
    report, terminal = v.parse(report_raw), v.parse(data["sdk_transport/worker/terminal.json"])
    assert terminal["report_sha256"] == v.sha(report_raw)
    assert report["exit_code"] == terminal["exit_code"] == 2
    assert report["status"] == terminal["status"] == "invalid-evidence"
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
    assert controller["error"] == "SDK named unconfined template label differs"
    assert not controller["sdk_exercised"] and controller["requests"] == controller["plane"]["executions"] == []
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
    kernel = v.parse(data["proof/outside-kernel.json"])
    assert kernel["errors"] == [] and len(kernel["observations"]) == 16
    samples = [s for s in kernel["observations"] if s["status"]["Uid"].startswith("10001")]
    assert len(samples) == 1
    sample, agent = samples[0], controller["agent"]
    assert sample == proof["outside_sdk_init"]
    assert sample["pidfd_held"] and sample["pid"] == agent["kernel"]["pid"]
    assert sample["start_ticks"] == agent["kernel"]["start_ticks"]
    assert sample["cgroup"] == agent["kernel"]["cgroup"]
    assert (
        sample["cgroup"]
        == "/holgauntletrust" + job["job_id"] + ".slice/libpod-" + agent["container_id"] + ".scope/container"
    )
    assert sample["lsm_label"] == "crun//&" + agent["name"] + " (unconfined)"
    assert sample["executable_sha256"] == "5b814cc93d7f2110d40c936f5f86a6135de783ae2a28afe25eabac4ecc25bf10"
    assert sample["status"]["NoNewPrivs"] == "1" and sample["status"]["Seccomp"] == "2"
    assert int(sample["status"]["Seccomp_filters"]) > 0
    assert sample["status"]["Uid"] == sample["status"]["Gid"] == "10001\t10001\t10001\t10001"
    assert all(sample["status"][n] == "0000000000000000" for n in ["CapAmb", "CapBnd", "CapEff", "CapInh", "CapPrm"])
    assert sample["limits"] == {"memory.max": "2147483648", "pids.max": "256", "cpu.max": "200000 100000"}
    assert agent["inspection"]["State"]["Pid"] == sample["pid"] and agent["cleanup_complete"]
    for name in ["native-supervisor-events.v1.jsonl", "native-image-events.v1.jsonl"]:
        rows = v.chain(data["sdk_transport/cell/" + name])
        if name.startswith("native-supervisor"):
            assert rows[-2]["kind"] == "terminal-cleanup" and rows[-2]["data"]["failures"] == []
            assert rows[-1]["kind"] == "rust-image-cleanup"
    for value in [report, controller, proof]:
        assert (
            not value["execution_eligible"] and not value["guard_causality_verified"] and value["model_requests"] == 0
        )
    for action in ["replay", "reconcile"]:
        result = v.parse(data["proof/worker-sdk_transport-" + action + ".json"])
        if action == "replay":
            assert result["returncode"] == 2
        else:
            value = v.parse(result["stdout"])
            assert result["returncode"] == 0 and value["state"] == "terminal"
            assert value["report_sha256"] == v.sha(report_raw) and value["exit_code"] == 2
    return {
        "schema": "hol-gauntlet-host-native-sdk-runtime-stack.v1",
        "export_members_verified": 80,
        "reused_input_generation": "030",
        "worker_files_preserved": 94,
        "outside_init_label": sample["lsm_label"],
        "sdk_exercised": False,
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

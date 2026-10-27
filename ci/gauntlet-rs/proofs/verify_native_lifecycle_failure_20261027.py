"""Preserve the genuine timeout that lacked independently joined readiness."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import native_sdk_readback_20261027 as sdk
from verify_native_mcp_transport_20261027 import archive, ineligible, parse, sha


def verify(directory):
    data = archive(
        directory / "native-role-controls-vm-results-006-timeout.tar",
        "5de76f155752e62d3655b75329ee30076c7d248e06cd4e4923d43274974f4652",
        1034240,
        138,
    )
    inputs = archive(
        directory / "native-role-controls-input-006.tar",
        "a95132642bd3719c58e8a39b14b5d9d952815bfdc66a88aad8931b1e1b7f4caf",
        65863680,
        5,
    )
    transfer = parse(inputs.pop("transfer.json"))
    assert transfer == parse(data["input/transfer.json"])
    assert transfer["source_commit"] == "f01deadbe43e31e41f4a6f93c540dbe31b2b8f0d"
    for name, raw in inputs.items():
        assert transfer["files"][name] == {"bytes": len(raw), "sha256": sha(raw)}
        assert raw[:4] == b"\x7fELF" and raw[18:20] == b"\xb7\0"
    prelaunch = parse((directory / "native-role-controls-prelaunch-006-timeout.json").read_bytes())
    assert prelaunch["courier_sha256"] == sha(
        (directory / "native-role-controls-proof-courier-006-timeout.py").read_bytes()
    )
    assert prelaunch["courier_sha256"] == "d32dc02e03658f51f285e9470387ae2e27b4f8f68444e1f1c8f5fa80799becca"
    assert prelaunch["observer_sha256"] == sha((directory / "native-role-lifecycle-observer-001.py").read_bytes())
    pin = prelaunch["pins"]
    assert pin == parse(data["proof/job-timeout.json"]) and pin["worker_generation"] == sha(
        inputs["gauntlet-vm-worker"]
    )
    hashes, prior = (parse(data["proof/" + n + ".json"]) for n in ["final-worker-hashes", "prior-worker-hashes"])
    assert len(hashes) == 197 and len(prior) == 191 and all(hashes[n] == h for n, h in prior.items())
    report = sdk.worker(
        data, "combined", pin, hashes, 2, "cd3ae78714048cca7af33152f6f1de94ec92c8d733bb3dd08fc3d01b6bab6e0f"
    )
    control = report["controller_report"]
    ineligible(control)
    assert control["status"] == "failed" and control["control_role"] == "timeout"
    assert control["qualified_role_complete"] is False
    lifecycle = control["router"]["lifecycle"]
    assert lifecycle["capture_exit_code"] == 124 and lifecycle["capture_error"] is None
    assert lifecycle["ready"] is lifecycle["detached_child"] is lifecycle["detached_child_dead"] is None
    assert lifecycle["late_effect_absent"] is None and lifecycle["status"] == "failed"
    assert lifecycle["error"] == "actual detached child was not observed before control termination"
    assert "sdk" not in control["measurements"] and control["effect"] is None
    assert all(
        report[k]
        for k in [
            "product_slice_absent",
            "image_lease_absent",
            "sdk_agent_absent",
            "sdk_profile_absent",
            "mcp_agent_absent",
            "mcp_profile_absent",
        ]
    )
    physical = parse(data["combined/physical-lifecycle-absence.json"])
    assert physical["absent"] == ["detached-ready.json", "detached-ready.pending", "late-detached-effect.txt"]
    samples = parse(data["proof/outside-kernel.json"])
    assert samples["errors"] == [] and len(samples["observations"]) == 66
    assert samples["observer_sha256"] == prelaunch["observer_sha256"]
    children = [r for r in samples["observations"] if "hol-gauntlet-native-detached-timeout-" in r["argv_utf8"]]
    assert (
        len(children) == 1
        and children[0]["executable_sha256"] == "c86f21d0da9290ece2d7d49a3f7ed52aed59cb029abdf0ea25c79634f6cbe960"
    )
    assert children[0]["namespace_pids"][-1] == 4 and children[0]["pidfd_held"]
    assert parse(data["proof/worker-tests.json"])["results"] == [["ok", "179", "0", "24"]]
    assert parse(data["proof/rootfs-tests.json"])["results"] == [["ok", "1", "0", "0"], ["ok", "36", "0", "0"]]
    replay = parse(data["proof/fast-replay-summary.json"])
    assert replay["worker_files_unchanged"] == 197 and replay["reconcile_original_terminal"]
    return {
        "schema": "hol-gauntlet-native-lifecycle-failure-readback.v1",
        "job_id": pin["job_id"],
        "actual_timeout_exit": 124,
        "outside_child_start_observed": True,
        "published_readiness_observed": False,
        "failure_preserved": True,
        "worker_files_preserved": 197,
        "execution_eligible": False,
        "guard_causality_verified": False,
        "model_requests": 0,
    }


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: verify_native_lifecycle_failure_20261027.py EVIDENCE_DIRECTORY")
    print(json.dumps(verify(Path(sys.argv[1])), sort_keys=True))

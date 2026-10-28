#!/usr/bin/env python3
"""Verify SDK diagnostic 035, including an actual outside post-exec Bun sample."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

import native_sdk_readback_20261027 as sdk
import verify_native_current_worker_20261026 as v
import verify_native_sdk_bash_custody_20261027 as previous

SOURCE = "d4d81a4bf74666556f2a6bbb626c5dccf65b16f4"
OBSERVER = "a2d8610ea73617e7349c36d15ad0c8ff0e0a44b70a1e66e6077fe23dc9f78568"
COURIER = "9de7056efffb2b84ff4bb94aca70885e0fb3d78c3db8401d0cb376eb75065e5f"
EXPORT = "fa75f7621aa51e8127ec05515f0b8ada1d50c8d85e313f20592aad935371650d"
MEMBERS = 119


def verify(base):
    retained = previous.verify(base)
    assert retained["full_diagnostic_passed"] is False
    old = v.exported(
        base / "native-sdk-transport-vm-results-034.tar",
        "b85d2c58faff9dbcf00d7e190d3efa26ce8cf30d884c7c7e8f0a3f5256f03deb",
        126,
    )
    data = v.exported(base / "native-sdk-transport-vm-results-035.tar", EXPORT, MEMBERS)
    inputs = v.archive(
        base / "native-sdk-transport-input-035.tar",
        "a121db96c380db95d0fc9230ec7817cde2138dc3332be6f3e87453323610d9ed",
        5,
    )
    transfer = v.parse(inputs.pop("transfer.json"))
    assert transfer["source_commit"] == SOURCE
    assert transfer["outside_observer_sha256"] == OBSERVER
    assert v.parse(data["input/transfer.json"]) == transfer
    assert set(inputs) == set(transfer["files"])
    for name, raw in inputs.items():
        assert v.sha(raw) == transfer["files"][name]["sha256"] and len(raw) == transfer["files"][name]["bytes"]
    jobs, proof = v.parse(data["proof/native-sdk-jobs.json"]), v.parse(data["proof/proof.json"])
    expected = v.parse(old["proof/proof.json"])["worker_hashes"]
    assert len(expected) == 117 and jobs["prior_worker_hashes"] == expected
    assert len(proof["worker_hashes"]) == proof["worker_files"] == 129
    assert all(proof["worker_hashes"][n] == h for n, h in expected.items())
    prelaunch_raw = v.stable(base / "native-sdk-transport-host-prelaunch-035.json")
    assert v.sha(prelaunch_raw) == "e348f79572e9d30467fb0701189fe79ea9409684422b177191dad8f16447b091"
    prelaunch = v.parse(prelaunch_raw)
    assert prelaunch["source_commit"] == jobs["source_commit"] == SOURCE
    assert prelaunch["records"] == jobs["records"] and prelaunch["prior_worker_hashes"] == expected
    assert prelaunch["worker_generation"] == v.sha(inputs["gauntlet-vm-worker"])
    assert prelaunch["fixture"]["sha256"] == v.sha(data["sdk_transport/fixture/test_control.py"])
    assert prelaunch["outside_observer_sha256"] == jobs["outside_observer_sha256"] == OBSERVER
    assert prelaunch["proof_courier_sha256"] == COURIER
    assert v.sha(v.stable(base / "native-sdk-transport-proof-courier-035.py")) == COURIER
    assert v.sha(v.stable(Path(__file__).with_name("native_sdk_kernel_sampler_20261027.py"))) == OBSERVER
    kernel = v.parse(data["proof/outside-kernel.json"])
    assert kernel["schema"] == "hol-gauntlet-outside-native-sdk-kernel.v2"
    assert kernel["observer_sha256"] == OBSERVER and not kernel["errors"]
    primary = sdk.worker(
        data,
        "sdk_transport",
        jobs["records"]["sdk_transport"],
        proof["worker_hashes"],
        0,
        "b49631bde77b3f3150d2f22f357743a4d3c0ae490f209786102afbbed369cd2e",
    )
    negative = sdk.worker(
        data,
        "wrong_sdk_publication",
        jobs["records"]["wrong_sdk_publication"],
        proof["worker_hashes"],
        2,
        "a7b46fe7a24850b31be7266cab0eaca45ba65fb36fd5c8ab1ceb916920007ad2",
    )
    assert negative["controller_report"] is None
    controller = primary["controller_report"]
    exchange = sdk.sdk_exchange(data, transfer, controller)
    assert exchange["outside_bun_executable_observed"]
    assert controller["status"] == "passed" and controller["error"] is None and controller["cleanup_errors"] == []
    assert controller["host_null_check"] == "identity-and-permissions-v1"
    assert controller["host_null_identity_unchanged"] is True
    before, after = controller["host_null_before"], controller["host_null_after"]
    for n in ["device", "inode", "uid", "gid", "mode", "links", "major", "minor"]:
        assert before[n] == after[n]
    assert before["uid"] == before["gid"] == 0
    final_device = v.parse(data["proof/outside-final-device.json"])
    for n in ["device", "inode", "uid", "gid", "mode"]:
        assert final_device[n] == before[n]
    tests = v.parse(data["proof/root-tests.json"])
    assert tests["gauntlet-worker-tests"]["results"] == [["ok", "157", "0", "24"]]
    assert tests["gauntlet-rootfs-tests"]["results"] == [["ok", "1", "0", "0"], ["ok", "31", "0", "0"]]
    for name, check in tests.items():
        assert check["returncode"] == 0 and v.sha(data["proof/" + name + ".log"]) == check["sha256"]
    for role in jobs["records"]:
        for action in ["replay", "reconcile"]:
            result = v.parse(data["proof/worker-" + role + "-" + action + ".json"])
            if action == "replay":
                assert result["returncode"] == 2
            else:
                value = v.parse(result["stdout"])
                assert result["returncode"] == 0 and value["state"] == "terminal"
                assert value["exit_code"] == (0 if role == "sdk_transport" else 2)
                assert value["report_sha256"] == proof["cases"][role]["report_sha256"]
    assert not proof["execution_eligible"] and not proof["guard_causality_verified"] and proof["model_requests"] == 0
    return {
        "schema": "hol-gauntlet-host-native-sdk-benign.v1",
        **exchange,
        "source_commit": SOURCE,
        "export_members_verified": MEMBERS,
        "worker_files_preserved": 129,
        "prior_failed_attempt_and_recovery_verified": True,
        "full_diagnostic_passed": True,
        "host_device_identity_preserved": True,
        "wrong_publication_refused": True,
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

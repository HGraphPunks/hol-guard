"""Read native ARM unit and actual Rust archive-grader results; grant no admission."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from verify_native_mcp_transport_20261027 import archive, parse, sha

SOURCE = "575c83a918a04aadb8d57676ced0a3721065cf0a"
INPUT = "70e94155d3b1210db4108ca8f68cf7a6c7cf8e2b9c942909c9f29980975c67b1"
EXPORT = "01ca467cf85dbed6391bbe92d5645078fad2cb07b19978999452cb02268fefd2"
MAC_PROOF = "72242b0d6a4120677fb5de5bcd3eb8c57d838cb5cb868d5435c34fbe343f7f18"
BINS = {
    "evidence-tests": (21918040, "88355e46041e0a19ce85050661ee6b275103a20111cfc031e8455638d5602778"),
    "rootfs-tests": (9698104, "d1a4e4ed407413dea6869448882b8dce0fd662fd6f64266ed35980d732e3fc47"),
    "worker-tests": (27960840, "203bd4b99e10dcdadfb427505176dcec56d0620ddd461d486fe197d079330a88"),
    "verifier": (7751792, "108c8f1361be7ff6109f83756b3135d7bb87710ea8b3e3c9d13433f02dc8ba7b"),
}
UNITS = [
    ("capture-stream-tests", "evidence-tests", "native_capture_stream::tests", 2),
    ("lifecycle-fixture-tests", "evidence-tests", "native_lifecycle_fixture::tests", 2),
    ("product-kernel-tests", "evidence-tests", "native_product_kernel::tests", 2),
    ("control-ledger-test", "evidence-tests", "native_control_diagnostic::tests", 1),
    ("native-request-tests", "rootfs-tests", "native_request::tests", 2),
    (
        "dependency-prefix-test",
        "worker-tests",
        "dependency_prefix_write::tests::real_export_materializes_without_pth_execution_and_replay_is_inert",
        1,
    ),
    (
        "console-launcher-test",
        "worker-tests",
        "native_candidate_launchers::tests::writer_preserves_all_alias_bytes_on_replay_and_refuses_foreign_metadata",
        1,
    ),
]
ROLES = ["success", "input-binding", "injection", "boundary", "timeout", "cancel"]
REFUSALS = ["wrong-archive-pin", "wrong-interpreter", "wrong-observer", "wrong-role", "cross-job"]


def ineligible(value):
    assert value["execution_eligible"] is False and value["model_requests"] == 0
    if "guard_causality_verified" in value:
        assert value["guard_causality_verified"] is False


def verify(directory):
    inputs = archive(directory / "native-control-arm-input-002.tar", INPUT, 77967360, 24)
    data = archive(directory / "native-control-arm-vm-results-002.tar", EXPORT, 256000, 69)
    mac_raw = (directory / "native-control-artifact-proof-001.json").read_bytes()
    assert len(mac_raw) == 18455 and sha(mac_raw) == MAC_PROOF
    mac = parse(mac_raw)
    assert mac["verifier_source_commit"] == SOURCE and len(mac["cases"]) == 81
    transfer = parse(inputs["transfer.json"])
    assert transfer == parse(data["transfer.json"]) and transfer["source_commit"] == SOURCE
    assert set(transfer["files"]) == set(inputs) - {"transfer.json"}
    for name, pin in transfer["files"].items():
        assert pin == {"bytes": len(inputs[name]), "sha256": sha(inputs[name])}
    for name, (size, pin) in BINS.items():
        raw = inputs[name]
        assert len(raw) == size and sha(raw) == pin and raw[:4] == b"\x7fELF" and raw[18:20] == b"\xb7\0"
    jobs = parse(inputs["jobs.json"])
    assert jobs["verifier_source_commit"] == SOURCE
    assert jobs["original_execution_source"] == "f53bc490f7483ad41a781d62dc4d0d2c6a47c6a9"
    assert set(jobs["jobs"]) == set(ROLES)
    assert jobs["copied_public_pin_records_are_fixtures"] is True and jobs["fresh_product_execution"] is False
    for role, job in jobs["jobs"].items():
        assert job["expected_stdout_sha256"] == mac["actual_readback_sha256"][role]
        for field in ["archive", "completion", "pin"]:
            assert sha(inputs[job[field]]) == job[field + "_sha256"]
        assert job["pin"] == "pins/" + job["job_id"] + ".controller-key-pin.json"
    install, proof = parse(data["install.json"]), parse(data["proof.json"])
    assert install["source_commit"] == proof["source_commit"] == SOURCE
    assert install["root_owned"] is True and install["files"] == transfer["files"]
    assert install["input_sha256"] == proof["input_sha256"] == INPUT
    for value in [transfer, jobs, install, proof, mac]:
        ineligible(value)
    for value in [transfer, install, proof]:
        assert value["copied_public_pin_records_are_fixtures"] is True
    assert proof["fresh_product_execution"] is False and proof["worker_files_preserved"] == 284
    assert proof["both_worker_leases_held"] is True and proof["owned_product_cgroups_absent"] is True
    assert proof["all_input_files_unchanged"] is True
    assert proof["unit_tests_passed"] == 11 and proof["actual_archive_readbacks"] == 6
    assert proof["identical_restarts"] == 6 and proof["refusals"] == 5
    metadata = parse(data["results.sha256.json"])["filesystem"]
    assert set(metadata) == set(data) - {"results.sha256.json"}
    for item in metadata.values():
        assert item["uid"] == item["gid"] == 0 and item["mode"] == 0o400 and item["links"] == 1
        assert item["device"] > 0 and item["inode"] > 0
    assert len(proof["unit_results"]) == len(UNITS)
    for position, (label, name, selector, count) in enumerate(UNITS):
        result = parse(data[label + ".json"])
        assert result == proof["unit_results"][position]
        assert result["source_commit"] == SOURCE and result["executable_sha256"] == BINS[name][1]
        assert result["filter"] == selector and result["returncode"] == 0
        assert result["results"] == [["ok", str(count), "0", "0"]]
        assert result["log_sha256"] == sha(data[label + ".log"])
        assert re.findall(
            rb"test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored", data[label + ".log"]
        ) == [(b"ok", str(count).encode(), b"0", b"0")]
        ineligible(result)
    cases = [(prefix + role, role, 0) for role in ROLES for prefix in ["actual-", "restart-"]]
    cases += [(name, "success", 2) for name in REFUSALS]
    assert len(proof["cli_results"]) == len(cases)
    for position, (label, role, code) in enumerate(cases):
        result = parse(data[label + ".json"])
        assert result == proof["cli_results"][position]
        assert result["case"] == label and result["role"] == role and result["returncode"] == code
        assert result["source_commit"] == SOURCE and result["verifier_sha256"] == BINS["verifier"][1]
        assert result["stdout_sha256"] == sha(data[label + ".stdout"])
        assert result["stderr_sha256"] == sha(data[label + ".stderr"])
        assert result["same_stdout_as_mac"] == (code == 0)
        if code == 0:
            assert result["stdout_sha256"] == mac["actual_readback_sha256"][role] and not data[label + ".stderr"]
            value = parse(data[label + ".stdout"])
            ineligible(value)
            relation = value["control_artifacts"]["relations"]
            ineligible(relation)
            assert relation["qualified_role_complete"] is False and relation["outside_signing_key_admitted"] is False
            assert relation["outside_child_death_observed"] is False
        else:
            assert not data[label + ".stdout"] and data[label + ".stderr"]
        ineligible(result)
    return {
        "schema": "hol-gauntlet-native-control-arm-host-readback.v1",
        "rust_source_commit": SOURCE,
        "input_sha256": INPUT,
        "export_sha256": EXPORT,
        "native_unit_tests": 11,
        "actual_archive_readbacks": 6,
        "byte_identical_mac_readbacks_and_restarts": 12,
        "refusals": 5,
        "retained_worker_files_unchanged": 284,
        "copied_public_pin_records_are_fixtures": True,
        "fresh_product_execution": False,
        "outside_signing_key_admitted": False,
        "qualified_role_complete": False,
        "execution_eligible": False,
        "guard_causality_verified": False,
        "model_requests": 0,
    }


if __name__ == "__main__":
    if not __debug__ or len(sys.argv) != 2:
        raise SystemExit("usage (assertions enabled): verify_native_control_arm_20261027.py EVIDENCE_DIRECTORY")
    print(json.dumps(verify(Path(sys.argv[1])), sort_keys=True))

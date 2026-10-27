"""Independently reauthenticate public v7 diagnostics; never grant admission."""

from __future__ import annotations

import base64
import json
import os
import stat
import sys
from pathlib import Path

import verify_native_lifecycle_control_20261027 as lifecycle
import verify_native_request_bindings_20261027 as binding
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from verify_native_boundary_control_20261027 import read_boundary_control
from verify_native_forbidden_control_20261027 import observation as forbidden
from verify_native_injection_control_20261027 import read_injection_control
from verify_native_mcp_transport_20261027 import canonical, digest, parse, sha

SOURCE = "f53bc490f7483ad41a781d62dc4d0d2c6a47c6a9"
COURIER = "c495242bf61d858976fc03832423a37b9727ec6b3002e601f351b3f24a552d6d"
PROOFS = {
    "cancel": {
        "report": "2657c493d6b73609e3b12419bc55fe00b6bd1364c26a356ff9154f5e3a101340",
        "export": ("247c6c2b808746acbc1b2fba383accb981b0958e0a0c4e18d5a5b17964b3cf5d", 1259520, 138),
        "prior": 277,
        "final": 284,
        "samples": 60,
    },
    "timeout": {
        "report": "69eacb8ddc945afefa6ec344b9cdf98af3ac305c1faad03b2ff1fbf4b8dea605",
        "export": ("08f5980f79304782597357a473fb541ae824ecbac0fcdfd2e8c096938f49a39d", 1310720, 140),
        "prior": 270,
        "final": 277,
        "samples": 64,
    },
    "boundary": {
        "report": "783ab402b2115c6689c04aa165c0be423aa9b013a1f1e94f4b45ae5d8993f545",
        "export": ("f6f838f80636da3a73afe36ca4272f6113fc8c2c82b449d0c26f114f88842670", 1341440, 151),
        "prior": 263,
        "final": 270,
        "samples": 65,
    },
    "injection": {
        "report": "31efb131ee33a38031001a1cb99ee8f5a98fd2f550f693bb88f54deb81621887",
        "export": ("86e4cb80869229a39e42a4f2d1fc599016bda2dc5d2bde07eed051b56205a652", 1413120, 152),
        "prior": 256,
        "final": 263,
        "samples": 75,
    },
    "success": {
        "report": "9db4288246e3f47f442ec5491a785ad63480b11230503e232e63cbbc70485e8c",
        "export": ("0c455bb6a6d18766ceca8773ad4ed7b8c1a931863d5dc45d6bbfba25d8afed30", 1280000, 141),
        "prior": 242,
        "final": 249,
        "samples": 66,
    },
    "input-binding": {
        "report": "47b04b9caca697c0397199bc5566664be23dc2bf792c5dab207533b9544bc09f",
        "export": ("5b9eb3ca04063bfb535dbc09f133ee8fb1409fa3b897964c46b8da2963aece94", 1587200, 172),
        "prior": 249,
        "final": 256,
        "samples": 90,
    },
}


def host_pin(directory, pin):
    root = directory / "native-host-keyed-host-pins-001"
    s = root.lstat()
    assert stat.S_ISDIR(s.st_mode) and s.st_uid == os.geteuid() and stat.S_IMODE(s.st_mode) == 0o700
    path = root / (pin["job_id"] + ".controller-key-pin.json")
    before = path.lstat()
    assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1
    assert before.st_uid == os.geteuid() and stat.S_IMODE(before.st_mode) == 0o600
    raw = path.read_bytes()
    after = path.lstat()
    assert (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) == (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    value = parse(raw)
    assert raw == canonical(value) and len(value) == 8
    assert value["schema"] == "hol-gauntlet-host-controller-key-pin.v1"
    return value, raw


def authenticate(directory, control, data, pin):
    retained, raw = host_pin(directory, pin)
    report = parse(data["combined/worker/report.json"])
    started = parse(data["combined/worker/started.json"])
    key = parse(data["combined/worker/controller-key.json"])
    terminal = parse(data["combined/worker/terminal.json"])
    result = parse(
        (directory / ("native-host-keyed-host-run-001-" + pin["declaration"]["role"] + ".stdout")).read_bytes()
    )
    assert result["readback_error"] is None and result["operation"] == "run"
    assert result["host_pin"] == {**retained, "raw_sha256": sha(raw), "execution_eligible": False}
    assert result["readback"]["host_pin_sha256"] == sha(raw)
    assert result["completion"] == {
        "schema": "hol-gauntlet-native-host-pinned-completion.v1",
        "started": started,
        "controller_key_pin": key,
        "terminal": terminal,
        "terminal_sha256": sha(data["combined/worker/terminal.json"]),
        "report": report,
        "execution_eligible": False,
        "guard_causality_verified": False,
        "model_requests": 0,
    }
    for value in [started, key, terminal]:
        assert value["controller_public_key_hex"] == retained["controller_public_key_hex"]
    assert retained["started_marker_sha256"] == sha(data["combined/worker/started.json"])
    assert retained["controller_key_pin_sha256"] == sha(data["combined/worker/controller-key.json"])
    for field in ["source_sha", "job_id", "worker_generation"]:
        assert retained[field] == pin[field]
    assert retained["deployment_digest"] == pin["deployment_sha256"]
    prepared = {**retained, "schema": "hol-gauntlet-controller-prepared.v1"}
    envelope_raw = data["combined/worker/native.stdout"]
    assert envelope_raw.decode() == report["controller_envelope_utf8"]
    envelope = parse(envelope_raw)
    assert set(envelope) == {"record", "signature"}
    record = envelope["record"]
    assert record == {
        "schema": "hol-gauntlet-native-controller-record.v1",
        "prelaunch": prepared,
        "preparation_sha256": pin["preparation_sha256"],
        "control_role": pin["declaration"]["role"],
        "controller_report": control,
    }
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(retained["controller_public_key_hex"])).verify(
        base64.b64decode(envelope["signature"], validate=True), canonical(record)
    )
    signature = report["controller_signature_verification"]
    assert signature == result["readback"]["controller_signature"]
    assert signature["envelope_sha256"] == sha(envelope_raw) and signature["record_sha256"] == digest(record)
    assert signature["signature_verified"] is True and signature["independent_effects_scored"] is False
    assert (
        signature["qualified_role_complete"]
        is signature["execution_eligible"]
        is signature["guard_causality_verified"]
        is False
    )
    assert report["controller_signature_error"] is None
    custody = report["prelaunch_custody"]
    assert custody["prepared"] == prepared and custody["host_ack_received_before_controller_spawn"] is True
    ack = {
        "schema": "hol-gauntlet-controller-prelaunch-ack.v1",
        "job_id": pin["job_id"],
        "prepared_sha256": digest(prepared),
        "host_pin_record_sha256": sha(raw),
    }
    assert custody["acknowledgement_sha256"] == digest(ack)
    outside = parse(data["proof/outside-controller.json"])
    assert outside["errors"] == [] and len(outside["observations"]) == 1
    actual = outside["observations"][0]
    assert (
        control["controller_identity"]
        == report["controller"]
        == {"pid": actual["pid"], "start_ticks": actual["start_ticks"]}
    )
    assert actual["pidfd_held"] and actual["executable_sha256"] == pin["worker_generation"]
    expected_argv = [
        "gauntlet-vm-worker",
        "--native-keyed-controller",
        pin["source_sha"],
        pin["job_id"],
        pin["deployment_sha256"],
        pin["worker_generation"],
    ]
    assert actual["argv"] == expected_argv and actual["argv_sha256"] == sha(("\0".join(expected_argv) + "\0").encode())
    assert actual["cgroup"] == "0::/system.slice/hol-gauntlet-rust-job-" + pin["job_id"]
    assert actual["status"] == {"Uid": "0\t0\t0\t0", "Gid": "0\t0\t0\t0", "Groups": "", "NoNewPrivs": "1"}
    return sha(raw)


def unit_proof(data):
    for name, results, log_pin in [
        (
            "worker-tests",
            [["ok", "186", "0", "24"]],
            "770ae71dd6abc4511c1eab21de6c184814e6da3d18e1974f436f5569d81aa927",
        ),
        (
            "evidence-tests",
            [["ok", "64", "0", "0"]],
            "e843c308ccf45f32b5fd301a43b007f541a224393ea1a0ba04684a358021c622",
        ),
        (
            "rootfs-tests",
            [["ok", "1", "0", "0"], ["ok", "40", "0", "0"]],
            "690359ba4bfc07b7341d7e70a444c3bbc1a473b6b90066b89f7130608d70df1e",
        ),
    ]:
        result = parse(data["unit/" + name + ".json"])
        assert result["returncode"] == 0 and result["results"] == results
        assert result["log_sha256"] == sha(data["unit/" + name + ".log"]) == log_pin
        assert result["executable_sha256"] == parse(data["input/transfer.json"])["files"][name]["sha256"]


def verify(directory, role):
    expected = PROOFS[role]
    proof = {
        **expected,
        "source": SOURCE,
        "index": "001-" + role,
        "input_file": "native-host-keyed-input-001.tar",
        "input": ("f554628652863c1e03a53b94cab2346ca3cd671569c2322930fa6a9e8da0b435", 83179520, 6),
        "export_file": "native-host-keyed-vm-results-001-" + role + ".tar",
        "prelaunch_file": "native-host-keyed-prelaunch-001-" + role + ".json",
        "courier_file": "native-host-keyed-live-courier-001.py",
        "courier": COURIER,
        "host_pinned": True,
        "job_file": role,
        "role": role,
        "forbidden": role in {"input-binding", "injection"},
    }
    lifecycle_reader = lifecycle.cancelled if role == "cancel" else lifecycle.timed_out if role == "timeout" else None
    control, data, pin = binding.read_transport(directory, proof, read_lifecycle=lifecycle_reader)
    outside_pin = authenticate(directory, control, data, pin)
    unit_proof(data)
    assert not any("/mcp-home/" in n or "/mcp-guard/" in n or "/sdk-home/" in n for n in data)
    role_facts = {}
    if role == "input-binding":
        role_facts.update(binding.read_binding_controls(control, data, pin))
        role_facts.update(forbidden(control, data, pin, authorization_required=True))
    elif role == "injection":
        role_facts.update(read_injection_control(control, data, pin, SOURCE))
    elif role == "boundary":
        role_facts.update(read_boundary_control(control, data, pin, SOURCE))
    elif role in {"timeout", "cancel"}:
        role_facts.update(
            {
                "root_cancellation_after_held_readiness": role == "cancel",
                "actual_timeout_and_sdk_error_output_bound": role == "timeout",
                "held_child_dead": True,
                "closed_overlay_and_lower_readback": True,
                "missing_sdk_result_and_post_preserved": role == "cancel",
            }
        )
    return {
        "schema": "hol-gauntlet-native-host-keyed-control-host-readback.v1",
        "rust_source_commit": SOURCE,
        "product_source_sha": pin["source_sha"],
        "job_id": pin["job_id"],
        "role": role,
        "report_sha256": expected["report"],
        "host_pin_sha256": outside_pin,
        "controller_signature_verified_against_prior_host_pin": True,
        "actual_sdk_mcp_bash_relations_checked": True,
        "outside_root_controller_bound": True,
        "kernel_samples": expected["samples"],
        "retained_worker_files": expected["final"],
        **role_facts,
        "qualified_role_complete": False,
        "outside_signing_key_admitted": False,
        "execution_eligible": False,
        "guard_causality_verified": False,
        "model_requests": 0,
    }


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[2] not in PROOFS:
        raise SystemExit("usage: verify_native_host_keyed_control_20261027.py EVIDENCE_DIRECTORY ROLE")
    print(json.dumps(verify(Path(sys.argv[1]), sys.argv[2]), sort_keys=True))

"""Check fixed public Linux proof custody; Rust owns Native image grading."""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
from pathlib import Path, PurePosixPath

SOURCE = "98a544f31207808ca52dcf08f620ead3dca53d7b"
PRODUCT = "dc3b9336308dab4892bf0c0e0f328a9c8b7efc12"
EXPORT = "baf9ed0df33b6ba778a902baa44dd67bd6fe799a78bfc3e5f44c3d7cb5140f4d"
MAC = "b9ab424dd1e31e04c844ea95710c0b6f5d66c926c9f9914f9f28d2d12234723c"
ARM = "f8ae31a0e5b5c9faa9538c778485aee2b551e630857efb7b0c8050f4b918a6a7"
TESTS = "9c273c9f3659870657c346e60fdf2461930b54fb5eb8b6c8da81c856f47661fe"
OUTPUT = "d2816485069ac1964e3737584ed1afc9e7456ebd1df24bdd495a8c244739ecae"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read(path, limit=32 * 1024**2):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= limit
        raw = stream.read(limit + 1)
        after = os.fstat(stream.fileno())

    def key(s):
        return (
            s.st_dev,
            s.st_ino,
            s.st_mode,
            s.st_uid,
            s.st_gid,
            s.st_nlink,
            s.st_size,
            s.st_mtime_ns,
            s.st_ctime_ns,
        )

    assert len(raw) == before.st_size and key(before) == key(after) == key(path.lstat())
    return raw


def verify(evidence, repository):
    raw = read(evidence / "native-lineage-vm-results-001.tar")
    assert len(raw) == 3594240 and sha(raw) == EXPORT
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        members = archive.getmembers()
        assert len(members) == len({m.name for m in members}) == 41
        files = {}
        for member in members:
            assert member.isfile() and member.uid == member.gid == member.mtime == 0 and member.mode == 0o600
            path = PurePosixPath(member.name)
            assert not path.is_absolute() and ".." not in path.parts and path.as_posix() == member.name
            assert 0 <= member.size <= 16 * 1024**2
            files[member.name] = archive.extractfile(member).read(member.size + 1)
            assert len(files[member.name]) == member.size
    index = json.loads(files.pop("results.sha256.json"))
    assert set(index["files"]) == set(files)
    assert set(index["filesystem"]) == set(files) - {"tools.json", "final.json"}
    for name, pin in index["files"].items():
        assert pin == dict(bytes=len(files[name]), sha256=sha(files[name]))
    for metadata in index["filesystem"].values():
        assert metadata["uid"] == metadata["gid"] == 0 and metadata["mode"] == 0o600 and metadata["links"] == 1

    def value(name):
        return json.loads(files[name])

    transfer = value("input/transfer.json")
    assert transfer["source_commit"] == SOURCE and transfer["product_source_commit"] == PRODUCT
    assert transfer["public_host_pin_fixture"] is True
    assert files["input/transfer.json"] == files["proof/failed/transfer.json"] == files["proof/corrected/transfer.json"]
    assert files["proof/failed/installation.json"] == files["proof/corrected/installation.json"]
    tools = value("tools.json")
    for name, pin in transfer["files"].items():
        if name in tools:
            actual = tools[name]
            assert pin == dict(bytes=actual["bytes"], sha256=actual["sha256"])
            assert actual["uid"] == actual["gid"] == 0 and actual["mode"] == 0o500 and actual["links"] == 1
        else:
            assert pin == dict(bytes=len(files["input/" + name]), sha256=sha(files["input/" + name]))
    assert tools["verifier"]["sha256"] == ARM and tools["evidence-tests"]["sha256"] == TESTS
    host_pin = value("input/host-pin.json")
    assert set(host_pin) == {
        "controller_key_pin_sha256",
        "controller_public_key_hex",
        "deployment_digest",
        "job_id",
        "schema",
        "source_sha",
        "started_marker_sha256",
        "worker_generation",
    }
    assert files["input/host-pin.json"] == read(
        evidence / "native-pressure-control-host-pins-002/e2c701baf1475602.controller-key-pin.json"
    )
    assert files["input/control.tar"] == read(evidence / "native-pressure-control-vm-results-002-success.tar")
    assert files["input/completion.json"] == read(
        evidence / "native-pressure-control-completion-002-success-valid.json"
    )
    for suffix in ["stdout", "stderr", "json"]:
        assert files["proof/failed/native-images." + suffix] == files["proof/corrected/native-images." + suffix]
    failure = json.loads(read(evidence / "native-lineage-arm-cases-remote-001.json"))
    assert failure["returncode"] == 1
    assert (
        "AssertionError: ('native-images', [])"
        in read(evidence / "native-lineage-arm-cases-remote-001.stderr").decode()
    )
    summary = value("proof/corrected/summary.json")
    assert summary["source_commit"] == SOURCE and summary["product_source_commit"] == PRODUCT and summary["passed"]
    assert summary["unit_tests_passed"] == 19 and summary["actual_restart_refusal_cases"] == 5
    assert summary["reconciled_retained_native_test_result"] and summary["initial_count_parser_failure_retained"]
    assert len(summary["cases"]) == 8
    for row in summary["cases"]:
        stem = "proof/corrected/" + row["case"]
        assert row == value(stem + ".json") and row["returncode"] == row["expected_returncode"]
        assert sha(files[stem + ".stdout"]) == row["stdout_sha256"]
        assert sha(files[stem + ".stderr"]) == row["stderr_sha256"]
        if row["expected_returncode"] == 2:
            assert files[stem + ".stdout"] == b"" and files[stem + ".stderr"]
        else:
            assert files[stem + ".stderr"] == b""
    for name, count in [("native-images", 9), ("event-replay", 6), ("signed-trace-joins", 4)]:
        result = re.findall(
            rb"test result: (ok|FAILED)[.] ([0-9]+) passed; ([0-9]+) failed; ([0-9]+) ignored",
            files["proof/corrected/" + name + ".stdout"],
        )
        assert result == [(b"ok", str(count).encode(), b"0", b"0")]
    expected = files["input/expected-control.json"]
    assert expected == files["proof/corrected/actual.stdout"] == files["proof/corrected/restart.stdout"]
    assert sha(expected) == OUTPUT
    toolset = json.loads(read(evidence / "native-lineage-tools-001.json"))
    assert toolset["source_commit"] == SOURCE and toolset["working_source_identical"]
    reader = evidence / "native-lineage-mac-reader-001"
    assert sha(read(reader)) == toolset["mac"]["sha256"] == MAC
    source_map = json.loads(read(evidence / "native-lineage-working-source-003.json"))["files"]
    for name, pin in source_map.items():
        blob = subprocess.check_output(["/usr/bin/git", "show", SOURCE + ":" + name], cwd=repository, timeout=30)
        assert sha(blob) == pin
    pins = value("input/job.json")
    args = [
        str(reader),
        str(evidence / "native-pressure-control-host-pins-002"),
        str(evidence / "native-pressure-control-completion-002-success-valid.json"),
        PRODUCT,
        pins["job_id"],
        pins["deployment_sha256"],
        pins["worker_generation"],
        pins["preparation_sha256"],
        "success",
        "--control-artifacts",
        str(evidence / "native-pressure-control-vm-results-002-success.tar"),
        "31364fd5f5fbcf0ca165952e6aef04a72394255c1b756fc31d2b792fef4de8f1",
        "c86f21d0da9290ece2d7d49a3f7ed52aed59cb029abdf0ea25c79634f6cbe960",
        "5003b229f827bfc8b8815c65f9e6c922a6beaff64cdf873731f9eb58abf56a8a",
    ]
    actual = subprocess.run(args, capture_output=True, timeout=60)
    assert actual.returncode == 0 and actual.stdout == expected and not actual.stderr
    images = json.loads(actual.stdout)["control_artifacts"]["relations"]["native_clients"]["process_event_images"]
    assert images["created_tasks"] == 392 and images["gates_joined"] == 9 and images["native_exec_images_checked"] == 60
    assert images["native_image_inheritances"] == 29 and images["tasks_with_observed_or_inherited_native_image"] == 87
    assert images["native_image_privilege_floors_checked"] and images["complete_task_history_checked"]
    for field in [
        "inherited_memory_contents_authenticated",
        "internal_native_request_bytes_checked",
        "effect_writer_attribution_checked",
        "all_native_runtime_descendants_graded",
        "outside_observer_admitted",
        "outside_signing_key_admitted",
        "execution_eligible",
        "guard_causality_verified",
    ]:
        assert images[field] is False
    legacy_raw = read(evidence / "native-lineage-legacy-proof-001.json")
    assert sha(legacy_raw) == "1c934b9955bb0392b87516d2d6887fd3db197a20e1b5627e19046eceb6327434"
    legacy = json.loads(legacy_raw)
    assert legacy["source_commit"] == SOURCE and legacy["unchanged_legacy_readbacks"] == 32
    final = value("final.json")
    assert (
        final["source_commit"] == SOURCE and final["worker_files_preserved"] == 326 and final["both_worker_leases_held"]
    )
    assert final["public_host_pin_fixture"] and final["fresh_product_execution"] is False
    for record in [index, transfer, summary, final]:
        assert (
            record["execution_eligible"] is record["guard_causality_verified"] is False
            and record["model_requests"] == 0
        )
    return dict(
        schema="hol-gauntlet-native-image-lineage-independent-host-proof.v1",
        source_commit=SOURCE,
        product_source_commit=PRODUCT,
        archive_sha256=EXPORT,
        archive_members=41,
        linux_unit_tests=19,
        linux_actual_restart_refusal_cases=5,
        mac_linux_output_identical=True,
        native_exec_images_checked=60,
        native_image_inheritances=29,
        tasks_with_observed_or_inherited_native_image=87,
        unchanged_legacy_readbacks=32,
        initial_count_parser_failure_retained=True,
        worker_files_preserved=326,
        public_host_pin_fixture=True,
        fresh_product_execution=False,
        execution_eligible=False,
        guard_causality_verified=False,
        model_requests=0,
    )


if __name__ == "__main__":
    if not __debug__ or len(sys.argv) != 3:
        raise SystemExit(
            "usage (assertions enabled): verify_native_image_lineage_20261028.py EVIDENCE_DIRECTORY REPOSITORY"
        )
    print(json.dumps(verify(Path(sys.argv[1]), Path(sys.argv[2])), sort_keys=True))

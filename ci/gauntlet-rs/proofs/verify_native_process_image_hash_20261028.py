"""Inspect pinned public Root test artifacts; no runtime/verdict authority."""

import hashlib
import io
import json
import os
import sys
import tarfile
from pathlib import Path

ATTEMPTS = {
    "native-trace-image": (
        "b434ab73075af3e512bfe55397d8eccc0f0af98e",
        "116928dcf6ffb06b3aa835a85a76af80dc61da19a3e10b5bbd92d0bfd69f0646",
        "aeee84286cb4bf157d78c24586baf247316318f7ecd809d3997c9056a56a63ec",
        False,
    ),
    "native-trace-image-full": (
        "e98f4887026289fcf6fc754a93987e7e72ca2ff3",
        "67d04460ae2587fe234fdf308c6b70eb1dcc4bdcf62cd45026e37c14d76d49e2",
        "38cf02368f2966d8451212273e23c39580d8d0ab02daaee80318a2e03b9658ee",
        True,
    ),
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def prove(evidence):
    attempts = []
    for prefix, (source, archive_pin, rootfs_pin, passed) in ATTEMPTS.items():
        raw = (evidence / (prefix + "-vm-results-001.tar")).read_bytes()
        assert len(raw) == 194560 and sha(raw) == archive_pin
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as tar:
            members = tar.getmembers()
            assert len(members) == 35
            files = {}
            for member in members:
                assert member.isfile() and member.name not in files
                assert member.uid == member.gid == member.mtime == 0 and member.mode == 0o600
                assert 0 <= member.size <= 1024**2
                contents = tar.extractfile(member).read(member.size + 1)
                assert len(contents) == member.size
                files[member.name] = contents
        index = json.loads(files["results.sha256.json"])
        assert index["source_commit"] == source and index["passed"] is passed
        assert index["execution_eligible"] is False and index["model_requests"] == 0
        assert index["both_worker_leases_held"] is True and index["worker_files_preserved"] == 305
        assert set(index["files"]) == set(index["filesystem"]) == set(files) - {"results.sha256.json"}
        for name, pin in index["files"].items():
            assert pin == dict(bytes=len(files[name]), sha256=sha(files[name]))
            metadata = index["filesystem"][name]
            assert metadata["uid"] == metadata["gid"] == 0
            assert metadata["links"] == 1 and metadata["mode"] == 0o600
        summary = json.loads(files["proof/summary.json"])
        assert summary["source_commit"] == source and summary["passed"] is passed
        assert summary["all_input_files_unchanged"] is True
        assert summary["both_worker_leases_held"] is True and summary["worker_files_preserved"] == 305
        assert summary["fresh_product_execution"] is False and summary["model_requests"] == 0
        cases = summary["cases"]
        assert len(cases) == 11 and sum(case["expected_tests"] for case in cases) == 36
        assert cases[0]["case"] == "image-generations" and cases[0]["expected_tests"] == 9
        total = failures = 0
        for case in cases:
            label = case["case"]
            log = files["proof/" + label + ".log"]
            assert sha(log) == case["log_sha256"]
            assert json.loads(files["proof/" + label + ".json"]) == case
            result = case["results"]
            if not passed and label == "image-generations":
                assert case["returncode"] == 101 and result == [["FAILED", "8", "1", "0"]]
                assert b"root_content_and_metadata_changes_force_full_reads ... FAILED" in log
            else:
                assert case["returncode"] == 0 and result == [["ok", str(case["expected_tests"]), "0", "0"]]
            if label not in ["event-replay", "signed-trace-joins", "launch-provenance"]:
                assert case["executable_sha256"] == rootfs_pin
            total += int(result[0][1])
            failures += int(result[0][2])
        assert (total, failures) == ((36, 0) if passed else (35, 1))
        if passed:
            log = files["proof/image-generations.log"]
            assert b"root_same_size_content_changes_are_rehashed_even_with_coarse_timestamps ... ok" in log
            assert b"repeated_measurements_do_not_retain_executable_descriptors ... ok" in log
        transfer = json.loads(files["proof/transfer.json"])
        installation = json.loads(files["proof/installation.json"])
        assert transfer["source_commit"] == installation["source_commit"] == source
        assert transfer["files"] == installation["files"]
        assert transfer["files"]["rootfs-tests"]["sha256"] == rootfs_pin
        attempts.append(dict(source_commit=source, archive_sha256=archive_pin,
                             members=35, passed=passed, tests_passed=total, tests_failed=failures))
    value = dict(schema="hol-gauntlet-native-process-image-hash-readback.v1", attempts=attempts,
                 metadata_cache_failure_retained=True, corrected_full_hash_proof_passed=True,
                 archive_members_verified=70, worker_files_preserved=305,
                 fresh_product_execution=False, execution_eligible=False,
                 guard_causality_verified=False, model_requests=0)
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    destination = evidence / "native-process-image-hash-readback-proof-001.json"
    with destination.open("xb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    print(json.dumps(dict(proof=str(destination), sha256=sha(raw), passed=True, archive_members=70)))


if __name__ == "__main__":
    prove(Path(sys.argv[1]))

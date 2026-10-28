"""Fixed public ARM readback proof, kept separate from benchmark admission."""

import hashlib
import io
import json
import re
import subprocess
import tarfile
from pathlib import PurePosixPath

READER_SOURCE = "bd262dcad72278b58ae1059866a217acf366c90b"
BASELINE = "16b21c170df5494738bc40b188694f186c87a2f9caca75d1f50d05459d4aa9be"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def archive(raw):
    assert len(raw) == 1085440 and sha(raw) == "7fd4b64adaf380b004becedc9387fe959df6b4fa6002ec60105e4a7c4bc9c701"
    files = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as stream:
        members = stream.getmembers()
        assert len(members) == 126
        for member in members:
            path = PurePosixPath(member.name)
            assert not path.is_absolute() and ".." not in path.parts and member.name not in files
            assert member.isfile() and member.uid == member.gid == member.mtime == 0
            assert member.mode == 0o600 and 0 <= member.size <= 2 * 1024 * 1024
            payload = stream.extractfile(member).read(member.size + 1)
            assert len(payload) == member.size
            files[member.name] = payload
    index = json.loads(files["results.sha256.json"])
    assert set(index["files"]) == set(files) - {"results.sha256.json"}
    for name, pin in index["files"].items():
        assert pin == dict(bytes=len(files[name]), sha256=sha(files[name]))
    for name, metadata in index["filesystem"].items():
        assert name in files and metadata["uid"] == metadata["gid"] == 0
        assert metadata["mode"] == 0o600 and metadata["links"] == 1
    return files


def verify(directory, repo, producer_files, host_runs, meta):
    files = archive((directory / "native-stdio-reader-vm-results-001.tar").read_bytes())
    assert files["input/fixture-proof.tar"] == (directory / "native-stdio-capture-vm-results-001.tar").read_bytes()
    assert files["input/source-tools.json"] == (directory / "native-stdio-readback-tools-001.json").read_bytes()
    assert meta["source_commit"] == READER_SOURCE
    transfer = json.loads(files["input/transfer.json"])
    installation = json.loads(files["proof/installation.json"])
    assert transfer["source_commit"] == installation["source_commit"] == READER_SOURCE
    assert transfer["files"] == installation["files"]
    assert installation["input_archive_sha256"] == "3a42dd989d934a170da81244310612c550500095b56ec1c064f3414b10a79323"
    tools = json.loads(files["tools.json"])
    for name, key in [
        ("stdio-reader", "arm-stdio-reader"),
        ("control-reader", "arm-control-reader"),
        ("evidence-tests", "arm-evidence-tests"),
    ]:
        tool = tools[name]
        assert {k: tool[k] for k in ["bytes", "sha256"]} == {k: meta["files"][key][k] for k in ["bytes", "sha256"]}
        assert tool["uid"] == tool["gid"] == 0 and tool["mode"] == 0o500 and tool["links"] == 1
    for name, pin in transfer["files"].items():
        value = (
            {k: tools[name][k] for k in ["bytes", "sha256"]}
            if name in tools
            else dict(bytes=len(files["input/" + name]), sha256=sha(files["input/" + name]))
        )
        assert pin == value
    summary = json.loads(files["proof/summary.json"])
    assert (
        summary["source_commit"] == READER_SOURCE
        and summary["producer_source_commit"] == "018890172c5a0976f9cad606bf55433d8be8a027"
    )
    assert summary["historical_product_source_commit"] == "dc3b9336308dab4892bf0c0e0f328a9c8b7efc12"
    assert (summary["unit_tests_passed"], summary["stdio_cases"], summary["historical_control_cases"]) == (27, 11, 5)
    assert (summary["captured_bytes"], summary["complete_frames"]) == (4161, 5)
    assert summary["mac_outputs_identical"] is True
    assert summary["both_worker_leases_held"] is True and summary["public_host_pin_fixture"] is True
    assert summary["fresh_product_execution"] is False
    rows = {row["case"]: row for row in summary["cases"]}
    assert len(rows) == 20 and len(summary["cases"]) == 20
    for name, row in rows.items():
        assert json.loads(files["proof/" + name + ".json"]) == row
        assert row["returncode"] == row["expected_returncode"]
        for kind in ["stdout", "stderr"]:
            assert row[kind + "_sha256"] == sha(files["proof/" + name + "." + kind])
    for name, count in [("stdio-units", 6), ("process-replay", 6), ("signed-trace-joins", 6), ("native-images", 9)]:
        row = rows[name]
        assert row["executable_sha256"] == tools["evidence-tests"]["sha256"] and row["returncode"] == 0
        assert not files["proof/" + name + ".stderr"]
        assert re.findall(
            rb"test result: ok\. ([0-9]+) passed; ([0-9]+) failed; ([0-9]+) ignored;",
            files["proof/" + name + ".stdout"],
        ) == [(str(count).encode(), b"0", b"0")]
    manifest = json.loads(files["input/cases.json"])
    assert set(manifest) == set(host_runs)
    for name, case in manifest.items():
        row = rows["stdio-" + name]
        assert row["executable_sha256"] == tools["stdio-reader"]["sha256"]
        assert row["returncode"] == case["expected_returncode"] == host_runs[name]["returncode"]
        for kind in ["stdout", "stderr"]:
            assert row[kind + "_sha256"] == host_runs[name][kind + "_sha256"]
            assert files["proof/stdio-" + name + "." + kind] == files["input/cases/" + name + "/" + kind]
    for name in ["historical-actual", "historical-restart"]:
        row = rows[name]
        assert (
            row["returncode"] == 0
            and row["stdout_sha256"] == "d2816485069ac1964e3737584ed1afc9e7456ebd1df24bdd495a8c244739ecae"
        )
        assert row["executable_sha256"] == tools["control-reader"]["sha256"] and not files["proof/" + name + ".stderr"]
    for name in ["historical-wrong-archive", "historical-wrong-interpreter", "historical-wrong-observer"]:
        assert (
            rows[name]["returncode"] == 2
            and not files["proof/" + name + ".stdout"]
            and files["proof/" + name + ".stderr"]
        )
    assert sha(files["proof/final-worker-hashes.json"]) == BASELINE
    assert files["proof/final-worker-hashes.json"] == producer_files["proof/003/final-worker-hashes.json"]
    final = json.loads(files["final.json"])
    assert (
        final["source_commit"] == READER_SOURCE
        and final["worker_files_preserved"] == summary["worker_files_preserved"] == 326
    )
    assert final["both_worker_leases_held"] is True and final["fresh_product_execution"] is False
    for value in [summary, final]:
        assert (
            value["execution_eligible"] is value["guard_causality_verified"] is False and value["model_requests"] == 0
        )
    # Establish the 615-test source match without relabeling the 607-test
    # producer run as occurring at the later verifier commit.
    source_raw = (directory / "native-stdio-readback-working-source-002.json").read_bytes()
    assert sha(source_raw) == "c25962ea86063009f3ef5a5799f532e120c5cfd213fc940760fa63fc8e79b544"
    source = json.loads(source_raw)
    assert len(source["files"]) == 673
    for path, pin in source["files"].items():
        assert path.startswith("ci/gauntlet-rs/crates/") and path.endswith(".rs")
        assert sha(subprocess.check_output(["git", "show", READER_SOURCE + ":" + path], cwd=repo)) == pin
    log = (directory / "native-stdio-readback-working-workspace-tests-002.log").read_bytes()
    assert sha(log) == "e559ee8b21fa4880cb272516bb2b9d19267413ca197e0dd9c3c88b5b9dcb4fd8"
    counts = re.findall(rb"test result: ok\. ([0-9]+) passed; ([0-9]+) failed; ([0-9]+) ignored;", log)
    assert [sum(int(row[i]) for row in counts) for i in range(3)] == [615, 0, 0]
    legacy = (directory / "native-stdio-legacy-proof-001.json").read_bytes()
    assert sha(legacy) == "1773d15fb04aaf0179a37d923cb4df85fe31c43b178c2268fd2f1eb259c4e49e"
    assert files["input/legacy-proof.json"] == legacy
    legacy = json.loads(legacy)
    assert (
        legacy["source_commit"] == READER_SOURCE
        and legacy["verifier_sha256"] == meta["files"]["mac-control-reader"]["sha256"]
    )
    assert legacy["unchanged_legacy_readbacks"] == len(legacy["cases"]) == 32
    for number in ["001", "002"]:
        record = json.loads((directory / ("native-stdio-reader-install-remote-" + number + ".json")).read_bytes())
        stderr = (directory / ("native-stdio-reader-install-remote-" + number + ".stderr")).read_bytes()
        assert record["returncode"] == 255 and record["stderr_sha256"] == sha(stderr)
        assert b"mm_send_fd" in stderr and b"Message too long" in stderr
    installed = json.loads((directory / "native-stdio-reader-install-remote-003.json").read_bytes())
    assert (
        installed["returncode"] == 0
        and installed["script_sha256"] == "3844239512669aa4ad026e7ed90ad6978034c4484132fe76567cc4369171a91f"
    )
    return dict(
        source_commit=READER_SOURCE,
        public_members=126,
        unit_tests_passed=27,
        stdio_cases=11,
        historical_control_cases=5,
        complete_frames=5,
        captured_bytes=4161,
        source_files_matched=673,
        current_mac_workspace_tests_passed=615,
        unchanged_legacy_control_readbacks=32,
        worker_files_preserved=326,
        transport_failures_retained=2,
        fresh_product_execution=False,
        execution_eligible=False,
        guard_causality_verified=False,
        model_requests=0,
    )

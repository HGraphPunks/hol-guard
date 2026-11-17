#!/usr/bin/env python3
"""Read back the fixed public syscall ABI proof; grants no benchmark admission."""

import hashlib
import io
import json
import re
import subprocess
import sys
import tarfile
from pathlib import Path, PurePosixPath

SOURCE = "483c29a0823ab77c48ed593e9867fa382e15f5d5"
ARCHIVE = "61daa708d0253718b83bc626b10d79d60af89f37f72da7740c8536d8256ac256"
ROOTFS = "26121816670af4f62fe0b68c1841014b4dd2207ce2747b2d055a9969125f099b"
READER = "1758bdfb925169ef31279d8a9d431dda502ee86914d09ca91f049c35c03a2c61"
BASELINE = "16b21c170df5494738bc40b188694f186c87a2f9caca75d1f50d05459d4aa9be"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    assert len(sys.argv) == 5, "usage: PROOF_TAR REPO FROZEN_READER NEW_OUTPUT_DIR"
    archive, repo, reader, output = map(Path, sys.argv[1:])
    raw = archive.read_bytes()
    assert len(raw) == 337920 and sha(raw) == ARCHIVE
    assert sha(reader.read_bytes()) == READER
    files = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as stream:
        members = stream.getmembers()
        assert len(members) == 25
        for member in members:
            path = PurePosixPath(member.name)
            assert not path.is_absolute() and all(p not in (".", "..") for p in path.parts)
            assert member.name not in files and member.isfile()
            assert member.uid == member.gid == member.mtime == 0 and member.mode == 0o600
            assert 0 <= member.size <= 1024 * 1024
            data = stream.extractfile(member).read(member.size + 1)
            assert len(data) == member.size
            files[member.name] = data
    def parsed(name):
        return json.loads(files[name])
    index = parsed("results.sha256.json")
    assert set(index["files"]) == set(files) - {"results.sha256.json"}
    for name, pin in index["files"].items():
        assert pin == dict(bytes=len(files[name]), sha256=sha(files[name]))
    for name, metadata in index["filesystem"].items():
        assert name in files
        assert metadata["uid"] == metadata["gid"] == 0
        assert metadata["mode"] == 0o600 and metadata["links"] == 1
    transfer = parsed("input/transfer.json")
    installation = parsed("proof/installation.json")
    source = parsed("input/source.json")
    final = parsed("final.json")
    result = parsed("proof/result.json")
    assert all(v["source_commit"] == SOURCE for v in (transfer, installation, source, final, result))
    assert installation["input_archive_sha256"] == ("ed00b735b54bdc1d68b862bef783e1daa5a765c2a5bb4d612568e2c57de753b7")
    assert installation["files"] == transfer["files"]
    tool = parsed("tools.json")["rootfs-tests"]
    assert tool["sha256"] == ROOTFS and tool["bytes"] == 10982032
    assert tool["uid"] == tool["gid"] == 0 and tool["mode"] == 0o500
    assert tool["links"] == 1
    assert transfer["files"]["rootfs-tests"] == dict(bytes=tool["bytes"], sha256=ROOTFS)
    for name in ("source.json", "mac-workspace.log"):
        assert transfer["files"][name] == dict(bytes=len(files["input/" + name]), sha256=sha(files["input/" + name]))
    for path, pin in source["files"].items():
        assert path.startswith("ci/gauntlet-rs/crates/gauntlet-cell-rootfs/src/")
        blob = subprocess.check_output(["git", "show", SOURCE + ":" + path], cwd=repo)
        assert sha(blob) == pin
    mac_rows = re.findall(
        rb"test result: ok\. ([0-9]+) passed; ([0-9]+) failed; ([0-9]+) ignored;",
        files["input/mac-workspace.log"],
    )
    assert len(mac_rows) == 219
    assert [sum(int(row[i]) for row in mac_rows) for i in range(3)] == [603, 0, 0]
    for label, count in (("syscall-decoder", 9), ("kernel-process-fixtures", 7)):
        record = parsed("proof/" + label + ".json")
        assert result["results"][label] == record and record["returncode"] == 0
        assert record["source_commit"] == SOURCE and record["counts"] == [[count, 0, 0]]
        stdout = files["proof/" + label + ".stdout"]
        stderr = files["proof/" + label + ".stderr"]
        assert sha(stdout) == record["stdout_sha256"]
        assert sha(stderr) == record["stderr_sha256"] and not stderr
        assert re.findall(
            rb"test result: ok\. ([0-9]+) passed; ([0-9]+) failed; ([0-9]+) ignored;",
            stdout,
        ) == [(str(count).encode(), b"0", b"0")]
    abi_names = [n for n in files if "/native-syscall-abi-" in n]
    assert len(abi_names) == 1 and abi_names[0].endswith("/result.json")
    abi = parsed(abi_names[0])
    assert abi == result["abi"] and abi["actual_final_exit_code"] == 97
    assert abi["actual_syscall_entries"] == 2 and abi["actual_syscall_exits"] == 1
    assert abi["entry_and_exit_abi_checked"] is True and abi["early_exit_seen"] is True
    assert abi["target_memory_read"] is False and abi["candidate_executed"] is False
    assert (result["passed"], result["failed"], result["ignored"]) == (16, 0, 0)
    assert final["both_worker_leases_held"] is True
    assert final["fresh_product_execution"] is False and final["target_memory_read"] is False
    assert all(v["worker_files_preserved"] == 326 for v in (installation, result, final))
    assert sha(files["proof/final-worker-hashes.json"]) == BASELINE
    assert len(parsed("proof/final-worker-hashes.json")) == 326
    for value in (index, final, result, abi, source, transfer, installation):
        assert value["execution_eligible"] is False and value["model_requests"] == 0

    # Re-run the separately frozen Rust v1 process-history reader. Four complete
    # fixtures must verify, while the lost-recorder history must refuse.
    output.mkdir(mode=0o700)
    readbacks = {}
    for label in ("fork-tree", "group-stop", "rapid-exit", "thread-exec", "lost-recorder"):
        journals = [
            n for n in files if "/fixtures/" + label + "-" in n and n.endswith("/native-process-events.v1.jsonl")
        ]
        assert len(journals) == 1
        journal_name = journals[0]
        checkpoint_name = journal_name.rsplit("/", 1)[0] + "/result.json"
        journal = output / (label + ".jsonl")
        checkpoint = output / (label + ".json")
        journal.write_bytes(files[journal_name])
        # A missing complete checkpoint cannot authorize replay.
        checkpoint.write_bytes(files.get(checkpoint_name, b"{}"))
        command = [str(reader), str(journal), sha(journal.read_bytes()), str(checkpoint), sha(checkpoint.read_bytes())]
        run = subprocess.run(command, capture_output=True, timeout=15)
        (output / (label + ".stdout")).write_bytes(run.stdout)
        (output / (label + ".stderr")).write_bytes(run.stderr)
        if label == "lost-recorder":
            assert run.returncode == 2 and not run.stdout and run.stderr
        else:
            assert run.returncode == 0 and not run.stderr
            value = json.loads(run.stdout)
            assert value["complete_task_relation_verified"] is True
            assert value["execution_eligible"] is False
        readbacks[label] = dict(
            returncode=run.returncode,
            stdout_sha256=sha(run.stdout),
            stderr_sha256=sha(run.stderr),
        )
    print(
        json.dumps(
            dict(
                schema="hol-gauntlet-native-stdio-independent-readback.v1",
                source_commit=SOURCE,
                archive_sha256=ARCHIVE,
                public_members=25,
                mac_tests_passed=603,
                arm_tests_passed=16,
                rust_process_readbacks=readbacks,
                entry_and_exit_abi_checked=True,
                pipe_bytes_captured=False,
                worker_files_preserved=326,
                execution_eligible=False,
                guard_causality_verified=False,
                model_requests=0,
            ),
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()

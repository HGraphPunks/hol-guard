#!/usr/bin/env python3
"""Verify the retained inert Rust SDK/Bun publication without executing packages."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import posixpath
import stat
import tarfile
from pathlib import Path

from verify_native_current_worker_20261026 import archive, canonical, exported, parse, sha

SDK = "4b12e74045c56e5f387c2a82312e38a97d665a88cc52bb698e55bf52747bf0b1"
NORMALIZED = "ad4d62276c7f7d4026411ceedc56bbd257b06cd6ffd0c9933a6ef3b91d901a3e"
BUN = "37141662ebed915a2ab89313156e455e2a1374395f5f6760d06407f49406f086"
SOURCE_ARCHIVE = "fb658d14d25a8a7c7906edd723b2d9dad54ef063661bbb773419de3a0c6df4fc"
GENERATION = "784bfa5825ca2ea4b46fc89335754ff75737fa39998320646ced4dab0f68c77e"
RECEIPT = "8af6afd12aaaf4e798d18846f33e93a959ce85d73c39a3f121769c9291a8c3fc"
DECLARATION = "1f4b60186253171767bf4784145095385ea362c6af9017730cd5027b7e45bc1a"
RUST = "8c868cbf4184e5317a76ea5c016bfcb0c626ab14"
JOB = "e2c701baf1472400"


def metadata(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def source_archive(path):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
        before = os.fstat(stream.fileno())
        assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size == 1200394240
        assert hashlib.file_digest(stream, "sha256").hexdigest() == SOURCE_ARCHIVE
        stream.seek(0)
        with tarfile.open(fileobj=stream, mode="r:") as source:
            members = source.getmembers()
            assert len(members) == 42324 and len({m.name for m in members}) == len(members)
            manifest_entry = source.getmember("transfer.json")
            assert manifest_entry.isfile() and manifest_entry.size <= 16 * 1024**2
            manifest = parse(source.extractfile(manifest_entry).read())
            rows = manifest["sdk_rows"]
            assert len(rows) == 42321 and sha(canonical(rows)) == SDK
            expected = {row["path"]: row for row in rows}
            assert len(expected) == len(rows)
            observed = []
            total = 0
            for member in members:
                assert member.isfile() or member.isdir() or member.issym()
                assert not member.name.startswith("/") and all(
                    part not in ["", ".", ".."] for part in member.name.split("/")
                )
                if member.name == "transfer.json":
                    continue
                if member.name == "node_modules":
                    assert member.isdir() and member.uid == member.gid == 0 and member.mode == 0o755
                    continue
                if member.name == "bun":
                    assert (
                        member.isfile()
                        and member.uid == member.gid == 0
                        and member.mode == 0o555
                        and member.size == 91801560
                    )
                    file = source.extractfile(member)
                    head = file.read(64)
                    assert head[:7] == b"\x7fELF\x02\x01\x01" and head[18:20] == b"\xb7\0"
                    file.seek(0)
                    assert hashlib.file_digest(file, "sha256").hexdigest() == BUN
                    continue
                assert member.name.startswith("node_modules/")
                relative = member.name.removeprefix("node_modules/")
                assert not any(part == ".env" or part.startswith(".env.") for part in relative.split("/"))
                row = {"path": relative, "uid": member.uid, "gid": member.gid, "mode": member.mode}
                if member.issym():
                    row["symlink"] = member.linkname
                    target = posixpath.normpath(posixpath.join(posixpath.dirname(relative), member.linkname))
                    assert (
                        not member.linkname.startswith("/")
                        and target not in [".", ".."]
                        and not target.startswith("../")
                    )
                elif member.isfile():
                    assert 0 <= member.size <= 2 * 1024**3
                    row.update(
                        size=member.size, sha256=hashlib.file_digest(source.extractfile(member), "sha256").hexdigest()
                    )
                    total += member.size
                    assert total <= 2 * 1024**3
                else:
                    assert member.isdir()
                assert row == expected[relative]
                observed.append(row)
            assert sorted(observed, key=lambda row: row["path"]) == rows and total == 1053309967
        assert metadata(before) == metadata(os.fstat(stream.fileno())) == metadata(path.lstat())
    normalized = [
        {**row, "uid": 0, "gid": 0, "mode": row["mode"] if "symlink" in row else row["mode"] & ~0o022} for row in rows
    ]
    assert sha(canonical(normalized)) == NORMALIZED and manifest["root_sdk_tree_sha256"] == NORMALIZED
    return manifest, normalized


def verify(root):
    manifest, normalized = source_archive(root / "native-sdk-public-source-024b.tar")
    data = exported(
        root / "native-sdk-publication-vm-results-024.tar",
        "7f111ec9f762737b0dd732511daa384d159a26d69349c2adfb6a6caa1d56ad53",
        20,
    )
    inputs = archive(
        root / "native-sdk-publisher-input-024.tar",
        "9895834f7e447cdbec563c98933f88abd1740d97d0adc0ded7153429644b4ec1",
        3,
    )
    previous = exported(
        root / "native-hook-transport-vm-results-023.tar",
        "01c1a8d8f6f354367439e8afdc48ae13a3b3a1a69f031a57e559ceb1883f76a6",
        56,
    )
    transfer = parse(inputs["transfer.json"])
    assert transfer["source_commit"] == RUST and data["input/transfer.json"] == inputs["transfer.json"]
    for name, pin in transfer["files"].items():
        assert len(inputs[name]) == pin["bytes"] and sha(inputs[name]) == pin["sha256"]
    assert sha(inputs["gauntlet-native-sdk-publish"]) == GENERATION
    for name in ["gauntlet-native-sdk-publish", "gauntlet-worker-tests"]:
        assert inputs[name][:7] == b"\x7fELF\x02\x01\x01" and inputs[name][18:20] == b"\xb7\0"
    assert parse(data["proof/original-source-transfer.json"]) == manifest
    normalized_tree = parse(data["proof/sdk-root-tree.json"])
    assert normalized_tree["rows"] == normalized and normalized_tree["sha256"] == NORMALIZED
    assert normalized_tree["entries"] == 42321 and normalized_tree["bytes"] == 1053309967
    assert data["job/sdk-publication.v1.json"] == data["published/sdk-publication.v1.json"]
    assert sha(data["job/sdk-publication.v1.json"]) == RECEIPT
    receipt = parse(data["published/sdk-publication.v1.json"])
    assert receipt["schema"] == "hol-gauntlet-native-sdk-publication.v1" and receipt["job_id"] == JOB
    assert receipt["publisher_generation"] == GENERATION and receipt["source_declaration_sha256"] == DECLARATION
    assert receipt["directory"] == "/opt/hol-gauntlet/sdk-assets/" + NORMALIZED + "-" + BUN
    assert (
        receipt["sdk_entries"] == 42321 and receipt["sdk_bytes"] == 1053309967 and receipt["sdk_version"] == "18.4.12"
    )
    for key in ["sdk_imported", "bun_executed", "artifact_admitted", "execution_eligible"]:
        assert receipt[key] is False
    assert receipt["model_requests"] == 0 and sha(data["job/sdk-source.v1.json"]) == DECLARATION
    pins = parse(data["job/sdk-source.v1.json"])
    assert pins == receipt["inputs"] and pins["source_archive_sha256"] == SOURCE_ARCHIVE
    assert pins["source_sdk_tree_sha256"] == SDK and pins["sdk_tree_sha256"] == NORMALIZED and pins["bun_sha256"] == BUN
    metadata_row = next(row for row in normalized if row["path"] == "@oh-my-pi/pi-coding-agent/package.json")
    assert sha(data["published/sdk-package.json"]) == metadata_row["sha256"]
    package = parse(data["published/sdk-package.json"])
    assert package["name"] == "@oh-my-pi/pi-coding-agent" and package["version"] == "18.4.12"
    for name in ["wrong-generation", "wrong-declaration", "rust-lease-busy", "legacy-lease-busy", "publication-replay"]:
        response = parse(data["proof/" + name + ".json"])
        assert response["returncode"] == 2 and response["stdout"] == "" and response["stderr"]
    output = parse(data["proof/publication.json"])
    assert output["returncode"] == 0 and output["stderr"] == ""
    assert parse(output["stdout"])["receipt_sha256"] == RECEIPT
    post = parse(data["proof/post-proof.json"])
    assert post["status"] == "passed" and post["source_commit"] == RUST
    assert all(
        post[key] is True
        for key in [
            "source_and_copy_equal",
            "source_original_metadata_retained",
            "replay_refused",
            "dual_receipts_unchanged",
        ]
    )
    prior = parse(previous["proof/proof.json"])
    prior = {**prior["prior_worker_hashes"], **prior["original_worker_hashes"]}
    assert len(prior) == post["prior_worker_files_preserved"] == 54 and prior == post["prior_worker_hashes"]
    tests = parse(data["proof/root-tests.json"])
    assert tests["returncode"] == 0 and tests["sha256"] == sha(data["proof/gauntlet-worker-tests.log"])
    assert b"141 passed; 0 failed; 24 ignored" in data["proof/gauntlet-worker-tests.log"]
    return {
        "schema": "hol-gauntlet-host-native-sdk-publication-verification.v1",
        "source_archive_members_verified": 42324,
        "publication_export_members_verified": 20,
        "binary_input_members_verified": 3,
        "sdk_entries": 42321,
        "sdk_bytes": 1053309967,
        "source_sdk_tree_sha256": SDK,
        "root_sdk_tree_sha256": NORMALIZED,
        "bun_sha256": BUN,
        "publication_receipt_sha256": RECEIPT,
        "prior_worker_files_preserved": 54,
        "root_tests_passed": 141,
        "existing_fixture_ignores": 24,
        "sdk_imported": False,
        "bun_executed": False,
        "artifact_admitted": False,
        "execution_eligible": False,
        "model_requests": 0,
    }


def main():
    if not __debug__:
        raise SystemExit("run this retained proof reader without Python optimization")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    raw = json.dumps(verify(args.evidence_dir), sort_keys=True, indent=2) + "\n"
    if args.output:
        with args.output.open("x") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    print(raw, end="")


if __name__ == "__main__":
    main()

"""Reconstruct the fixed public merged-source worker-budget runtime proof; never admit it."""

from __future__ import annotations

import ast
import email.parser
import hashlib
import io
import json
import os
import stat
import subprocess
import sys
import tarfile
import types
import zipfile
from pathlib import Path, PurePosixPath
from unittest.mock import patch

from packaging.requirements import Requirement

SOURCE = "dc3b9336308dab4892bf0c0e0f328a9c8b7efc12"
JOB, DEP = "e2c701baf1475501", "e2c701baf1475503"
EXPORT = "a73bbaf48f5cfa42c753f54f98457d06bf65a0d427ad49c49e90e8c17d273338"
WORKER = "5cab26ac79cba113c79d50d6401c8b0286206a944576ba0255b86e33fba36baf"
NATIVE = "bdaf053911cd278930c17e3c58b7741e23334a5156817db78780349f8635eb10"
SITE = "lib/python3.12/site-packages/"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= 64 * 1024**2
        raw = stream.read(64 * 1024**2 + 1)
        after = os.fstat(stream.fileno())

    def key(s):
        return (
            s.st_dev,
            s.st_ino,
            s.st_uid,
            s.st_gid,
            s.st_mode,
            s.st_nlink,
            s.st_size,
            s.st_mtime_ns,
            s.st_ctime_ns,
        )

    assert len(raw) == before.st_size and key(before) == key(after) == key(path.lstat())
    return raw


def archive(path):
    raw = read(path)
    assert len(raw) == 48455680 and sha(raw) == EXPORT
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as stream:
        members = stream.getmembers()
        assert len(members) == len({m.name for m in members}) == 86
        for m in members:
            assert m.isfile() and m.mode == 0o600 and m.uid == m.gid == m.mtime == 0
            assert 0 <= m.size <= 32 * 1024**2 and not PurePosixPath(m.name).is_absolute()
            assert ".." not in m.name.split("/") and PurePosixPath(m.name).as_posix() == m.name
        data = {m.name: stream.extractfile(m).read() for m in members}
    index = json.loads(data.pop("results.sha256.json"))
    assert set(data) == set(index["files"])
    for name, pin in index["files"].items():
        assert pin == {"bytes": len(data[name]), "sha256": sha(data[name])}
    derived = {"trees/" + n + ".json" for n in ["wheel", "dependency", "candidate", "published"]} | {
        "final.json",
        "source-archives.json",
    }
    assert set(index["filesystem"]) == set(data) - derived
    for metadata in index["filesystem"].values():
        assert metadata["uid"] == metadata["gid"] == 0 and metadata["links"] == 1 and metadata["mode"] & 0o022 == 0
    assert index["execution_eligible"] is index["guard_causality_verified"] is False and index["model_requests"] == 0
    return data


def zipped(raw):
    with zipfile.ZipFile(io.BytesIO(raw)) as stream:
        entries = stream.infolist()
        assert len(entries) == len({e.filename for e in entries}) <= 10000
        result = {}
        for entry in entries:
            name = entry.filename
            assert not entry.is_dir() and not PurePosixPath(name).is_absolute()
            assert ".." not in name.split("/") and "\\" not in name
            assert 0 <= entry.file_size <= 128 * 1024**2
            result[name] = stream.read(entry)
        assert sum(map(len, result.values())) <= 256 * 1024**2
    return result


def framed(files):
    digest = hashlib.sha256()
    for name, raw in files.items():
        encoded = name.encode()
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
        digest.update(len(raw).to_bytes(8, "big"))
        digest.update(raw)
    return digest.hexdigest()


def insert(rows, name, raw, mode=0o644, directory_mode=0o755):
    assert name not in rows
    rows[name] = {"uid": 0, "mode": mode, "sha256": sha(raw)}
    for parent in PurePosixPath(name).parents:
        if parent.as_posix() != ".":
            rows.setdefault(parent.as_posix(), {"uid": 0, "mode": directory_mode})


def tree(data, name, rows, total, pin):
    measured = json.loads(data["trees/" + name + ".json"])
    assert measured == {"rows": rows, "sha256": sha(canonical(rows)), "entries": len(rows) - 1, "bytes": total}
    assert measured["sha256"] == pin


def kernel(data, prefix, job, executable):
    before = json.loads(data[prefix + "-kernel.json"])
    after = json.loads(data[prefix + "-final.json"])
    assert before["job_id"] == after["job_id"] == job
    assert before["executable_sha256"] == executable and before["pidfd_held_during_snapshot"] is True
    assert before["argv_sha256"] == sha(("\0".join(before["argv"]) + "\0").encode())
    status = before["status"]
    assert status["Uid"] == status["Gid"] == "65532\t65532\t65532\t65532" and status["Groups"] == "65532"
    assert all(status[n] == "0000000000000000" for n in ["CapAmb", "CapBnd", "CapEff", "CapInh", "CapPrm"])
    assert status["NoNewPrivs"] == "1" and status["Seccomp"] == "2"
    assert (
        before["job_profile_enforcing"] is True
        and before["lsm_label"] == "crun//&hol-gauntlet-build-" + job + " (mixed)"
    )
    assert before["effective_limits"] == {
        "cpu_period": 100000,
        "cpu_quota": 200000,
        "memory.max": 12884901888,
        "memory.swap.max": 0,
        "pids.max": 512,
    }
    assert before["network_mode"] == "slirp4netns"
    for field in [
        "original_entrypoint_dead",
        "container_absent",
        "client_and_container_cgroups_absent",
        "job_profile_absent",
    ]:
        assert after[field] is True
    assert after["worker_files_preserved"] == 312 and after["model_requests"] == 0
    return before, after


def verify(directory, repository):
    data = archive(directory / "native-pressure-vm-results-001.tar")

    def value(name):
        return json.loads(data[name])

    def local(name):
        return json.loads((directory / name).read_bytes())

    result = value("build/candidate-run.result.json")
    anchor = value("build/candidate-run.host-anchor.json")
    assert (
        sha(data["build/candidate-run.result.json"])
        == "833b0331607400a4949cf6ba51f629d28c8b8dc205641d220b8b89e7861d6e13"
    )
    assert (
        sha(data["build/candidate-run.host-anchor.json"])
        == result["host_anchor_sha256"]
        == "a81646415cd691f74337b275f5d051be2893b2a0636705f24a3fe0a960061266"
    )
    host_raw = read(directory / "native-pressure-host-build-pins-001" / (JOB + ".candidate-build-pin.json"))
    assert (
        sha(host_raw)
        == result["host_pin_sha256"]
        == anchor["host_pin_sha256"]
        == "f4993dfee3e60a9f092a2e9aa6e2f08b76926f5b5f77ef89b9f9b15bd2a1a86e"
    )
    assert result["exit_code"] == 0 and result["source_sha"] == anchor["source_sha"] == SOURCE
    assert result["tag"] == "local-" + SOURCE and result["local_version"] == anchor["version"] == "3.58.0"
    for stream in ["stdout", "stderr"]:
        assert sha(data["build/candidate-run." + stream + ".log"]) == result[stream + "_sha256"]
    assert (
        b"4 passed, 96 deselected" in data["build/candidate-run.stdout.log"]
        and b"187 passed" in data["build/candidate-run.stdout.log"]
    )
    build_before, build_after = kernel(
        data, "proof/build/outside-builder", JOB, "c899b9b9ff4c0d1dcdebe2880af5133094f956f75ec21f920ae0fa2427d5de20"
    )
    assert build_before["builder_script_sha256"] == sha(data["build/context/builder_entry.py"])
    assert build_before["argv"] == ["/usr/local/bin/gauntlet-python", "-I", "-B", "/opt/gauntlet/builder_entry.py"]
    assert (
        build_after["dormant_archive_sha256"] == result["unadmitted_export_sha256"] == sha(data["build/candidate.zip"])
    )
    reconciled = json.loads(local("native-pressure-host-result-readback-001.json")["stdout"])
    assert reconciled["retained_files_match"] and reconciled["cleanup_absent"] and reconciled["host_pin_journal_match"]
    for field in ["result_sha256", "host_pin_sha256", "host_anchor_sha256"]:
        expected = sha(data["build/candidate-run.result.json"]) if field == "result_sha256" else result[field]
        assert reconciled[field] == expected
    for job, source_pin in value("source-archives.json").items():
        root = "native-pressure-source-state-002" if job == JOB else "native-pressure-dependency-source-state-001"
        raw = read(directory / root / "private/local-builds" / job / "source.tar.gz")
        assert len(raw) == source_pin["bytes"] and sha(raw) == source_pin["sha256"]
        assert source_pin["uid"] == 0 and source_pin["mode"] == 0o444 and source_pin["links"] == 1
    dep_result = value("dependency-state/" + DEP + ".report.json")
    assert dep_result == json.loads(local("native-pressure-dependency-host-run-001.json")["stdout"])
    intent_raw = read(
        directory / "native-pressure-dependency-host-state-001/intents" / (DEP + ".dependency-intent.json")
    )
    assert intent_raw == data["dependency/dependency-intent.v1.json"] and sha(intent_raw) == dep_result["intent_sha256"]
    assert dep_result["source_sha"] == SOURCE and dep_result["exit_code"] == 0 and dep_result["execution_error"] is None
    for suffix in ["started", "running", "terminal"]:
        record = value("dependency-state/" + DEP + "." + suffix + ".json")
        assert (
            record["source_sha"] == SOURCE
            and record["job_id"] == DEP
            and record["deployment_digest"] == sha(intent_raw)
        )
    terminal = value("dependency-state/" + DEP + ".terminal.json")
    assert (
        terminal["report_sha256"]
        == sha(data["dependency-state/" + DEP + ".report.json"])
        == "e4fd584e8669fd3d4d9c9a65840b3a3d23062963109e10d82f2b8ed16e22c33f"
    )
    assert terminal["status"] == "invalid-evidence" and terminal["exit_code"] == 0
    for stream in ["stdout", "stderr"]:
        assert sha(data["dependency/dependency-run." + stream + ".log"]) == dep_result[stream + "_sha256"]
    dep_before, dep_after = kernel(
        data, "proof/dependency/outside-dependency", DEP, sha(data["dependency/inputs/gauntlet-dependency-exporter"])
    )
    pins = dep_result["intent"]["pins"]
    assert dep_before["intent_sha256"] == dep_result["intent_sha256"]
    assert dep_before["container_id"] == dep_result["container_id"]
    assert dep_before["argv"] == [
        "/input/gauntlet-dependency-exporter",
        DEP,
        SOURCE,
        pins["pyproject_sha256"],
        pins["uv_lock_sha256"],
    ]
    capsule = zipped(data["dependency/dependency-inputs.zip"])
    assert set(capsule) == {"pyproject.toml", "uv.lock", "gauntlet-dependency-exporter"}
    assert sha(data["dependency/dependency-inputs.zip"]) == pins["capsule_sha256"]
    for name in capsule:
        assert capsule[name] == data["dependency/inputs/" + name]
    for name, field in [("pyproject.toml", "pyproject_sha256"), ("uv.lock", "uv_lock_sha256")]:
        blob = subprocess.check_output(["/usr/bin/git", "show", SOURCE + ":" + name], cwd=repository, timeout=30)
        assert capsule[name] == blob and sha(blob) == pins[field]
    dependencies = zipped(data["dependency/dependencies.zip"])
    manifest = json.loads(dependencies.pop("dependency-export.v1.json"))
    assert (
        len(dependencies) == manifest["files"] == 2302
        and sum(map(len, dependencies.values())) == manifest["decoded_bytes"] == 54452716
    )
    assert (
        framed(dependencies)
        == manifest["entry_bytes_sha256"]
        == "62b019ab339c6471c20e62890f89f9a9fae056ba86757c654cee4718f71d09ed"
    )
    assert manifest["job_id"] == DEP and manifest["source_sha"] == SOURCE and manifest["wheel_only_install"] is True
    assert (
        sha(data["dependency/dependencies.zip"])
        == dep_result["captured_dependencies_sha256"]
        == dep_after["dormant_archive_sha256"]
    )
    product = zipped(data["build/candidate.zip"])
    declaration = json.loads(product.pop("artifact.json"))
    assert (
        set(product) == {declaration["wheel"]}
        and declaration["source_sha"] == SOURCE
        and declaration["version"] == "3.58.0"
    )
    wheel_raw = product[declaration["wheel"]]
    assert (
        sha(wheel_raw)
        == declaration["wheel_sha256"]
        == "32f9aae2854605f39d94aeceedec17d6826a40e595d7a74543f492f33f4eb575"
    )
    wheel = zipped(wheel_raw)
    assert len(wheel) == 1656 and sum(map(len, wheel.values())) == 62745767
    assert framed(wheel) == "0f2855187f39f69093318e3897f5f4162d95870cc21cf5aa57cb879b558daf11"
    assert sha(wheel["codex_plugin_scanner/_native/hol-guard-runtime"]) == declaration["native_sha256"] == NATIVE
    distributions = []
    for name, raw in list(dependencies.items()) + list(wheel.items()):
        if name.endswith(".dist-info/METADATA"):
            metadata = email.parser.BytesParser().parsebytes(raw)
            distributions.append(
                types.SimpleNamespace(
                    metadata=metadata, version=metadata["Version"], requires=metadata.get_all("Requires-Dist", [])
                )
            )
    wheel_rows = {".": {"uid": 0, "mode": 0o700}}
    for name, raw in wheel.items():
        insert(wheel_rows, name, raw, 0o444, 0o700)
    tree(data, "wheel", wheel_rows, 62745767, "04800b680e1fc9c4f0c15002876645c92b278cb41301de5c990f5b287124eb0c")
    rows = {".": {"uid": 0, "mode": 0o755}, "bin": {"uid": 0, "mode": 0o755}}
    total = 0
    for name, raw in dependencies.items():
        assert name.startswith("site-packages/")
        insert(rows, SITE + name.removeprefix("site-packages/"), raw)
        total += len(raw)
    for name, target in [("python", "python3.12"), ("python3", "python3.12"), ("python3.12", "/usr/bin/python3.12")]:
        rows["bin/" + name] = {"uid": 0, "mode": 0o777, "link": target}
    cfg = b"home = /usr/bin\ninclude-system-site-packages = false\nversion = 3.12\nexecutable = /usr/bin/python3.12\n"
    insert(rows, "pyvenv.cfg", cfg)
    total += len(cfg)
    tree(data, "dependency", rows, total, "df07ad782d2bea44d49a3ac4a84a1ae3a160d4fe96764adc4b591d4a82acebb2")
    for name, raw in wheel.items():
        insert(rows, SITE + name, raw, 0o755 if name == "codex_plugin_scanner/_native/hol-guard-runtime" else 0o644)
        total += len(raw)
    entries = {
        "hol-guard": "codex_plugin_scanner.cli",
        "hol-guard-eval": "codex_plugin_scanner.guard.evaluation_cli",
        "hol-guard-secrets": "codex_plugin_scanner.guard.secrets.cli",
        "plugin-ecosystem-scanner": "codex_plugin_scanner.cli",
        "plugin-guard": "codex_plugin_scanner.cli",
        "plugin-scanner": "codex_plugin_scanner.cli",
    }
    for name, module in entries.items():
        raw = (
            "#!/bin/sh\n'''exec' \"${0%/*}/python3\" -I -B \"$0\" \"$@\"\n' '''\nfrom "
            + module
            + " import main\nraise SystemExit(main())\n"
        ).encode()
        ast.parse(raw)
        insert(rows, "bin/" + name, raw, 0o755)
        total += len(raw)
    pin = "742c7726d39dc3a73c6015329374410eb55f1d9e543539daf17f1f7d0d6e6736"
    assert len(rows) - 1 == 4361 and total == 117199371
    for name in ["candidate", "published"]:
        tree(data, name, rows, total, pin)
    receipts = [
        ("dependency/dependency-prefix.v1.json", "897cf427c9af1b1d6895937b1cc567fccb5962d7792ec0ae39271c625d4cb5d1"),
        ("build/native-candidate-prefix.v1.json", "830498e15bb4c07cce438952c3f8743dcd8c4e1bc854708fbedd0362d0a11316"),
        (
            "build/native-runtime-publication.v1.json",
            "7e8ea23d84d87b807133298fdff6d4306b0823902360eb23072732dd230b73f3",
        ),
    ]
    for name, receipt_pin in receipts:
        receipt = value(name)
        assert sha(data[name]) == receipt_pin and data[name] == canonical(receipt) and receipt["source_sha"] == SOURCE
        assert (
            receipt["execution_eligible"]
            is receipt["guard_causality_verified"]
            is receipt["artifact_admitted"]
            is False
            and receipt["model_requests"] == 0
        )
    assert data["runtime/native-runtime.v1.json"] == data["build/native-runtime-publication.v1.json"]
    requirements = value("build/native-runtime-publication.v1.json")["dependency_requirements"]
    dependency, clone, publication = (value(name) for name, _ in receipts)
    assert dependency["prefix_tree_sha256"] == value("trees/dependency.json")["sha256"]
    assert dependency["python_sha256"] == value("proof/dependency/system-python-observation.json")["sha256"]
    assert clone["dependency_job_id"] == DEP and clone["dependency_prefix_receipt_sha256"] == receipts[0][1]
    assert publication["clone_receipt_sha256"] == receipts[1][1]
    assert publication["prefix"] == "/opt/hol-gauntlet/candidates/" + SOURCE + "/prefix"
    assert publication["publisher_generation"] == clone["clone_generation"] == WORKER
    assert requirements["native_sha256"] == publication["native_sha256"] == NATIVE
    for report in [clone, publication]:
        for field, expected in {
            "job_id": JOB,
            "source_archive_sha256": result["source_archive_sha256"],
            "archive_sha256": sha(data["build/candidate.zip"]),
            "prefix_tree_sha256": pin,
            "prefix_entries": len(rows) - 1,
            "prefix_bytes": total,
        }.items():
            assert report[field] == expected
    final = value("final.json")
    source = subprocess.check_output(
        ["/usr/bin/git", "show", SOURCE + ":ci/gauntlet/control_plane/stage_candidate.py"], cwd=repository, timeout=30
    )
    function = next(n for n in ast.parse(source).body if isinstance(n, ast.FunctionDef) and n.name == "stage")

    def assignment(name):
        return next(
            n
            for n in function.body
            if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in n.targets)
        )

    loop = next(
        n for n in function.body if isinstance(n, ast.For) and isinstance(n.target, ast.Name) and n.target.id == "spec"
    )
    environment = {
        "implementation_name": "cpython",
        "implementation_version": "3.12.3",
        "os_name": "posix",
        "platform_machine": "aarch64",
        "platform_python_implementation": "CPython",
        "platform_release": final["uname"][2],
        "platform_system": "Linux",
        "platform_version": final["uname"][3],
        "python_full_version": "3.12.3",
        "python_version": "3.12",
        "sys_platform": "linux",
    }
    scope = {
        "Requirement": Requirement,
        "distributions": lambda path: distributions,
        "prefix": Path("/inert-prefix"),
        "SITE": SITE,
    }
    with patch("packaging.markers.default_environment", return_value=environment):
        exec(
            compile(
                ast.Module(body=[assignment("installed"), assignment("product"), loop], type_ignores=[]),
                "exact-source-inert-requirement-oracle",
                "exec",
            ),
            scope,
        )
        specs = [Requirement(s) for s in scope["product"].requires]
        active = [s for s in specs if not s.marker or s.marker.evaluate({"extra": ""})]
    assert len(scope["installed"]) == requirements["installed_distributions"] == 63
    assert len(specs) == requirements["requirements"] == 23 and len(active) == requirements["active_requirements"] == 13
    assert requirements["inactive_requirements"] == 10 and requirements["all_active_requirements_satisfied"] is True
    assert (
        sorted(s.name.lower().replace("_", "-") for s in active) == requirements["active_names"]
        and scope["installed"]["mcp"].version == "1.30.0"
    )
    for phase, count, preserved in [("prefix", 9, 17), ("clone", 16, 1668), ("publication", 11, 5637)]:
        proof = value("proof/prefix/" + phase + "-proof.json")
        assert len(proof["cases"]) == count and proof["original_files_preserved"] == preserved
        for case in proof["cases"]:
            assert case == value("proof/prefix/" + phase + "-" + case["case"] + ".json")
            assert case["returncode"] == case["expected_returncode"]
            if case["expected_returncode"] == 2:
                assert case["stdout"] == "" and case["stderr"]
            assert case["execution_eligible"] is False and case["model_requests"] == 0
        assert (
            proof["execution_eligible"] is proof["guard_causality_verified"] is False and proof["model_requests"] == 0
        )
    stale = value("proof/dependency/system-python-observation.json")
    assert stale["sha256"] == "c86f21d0da9290ece2d7d49a3f7ed52aed59cb029abdf0ea25c79634f6cbe960" and stale[
        "version_info"
    ][:3] == [3, 12, 3]
    assert stale["dependency_prefix_exists"] is True and stale["dependency_partial_exists"] is False
    assert (
        final["worker_files_preserved"] == 312
        and final["both_worker_leases_held"]
        and final["current_containers_cgroups_profiles_absent"]
    )
    assert final["execution_eligible"] is final["guard_causality_verified"] is False and final["model_requests"] == 0
    return {
        "schema": "hol-gauntlet-native-pressure-runtime-independent-host-proof.v1",
        "source_commit": SOURCE,
        "export_sha256": EXPORT,
        "public_members": 86,
        "wheel_entries": len(wheel),
        "dependency_files": len(dependencies),
        "complete_prefix_entries": len(rows) - 1,
        "complete_prefix_bytes": total,
        "prefix_tree_sha256": pin,
        "installed_distributions": 63,
        "requirements": 23,
        "active_requirements": 13,
        "python_source_oracle_matches": True,
        "staging_composition_publication_cases": 36,
        "worker_files_preserved": 312,
        "artifact_admitted": False,
        "execution_eligible": False,
        "guard_causality_verified": False,
        "conformance_completed": False,
        "model_requests": 0,
    }


if __name__ == "__main__":
    if not __debug__ or len(sys.argv) != 3:
        raise SystemExit(
            "usage (assertions enabled): verify_native_pressure_runtime_20261028.py EVIDENCE_DIRECTORY REPOSITORY"
        )
    print(json.dumps(verify(Path(sys.argv[1]), Path(sys.argv[2])), sort_keys=True))

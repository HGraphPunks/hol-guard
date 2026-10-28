"""Reproduce the fixed 5802 feature audit without rerunning product or model jobs."""

import ast
import hashlib
import io
import json
import os
import stat
import subprocess
import sys
import tarfile
import xml.etree.ElementTree as ET
from pathlib import Path

W = Path(__file__).resolve().parents[3]
PRODUCT = "dc3b9336308dab4892bf0c0e0f328a9c8b7efc12"
EXECUTOR_COMMIT = "1711967de0a4df429c112bd7f8e98784da4d42db"
PYTHON_BASELINE = "b4efd8171b06d0e13cbe12a077c376ecdc891fd1"
AUDIT_HASH = "aba4afcb915915ce4fe95408183501d2cefba1cd9267eec186def1aa2fb3f8aa"
REPORT_HASH = "c3af621accac096ee61cdc77c95a0ac156fb117ed4ec4565c1b1b84525b123e0"
ARM_HASH = "c019759cea2aa9b4d80abadb9ff75ef2a3f0685a61a6a1e26dbafd868c776ec3"
MAC_READER_HASH = "a54b7ba15e7b7f9152f1d580e574282ac4f933acf8f164a5ea6c2f078c26ffd9"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read(path, bound):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= bound
        raw = stream.read(bound + 1)

        def stamp(s):
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

        assert len(raw) == before.st_size and stamp(before) == stamp(os.fstat(stream.fileno())) == stamp(path.lstat())
        return raw


def archive(path, bound, expected, count):
    raw = read(path, bound)
    assert sha(raw) == expected
    result = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as tar:
        entries = tar.getmembers()
        assert len(entries) == count
        for entry in entries:
            parts = entry.name.split("/")
            assert all(p and p not in (".", "..") for p in parts) and not entry.name.startswith("/")
            assert entry.isfile() and not entry.linkname and entry.name not in result and entry.size <= 32 * 1024**2
            data = tar.extractfile(entry).read(entry.size + 1)
            assert len(data) == entry.size
            result[entry.name] = data
    assert sum(map(len, result.values())) <= bound
    return result


def write(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(raw)


def git_sources(raw):
    files = json.loads(raw)["files"]
    assert len(files) == 706
    names = sorted(files)
    assert all(n.startswith("ci/gauntlet-rs/") and ":" not in n and "\n" not in n for n in names)
    query = "".join(EXECUTOR_COMMIT + ":" + n + "\n" for n in names).encode()
    blobs = subprocess.run(["git", "cat-file", "--batch"], cwd=W, input=query, capture_output=True, check=True)
    assert not blobs.stderr and len(blobs.stdout) <= 32 * 1024**2
    at = 0
    for name in names:
        end = blobs.stdout.index(b"\n", at)
        header = blobs.stdout[at:end].split()
        assert len(header) == 3 and header[1] == b"blob"
        size = int(header[2])
        at = end + 1
        assert sha(blobs.stdout[at : at + size]) == files[name]
        at += size
        assert blobs.stdout[at : at + 1] == b"\n"
        at += 1
    assert at == len(blobs.stdout)


def main(evidence):
    data = archive(evidence / "native-feature-executor-vm-results-002.tar", 32 * 1024**2, AUDIT_HASH, 104)
    manifest = json.loads(data["manifest.json"])
    assert set(manifest) == set(data) - {"manifest.json"}
    for name, record in manifest.items():
        assert record == {"bytes": len(data[name]), "sha256": sha(data[name])}
    assert sha(data["producer.py"]) == "ddec434c27c4f5102e3cd80b671293b40c9ff479bb7e747cdeb40433efde3e56"
    assert sha(data["inputs/source-map.json"]) == "c77aa8abddc281a4858b4165f619b78ffce7d811771c6788ba8ed6371a6d5ac6"
    git_sources(data["inputs/source-map.json"])
    executor = data["inputs/gauntlet-feature-executor"]
    assert (
        len(executor) == 9848344 and sha(executor) == "564df9b01bd3f3e8c4460c586df63f31397b03795334120f41a70fde6829ce92"
    )
    assert executor[:6] == b"\x7fELF\x02\x01" and int.from_bytes(executor[18:20], "little") == 183
    spec = json.loads(data["inputs/feature-spec.json"])
    assert spec["source_sha"] == PRODUCT and spec["audit_id"] == "e2c701baf1475802"
    assert spec["executor_sha256"] == sha(executor) and spec["catalog_sha256"] == sha(data["inputs/catalog.json"])
    report_raw = data["proof/feature-stdout.json"]
    assert sha(report_raw) == REPORT_HASH and report_raw == data["output/contracts.v2.json"]
    report = json.loads(report_raw)
    catalog = json.loads(data["inputs/catalog.json"])["groups"]
    assert len(catalog) == len(report["groups"]) == 28
    baseline = subprocess.check_output(
        ["git", "show", PYTHON_BASELINE + ":ci/gauntlet/control_plane/feature_entry.py"], cwd=W
    )
    assert sha(baseline) == "d3d5b72d7bd9c725d7cc9b90aa3bb7bc442a99a5e188943f4686bf34e4c048de"
    fn = next(n for n in ast.parse(baseline).body if isinstance(n, ast.FunctionDef) and n.name == "junit")
    ns = {"Path": Path, "ET": ET}
    exec(compile(ast.Module(body=[fn], type_ignores=[]), "<immutable-python-junit>", "exec"), ns)
    stage = evidence / "native-feature-executor-host-readback-001"
    stage.mkdir()
    for name, raw in data.items():
        write(stage / name, raw)
    counts = dict(tests=0, failures=0, errors=0, skipped=0)
    statuses = []
    for group, declared in zip(report["groups"], catalog, strict=True):
        for key in ["id", "label", "tests", "evidence_kind"]:
            assert group[key] == declared[key]
        name = group["id"]
        assert sha(data[f"output/{name}.xml"]) == group["junit_sha256"]
        assert sha(data[f"output/{name}.log"]) == group["log_sha256"]
        observed = ns["junit"](stage / "output" / (name + ".xml"))
        assert observed == group["counts"]
        cases = list(ET.fromstring(data[f"output/{name}.xml"]).iter("testcase"))
        actual = dict(
            tests=len(cases),
            failures=sum(len(c.findall("failure")) for c in cases),
            errors=sum(len(c.findall("error")) for c in cases),
            skipped=sum(len(c.findall("skipped")) for c in cases),
        )
        assert actual == observed and group["attempted"] is True
        for key in counts:
            counts[key] += actual[key]
        statuses.append(group["status"])
    assert counts == dict(tests=1289, failures=1, errors=0, skipped=1)
    assert statuses.count("passed") == 26 and statuses.count("failed") == statuses.count("incomplete") == 1
    assert report["status"] == "failed" and report["qualification_eligible"] is False
    cleanup = json.loads(data["proof/cleanup.json"])
    assert cleanup["preserved_records"] == 333 and all(
        cleanup[k] is True for k in ["container_absent", "cgroup_absent", "profile_absent"]
    )
    samples = json.loads(data["proof/outside-samples.json"])
    assert len(samples) == 60
    for row in samples:
        assert row["exe_sha256"] == sha(executor) and row["nspid"][-1] == "1"
        assert row["limits"]["memory.max"] == str(12 * 1024**3) and row["limits"]["memory.swap.max"] == "0"
        assert row["limits"]["pids.max"] == "2048"
        quota, period = map(int, row["limits"]["cpu.max"].split())
        assert quota == 2 * period
    arm = archive(evidence / "native-feature-readback-vm-results-001.tar", 2 * 1024**2, ARM_HASH, 16)
    arm_result = json.loads(arm["result.json"])
    assert (
        arm_result["unit_tests_passed"] == 8
        and arm_result["readback_cases"] == 5
        and arm_result["preserved_records"] == 333
    )
    assert arm_result["reader_sha256"] == "ce3384735e511f83ac7401bec1b52be3feb6bca741ddedc7c1b3b0c72e6062af"
    for case in arm_result["cases"]:
        assert sha(arm[case["name"] + ".stdout"]) == case["stdout_sha256"]
        assert sha(arm[case["name"] + ".stderr"]) == case["stderr_sha256"]
    assert b"3 passed; 0 failed; 0 ignored" in arm["junit.stdout"]
    assert b"5 passed; 0 failed; 0 ignored" in arm["report.stdout"]
    reader = evidence / "native-feature-readback-mac-reader-001"
    assert sha(read(reader, 8 * 1024**2)) == MAC_READER_HASH
    args = [
        str(reader),
        str(stage / "inputs/feature-spec.json"),
        sha(data["inputs/feature-spec.json"]),
        str(stage / "proof/feature-stdout.json"),
        REPORT_HASH,
        str(stage / "output"),
    ]
    outcomes = []

    def invoke(label, argv, code):
        result = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            env={"PATH": "/usr/bin:/bin"},
            timeout=30,
        )
        assert len(result.stdout) <= 128 * 1024 and len(result.stderr) <= 128 * 1024 and result.returncode == code
        write(stage / (label + ".stdout"), result.stdout)
        write(stage / (label + ".stderr"), result.stderr)
        outcomes.append(
            dict(name=label, exit_code=code, stdout_sha256=sha(result.stdout), stderr_sha256=sha(result.stderr))
        )
        return result.stdout

    first = invoke("mac-actual", args, 1)
    assert first == arm["actual.stdout"] == arm["restart.stdout"]
    assert invoke("mac-restart", args, 1) == first
    for index, label in [(2, "mac-wrong-spec"), (4, "mac-wrong-report")]:
        changed = args.copy()
        changed[index] = "0" * 64
        assert not invoke(label, changed, 2)
    link = stage / "artifact-link"
    link.symlink_to(stage / "output", target_is_directory=True)
    changed = args.copy()
    changed[5] = str(link)
    assert not invoke("mac-symlink-root", changed, 2)
    forged = json.loads(report_raw)
    failed = next(g for g in forged["groups"] if g["status"] == "failed")
    failed["counts"]["failures"] = 0
    failed["status"] = "passed"
    forged["status"] = "incomplete"
    forged_raw = json.dumps(forged, sort_keys=True, separators=(",", ":")).encode()
    path = stage / "forged-report.json"
    write(path, forged_raw)
    changed = args.copy()
    changed[3:5] = [str(path), sha(forged_raw)]
    assert not invoke("mac-hidden-live-failure", changed, 2)
    assert sha(read(reader, 8 * 1024**2)) == MAC_READER_HASH
    result = dict(
        schema="hol-gauntlet-feature-executor-fixed-host-proof.v1",
        audit_archive_sha256=AUDIT_HASH,
        arm_archive_sha256=ARM_HASH,
        executor_commit=EXECUTOR_COMMIT,
        source_commit=PRODUCT,
        executor_git_blobs_checked=706,
        groups=28,
        counts=counts,
        audit_status="failed",
        python_baseline_junit_matches=28,
        outside_samples=60,
        arm_unit_tests=8,
        arm_readback_cases=5,
        mac_readback_cases=outcomes,
        readback_sha256=sha(first),
        worker_records_preserved=333,
        script_sha256=sha(read(Path(__file__).resolve(), 128 * 1024)),
        execution_eligible=False,
        qualification_eligible=False,
    )
    write(evidence / "native-feature-executor-fixed-host-proof-001.json", json.dumps(result, sort_keys=True).encode())
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    assert len(sys.argv) == 2
    main(Path(sys.argv[1]).resolve(strict=True))

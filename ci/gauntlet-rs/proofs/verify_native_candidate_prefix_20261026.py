"""Reproduce the source-pinned Native build/prefix and Python AST oracle proof.

This is an offline proof fixture, not a product runtime or admission reader.
The fixed hashes deliberately reject other generations. It imports no candidate.
"""

import argparse
import ast
import email.parser
import hashlib
import io
import json
import os
import pathlib
import stat
import subprocess
import tarfile
import types
import zipfile
from unittest.mock import patch

from packaging.requirements import Requirement

if not __debug__:
    raise SystemExit("This proof fixture requires assertions; Python optimization is unsupported.")


def bounded_file(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 < before.st_size <= 64 * 1024**2:
            raise ValueError("ordinary single-link proof file within 64 MiB required")
        raw = stream.read(64 * 1024**2 + 1)
        after = os.fstat(stream.fileno())

    def identity(value):
        return (
            value.st_dev,
            value.st_ino,
            value.st_uid,
            value.st_gid,
            value.st_mode,
            value.st_nlink,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
        )

    if len(raw) != before.st_size or identity(before) != identity(after) or identity(before) != identity(path.lstat()):
        raise ValueError("proof file changed during readback")
    return raw


parser = argparse.ArgumentParser(
    description="Recompute the retained 2026-10-26 build/prefix proof offline; this never admits an artifact."
)
parser.add_argument("--export", type=pathlib.Path, required=True)
parser.add_argument("--dependency-export", type=pathlib.Path, required=True)
parser.add_argument("--source-archive", type=pathlib.Path, required=True)
parser.add_argument("--publication-export", type=pathlib.Path)
parser.add_argument("--repository", type=pathlib.Path, default=pathlib.Path(__file__).resolve().parents[3])
parser.add_argument("--output", type=pathlib.Path)
args = parser.parse_args()
work = args.repository
inputs = {
    "native-candidate-prefix-vm-results-016.tar": args.export,
    "native-dependency-prefix-vm-results-014.tar": args.dependency_export,
}
if args.publication_export is not None:
    inputs["native-runtime-publication-vm-results-017.tar"] = args.publication_export


def archive(name, pin):
    raw = bounded_file(inputs[name])
    assert hashlib.sha256(raw).hexdigest() == pin
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as t:
        members = t.getmembers()
        assert len({m.name for m in members}) == len(members) and all(m.isfile() for m in members)
        return {m.name: t.extractfile(m).read() for m in members}


data = archive(
    "native-candidate-prefix-vm-results-016.tar", "861ec18d4be685b54a801900cd39309c8cfbd84e2feed217aced63838ea4ee18"
)
assert len(data) == 46
manifest = json.loads(data.pop("results.sha256.json"))
assert set(data) == set(manifest["files"])
for name, pin in manifest["files"].items():
    assert len(data[name]) == pin["bytes"] and hashlib.sha256(data[name]).hexdigest() == pin["sha256"]
v = json.loads(data["build/native-candidate-prefix.v1.json"])
assert (
    len(v) == 23
    and hashlib.sha256(data["build/native-candidate-prefix.v1.json"]).hexdigest()
    == "42a86cca874c40739f48019399b10c20a05f3d528c756f22efbe3833661f9433"
)
assert (
    v["source_sha"] == "62aa7ba777a5a4cc0806c34ee94e9822eaa58d32"
    and v["version"] == "3.57.0"
    and v["clone_generation"] == "11acd7f70119e504435c2a7e6a2a5ec96ec0496bad4e67b5e7aba0b92244e08f"
)
assert (
    hashlib.sha256(data["build/candidate.zip"]).hexdigest()
    == v["archive_sha256"]
    == "77dec4add32586606a1885d7a285f78c03e64bfe14a2877148086ddd0bf69177"
)
assert (
    hashlib.sha256(data["build/candidate-run.result.json"]).hexdigest()
    == "9afcea963f7a14eb2b9526d56b19b0cee00776d5258c122263f15f5a3aa59530"
)
assert (
    hashlib.sha256(bounded_file(args.source_archive)).hexdigest()
    == v["source_archive_sha256"]
    == "a02196e45587cdd9a82912c76bbe435d4fb7dc974b237b24597c5ac64f594869"
)
deps = archive(
    "native-dependency-prefix-vm-results-014.tar", "49a47fbcf6bc9b3ebad40406e36349a59d706155f4d0f153f19bd519c83f76aa"
)
rows = json.loads(deps["proof/prefix-tree.json"])["rows"]
total = 54452817
distributions = []
with zipfile.ZipFile(io.BytesIO(deps["build/dependencies.zip"])) as z:
    for item in z.infolist():
        if item.filename.endswith(".dist-info/METADATA"):
            m = email.parser.BytesParser().parsebytes(z.read(item))
            distributions.append(
                types.SimpleNamespace(metadata=m, version=m["Version"], requires=m.get_all("Requires-Dist", []))
            )
with zipfile.ZipFile(io.BytesIO(data["build/candidate.zip"])) as z:
    declaration = json.loads(z.read("artifact.json"))
    wheel = z.read(declaration["wheel"])
    assert len(z.infolist()) == 2
assert hashlib.sha256(wheel).hexdigest() == "4f29b6f76417b7172db007a64ac99f5de9c68b62078d95be5545f1fecd30c2f0"
framed = hashlib.sha256()
with zipfile.ZipFile(io.BytesIO(wheel)) as z:
    assert len(z.infolist()) == 1705
    for item in z.infolist():
        raw = z.read(item)
        total += len(raw)
        full = "lib/python3.12/site-packages/" + item.filename
        assert full not in rows
        rows[full] = {
            "uid": 0,
            "mode": 0o755 if item.filename == "codex_plugin_scanner/_native/hol-guard-runtime" else 0o644,
            "sha256": hashlib.sha256(raw).hexdigest(),
        }
        for parent in pathlib.PurePosixPath(full).parents:
            if parent.as_posix() == ".":
                break
            rows.setdefault(parent.as_posix(), {"uid": 0, "mode": 0o755})
        name = item.filename.encode()
        framed.update(len(name).to_bytes(8, "big"))
        framed.update(name)
        framed.update(len(raw).to_bytes(8, "big"))
        framed.update(raw)
        if item.filename.endswith(".dist-info/METADATA"):
            m = email.parser.BytesParser().parsebytes(raw)
            distributions.append(
                types.SimpleNamespace(metadata=m, version=m["Version"], requires=m.get_all("Requires-Dist", []))
            )
assert framed.hexdigest() == "386a5fca7880da49c1a18b8ecda229ca68d2a0c786bb7736c3b2acd7457dcf6b"
aliases = {
    "hol-guard": "codex_plugin_scanner.cli",
    "hol-guard-eval": "codex_plugin_scanner.guard.evaluation_cli",
    "hol-guard-secrets": "codex_plugin_scanner.guard.secrets.cli",
    "plugin-ecosystem-scanner": "codex_plugin_scanner.cli",
    "plugin-guard": "codex_plugin_scanner.cli",
    "plugin-scanner": "codex_plugin_scanner.cli",
}
for name, module in aliases.items():
    raw = (
        "#!/bin/sh\n'''exec' \"\u0024{0%/*}/python3\" -I -B \"\u00240\" \"\u0024@\"\n' '''\nfrom "
        + module
        + " import main\nraise SystemExit(main())\n"
    ).encode()
    total += len(raw)
    rows["bin/" + name] = {"uid": 0, "mode": 0o755, "sha256": hashlib.sha256(raw).hexdigest()}
    ast.parse(raw)
actual = json.loads(data["proof/prefix-tree.json"])
assert (
    actual["rows"] == rows and len(rows) - 1 == v["prefix_entries"] == 4411 and total == v["prefix_bytes"] == 117018419
)
digest = hashlib.sha256(
    json.dumps(rows, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
).hexdigest()
assert (
    digest
    == actual["sha256"]
    == v["prefix_tree_sha256"]
    == "cd092b3c0658a3aee2b436b3e4f3639627f244190ef255e1e3463487b6621637"
)
requirements = json.loads(json.loads(data["proof/requirements.json"])["stdout"])
proof = json.loads(data["proof/proof.json"])
source = subprocess.check_output(
    ["/usr/bin/git", "show", "62aa7ba777a5a4cc0806c34ee94e9822eaa58d32:ci/gauntlet/control_plane/stage_candidate.py"],
    cwd=work,
    timeout=30,
)
assert hashlib.sha256(source).hexdigest() == "5efea18a042264b74b9ae44e5450e53552d20d79a04e76add55dbf8ab3be0a97"
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
    "platform_release": proof["uname"][2],
    "platform_system": "Linux",
    "platform_version": proof["uname"][3],
    "python_full_version": "3.12.3",
    "python_version": "3.12",
    "sys_platform": "linux",
}
scope = {
    "Requirement": Requirement,
    "distributions": lambda path: distributions,
    "prefix": pathlib.Path("/inert-prefix"),
    "SITE": "lib/python3.12/site-packages/",
}
with patch("packaging.markers.default_environment", return_value=environment):
    exec(
        compile(
            ast.Module(body=[assignment("installed"), assignment("product"), loop], type_ignores=[]),
            "exact-source-requirement-oracle",
            "exec",
        ),
        scope,
    )
    specs = [Requirement(s) for s in scope["product"].requires]
    active = [s for s in specs if not s.marker or s.marker.evaluate({"extra": ""})]
assert (
    len(scope["installed"]) == requirements["installed_distributions"] == 63
    and len(specs) == requirements["requirements"] == 23
    and len(active) == requirements["active_requirements"] == 13
    and len(specs) - len(active) == requirements["inactive_requirements"] == 10
)
names = sorted(s.name.lower().replace("_", "-") for s in active)
assert names == requirements["active_names"] and scope["installed"]["mcp"].version == "1.30.0"
for name in [
    "wrong-source",
    "wrong-source-archive",
    "wrong-artifact",
    "wrong-version",
    "wrong-dependency-job",
    "wrong-dependency-receipt",
    "wrong-dependency-tree",
    "wrong-wheel-tree",
    "wrong-generation",
    "rust-lease-busy",
    "legacy-lease-busy",
    "replay",
    "dependency-wrong-tree",
    "dependency-wrong-native",
]:
    assert json.loads(data["proof/" + name + ".json"])["returncode"] == 2
assert (
    proof["original_files_unchanged"] == 4041 and proof["status"] == "passed" and proof["all_containers_absent"] is True
)
assert (
    hashlib.sha256(data["proof/worker-lib.log"]).hexdigest()
    == "ca5e7f1479a781eaff5723afa5a277ac25757725587eefc63615d7ba225daca6"
)
assert all(
    v[k] is False
    for k in [
        "artifact_admitted",
        "execution_eligible",
        "guard_causality_verified",
        "candidate_executed",
        "conformance_completed",
    ]
)
out = {
    "schema": "hol-gauntlet-host-native-candidate-prefix-verification.v1",
    "all_46_members_verified": True,
    "prefix_tree_independently_reconstructed": True,
    "prefix_tree_sha256": digest,
    "receipt_sha256": "42a86cca874c40739f48019399b10c20a05f3d528c756f22efbe3833661f9433",
    "prefix_entries": 4411,
    "prefix_bytes": total,
    "python_source_ast_requirement_oracle_matched": True,
    "python_oracle_source_sha256": hashlib.sha256(source).hexdigest(),
    "installed_distributions": 63,
    "requirements": 23,
    "active_requirements": 13,
    "inactive_requirements": 10,
    "active_names": names,
    "mcp_version": "1.30.0",
    "refusals_verified": 14,
    "artifact_admitted": False,
    "execution_eligible": False,
    "guard_causality_verified": False,
    "model_requests": 0,
}
if args.publication_export is not None:
    publication = archive(
        "native-runtime-publication-vm-results-017.tar",
        "22d3eb8c01e63e01b36c63b130491049295dea0599ea4e1990da855bca17e161",
    )
    assert len(publication) == 23
    manifest = json.loads(publication.pop("results.sha256.json"))
    assert set(publication) == set(manifest["files"])
    for name, pin in manifest["files"].items():
        assert len(publication[name]) == pin["bytes"]
        assert hashlib.sha256(publication[name]).hexdigest() == pin["sha256"]
    receipt = publication["runtime/native-runtime.v1.json"]
    assert receipt == publication["build/native-runtime-publication.v1.json"]
    receipt_hash = hashlib.sha256(receipt).hexdigest()
    assert receipt_hash == "3b5ed1b9d5ea1faa395aae6526d7ec746408d376fb134ae5e6b0bc9df930f432"
    runtime = json.loads(receipt)
    assert runtime["schema"] == "hol-gauntlet-native-runtime-publication.v1"
    assert runtime["source_sha"] == v["source_sha"] and runtime["version"] == v["version"]
    assert runtime["publisher_generation"] == "47cd8c5a8b110870e0d1be2439818121a89ab2797ab60d2011ad5ca532792235"
    assert runtime["prefix_tree_sha256"] == digest
    assert runtime["prefix_entries"] == 4411 and runtime["prefix_bytes"] == total
    assert runtime["dependency_requirements"] == requirements
    assert publication["build/native-candidate-prefix.v1.json"] == data["build/native-candidate-prefix.v1.json"]
    assert runtime["clone_receipt_sha256"] == out["receipt_sha256"]
    assert json.loads(publication["proof/published-prefix-tree.json"])["rows"] == rows
    assert all(
        runtime[key] is False
        for key in [
            "candidate_executed",
            "conformance_completed",
            "artifact_admitted",
            "execution_eligible",
            "guard_causality_verified",
        ]
    )
    assert runtime["model_requests"] == 0
    for name in [
        "wrong-source",
        "wrong-version",
        "wrong-clone-receipt",
        "wrong-prefix-tree",
        "wrong-native",
        "wrong-python-version",
        "wrong-generation",
        "rust-lease-busy",
        "legacy-lease-busy",
        "replay",
    ]:
        assert json.loads(publication["proof/" + name + ".json"])["returncode"] == 2
    proof = json.loads(publication["proof/proof.json"])
    assert proof["status"] == "passed" and proof["all_original_files_unchanged"] == 8059
    assert proof["dual_receipts_match"] is True
    assert hashlib.sha256(publication["proof/worker-lib.log"]).hexdigest() == (
        "b12eb1186550da5c296b068572f14052212213cc6d61bd2927df4bea66f4c11a"
    )
    out["runtime_publication"] = {
        "all_23_members_verified": True,
        "published_tree_matches": True,
        "dual_receipts_identical": True,
        "receipt_sha256": receipt_hash,
        "refusals_verified": 10,
        "root_tests_passed": 135,
        "root_fixture_ignores": 24,
    }
if args.output is not None:
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(out, f, sort_keys=True)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
print(json.dumps(out, sort_keys=True))

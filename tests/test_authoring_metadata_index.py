"""Real offline CLI evidence; synthetic metadata is not bundle authentication."""

from __future__ import annotations

import base64
import copy
import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.catalog_delivery.metadata_objects import ObjectStore, encoded
from codex_plugin_scanner.guard.extension_builder.metadata_index import write_index as native_write_index

ROOT = Path(__file__).resolve().parents[1]


def write_index(directory, catalog, engine, source_context):
    return native_write_index(
        directory, catalog, engine, source_context, compiler=ROOT / "rust/target/debug/guard-command-source"
    )


def invoke(compiler, request, operation="compile"):
    return subprocess.run(
        [str(compiler), operation],
        input=encoded(request),
        capture_output=True,
        timeout=120,
        check=False,
    )


@pytest.fixture(scope="module")
def native(tmp_path_factory):
    compiler = ROOT / "rust/target/debug/guard-command-source"
    if not compiler.is_file():
        pytest.skip("build the actual native source CLI before running index qualification")
    built = json.loads(subprocess.check_output([str(compiler), "export-built"], timeout=60))
    trust = json.loads(subprocess.check_output([str(compiler), "export-trust"], timeout=60))
    source = json.loads((ROOT / "rust/crates/guard-command/tests/fixtures/command-source-example.v1.json").read_bytes())
    dependency = json.loads(json.dumps(source).replace("command.example-cli", "command.dependency"))

    def frame(value):
        data = encoded(value)
        return len(data).to_bytes(4, "big") + data

    sys.path.insert(0, str(ROOT / "scripts"))
    try:
        from build_native_command_packs import input_stream

        buffer = io.BytesIO()
        count = input_stream(ROOT, buffer)
    finally:
        sys.path.remove(str(ROOT / "scripts"))
    canonical = buffer.getvalue()
    header_length = int.from_bytes(canonical[5:9], "big")
    stream = b"HGPS\x01" + frame({"schema": "guard.command-pack-source-stream.v1", "count": count + 1})
    stream += canonical[9 + header_length :]
    pack_trust = copy.deepcopy(trust)
    pack_trust["classes"] = {"external": ["command.dependency"], "first-party": [], "trusted-library": []}
    stream += frame({"kind": "command", "trust": pack_trust}) + frame(dependency)
    response = subprocess.run([str(compiler), "compile-packs"], input=stream, capture_output=True, timeout=60)
    assert response.returncode == 0, response.stdout
    store = ObjectStore(tmp_path_factory.mktemp("core-index-pack").resolve())
    release = None
    for line in response.stdout.splitlines():
        row = json.loads(line)
        if row["kind"] == "object":
            store.put(base64.b64decode(row["data"]))
        elif row["kind"] == "root":
            release = row
    from codex_plugin_scanner.guard.catalog_delivery.metadata_objects import entries

    assert release is not None
    manifest = store.json(dict(entries(store, release["index"], count + 1))["command.dependency"])
    program = store.json(manifest["program"])
    program["nodes"] = {identity: store.json(reference) for identity, reference in program["nodes"].items()}
    selected = {"catalog": store.json(manifest["catalog"]), "program": program}
    candidate = copy.deepcopy(source)
    candidate["extension"]["dependencies"] = ["command.dependency"]
    candidate["extension"]["permissions"][0]["dependencies"] = ["command.dependency.permission.destroy"]
    request = {"schema": "guard.command-extension-build.v1", "base": "packaged", "sources": [candidate], "trust": trust}
    return compiler, built, selected, request


def inventory(native, count):
    _, built, selected, _ = native
    catalog = copy.deepcopy(built["catalog"] + selected["catalog"])
    template = json.dumps(selected["catalog"][0])
    for index in range(count - len(catalog)):
        catalog.append(json.loads(template.replace("command.dependency", f"command.zzinactive{index:05d}")))
    return catalog


def request_for(native, directory, catalog):
    _, built, selected, request = native
    request = copy.deepcopy(request)
    request["validation_base"] = {
        "metadata_index": write_index(directory, catalog, built["implementation_digest"], "a" * 64),
        "programs": [selected["program"]],
    }
    return request


def test_actual_cli_scales_complete_inventory_with_fixed_selected_ir(native, tmp_path):
    compiler, _, _, _ = native
    digests = []
    evidence = []
    for count in (166, 1660, 16600):
        catalog = inventory(native, count)
        request = request_for(native, tmp_path / str(count), catalog)
        response = invoke(compiler, request)
        assert response.returncode == 0, response.stdout
        result = json.loads(response.stdout)
        digests.append(result["program"]["program_digest"])
        assert len(encoded(request)) < 64 * 1024
        assert len(result["program"]["extensions"]) == len(native[1]["program"]["extensions"]) + 2
        evidence.append(
            {"inventory": count, "request_bytes": len(encoded(request)), "metadata_bytes": len(encoded(catalog))}
        )
        if count == 16600:
            # Only the last inactive extension collides with the contributor.
            catalog[-1]["aliases"] = ["command.example-cli"]
            bad = request_for(native, tmp_path / "last-collision", catalog)
            rejected = invoke(compiler, bad)
            assert rejected.returncode == 2
            assert json.loads(rejected.stdout)["code"] == "command_source_alias_collision"
    assert len(set(digests)) == 1
    print(json.dumps({"core_index_scale": evidence, "fixed_program_digest": digests[0]}, sort_keys=True))


@pytest.mark.parametrize(
    "fault",
    ["ownership", "owner-field", "dependency", "permission-dependency", "cycle", "conflict", "family", "mcp", "core"],
)
def test_global_inactive_relationships_are_not_hidden(native, tmp_path, fault):
    catalog = inventory(native, 166)
    last, previous = catalog[-1], catalog[-2]
    if fault == "ownership":
        last["permissions"][0]["permission_id"] = previous["permissions"][0]["permission_id"]
    elif fault == "owner-field":
        last["permissions"][0]["extension_id"] = previous["extension_id"]
    elif fault == "dependency":
        last["dependencies"] = ["command.absent"]
    elif fault == "permission-dependency":
        last["permissions"][0]["dependencies"] = ["command.absent.permission.destroy"]
    elif fault == "cycle":
        last["dependencies"] = [previous["extension_id"]]
        previous["dependencies"] = [last["extension_id"]]
    elif fault == "conflict":
        last["conflicts"] = ["command.absent"]
    elif fault == "family":
        last["permissions"][0]["family"] = previous["permissions"][0]["family"] = "shared.family"
    elif fault == "mcp":
        # Duplicate targets in two globally inactive metadata records.
        last["mcp_launch"] = previous["mcp_launch"] = {"kind": "direct-command", "command": "same-mcp-target"}
    else:
        catalog[0]["description"] += " substituted"
    rejected = invoke(native[0], request_for(native, tmp_path / "index", catalog))
    assert rejected.returncode == 2, rejected.stdout


def replace_root(handle, change):
    store = ObjectStore(Path(handle["directory"]))
    root = store.json(handle["root"])
    change(store, root)
    handle["root"] = store.put_json(root)
    for path in store.directory.iterdir():
        path.chmod(0o400)


@pytest.mark.parametrize(
    "fault",
    [
        "missing",
        "corrupt",
        "hash",
        "duplicate",
        "order",
        "page-count",
        "count",
        "total-budget",
        "total-mismatch",
        "source-context",
        "engine",
        "substitution",
        "extra-page",
        "page-items",
        "record-budget",
        "symlink",
        "hardlink",
        "nonregular",
        "mutable",
    ],
)
def test_index_integrity_and_resource_rejections(native, tmp_path, fault):
    request = request_for(native, tmp_path / "index", inventory(native, 166))
    handle = request["validation_base"]["metadata_index"]
    store = ObjectStore(Path(handle["directory"]))
    root = store.json(handle["root"])
    path = store.directory / (root["first"]["sha256"] + ".json")
    if fault in {"missing", "corrupt", "symlink", "hardlink", "nonregular", "mutable"}:
        data = path.read_bytes()
        path.unlink()
        if fault == "corrupt":
            path.write_bytes(b"!" + data[1:])
            path.chmod(0o400)
        elif fault == "symlink":
            target = tmp_path / "target"
            target.write_bytes(data)
            path.symlink_to(target)
        elif fault == "hardlink":
            target = tmp_path / "target"
            target.write_bytes(data)
            target.chmod(0o400)
            os.link(target, path)
        elif fault == "nonregular":
            path.mkdir()
        elif fault == "mutable":
            path.write_bytes(data)
    else:

        def change(store, root):
            if fault == "page-count":
                root["pages"] += 1
            elif fault == "count":
                root["count"] = 100001
            elif fault == "total-budget":
                root["total_bytes"] = 128 * 1024 * 1024 + 1
            elif fault == "total-mismatch":
                root["total_bytes"] -= 1
            elif fault == "source-context":
                root["source_context"] = "0" * 64
            elif fault == "engine":
                root["engine"] = "0" * 64
            elif fault == "hash":
                root["first"]["sha256"] = "0" * 64
            else:
                page = store.json(root["first"])
                if fault == "duplicate":
                    page["entries"][1] = page["entries"][0]
                elif fault == "order":
                    page["entries"].reverse()
                elif fault == "substitution":
                    page["entries"][0][1] = page["entries"][1][1]
                elif fault == "extra-page":
                    page["next"] = None
                elif fault == "page-items":
                    page["entries"] *= 65
                elif fault == "record-budget":
                    root["total_bytes"] += 8 * 1024 * 1024
                    page["entries"][0][1]["expanded_length"] = 8 * 1024 * 1024 + 1
                root["first"] = store.put_json(page)

        replace_root(handle, change)
    rejected = invoke(native[0], request)
    assert rejected.returncode == 2, rejected.stdout


def test_per_record_and_legacy_json_caps_remain_fixed(native, tmp_path):
    from codex_plugin_scanner.guard.extension_builder.native_source_compiler import NativeSourceCompilerError

    with pytest.raises(NativeSourceCompilerError, match="authoring_transport_record_invalid"):
        write_index(
            tmp_path / "oversize",
            [{"extension_id": "command.large", "padding": "x" * (8 * 1024 * 1024)}],
            native[1]["implementation_digest"],
            "b" * 64,
        )
    request = copy.deepcopy(native[3])
    request["validation_base"] = {"catalog": [0] * 4097, "programs": []}
    assert invoke(native[0], request).returncode == 2
    result = subprocess.run(
        [str(native[0]), "compile"], input=b" " * (8 * 1024 * 1024 + 1), capture_output=True, timeout=30
    )
    assert result.returncode == 2


def test_metadata_cannot_grant_candidate_publisher_trust(native, tmp_path):
    catalog = inventory(native, 166)
    catalog[-1]["trust_class"] = "first-party"
    request = request_for(native, tmp_path / "index", catalog)
    response = invoke(native[0], request)
    assert response.returncode == 0, response.stdout
    candidate = next(
        entry
        for entry in json.loads(response.stdout)["program"]["extensions"]
        if entry["extension_id"] == "command.example-cli"
    )
    assert candidate["trust_class"] == "external"
    assert candidate["publisher"]["id"] == "community"


def test_builder_real_development_stream_preserves_commands_and_overwrites_opaque_context(native):
    from codex_plugin_scanner.guard.extension_builder.native_source_compiler import run_source_compiler

    request = copy.deepcopy(native[3])
    request["sources"][0]["extension"]["dependencies"] = []
    request["sources"][0]["extension"]["permissions"][0]["dependencies"] = []
    # Even an oversized unserializable kit field must be replaced before JSON
    # admission. This exercises the real globally validated development stream.
    request["validation_base"] = {"opaque": object(), "padding": "x" * (8 * 1024 * 1024)}
    compiled = run_source_compiler("compile", request, compiler=native[0], timeout=120)
    digest = compiled["program"]["program_digest"]
    validated = run_source_compiler("validate", request, compiler=native[0], timeout=120)
    assert validated["program_digest"] == digest
    checked = run_source_compiler("check", request, compiler=native[0], digest=digest, timeout=120)
    assert checked["program_digest"] == digest
    fixture = json.loads(
        (ROOT / "rust/crates/guard-command/tests/fixtures/command-source-behavior.v1.json").read_bytes()
    )
    fixture["build"] = request
    tested = run_source_compiler("test", fixture, compiler=native[0], timeout=120)
    assert tested["ok"] is True
    assert tested["target_commands_executed"] == 0
    compared = run_source_compiler(
        "compare",
        {
            "schema": "guard.command-extension-parity.v1",
            "build": request,
            "baseline_program": compiled["program"],
            "cases": [
                {"id": "same", "payload": {"tool_name": "Bash", "tool_input": {"command": "pwd"}}, "controls": []}
            ],
        },
        compiler=native[0],
        timeout=120,
    )
    assert compared["ok"] is True


def test_native_index_assembles_metadata_from_bounded_cas_objects(native, tmp_path):
    catalog = inventory(native, 166)
    catalog[-1]["diagnostic_metadata"] = ["x" * 4000] * 30
    request = request_for(native, tmp_path / "index", catalog)
    response = invoke(native[0], request)
    assert response.returncode == 0, response.stdout


def test_prepare_fixture_native_context_lives_until_cli_returns(native):
    from scripts import prepare_extension_contribution as prepare

    path = ROOT / "tests/fixtures/command-source-theourgia.v1.json"
    assert prepare._validate_fixture(native[0], path) == path.relative_to(ROOT).as_posix()

"""Replay frozen host-event vectors against reviewed, unchanged Python reducers.

Reviewed Main generations changed other parts of evidence.py. The historical vectors
and generators remain immutable. This proof accepts only the exact reviewed
source generation, checks normalized function ASTs against 7eba6064, and executes
only the generators' isolated stdlib-only functions, never controller imports.
The retained legacy scope stays immutable; newer known Source drift is a
separate unsupported observation, never current assessment parity.
"""

from __future__ import annotations

import ast
import hashlib
import importlib.util
import io
import json
import sys
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
PROOFS = ROOT / "ci/gauntlet-rs/proofs"
FIXTURES = ROOT / "ci/gauntlet-rs/crates/gauntlet-evidence/tests"
HISTORICAL = "b76344cf9700c73abebd5d65a81d34aa28c960b591fc2bc485423afa038efe2f"
# Prior reviewed generation: b5a2ba7d80f6bb16eb60d125299b0f7874e1befded2680b0394cb065e4ba2a51.
# Main2a changed whole-case lifecycle grading. Neither host-event reducer changed.
CURRENT = "a5a14240089ce24010c0befa0acbdd7cf45cd29a91bcaf20a7aaa153cf82c533"
FUNCTIONS = {
    "reconcile": "a70ae54c39ced369635adfab98f73cf8f719b359bdee92704fdf6459db584605",
    "read_events": "408a5d0412c2b2e91031b017e84bbbcb377495226bdeffe04757cec950e62c40",
}
GENERATORS = {
    "host-calls": (
        "freeze_host_calls_v1.py",
        "3969076a9926c8b5dd849ec190b4da205c9fb2f27cbb4c57c3a3218abb21ed16",
        "python_host_calls_v1.json",
        31,
    ),
    "omp-transcript": (
        "freeze_omp_transcript_v1.py",
        "8a9f211795f2f18f4f5db2f5df73a7edcaf972189d52f997ac97d9f6125c2913",
        "python_omp_transcript_v1.json",
        15,
    ),
}
KNOWN_CURRENT_UNSUPPORTED = {
    "schema": "gauntlet-known-current-unsupported-observation.v1",
    "upstream_commit": "fc0486a63e0664ab1002080a1d96fa84ca74c1bc",
    "source_generation": "fc0486-core378-approval19",
    "source_sha256": {
        "ci/gauntlet/approval_retry.json": "342f15e622148a5405fdc6efc97b2c2f1ee1ab8efb28d61aa3e78235bfc09577",
        "ci/gauntlet/connector_judge.py": "b481c3d794cdd7bd1ccb4b85f7486209925dd159891471ef26911e10c37eb9ad",
    },
    "approval_retry_scenarios": 19,
    "retained_approval_retry_scenarios": 16,
    "additional_changed_definition_asts": 1,
    "current_legacy_generation_supported": False,
    "full_current_assessment_parity": False,
}
CONNECTOR_SETUP_ASTS = (
    "2d2bce4719d3c2e2dd55f0c40e131379083ba7d638cddc3129fdb0b8a33142d0",
    "6fde59b4ffd72a84295e268222c551cd96b5cbe901d71b63b8fcc9d1c7e46657",
)


def normalized(node):
    if isinstance(node, ast.AST):
        fields = {}
        for name, value in ast.iter_fields(node):
            # Python 3.12 adds this empty field to ordinary functions. Reject
            # generics, while comparing the same AST on Python 3.9 and 3.12+.
            if name == "type_params":
                if value:
                    raise ValueError("unexpected generic reducer")
                continue
            fields[name] = normalized(value)
        return [type(node).__name__, fields]
    if isinstance(node, list):
        return [normalized(value) for value in node]
    if isinstance(node, bytes):
        return ["bytes", node.hex()]
    if node is Ellipsis:
        return ["ellipsis"]
    return node


def definition_asts(raw):
    result = {}
    for node in ast.parse(raw).body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.name in result:
                raise ValueError("ambiguous Source definition")
            canonical = json.dumps(normalized(node), sort_keys=True, separators=(",", ":"),
                                   ensure_ascii=False).encode()
            result[node.name] = hashlib.sha256(canonical).hexdigest()
    return result


def check_definition_asts(actual, row, path):
    expected = dict(row["unchanged_definition_asts"])
    expected.update({name: pair["current"] for name, pair in row["changed_definition_asts"].items()})
    expected.update(row["added_definition_asts"])
    if path == "ci/gauntlet/connector_judge.py":
        if expected.get("connector_setup_outcome") != CONNECTOR_SETUP_ASTS[0]:
            raise ValueError("immutable connector predecessor AST changed")
        expected["connector_setup_outcome"] = CONNECTOR_SETUP_ASTS[1]
    if actual != expected or set(actual) & set(row["removed_definition_asts"]):
        raise ValueError("Source differs outside the known unsupported AST drift")


def known_current_observation(scope):
    for path, digest in KNOWN_CURRENT_UNSUPPORTED["source_sha256"].items():
        if hashlib.sha256((ROOT / path).read_bytes()).hexdigest() != digest:
            raise ValueError("Source is outside the known unsupported generation")
    approval = json.loads((ROOT / "ci/gauntlet/approval_retry.json").read_bytes())["scenarios"]
    if (len(approval) != 19 or len({row["id"] for row in approval}) != 19
            or not any(row["id"] == "approved-retry-waited-command" for row in approval)):
        raise ValueError("known unsupported approval catalog changed")
    path = "ci/gauntlet/connector_judge.py"
    row = scope["source_lineage"][path]
    actual = definition_asts((ROOT / path).read_bytes())
    check_definition_asts(actual, row, path)
    for name, digest in [("connector_setup_outcome", CONNECTOR_SETUP_ASTS[0]),
                         ("connector_identity", "0" * 64),
                         ("unreviewed_definition", "0" * 64), ("_group_error", None)]:
        changed = dict(actual)
        if digest is None:
            del changed[name]
        else:
            changed[name] = digest
        try:
            check_definition_asts(changed, row, path)
        except ValueError:
            continue
        raise ValueError("counterfactual connector AST drift was accepted")
    return {**KNOWN_CURRENT_UNSUPPORTED, "counterfactual_ast_refusals": 4}


def retained_legacy_scope() -> dict:
    """Verify historical identity and scoped ASTs, not current legacy grading."""
    directory = FIXTURES / "fixtures"
    raw = (directory / "python_legacy_source_scope_main2a_v1.json").read_bytes()
    if hashlib.sha256(raw).hexdigest() != "79b9b02eac0a0a5483d9dce294314304a457588daf19d408dc4888e612f02dee":
        raise ValueError("retained legacy lineage changed")
    scope = json.loads(raw)
    if (scope["schema"] != "gauntlet-retained-legacy-source-scope.v1"
            or scope["supported_generation"] != "retained-legacy-v1-core310-approval16"
            or scope["current_generation"] != "main2a-core378-approval18"
            or scope["full_current_assessment_parity"] is not False
            or scope["current_legacy_generation_supported"] is not False):
        raise ValueError("historical and current legacy generations must remain distinct")
    known_current = known_current_observation(scope)
    identities = {}
    for name, digest in scope["immutable_fixtures"].items():
        if Path(name).name != name or not name.endswith(".json"):
            raise ValueError("invalid immutable fixture name")
        frozen = (directory / name).read_bytes()
        if hashlib.sha256(frozen).hexdigest() != digest:
            raise ValueError("historical full-result golden changed")
        for source, original in json.loads(frozen).get("source_sha256", {}).items():
            path = source if "/" in source else "ci/gauntlet/" + source
            identities.setdefault(path, set()).add(original)
    unchanged = changed = 0
    for path, row in scope["source_lineage"].items():
        if (".." in Path(path).parts or Path(path).is_absolute()
                or set(row["historical_sha256"]) != identities[path]
                or row["full_current_assessment_parity"] is not False):
            raise ValueError("legacy source identity or claim scope changed")
        current = (ROOT / path).read_bytes()
        expected_sha = known_current["source_sha256"].get(path, row["current_sha256"])
        if hashlib.sha256(current).hexdigest() != expected_sha:
            raise ValueError("Source is outside the reviewed historical/current pair")
        if not path.endswith(".py"):
            if row["current_data_generation_supported"] is not False:
                raise ValueError("new catalog generation is not admitted")
            continue
        actual = definition_asts(current)
        unchanged += len(row["unchanged_definition_asts"])
        for pair in row["changed_definition_asts"].values():
            if pair["historical"] == pair["current"]:
                raise ValueError("changed oracle cannot claim AST identity")
            changed += 1
        check_definition_asts(actual, row, path)
    if len(scope["immutable_fixtures"]) != 9 or len(scope["source_lineage"]) != 17:
        raise ValueError("historical fixture/source scope changed")
    return {"schema":scope["schema"], "historical_fixtures":9, "source_files":17,
            "unchanged_definition_asts":unchanged, "changed_definition_asts":changed,
            "definition_counts_generation":scope["current_generation"],
            "known_current_observation":known_current,
            "current_legacy_generation_supported":False, "full_current_assessment_parity":False}


def verify(kind: str) -> dict:
    source = ROOT / "ci/gauntlet/evidence.py"
    raw = source.read_bytes()
    if hashlib.sha256(raw).hexdigest() != CURRENT:
        raise ValueError("current evidence source is outside the reviewed compatibility pair")
    tree = ast.parse(raw)
    for name, expected in FUNCTIONS.items():
        found = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name]
        if len(found) != 1:
            raise ValueError("reducer is absent or ambiguous")
        canonical = json.dumps(normalized(found[0]), sort_keys=True, separators=(",", ":"),
                               ensure_ascii=False).encode()
        if hashlib.sha256(canonical).hexdigest() != expected:
            raise ValueError("reviewed reducer AST changed")
    generator, digest, fixture_name, count = GENERATORS[kind]
    path = PROOFS / generator
    if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
        raise ValueError("historical fixture generator changed")
    spec = importlib.util.spec_from_file_location("frozen_host_event_proof", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    fixture = json.loads((FIXTURES / fixture_name).read_bytes())
    if kind == "host-calls":
        original, function = module.SOURCES["ci/gauntlet/evidence.py"]
        module.SOURCES = {**module.SOURCES, "ci/gauntlet/evidence.py": (CURRENT, function)}
        frozen = next(row["sha256"] for row in fixture["sources"]
                      if row["path"] == "ci/gauntlet/evidence.py")
    else:
        original = module.SOURCE_SHA256
        module.SOURCE_SHA256 = CURRENT
        frozen = fixture["source_sha256"]
    if original != HISTORICAL or frozen != HISTORICAL:
        raise ValueError("historical fixture source binding changed")
    captured = io.StringIO()
    with redirect_stdout(captured):
        module.main()
    replayed = json.loads(captured.getvalue())
    if (replayed["schema"] != fixture["schema"] or len(replayed["cases"]) != count
            or replayed["cases"] != fixture["cases"]):
        raise ValueError("current Python reducer differs from the immutable frozen cases")
    return {"schema": "gauntlet-host-event-source-compatibility.v1", "kind": kind,
            "historical_source_sha256": HISTORICAL, "current_source_sha256": CURRENT,
            "replayed_cases": count, "unchanged_function_asts": len(FUNCTIONS)}


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in {*GENERATORS, "retained-legacy-v1"}:
        raise SystemExit("usage: verify_host_event_fixture_compatibility.py host-calls|omp-transcript|retained-legacy-v1")
    result = retained_legacy_scope() if sys.argv[1] == "retained-legacy-v1" else verify(sys.argv[1])
    print(json.dumps(result, sort_keys=True))

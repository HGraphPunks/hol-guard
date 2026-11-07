"""Freeze actual source-pinned Python NativeHook normalization as inert cases."""

from __future__ import annotations

import ast
import base64
import copy
import hashlib
import json
import re
import subprocess
from pathlib import Path

SOURCE = "62aa7ba777a5a4cc0806c34ee94e9822eaa58d32"
REPO = Path(__file__).resolve().parents[3]


def blob(path):
    return subprocess.check_output(["git", "show", SOURCE + ":" + path], cwd=REPO)


def main():
    source = blob("ci/gauntlet/benchmark/native_builtin_plane.py")
    json_source = blob("ci/gauntlet/benchmark/json_data.py")
    namespace = {"__name__": "frozen_gauntlet_json_oracle"}
    exec(compile(json_source, "pinned-json-oracle", "exec"), namespace)
    function = next(
        n for n in ast.parse(source).body if isinstance(n, ast.FunctionDef) and n.name == "decode_hook_response"
    )
    oracle = {"strict_json_loads": namespace["strict_json_loads"], "re": re}
    exec(compile(ast.Module(body=[function], type_ignores=[]), "pinned-hook-oracle", "exec"), oracle)
    decode = oracle["decode_hook_response"]
    rows = []

    def add(name, value, code=0, event="PreToolUse", *, raw=None):
        raw = (
            json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
            if raw is None
            else raw
        )
        try:
            expected = {"accepted": True, "value": decode(raw, returncode=code, event=event)}
        except ValueError as error:
            reason = str(error)
            kind = (
                "prompt"
                if reason.startswith("normal OMP prompt")
                else "mediation"
                if reason.startswith("normal OMP structured")
                else "decision"
                if reason.startswith("actual installed OMP")
                else "json"
            )
            expected = {"accepted": False, "kind": kind, "reason": reason}
        rows.append(
            {
                "name": name,
                "raw_base64": base64.b64encode(raw).decode(),
                "returncode": code,
                "event": event,
                "expected": expected,
            }
        )

    for decision in ["allow", "deny", "block"]:
        for code in [0, 2, -9]:
            add(f"{decision}-exit-{code}", {"decision": decision}, code)
    for name, value in [
        ("null", None),
        ("array", []),
        ("boolean", True),
        ("missing-decision", {}),
        ("wrong-decision", {"decision": "warn"}),
        ("null-decision", {"decision": None}),
        ("null-reason", {"decision": "deny", "reason": None}),
        ("number-reason", {"decision": "deny", "reason": 1}),
        ("string-reason", {"decision": "deny", "reason": "retained"}),
        (
            "extra-product-fields",
            {"decision": "deny", "reason_code": "sandbox", "required_execution_profile": "workspace-contained-v1"},
        ),
    ]:
        add(name, value)
    prompt = {
        "policy_action": "allow",
        "reason_code": "prompt_context",
        "hookSpecificOutput": {"hookEventName": "UserPromptSubmit"},
    }
    add("prompt-v2", prompt, event="UserPromptSubmit")
    add("prompt-v2-warn", {**prompt, "policy_action": "warn"}, event="UserPromptSubmit")
    add("prompt-v2-nonzero", prompt, 2, "UserPromptSubmit")
    add("prompt-v2-wrong-event", prompt)
    add("prompt-v1-denial", {"decision": "deny", "reason": "retained"}, 2, "UserPromptSubmit")
    for field, value in [
        ("policy_action", "deny"),
        ("reason_code", ""),
        ("reason_code", None),
        ("hookSpecificOutput", {}),
        ("hookSpecificOutput", {"hookEventName": "UserPromptSubmit", "extra": True}),
        ("risk_signals", []),
        ("risk_signals", ["observed"]),
        ("risk_signals", [True]),
        ("risk_signals", None),
        ("extra", True),
    ]:
        add(f"prompt-{field}-{len(rows)}", {**prompt, field: value}, event="UserPromptSubmit")
    for field in prompt:
        value = dict(prompt)
        del value[field]
        add("prompt-missing-" + field, value, event="UserPromptSubmit")
    forward = {
        "schema": "guard-structured-content-mediation.v1",
        "action": "forward",
        "reason_code": "structured_clean",
        "native_decision_id": "native.1:decision-x",
        "content_sha256": "a" * 64,
    }
    add("forward", {"decision": "allow", "structured_content_mediation": forward})
    for field, value in [
        ("schema", "other"),
        ("action", "unknown"),
        ("reason_code", "structured_"),
        ("reason_code", "structured_Clean"),
        ("native_decision_id", ""),
        ("native_decision_id", "x" * 257),
        ("native_decision_id", "ümlaut"),
        ("native_decision_id", True),
        ("content_sha256", "A" * 64),
        ("content_sha256", None),
        ("extra", True),
    ]:
        add(
            "forward-" + field + "-" + str(len(rows)),
            {"decision": "allow", "structured_content_mediation": {**forward, field: value}},
        )
    for field in forward:
        value = dict(forward)
        del value[field]
        add("forward-missing-" + field, {"decision": "allow", "structured_content_mediation": value})
    withhold = {"schema": forward["schema"], "action": "withhold", "reason_code": "structured_sensitive"}
    add("withhold-no-id", {"decision": "deny", "structured_content_mediation": withhold}, 2)
    add(
        "withhold-id",
        {"decision": "block", "structured_content_mediation": {**withhold, "native_decision_id": "held"}},
        2,
    )
    add(
        "withhold-wrong-id",
        {"decision": "deny", "structured_content_mediation": {**withhold, "native_decision_id": None}},
    )
    add(
        "withhold-content",
        {"decision": "deny", "structured_content_mediation": {**withhold, "content_sha256": "a" * 64}},
    )
    add("mediation-array", {"decision": "deny", "structured_content_mediation": []})
    add("decision-without-event", {"decision": "allow"}, event=None)
    add("duplicate-decision", None, raw=b'{"decision":"allow","decision":"deny"}')
    add("nonfinite", None, raw=b'{"decision":"allow","risk":NaN}')
    add("invalid-json", None, raw=b"{")
    add("utf16", None, raw=json.dumps({"decision": "allow", "reason": "retained"}).encode("utf-16"))
    out = {
        "schema": "hol-gauntlet-python-native-hook-response.v1",
        "source_commit": SOURCE,
        "source_sha256": hashlib.sha256(source).hexdigest(),
        "json_source_sha256": hashlib.sha256(json_source).hexdigest(),
        "cases": copy.deepcopy(rows),
    }
    target = REPO / "ci/gauntlet-rs/crates/gauntlet-evidence/tests/fixtures/python_native_hook_responses_v1.json"
    with target.open("x") as stream:
        json.dump(out, stream, ensure_ascii=False, sort_keys=True, indent=2)
        stream.write("\n")
    print(
        json.dumps(
            {
                "cases": len(rows),
                "accepted": sum(r["expected"]["accepted"] for r in rows),
                "source_sha256": out["source_sha256"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()

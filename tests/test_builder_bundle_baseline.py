"""Authoring loads dependency policy separately from complete interface metadata."""

from __future__ import annotations

import pytest


@pytest.mark.parametrize("operation", ["compile", "test", "compare"])
def test_kit_cannot_supply_its_own_global_validation_context(monkeypatch, operation):
    from codex_plugin_scanner.guard.extension_builder import bundle_baseline

    verified_context = {"catalog": ["verified metadata"], "programs": []}
    monkeypatch.setattr(bundle_baseline, "validation_base", lambda *args, **kwargs: verified_context)
    build = {"base": "packaged", "validation_base": {"catalog": [], "programs": []}}
    request = build if operation == "compile" else {"build": build, "cases": []}
    result = bundle_baseline.authoring_request(operation, request, None, installed=True)
    actual_build = result if operation == "compile" else result["build"]
    assert actual_build["validation_base"] == verified_context
    assert build["validation_base"]["catalog"] == []

"""A release must not silently place a default policy outside its resident core."""

from __future__ import annotations

import importlib
import json
from pathlib import Path

import pytest


@pytest.mark.parametrize("actual", [[], ["command.other"], ["command.core", "command.added-default"]])
def test_bundle_rejects_defaults_outside_reviewed_core(tmp_path, monkeypatch, actual):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    builder = importlib.import_module("build_command_pack_bundle")
    from codex_plugin_scanner.guard.catalog_delivery.metadata_objects import ObjectStore

    manifest = tmp_path / "contracts/extensions/core-defaults.v1.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(
        json.dumps(
            {
                "schema": "guard.core-defaults.v1",
                "entries": [
                    {"extension_id": "command.core", "source": "reviewed-source", "trust": "reviewed-trust"},
                ],
            }
        )
    )
    store = ObjectStore(tmp_path / "objects")
    reference = store.put_json({"available": True})
    defaults = {
        "count": len(actual),
        "index": store.index({identity: reference for identity in actual}) if actual else None,
    }
    with pytest.raises(ValueError, match="defaults differ"):
        builder.validate_core_defaults(tmp_path, {"defaults": defaults}, store)


def test_bundle_accepts_exact_core_defaults_and_legacy_archive_absence(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    builder = importlib.import_module("build_command_pack_bundle")
    from codex_plugin_scanner.guard.catalog_delivery.metadata_objects import ObjectStore

    store = ObjectStore(tmp_path / "objects")
    reference = store.put_json({"available": True})
    policy = {"defaults": {"count": 1, "index": store.index({"command.core": reference})}}
    builder.validate_core_defaults(tmp_path, policy, store)
    manifest = tmp_path / "contracts/extensions/core-defaults.v1.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(
        json.dumps(
            {
                "schema": "guard.core-defaults.v1",
                "entries": [
                    {"extension_id": "command.core", "source": "reviewed-source", "trust": "reviewed-trust"},
                ],
            }
        )
    )
    builder.validate_core_defaults(tmp_path, policy, store)

"""Strict release-bound Root shape shared by package assembly and installed reads."""

from __future__ import annotations

import hashlib
import re
from typing import Any

from .authority import MAX_ROOT_BYTES, _index_reference, decode
from .containers import location
from .pack_store import digest

SCHEMA = "guard.command-pack-bundle.v1"
MANIFEST = "command-pack-bundle.v1.json"
PREFIX = "codex_plugin_scanner/guard/contracts/data/extensions/command-pack-bundle/"
ROOT = PREFIX + MANIFEST
MAX_BYTES = 512 * 1024 * 1024
MAX_FILES = 8192


def validate_compatibility(value: Any, extensions: int) -> None:
    """Compatibility references confer metadata integrity, never policy authority."""
    if not isinstance(value, dict) or set(value) != {"commands", "mcp"}:
        raise ValueError("installed bundle compatibility inventory invalid")
    total = 0
    for row in value.values():
        if (
            not isinstance(row, dict)
            or set(row) != {"count", "index"}
            or type(row["count"]) is not int
            or not 0 <= row["count"] <= extensions
        ):
            raise ValueError("installed bundle compatibility count invalid")
        total += row["count"]
        if row["count"]:
            _index_reference(row["index"], located=True)
        elif row["index"] is not None:
            raise ValueError("empty compatibility inventory has an index")
    if total != extensions:
        raise ValueError("installed bundle compatibility count differs from native inventory")


def validate(data: bytes, *, source_sha: str, engine: str) -> dict[str, Any]:
    if (
        not isinstance(data, bytes)
        or not 0 < len(data) <= MAX_ROOT_BYTES
        or not isinstance(source_sha, str)
        or re.fullmatch(r"[0-9a-f]{40}", source_sha) is None
        or not digest(engine)
    ):
        raise ValueError("installed bundle identity or Root bounds invalid")
    root = decode(data)
    if (
        not isinstance(root, dict)
        or set(root)
        not in (
            {"schema", "source_sha", "engine", "authority_epoch", "publication_id", "policy"},
            {"schema", "source_sha", "engine", "authority_epoch", "publication_id", "policy", "compatibility"},
        )
        or root["schema"] != SCHEMA
        or root["source_sha"] != source_sha
        or root["engine"] != engine
        or root["publication_id"] != "0.0"
        or type(root["authority_epoch"]) is not int
        or not 0 < root["authority_epoch"] < 2**64
    ):
        raise ValueError("installed bundle Root differs from native release identity")
    policy = root["policy"]
    if not isinstance(policy, dict) or set(policy) != {"root", "transport", "defaults", "revocations"}:
        raise ValueError("installed bundle policy references incomplete")
    native = policy["root"]
    if (
        not isinstance(native, dict)
        or set(native)
        != {
            "schema",
            "kind",
            "authority",
            "engine",
            "extensions",
            "index",
            "index_fanout",
            "objects",
            "object_bytes",
            "object_bytes_limit",
        }
        or native["schema"] != "guard.command-pack-release.v1"
        or native["engine"] != engine
        or native["kind"] != "root"
        or native["authority"] != "requires-authenticated-release-binding"
        or type(native["index_fanout"]) is not int
        or native["index_fanout"] != 64
        or type(native["object_bytes_limit"]) is not int
        or native["object_bytes_limit"] != 65536
        or any(
            type(native[key]) is not int or not 0 < native[key] < 2**64
            for key in ("extensions", "objects", "object_bytes")
        )
    ):
        raise ValueError("installed bundle native Root invalid")
    _index_reference(native["index"], located=False)
    _index_reference(policy["transport"], located=True)
    references = [policy["transport"]]
    if "compatibility" in root:
        validate_compatibility(root["compatibility"], native["extensions"])
        references.extend(row["index"] for row in root["compatibility"].values() if row["count"])
    for name in ("defaults", "revocations"):
        row = policy[name]
        fields = {"count", "index"} | ({"epoch"} if name == "revocations" else set())
        if (
            not isinstance(row, dict)
            or set(row) != fields
            or type(row["count"]) is not int
            or not 0 <= row["count"] < 2**64
        ):
            raise ValueError("installed bundle security index invalid")
        if name == "defaults" and row["count"] > native["extensions"]:
            raise ValueError("installed bundle defaults exceed inventory")
        if name == "revocations" and (type(row["epoch"]) is not int or not 0 <= row["epoch"] < 2**64):
            raise ValueError("installed bundle revocation epoch invalid")
        if row["count"]:
            _index_reference(row["index"], located=True)
            references.append(row["index"])
        elif row["index"] is not None:
            raise ValueError("empty installed bundle index has a reference")
    for reference in references:
        target(reference["location"], source_sha=source_sha)
    return root


def descriptor(data: bytes, *, source_sha: str, engine: str) -> dict[str, Any]:
    validate(data, source_sha=source_sha, engine=engine)
    return {
        "schema": SCHEMA,
        "path": ROOT,
        "sha256": hashlib.sha256(data).hexdigest(),
        "length": len(data),
        "source_sha": source_sha,
        "engine": engine,
    }


def target(value: dict[str, Any], *, source_sha: str) -> tuple[str, str, str]:
    if not isinstance(value, dict):
        raise ValueError("installed bundle location invalid")
    name = value.get("member", value.get("asset", ""))
    match = re.fullmatch(r"(object|pack)-([0-9a-f]{64})\.(json|zip)", name) if isinstance(name, str) else None
    if match is None or match[3] != ("json" if match[1] == "object" else "zip"):
        raise ValueError("installed bundle asset invalid")
    location(value, match[2], match[1])
    if not value["tag"].startswith("extension-data-" + source_sha + "-0.0-"):
        raise ValueError("installed bundle asset source differs")
    return name, match[2], match[1]


def asset_path(relative: str, *, source_sha: str) -> None:
    parts = relative.split("/")
    if (
        len(parts) != 3
        or parts[0] != "assets"
        or re.fullmatch(r"extension-data-" + re.escape(source_sha) + r"-0\.0-[0-9]{6}", parts[1]) is None
        or re.fullmatch(
            r"(?:(?:objects|packs)-[0-9]{6}\.zip|object-[0-9a-f]{64}\.json|pack-[0-9a-f]{64}\.zip)", parts[2]
        )
        is None
    ):
        raise ValueError("installed bundle asset path invalid")

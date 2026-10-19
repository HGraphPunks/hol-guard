"""Read policy packs authenticated by the normal installed release channel.

This profile supplies no remote update authority or freshness claim. Its Root
must be bound by both installed native manifests to the same executable bytes.
"""

from __future__ import annotations

import hashlib
import sys
import zipfile
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, cast

from ..extension_builder.io import read_bytes
from ..extension_builder.native_source_compiler import NativeSourceCompilerError, run_source_compiler
from .authority import decode
from .bundle_metadata import MANIFEST, MAX_BYTES, target
from .containers import maximum, member


def _package() -> Path:
    meipass = getattr(sys, "_MEIPASS", None)
    if bool(getattr(sys, "frozen", False)) and isinstance(meipass, str):
        return Path(meipass) / "codex_plugin_scanner"
    return Path(__file__).absolute().parents[2]


def compatibility_payloads(family: str) -> tuple[dict[str, Any], ...] | None:
    """Explicit offline legacy API; never load the library on decision paths.

    Only genuine legacy absence permits fallback. An advertised installed bundle
    must authenticate through both release manifests before any metadata reads.
    """
    if family not in {"commands", "mcp"}:
        raise ValueError("unknown compatibility metadata family")
    package = _package()
    directory = package / "guard/contracts/data/extensions/command-pack-bundle"
    advertised = directory.exists() or directory.is_symlink()
    for name in ("runtime-manifest.json", "source-compiler-manifest.json"):
        path = package / "_native" / name
        if path.exists() or path.is_symlink():
            manifest = decode(read_bytes(path, limit=65536))
            if not isinstance(manifest, dict):
                raise ValueError("installed native manifest invalid")
            advertised |= "command_pack_bundle" in manifest
    if not advertised:
        return None
    bundle = load_installed_bundle()

    @lru_cache(maxsize=2)
    def read_asset(path: Path, *, limit: int) -> bytes:
        # Offline traversals commonly read thousands of members in one bounded
        # container. Keep at most two containers, scoped to this explicit read.
        return read_bytes(path, limit=limit)

    try:
        result = run_source_compiler(
            "bundle-compatibility",
            {
                "family": family,
                "source_sha": bundle.source_sha,
                "engine": bundle.engine,
                "data": bundle.data.decode("utf-8"),
                "max_bytes": MAX_BYTES,
            },
            fetch=lambda reference: bundle._fetch(
                cast(dict[str, Any], reference["location"]), cast(int, reference["length"]), read_asset
            ),
        )
    except NativeSourceCompilerError as error:
        raise ValueError(f"installed compatibility metadata unavailable: {error}") from error
    return tuple(cast(list[dict[str, Any]], result["payloads"])) if result["available"] else None


@dataclass(frozen=True, slots=True, init=False)
class VerifiedInstalledBundle:
    data: bytes
    source_sha: str
    digest: str
    engine: str
    kind = "installed-release-bundle"

    def __new__(cls) -> VerifiedInstalledBundle:
        raise TypeError("installed bundles must be loaded from the installed release")

    def manifest(self) -> dict[str, Any]:
        return cast(dict[str, Any], decode(self.data))

    def fetch(self, target_location: dict[str, Any], max_bytes: int) -> bytes:
        return self._fetch(target_location, max_bytes, read_bytes)

    def preparation_fetch(self):
        """Keep one bounded container for the current native preparation."""
        reader = lru_cache(maxsize=1)(read_bytes)
        return lambda location, maximum: self._fetch(location, maximum, reader)

    def _fetch(self, target_location: dict[str, Any], max_bytes: int, read_asset) -> bytes:
        name, digest, kind = target(target_location, source_sha=self.source_sha)
        limit = 65536 if kind == "object" else 32 * 1024 * 1024
        if type(max_bytes) is not int or not 0 < max_bytes <= limit:
            raise ValueError("installed bundle fetch bounds invalid")
        path = (
            _package()
            / "guard/contracts/data/extensions/command-pack-bundle/assets"
            / target_location["tag"]
            / target_location["asset"]
        )
        if not path.exists() and not path.is_symlink() and kind == "pack" and "member" not in target_location:
            # The fixed native factory checks the installed release/executable
            # binding and constructs the public URL. No selector, caller URL,
            # remote Root or new publisher authority enters this path.
            from . import lifecycle
            from .transport import download

            request = lifecycle.invoke(
                "installed-asset", **lifecycle.release_evidence(self), location=target_location, length=max_bytes
            )
            try:
                data = download(request["url"], max_bytes)
            except OSError as error:
                raise ValueError("Optional protection data is unavailable; existing controls were retained.") from error
        elif "member" in target_location:
            try:
                data = member(
                    read_asset(path, limit=maximum(target_location["asset"])), target_location["asset"], name, max_bytes
                )
            except zipfile.BadZipFile as error:
                raise ValueError("installed bundle container invalid") from error
        else:
            data = read_asset(path, limit=max_bytes)
        if len(data) != max_bytes or hashlib.sha256(data).hexdigest() != digest:
            raise ValueError("installed bundle member integrity invalid")
        return data


def load_installed_bundle() -> VerifiedInstalledBundle:
    package = _package()
    native = package / "_native"
    runtime = decode(read_bytes(native / "runtime-manifest.json", limit=65536))
    compiler = decode(read_bytes(native / "source-compiler-manifest.json", limit=65536))
    evidence = {"runtime_manifest": runtime, "compiler_manifest": compiler}
    plan = _native_metadata("installed-plan", **evidence)
    binary = read_bytes(native / cast(str, plan["executable"]), limit=cast(int, plan["size"]))
    data = read_bytes(package / "guard/contracts/data/extensions/command-pack-bundle" / MANIFEST, limit=65536)
    identity = _native_metadata(
        "installed",
        **evidence,
        binary_length=len(binary),
        binary_digest=hashlib.sha256(binary).hexdigest(),
        data=data.decode("utf-8"),
    )
    result = object.__new__(VerifiedInstalledBundle)
    for name, value in (
        ("data", bytes(data)),
        ("source_sha", identity["source_sha"]),
        ("digest", identity["digest"]),
        ("engine", identity["engine"]),
    ):
        object.__setattr__(result, name, value)
    return result


def _native_metadata(operation: str, **fields: object) -> dict[str, object]:
    try:
        return run_source_compiler("bundle-metadata", {"operation": operation, **fields})
    except NativeSourceCompilerError as error:
        raise ValueError(f"installed bundle metadata unavailable: {error}") from error

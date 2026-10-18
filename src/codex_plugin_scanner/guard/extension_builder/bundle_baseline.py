"""Fixed verified authority and transport IO for native authoring planning."""

from __future__ import annotations

import importlib
import importlib.util
import json
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path


def admission_request(request, compiler, *, installed, directory):
    from .native_source_compiler import NativeSourceCompilerError

    try:
        return validation_base({}, compiler, installed=installed, directory=directory, admission=request)
    except (ImportError, ValueError, OSError, subprocess.SubprocessError) as exc:
        raise NativeSourceCompilerError(f"source compiler global validation context unavailable: {exc}") from exc


def authoring_request(operation, request, compiler, *, installed, cache_directory=None):
    from .native_source_compiler import NativeSourceCompilerError

    if operation not in {"compile", "validate", "check", "test", "compare"} or request is None:
        return request
    candidate = request.get("build") if operation in {"test", "compare"} else request
    if not isinstance(candidate, Mapping) or candidate.get("base") != "packaged":
        return request
    try:
        augmented = {
            **candidate,
            "validation_base": validation_base(
                candidate,
                compiler,
                installed=installed,
                directory=cache_directory,
                fixture=operation in {"test", "compare"},
            ),
        }
    except (ImportError, ValueError, OSError, subprocess.SubprocessError) as exc:
        raise NativeSourceCompilerError(f"source compiler global validation context unavailable: {exc}") from exc
    return {**request, "build": augmented} if operation in {"test", "compare"} else augmented


def _development(root, compiler, directory):
    scripts = root / "scripts"
    sys.path.insert(0, str(scripts))
    try:
        spec = importlib.util.spec_from_file_location("authoring_pack_build", scripts / "build_native_command_packs.py")
        if spec is None or spec.loader is None:
            raise ImportError("development pack compiler is unavailable")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.stage(compiler, directory, source_root=root)
        return json.loads((directory / "release.json").read_bytes())
    finally:
        sys.path.remove(str(scripts))


def validation_base(request, compiler, *, installed, directory, fixture=False, admission=None):
    import hashlib

    from .metadata_index import exchange

    if directory is None:
        raise ValueError("authoring cache lifetime must enclose native compilation")
    # Kit context is discarded. Only candidate records reach the native planner.
    candidate = {"sources": request.get("sources", []), "mcp_sources": request.get("mcp_sources", [])}
    bundle = None
    if installed:
        module = importlib.import_module("..catalog_delivery.installed_bundle", __package__)
        bundle = module.load_installed_bundle()
        policy = bundle.manifest()["policy"]
        native_request = {
            "mode": "installed",
            "root": policy["root"],
            "transport": policy["transport"],
            "source_context": bundle.digest,
        }
        objects = directory / "packs"
    else:
        root = Path(__file__).resolve().parents[4]
        if not (root / "scripts/build_native_command_packs.py").is_file():
            raise ValueError("authoring requires the verified installed command pack bundle")
        release = _development(root, compiler, directory)
        native_request = {
            "mode": "development",
            "root": release,
            "source_context": hashlib.sha256((directory / "release.json").read_bytes()).hexdigest(),
        }
        objects = directory / "objects"
    native_request.update(request=candidate, fixture=fixture)
    if admission is not None:
        native_request["admission"] = admission

    def fetch(reference):
        if "location" in reference:
            if bundle is None:
                raise ValueError("located authoring data requires a verified bundle")
            return bundle.fetch(reference["location"], reference["length"])
        from .io import read_bytes

        identity = reference["sha256"]
        if not isinstance(identity, str) or len(identity) != 64 or any(c not in "0123456789abcdef" for c in identity):
            raise ValueError("authoring object identity invalid")
        return read_bytes(objects / (identity + ".json"), limit=64 * 1024)

    def archive(reference):
        from ..catalog_delivery.pack_archives import ingest

        if bundle is None:
            raise ValueError("authoring archive requires a verified bundle")
        ingest(
            bundle.fetch(reference["location"], reference["length"]), reference["sha256"], reference["length"], objects
        )

    result = exchange(
        compiler, "authoring-context", [native_request], directory / "authoring-index", fetch=fetch, archive=archive
    )
    if admission is not None:
        return result
    return {"metadata_index": result["metadata_index"], "programs": result["programs"]}

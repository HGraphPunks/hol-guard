"""Unprivileged product identity adapter; no orchestration or verdict authority.

Body retained from installed_guard._PROBE at product source 62aa7ba7.
"""

import dataclasses
import importlib.metadata
import json
import pathlib
import sys

import codex_plugin_scanner
from codex_plugin_scanner.guard.native_runtime import native_runtime_status

status = native_runtime_status()
module = pathlib.Path(codex_plugin_scanner.__file__).resolve()
prefix = pathlib.Path(sys.prefix).resolve()
print(
    json.dumps(
        {
            "available": status.available,
            "compatible": status.compatible,
            "reason": status.reason,
            "installed": module.is_relative_to(prefix),
            "module": str(module),
            "prefix": str(prefix),
            "package_version": importlib.metadata.version("hol-guard"),
            "manifest": dataclasses.asdict(status.manifest) if status.manifest else None,
            "capabilities": dataclasses.asdict(status.capabilities) if status.capabilities else None,
            "runtime_sha256": status.identity.sha256 if status.identity else None,
        }
    )
)

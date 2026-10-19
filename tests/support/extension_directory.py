"""Directory behavior fixtures use the validated native authoring inventory."""

from __future__ import annotations

import shutil
from pathlib import Path

from scripts.export_extension_directory import native_extensions


def copy_projected_contribution_sources(source: Path, destination: Path) -> None:
    """Keep pending additions in contribution tests, outside projected-directory fixtures."""
    catalog_ids = {row.extension_id for row in native_extensions()}
    for family, pattern in (
        ("extensions", "command.*.json"),
        ("mcp-servers", "mcp.*.json"),
        ("command-sources", "command.*.json"),
    ):
        directory = destination / "contributions" / family
        shutil.copytree(source / "contributions" / family, directory)
        for path in directory.glob(pattern):
            identity = path.stem
            if family == "mcp-servers":
                identity = "command.mcp-" + identity.removeprefix("mcp.")
            if identity not in catalog_ids:
                path.unlink()

"""A clone of ``app-portal`` whose own hooks directory holds a ``post-merge`` hook.

A fast-forward merge of ``origin/main`` runs ``post-merge``, so the same merge
that runs quietly in ``app-portal`` must stay reviewed here. Only the hook sets
the two checkouts apart: both name the same GitHub ``origin``.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path

ORIGIN_URL = "https://github.com/example-org/app-portal.git"


def hooked_clone_path(org: Path) -> Path:
    return org.parent / "app-portal-hooked"


def write_hooked_clone(org: Path, home: Path, git: Callable[..., str]) -> None:
    clone = hooked_clone_path(org)
    git(home, "clone", "--quiet", str(org / "app-portal"), str(clone), home=home)
    git(clone, "remote", "set-url", "origin", ORIGIN_URL, home=home)
    hook = clone / ".git" / "hooks" / "post-merge"
    hook.write_text("#!/bin/sh\necho merged\n", encoding="utf-8")
    os.chmod(hook, 0o755)

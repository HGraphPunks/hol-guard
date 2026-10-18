"""Bounded cache IO for the existing authenticated publisher factory."""

from __future__ import annotations

import os
import tempfile
from contextlib import contextmanager
from itertools import islice
from pathlib import Path

from ..extension_builder.io import checked_path, read_bytes
from .authority import MAX_PROVENANCE_BYTES, verify_distribution


@contextmanager
def stage(directory, authority, provenance):
    directory = checked_path(directory)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    pending = []
    try:
        for suffix, data in (("root", authority.data), ("provenance", provenance)) if provenance is not None else ():
            path = checked_path(directory / (authority.digest + "." + suffix))
            with tempfile.NamedTemporaryFile(dir=directory, prefix=".publication-", delete=False) as stream:
                temporary = Path(stream.name)
                pending.append((temporary, path))
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
        yield pending
    finally:
        for temporary, _ in pending:
            temporary.unlink(missing_ok=True)


def publish(pending):
    for temporary, path in pending:
        os.replace(temporary, path)


def load(directory, retained, *, now):
    # The native protected cursor selects the digest, never an unsigned file or
    # request Root. A torn cache pair fails verification without changing it.
    if retained is None:
        raise ValueError("discovery_current_cached_publication_unavailable")
    root = retained["root"]
    data = read_bytes(directory / (root + ".root"), limit=65536)
    provenance = read_bytes(directory / (root + ".provenance"), limit=MAX_PROVENANCE_BYTES)
    return verify_distribution(data, provenance, expected_source_sha=retained["source"], now=now, offline=True)


def filenames(directory):
    with os.scandir(checked_path(directory)) as entries:
        return [entry.name for entry in islice(entries, 8193)]


def remove(directory, names):
    # Names are the native cache plan, never paths supplied by an HTTP caller.
    for name in names:
        checked_path(directory / name).unlink(missing_ok=True)

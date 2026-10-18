"""One verified executable capability for a complete preparation exchange."""

from __future__ import annotations

import json
from contextlib import contextmanager

from ..extension_builder import native_source_compiler as transport


@contextmanager
def verified_preparation():
    """Pin verified bytes for all requests; never accept an executable from callers."""
    try:
        manifest = transport._verify_manifest(transport._NATIVE_PACKAGE / transport._MANIFEST_NAME)
        raw = transport._verify_compiler(transport._NATIVE_PACKAGE / transport._COMPILER_NAME, manifest)
        with transport._verified_executable(raw) as executable:

            def invoke(kind="preparation", **fields):
                try:
                    request = json.dumps({"kind": kind, **fields}, sort_keys=True, separators=(",", ":")).encode()
                    code, stdout, stderr = transport._run_bounded(
                        [str(executable), "pack-lifecycle", "--stdin"], request, timeout=60
                    )
                    return transport._decode_output(stdout, returncode=code, stderr=stderr)
                except transport.NativeSourceCompilerError as exc:
                    raise ValueError(f"native_pack_lifecycle_unavailable: {exc}") from exc

            yield invoke
    except transport.NativeSourceCompilerError as exc:
        raise ValueError(f"native_pack_lifecycle_unavailable: {exc}") from exc

"""One bounded background preparation slot, outside HTTP/hook/lease execution.

Only a handle is cached. Errors are retried automatically after a short backoff;
no contributor or user preparation command is needed. Rust remains the owner of
proofs, traversal, resource limits and the registered handle's validity.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path

_lock = threading.Lock()
_home: Path | None = None
_worker: threading.Thread | None = None
_handle = None
_retry_after = 0.0
_refresh_worker: threading.Thread | None = None
_refresh_after = 0.0


def _prepare(home):
    global _handle, _worker, _retry_after
    handle = None
    try:
        from .discovery import prepare_discovery
        from .installed_bundle import load_installed_bundle

        handle = prepare_discovery(home, load_installed_bundle())
    except (ImportError, OSError, ValueError, KeyError, TypeError):
        pass
    finally:
        with _lock:
            if _home == home and _handle is None:
                _handle = handle
            _worker = None
            _retry_after = time.monotonic() + (1.0 if handle is None else 0.0)
        request_refresh(home)


def _refresh(home, store):
    global _handle, _refresh_worker
    try:
        from .current_refresh import refresh, restore

        if store is None:
            from ..store import GuardStore

            store = GuardStore(home)
        try:
            handle = refresh(store)
        except Exception:
            # Vetted verifier errors are not all ValueError/OSError. Restore
            # still requires its own factory and native completed-view proof.
            handle = restore(store)
        with _lock:
            if _home == home:
                _handle = handle
    except Exception:
        pass  # Complete previous view and active protection remain independent.
    finally:
        with _lock:
            _refresh_worker = None


def request_refresh(home: Path, *, store=None):
    """Daemon timer and initial control-plane preparation share one IO worker."""
    global _home, _refresh_worker, _refresh_after
    home = home.absolute()
    with _lock:
        if _home is None:
            _home = home
        if _home != home or _refresh_worker is not None or time.monotonic() < _refresh_after:
            return
        _refresh_after = time.monotonic() + 300.0
        _refresh_worker = threading.Thread(
            target=_refresh, args=(home, store), name="catalog-current-publication", daemon=True
        )
        _refresh_worker.start()


def installed_ready(home: Path):
    global _home, _worker, _handle
    home = home.absolute()
    with _lock:
        if _home == home and _handle is not None:
            return _handle
        if _worker is None and time.monotonic() >= _retry_after:
            _home, _handle = home, None
            _worker = threading.Thread(target=_prepare, args=(home,), name="catalog-preparation", daemon=True)
            _worker.start()
    raise ValueError("native discovery preparing")


def invalidate(home, handle):
    global _handle
    from . import discovery

    with _lock:
        if _home == home.absolute() and _handle is handle:
            _handle = None
            # A child CAS object may have failed although the root is intact.
            # Force full Rust proof reconstruction, not just root validation.
            if discovery._cached is not None and discovery._cached[2] is handle:
                discovery._cached = None

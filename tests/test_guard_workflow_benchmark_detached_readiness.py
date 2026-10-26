"""Cancellation must follow fixture startup, not merely matching process argv."""

import json
import os
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from ci.gauntlet.benchmark import deterministic_probes as module


def ready(path, value):
    path.write_text(json.dumps(value))
    path.chmod(0o600)


def test_readiness_binds_actual_namespace_pid_session_and_role(tmp_path):
    path = tmp_path / "detached-ready.json"
    owner = (os.getuid(), os.getgid())
    assert not module.detached_ready(tmp_path, 7, "cancel", identity=owner)
    value = {"pid": 7, "sid": 7, "pgrp": 7, "token": "native-lifecycle-detached-059"}
    ready(path, value)
    assert module.detached_ready(tmp_path, 7, "cancel", identity=owner)
    assert not module.detached_ready(tmp_path, 8, "cancel", identity=owner)
    assert not module.detached_ready(tmp_path, 7, "timeout", identity=owner)
    assert not module.detached_ready(tmp_path, 7, "cancel", identity=(owner[0] + 1, owner[1]))
    for changed in ({**value, "pid": True}, {**value, "sid": 8}, {**value, "extra": True}):
        ready(path, changed)
        assert not module.detached_ready(tmp_path, 7, "cancel", identity=owner)


@pytest.mark.parametrize("mutation", ["symlink", "hardlink", "mode", "truncated", "oversized"])
def test_unsafe_or_partial_ready_file_never_triggers_cancellation(tmp_path, mutation):
    path = tmp_path / "detached-ready.json"
    value = {"pid": 7, "sid": 7, "pgrp": 7, "token": "native-lifecycle-detached-059"}
    ready(path, value)
    if mutation == "symlink":
        path.rename(tmp_path / "other")
        path.symlink_to("other")
    elif mutation == "hardlink":
        os.link(path, tmp_path / "other")
    elif mutation == "mode":
        path.chmod(0o644)
    elif mutation == "truncated":
        path.write_text("{")
    else:
        path.write_bytes(b" " * 4097)
    assert not module.detached_ready(tmp_path, 7, "cancel", identity=(os.getuid(), os.getgid()))


def test_watcher_does_not_cancel_when_process_is_visible_before_ready(tmp_path, monkeypatch):
    hooks = SimpleNamespace(contained=SimpleNamespace(timeout=0), stopped=threading.Event())
    plane = SimpleNamespace(cell=SimpleNamespace(_pids=lambda: [123]))
    watcher = module.Lifecycle("cancel", plane, hooks, tmp_path)
    original_bytes, original_text = Path.read_bytes, Path.read_text

    def read_bytes(path, *args, **kwargs):
        return (
            b"python\x00native-lifecycle-detached-059"
            if str(path) == "/proc/123/cmdline"
            else original_bytes(path, *args, **kwargs)
        )

    def read_text(path, *args, **kwargs):
        if str(path) == "/proc/123/stat":
            return "123 (python) S 1 123 123 0"
        if str(path) == "/proc/123/status":
            return "NSpid:\t123\t7\n"
        return original_text(path, *args, **kwargs)

    attempts = []

    def readiness(*args, **kwargs):
        assert not hooks.stopped.is_set()
        attempts.append(True)
        return len(attempts) == 3

    monkeypatch.setattr(Path, "read_bytes", read_bytes)
    monkeypatch.setattr(Path, "read_text", read_text)
    monkeypatch.setattr(module, "detached_ready", readiness)
    monkeypatch.setattr(module, "process_identity", lambda pid: {"start_time": 1})
    watcher.watch()
    assert len(attempts) == 3 and hooks.stopped.is_set() and len(watcher.samples) == 1

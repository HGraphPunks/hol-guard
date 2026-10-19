"""Native round trips one CLI PreToolUse hook may spend.

``tests/test_guard_hook_rpc_budget.py`` bounds the daemon's pi PostToolUse
path. The CLI hook is a different composition — ``commands_hook`` builds its
own worker and runs the native pipeline in the calling process — so nothing
bounded how many times it asked the resident, and a port that added one more
un-memoized call per request landed straight in the CLI hook's p95.

Measured on the fixture below, a `git status --short` PreToolUse hook spends
26 round trips, of which 24 are on the hook's own path. Three of them hold
most of the time: the raw-envelope edge review and the ``compose_current``
and ``finalize`` decisions. The remaining calls are individually under a
millisecond, so this budget is a ceiling on growth rather than a latency
target — it catches a new call per request, not the cost of the three.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import shutil
import sys
import tempfile
from collections import Counter
from collections.abc import Iterator
from itertools import pairwise
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli import commands_hook
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.hook_execution_environment import collect_hook_execution_environment
from codex_plugin_scanner.guard.store import GuardStore
from tests.benign_fp_gate_connectors import allow_ready_cli
from tests.benign_fp_gate_fixture import BenignFixture, build_fixture
from tests.benign_fp_gate_projects import host_tool_path

# Round trips one CLI PreToolUse hook may spend on its own path. A new port
# must fold its work into these or memoize it for the invocation.
_RESIDENT_ROUND_TRIPS_PER_CLI_PRE_TOOL_HOOK = 24

# Work the hook does not drive request by request: the direct-hook evidence
# drain pages on its own wake-ups and the snapshot publisher runs on its own
# thread, so how often either lands in a batch is a matter of timing. They are
# still on the hook's clock — a one-shot CLI hook starts a worker that waits
# for the publisher to report ready and closes it afterwards — so they get a
# ceiling of their own rather than an exemption. The slack above the hook's own
# budget absorbs a thread that happens to run twice in one batch; it does not
# absorb a port that adds a publication per request.
_BACKGROUND_OPERATIONS = frozenset({"hook_direct_evidence_drain", "policy_snapshot_push"})

_RESIDENT_ROUND_TRIPS_PER_CLI_PRE_TOOL_HOOK_WITH_BACKGROUND = 28

_BATCH = 3


def _measured_operations(log_path: Path) -> list[str]:
    """Every operation the resident request log holds, warmup markers removed."""

    if not log_path.is_file():
        return []
    return [line.decode() for line in log_path.read_bytes().splitlines() if line != b"W"]


def _hook_path_operations(log_path: Path) -> Counter[str]:
    return Counter(name for name in _measured_operations(log_path) if name not in _BACKGROUND_OPERATIONS)


def _all_operations(log_path: Path) -> Counter[str]:
    return Counter(_measured_operations(log_path))


def _assert_growth_within(samples: list[Counter[str]], ceiling: int) -> None:
    for before, after in pairwise(samples):
        growth = after - before
        assert sum(growth.values()) <= _BATCH * ceiling, growth


def _assert_round_trip_growth(samples: list[Counter[str]]) -> None:
    _assert_growth_within(samples, _RESIDENT_ROUND_TRIPS_PER_CLI_PRE_TOOL_HOOK)


@pytest.fixture(scope="module")
def cli_hook_environment(tmp_path_factory: pytest.TempPathFactory) -> Iterator[tuple[BenignFixture, GuardStore, Path]]:
    """The benign gate's sealed home, driven through the CLI hook entry point.

    Same reasoning as ``test_guard_benign_false_positive_gate``: a macOS pytest
    temp dir is not a place a real HOME lives, and the native Git proofs fail
    closed on any ``GIT_*``, ``LD_*`` or ``DYLD_*`` override the agent carries.
    """

    root = (
        Path(tempfile.mkdtemp(prefix="cli-hook-rpc-", dir="/tmp")).resolve()
        if sys.platform == "darwin"
        else tmp_path_factory.mktemp("cli-hook-rpc")
    )
    fixture = build_fixture(root)
    patch = pytest.MonkeyPatch()
    patch.setenv("HOME", str(fixture.home))
    for name in list(os.environ):
        if name.upper().startswith(("GIT_", "LD_", "DYLD_")) or name.upper() == "RIPGREP_CONFIG_PATH":
            patch.delenv(name)
    patch.setenv("XDG_CONFIG_HOME", str(fixture.home / ".config"))
    patch.setenv("HOL_GUARD_NATIVE", "force")
    binary = os.environ.get("HOL_GUARD_NATIVE_BINARY")
    if not binary:
        pytest.fail("HOL_GUARD_NATIVE_BINARY must name the compiled native runtime")
    patch.setenv("HOL_GUARD_NATIVE_BINARY", binary)
    patch.setenv("PATH", host_tool_path(fixture.home, os.environ.get("PATH", "")))
    log_path = root / "resident-requests.log"
    patch.setenv("HOL_GUARD_RESIDENT_REQUEST_LOG", os.fspath(log_path))
    store = GuardStore(fixture.guard_home)
    allow_ready_cli(store, fixture.home)
    try:
        yield fixture, store, log_path
    finally:
        patch.undo()
        fixture.cleanup()
        if sys.platform == "darwin":
            shutil.rmtree(root, ignore_errors=True)


def _decision(response: dict[str, object]) -> str:
    """The effective verdict in a claude-code hook response: allow, deny or ask."""

    specific = response.get("hookSpecificOutput")
    permission = specific.get("permissionDecision") if isinstance(specific, dict) else None
    permission = permission or response.get("permission") or response.get("decision")
    if response.get("continue") is False or response.get("policy_action") == "block":
        return "deny"
    if permission in {"deny", "block"}:
        return "deny"
    if permission == "ask":
        return "ask"
    return "allow"


def _run_hook(fixture: BenignFixture, store: GuardStore, index: int) -> None:
    """Run one hook and fail unless it reached the decision the budget measures.

    A ceiling alone passes when a hook stops short: a regression that fails
    closed after its first resident request spends fewer round trips, not more.
    Each invocation has to come back a quiet allow for its requests to count.
    """

    cwd = Path(str(fixture.cwd("worktree")))
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "git status --short"},
        "session_id": "cli-hook-rpc-budget",
        "tool_call_id": f"cli-rpc-{index}",
        "cwd": str(cwd),
        "home_dir": str(fixture.home),
        "guard_execution_environment": collect_hook_execution_environment(),
    }
    output_stream = io.StringIO()
    status = commands_hook._run_guard_hook_command(
        argparse.Namespace(
            artifact_id=None,
            artifact_name=None,
            event_file=None,
            harness="claude-code",
            json=True,
            policy_action=None,
            runtime_harness=None,
        ),
        guard_home=fixture.guard_home,
        workspace=cwd,
        context=HarnessContext(fixture.home, cwd, fixture.guard_home),
        store=store,
        config=GuardConfig(guard_home=fixture.guard_home, workspace=fixture.worktree, default_action="review"),
        input_text=json.dumps(payload),
        output_stream=output_stream,
    )
    rendered = output_stream.getvalue().strip()
    assert status == 0, f"hook {index} exited {status}: {rendered}"
    response = json.loads(rendered) if rendered else {}
    assert isinstance(response, dict), f"hook {index} wrote no response object: {rendered}"
    assert _decision(response) == "allow", f"hook {index} did not allow: {rendered}"


def test_cli_pre_tool_hook_resident_round_trips_per_request_are_bounded(
    cli_hook_environment: tuple[BenignFixture, GuardStore, Path],
) -> None:
    fixture, store, log_path = cli_hook_environment
    # The first hooks in this process pay one-time resident startup. Sampling
    # prefixes afterwards makes that traffic common to every sample, so the
    # growth between two samples is the batch's own round trips.
    for index in range(_BATCH):
        _run_hook(fixture, store, index)
    samples: list[Counter[str]] = [_hook_path_operations(log_path)]
    everything: list[Counter[str]] = [_all_operations(log_path)]
    for batch in range(1, 4):
        for index in range(_BATCH):
            _run_hook(fixture, store, batch * _BATCH + index)
        samples.append(_hook_path_operations(log_path))
        everything.append(_all_operations(log_path))
    assert sum(samples[0].values()) > 0, "no resident request was recorded"
    _assert_round_trip_growth(samples)
    # Publication and the evidence drain are on the hook's clock too, so they
    # answer to the looser ceiling rather than to none at all.
    _assert_growth_within(everything, _RESIDENT_ROUND_TRIPS_PER_CLI_PRE_TOOL_HOOK_WITH_BACKGROUND)


def _replay(log_path: Path, *, extra: bytes, batches: int = 3) -> tuple[list[Counter[str]], list[Counter[str]]]:
    """Write a hook-shaped request log and sample it the way the budget does."""

    log_path.write_bytes(b"W\npolicy_snapshot_push\n")
    samples: list[Counter[str]] = [_hook_path_operations(log_path)]
    everything: list[Counter[str]] = [_all_operations(log_path)]
    for batch in range(batches):
        with log_path.open("ab") as output:
            for index in range(_BATCH):
                output.write(b"hook_decide\n" * _RESIDENT_ROUND_TRIPS_PER_CLI_PRE_TOOL_HOOK)
                output.write(b"hook_direct_evidence_drain\npolicy_snapshot_push\n")
                if extra and (batch, index) >= (1, 0):
                    output.write(extra)
        samples.append(_hook_path_operations(log_path))
        everything.append(_all_operations(log_path))
    return samples, everything


@pytest.mark.parametrize("extra", ["none", "per-request"])
def test_growth_tolerates_background_jitter_but_detects_an_extra_call(tmp_path: Path, extra: str) -> None:
    """The measurement itself: a new call on the hook's path fails the budget."""

    added = b"" if extra == "none" else b"hook_render\n"
    samples, _ = _replay(tmp_path / "resident-requests.log", extra=added)
    assert sum(samples[0].values()) == 0
    if extra == "none":
        _assert_round_trip_growth(samples)
        return
    with pytest.raises(AssertionError):
        _assert_round_trip_growth(samples)


@pytest.mark.parametrize("extra", ["none", "one-more-publication", "per-request"])
def test_publication_growth_answers_to_the_background_ceiling(tmp_path: Path, extra: str) -> None:
    """Publication is counted, with room for a thread that runs out of step.

    The slack is deliberate: one extra push across a batch is timing, not a
    port. Growth that tracks the request count exhausts it and fails.
    """

    added = {
        "none": b"",
        "one-more-publication": b"policy_snapshot_push\n",
        "per-request": b"policy_snapshot_push\n" * 3,
    }[extra]
    _, everything = _replay(tmp_path / "resident-requests.log", extra=added)
    if extra == "per-request":
        with pytest.raises(AssertionError):
            _assert_growth_within(everything, _RESIDENT_ROUND_TRIPS_PER_CLI_PRE_TOOL_HOOK_WITH_BACKGROUND)
        return
    _assert_growth_within(everything, _RESIDENT_ROUND_TRIPS_PER_CLI_PRE_TOOL_HOOK_WITH_BACKGROUND)

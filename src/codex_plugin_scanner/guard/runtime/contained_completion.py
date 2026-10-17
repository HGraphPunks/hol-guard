"""One-use proof for reviewing output of a completed workspace-contained command.

This is not an approval and is never consulted by PreToolUse. Only the contained
CLI records completed executions in private Guard state. Post may use a matching
proof to avoid reclassifying completed execution as a new execution request.
Explicit artifact policy, native output review and scanner/data-flow policy still
apply. Unproven calls keep the existing behavior.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import secrets
import stat
import sys
import time
from collections.abc import Callable, Mapping
from contextlib import redirect_stderr, redirect_stdout, suppress
from dataclasses import replace
from pathlib import Path

from ..config import GuardConfig
from ..models import GuardArtifact

SCHEMA = "guard-contained-completion.v1"
DIRECTORY = "contained-completions-v1"
TTL_NS = 30_000_000_000
MAX_OUTPUT = 900_000


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def _binding(payload: Mapping[str, object], harness: str, workspace: Path) -> str | None:
    if (
        harness != "omp"
        or payload.get("tool_name") != "bash"
        or payload.get("guard_contained_output_profile") != "controller-contained-output.v1"
    ):
        return None
    fields = {name: payload.get(name) for name in ("session_id", "tool_call_id", "config_path")}
    if any(type(value) is not str or not 1 <= len(value) <= 4096 for value in fields.values()):
        return None
    tool_input = payload.get("tool_input")
    if type(tool_input) is not dict or type(tool_input.get("command")) is not str:
        return None
    value = {
        "harness": harness,
        "workspace": str(workspace.resolve(strict=True)),
        **fields,
        "tool_input": tool_input,
        "execution_environment": payload.get("guard_execution_environment"),
    }
    raw = _canonical(value)
    return hashlib.sha256(raw).hexdigest() if len(raw) <= 1024**2 else None


def _private(directory: Path, *, create: bool = False) -> int:
    parent = os.open(directory.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        _directory(os.fstat(parent))
        if create:
            with suppress(FileExistsError):
                os.mkdir(directory.name, 0o700, dir_fd=parent)
        fd = os.open(directory.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        try:
            _directory(os.fstat(fd))
        except BaseException:
            os.close(fd)
            raise
        return fd
    finally:
        os.close(parent)


def _directory(info: os.stat_result) -> None:
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("private owner-only Guard completion state required")


def _boot() -> str:
    # The first profile is Linux/OMP only; no cross-platform/reboot assumption.
    value = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    if re.fullmatch("[0-9a-f-]{36}", value) is None:
        raise ValueError("kernel boot identity required")
    return value


def output_text(exit_code: int, stdout: str, stderr: str) -> str:
    return f"Exit code: {exit_code}\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"


class CompletionCapture(io.TextIOBase):
    """Forward normal CLI output while retaining bounded exact text for a digest."""

    def __init__(self, stream: io.TextIOBase):
        self.stream = stream
        self.parts: list[str] = []
        self.size = 0
        self.eligible = True

    def write(self, text: str) -> int:
        size = len(text.encode())
        self.size += size
        if self.size <= MAX_OUTPUT and self.eligible:
            self.parts.append(text)
        else:
            self.parts.clear()
            self.eligible = False
        return self.stream.write(text)

    def flush(self) -> None:
        self.stream.flush()

    def text(self) -> str:
        return "".join(self.parts)


def record_completion(
    *,
    payload: Mapping[str, object],
    harness: str,
    workspace: Path,
    guard_home: Path,
    exit_code: int,
    stdout: str,
    stderr: str,
    receipts: list[str],
) -> bool:
    """Called only after normal return and two matching live workspace receipts."""
    if (
        sys.platform != "linux"
        or type(exit_code) is not int
        or not -255 <= exit_code <= 255
        or type(receipts) is not list
        or len(receipts) < 2
        or any(type(value) is not str or not value or len(value) > 256 for value in receipts)
        or len(set(receipts)) != 1
        or len(stdout.encode()) + len(stderr.encode()) > MAX_OUTPUT
    ):
        return False
    descriptor = None
    temporary = None
    try:
        binding = _binding(payload, harness, workspace)
        if binding is None:
            return False
        descriptor = _private(guard_home / DIRECTORY, create=True)
        if len(os.listdir(descriptor)) >= 128:
            return False
        now = time.monotonic_ns()
        row = {
            "schema": SCHEMA,
            "binding": binding,
            "output_sha256": hashlib.sha256(output_text(exit_code, stdout, stderr).encode()).hexdigest(),
            "is_error": exit_code != 0,
            "created_ns": now,
            "expires_ns": now + TTL_NS,
            "boot_id": _boot(),
        }
        temporary = "pending-" + secrets.token_hex(32)
        fd = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=descriptor
        )
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(_canonical(row))
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, binding, src_dir_fd=descriptor, dst_dir_fd=descriptor, follow_symlinks=False)
        return True
    except (OSError, ValueError, TypeError):
        return False
    finally:
        if descriptor is not None:
            if temporary is not None:
                with suppress(FileNotFoundError):
                    os.unlink(temporary, dir_fd=descriptor)
            os.close(descriptor)


def _consume(*, payload: Mapping[str, object], harness: str, workspace: Path, guard_home: Path) -> str | None:
    if sys.platform != "linux" or payload.get("hook_event_name") != "PostToolUse":
        return None
    descriptor = None
    claim = None
    try:
        binding = _binding(payload, harness, workspace)
        content = payload.get("tool_response")
        if (
            binding is None
            or type(content) is not list
            or len(content) != 1
            or type(content[0]) is not dict
            or set(content[0]) != {"type", "text"}
            or content[0]["type"] != "text"
            or type(content[0]["text"]) is not str
            or len(content[0]["text"].encode()) > 1024**2
            or type(payload.get("is_error")) is not bool
        ):
            return None
        descriptor = _private(guard_home / DIRECTORY)
        claim = "claimed-" + secrets.token_hex(32)
        os.rename(binding, claim, src_dir_fd=descriptor, dst_dir_fd=descriptor)
        fd = os.open(claim, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=descriptor)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_nlink != 1
                or info.st_size > 8192
            ):
                return None
            raw = stream.read(8193)

        def unique(pairs):
            value = {}
            for key, item in pairs:
                if key in value:
                    raise ValueError("duplicate completion field")
                value[key] = item
            return value

        row = json.loads(raw, object_pairs_hook=unique)
        now = time.monotonic_ns()
        if (
            type(row) is not dict
            or set(row) != {"schema", "binding", "output_sha256", "is_error", "created_ns", "expires_ns", "boot_id"}
            or row["schema"] != SCHEMA
            or row["binding"] != binding
            or row["boot_id"] != _boot()
            or type(row["created_ns"]) is not int
            or type(row["expires_ns"]) is not int
            or not 0 <= row["created_ns"] <= now < row["expires_ns"]
            or row["expires_ns"] - row["created_ns"] != TTL_NS
            or type(row["is_error"]) is not bool
            or row["is_error"] != payload["is_error"]
            or row["output_sha256"] != hashlib.sha256(content[0]["text"].encode()).hexdigest()
        ):
            return None
        return hashlib.sha256(raw).hexdigest()
    except (OSError, ValueError, TypeError, KeyError):
        return None
    finally:
        if descriptor is not None:
            if claim is not None:
                with suppress(FileNotFoundError):
                    os.unlink(claim, dir_fd=descriptor)
            os.close(descriptor)


def _completed_execution_risk(metadata: Mapping[str, object]) -> str | None:
    """Only the two default execution requests supported by private completion."""
    risks = metadata.get("risk_classes")
    count = metadata.get("compound_finding_count", 1)
    if type(risks) is not list or len(risks) != 1 or type(count) is not int or count != 1:
        return None
    if metadata.get("action_class") == "destructive shell command" and risks == ["destructive_shell"]:
        return "destructive_shell"
    if (
        metadata.get("action_class") == "local script execution shell command"
        and risks == ["execution"]
        and metadata.get("reason_code") == "shell_local_script_execution_review"
    ):
        return "execution"
    return None


def completed_output_artifact(
    artifact: GuardArtifact | None,
    *,
    payload: Mapping[str, object],
    harness: str,
    workspace: Path | None,
    guard_home: Path,
    native_edge: Mapping[str, object] | None,
    has_data_flow: bool,
    config: GuardConfig,
) -> GuardArtifact | None:
    """Change only a proven completed execution's default artifact classification.

    The stable artifact ID/configured override is retained. Pre and explicit
    current blocks, sensitive output, compound findings and output floors stay.
    """
    if (
        artifact is None
        or workspace is None
        or has_data_flow
        or not isinstance(native_edge, Mapping)
        or payload.get("hook_event_name") != "PostToolUse"
        or native_edge.get("decision") != "allow"
        or native_edge.get("model_output_action") != "allow_original"
        or native_edge.get("policy_action") not in {"allow", "warn"}
        or artifact.artifact_type != "tool_action_request"
        or artifact.metadata.get("command_action_floor") == "block"
    ):
        return artifact
    risk = _completed_execution_risk(artifact.metadata)
    if risk is None:
        return artifact
    # Explicit risk policy is still an operator decision, even after execution.
    # Changing the stage's default must not erase a configured stronger action.
    for actions in (config.risk_actions or {},(config.harness_risk_actions or {}).get(harness,{}) or {}):
        if risk in actions and actions[risk] not in {"allow", "warn"}:
            return artifact
    content = payload.get("tool_response")
    if (
        type(content) is not list
        or len(content) != 1
        or type(content[0]) is not dict
        or type(content[0].get("text")) is not str
        or native_edge.get("reviewed_output_sha256") != hashlib.sha256(content[0]["text"].encode()).hexdigest()
    ):
        return artifact
    proof = _consume(payload=payload, harness=harness, workspace=workspace, guard_home=guard_home)
    if proof is None:
        return artifact
    metadata = dict(artifact.metadata)
    if risk == "execution":
        # This reason alone requests local-script approval during composition.
        # Preserve its audit value, but retire it only after consuming proof.
        metadata["contained_completion_original_reason_code"] = metadata.pop("reason_code")
    for key in ("command_action_floor", "command_decision_plane", "command_rule_matches"):
        metadata.pop(key, None)
    metadata.update(
        action_class="completed contained tool output",
        risk_classes=[],
        guard_default_action="warn",
        runtime_request_signals=[],
        runtime_request_summary="Output of the completed contained command was reviewed.",
        runtime_request_reason="One-use private completion proof binds this exact input and captured output.",
        contained_completion_schema=SCHEMA,
        contained_completion_digest=proof,
    )
    return replace(artifact, name="bash completed contained output", metadata=metadata)


def run_with_completion(
    run: Callable[[Callable], int],
    *,
    authorize: Callable,
    payload: Mapping[str, object],
    harness: str,
    workspace: Path,
    guard_home: Path,
) -> int:
    """Recording is opt-in, but a payload hint alone never grants Post authority."""
    from .restricted_workspace import receipt_matches

    if sys.platform != "linux" or _binding(payload, harness, workspace) is None:
        return run(authorize)
    receipts: list[str] = []

    def checked(original):
        answer = authorize(original)
        if (
            receipt_matches(answer)
            and isinstance(answer, Mapping)
            and _binding(original, harness, workspace) == _binding(payload, harness, workspace)
        ):
            receipts.append(str(answer["command_binding_digest"]))
        return answer

    stdout, stderr = CompletionCapture(sys.stdout), CompletionCapture(sys.stderr)
    with redirect_stdout(stdout), redirect_stderr(stderr):
        status = run(checked)
    if stdout.eligible and stderr.eligible:
        record_completion(
            payload=payload,
            harness=harness,
            workspace=workspace,
            guard_home=guard_home,
            exit_code=status,
            stdout=stdout.text(),
            stderr=stderr.text(),
            receipts=receipts,
        )
    return status

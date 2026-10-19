"""Native claim for an optional trusted MCP task mutation budget."""

from __future__ import annotations

import os
from pathlib import Path
from uuid import uuid4

from .native_context import ensure_resident_prerequisite
from .native_execution import _resident_request

FEATURE = "mcp-task-write-budget-v1"
_REQUEST_SCHEMA = "guard-mcp-write-budget-claim-request.v1"
_RESULT_SCHEMA = "guard-mcp-write-budget-claim-result.v1"
_DECISIONS = frozenset({"inactive", "allow", "block"})
_REASONS = frozenset({
    "no_policy", "read_only", "claimed", "invalid_request", "write_budget_exhausted",
    "budget_state_invalid", "policy_invalid", "guard_home_invalid",
})


class NativeMcpWriteBudgetError(ValueError):
    """No bound native answer; the MCP call must not reach its server."""


def claim_mcp_write_budget(*, guard_home: Path, tool_name: str) -> tuple[str, str]:
    if os.name != "posix":
        return "inactive", "no_policy"
    request_id = f"mcp-write-budget-{uuid4().hex}"
    if not ensure_resident_prerequisite(guard_home):
        raise NativeMcpWriteBudgetError("resident prerequisite unavailable")
    reply = _resident_request(
        operation="mcp_write_budget_claim",
        request={
            "schema": _REQUEST_SCHEMA,
            "request_id": request_id,
            "guard_home": str(guard_home),
            "tool_name": tool_name,
        },
        guard_home=guard_home,
        timeout_seconds=5,
        required_feature=FEATURE,
        response_schema=_RESULT_SCHEMA,
    )
    if (
        reply is None
        or set(reply) != {"schema", "request_id", "status", "decision", "reason", "remaining"}
        or reply.get("request_id") != request_id
        or reply.get("status") != "ok"
        or reply.get("decision") not in _DECISIONS
        or reply.get("reason") not in _REASONS
        or not (reply.get("remaining") is None or type(reply.get("remaining")) is int)
    ):
        raise NativeMcpWriteBudgetError("native mutation-budget answer invalid")
    decision = reply["decision"]
    reason = reply["reason"]
    if (decision == "inactive") != (reason == "no_policy"):
        raise NativeMcpWriteBudgetError("native mutation-budget answer inconsistent")
    return decision, reason

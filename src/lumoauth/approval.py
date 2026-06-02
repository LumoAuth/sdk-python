"""Push-approval-for-agent-actions.

The agent calls ``require_approval(...)`` when it's about to do something
irreversible. A push lands on the user's phone with the action context;
the user taps approve or deny; this function returns once the user responds
or the request expires.

Example::

    from lumoauth import LumoAuthAgent, require_approval

    agent = LumoAuthAgent()
    agent.authenticate()

    result = require_approval(
        agent,
        task_id="wire-2026-05-07-001",
        reason="Wire $4,500 to vendor INV-7741",
        impact="high",
        on_behalf_of="ada@acme.com",
        meta={"action": "wire-transfer", "amount": 4500, "vendor": "INV-7741"},
    )
    if result.status != "approved":
        raise RuntimeError(f"action denied: {result.status} ({result.reason})")
    # Use result.token as auth header for the actual side-effecting call.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Literal, Mapping, Optional
import time

ApprovalImpact = Literal["low", "medium", "high", "critical"]
ApprovalStatus = Literal["pending", "approved", "denied", "expired"]


@dataclass(frozen=True)
class ApprovalResult:
    status: ApprovalStatus
    token: str
    task_id: str
    impact: Optional[ApprovalImpact]
    reason: Optional[str]
    responded_at: Optional[str]
    approved_by: Optional[Dict[str, Any]]


def require_approval(
    agent: Any,
    *,
    task_id: str,
    reason: str,
    on_behalf_of: str,
    impact: ApprovalImpact = "medium",
    meta: Optional[Mapping[str, Any]] = None,
    poll_interval_s: float = 1.5,
    timeout_s: float = 90.0,
) -> ApprovalResult:
    """Request human approval for an agent action and block until decision.

    ``agent`` must be a ``LumoAuthAgent`` whose ``authenticate()`` has been
    called. We use ``agent.api_request`` so the call inherits OAuth headers
    and auto-refresh.
    """
    if not task_id:
        raise ValueError("task_id is required")
    if not reason:
        raise ValueError("reason is required")
    if impact not in ("low", "medium", "high", "critical"):
        raise ValueError(f"invalid impact: {impact!r}")

    org_id = getattr(agent, "org_id", None)
    if not org_id:
        raise RuntimeError("agent has no org_id; call agent.authenticate() first")

    create_resp = agent.api_request(
        "POST",
        f"/orgs/{org_id}/api/v1/agents/me/approvals",
        json={
            "task_id": task_id,
            "reason": reason,
            "impact": impact,
            "on_behalf_of": on_behalf_of,
            "meta": dict(meta) if meta else None,
        },
    )
    create_resp.raise_for_status()
    created = create_resp.json()
    token = created["approval_token"]

    deadline = time.monotonic() + timeout_s
    last: Dict[str, Any] = {"status": "pending"}
    while time.monotonic() < deadline:
        time.sleep(poll_interval_s)
        status_resp = agent.api_request(
            "GET",
            f"/orgs/{org_id}/api/v1/agents/me/approvals/{token}/status",
        )
        status_resp.raise_for_status()
        last = status_resp.json()
        if last.get("status") != "pending":
            break

    return ApprovalResult(
        status=last.get("status", "expired"),
        token=last.get("approval_token", token),
        task_id=last.get("task_id", task_id),
        impact=last.get("impact"),
        reason=last.get("reason"),
        responded_at=last.get("responded_at"),
        approved_by=last.get("approved_by"),
    )

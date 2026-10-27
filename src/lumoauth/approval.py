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

When no push prompt can reach the user, ``require_approval`` raises
:class:`~lumoauth.errors.LumoAuthApprovalNotDeliveredError` instead of
polling. Its ``reason`` is ``"email_fallback_sent"`` (HTTP 202: the user got a
plain email notice, or does not exist) or ``"no_enrolled_device"`` (HTTP 428).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Literal, Mapping, Optional
import time

from lumoauth._routes import format_path
from lumoauth.errors import (
    LumoAuthApprovalNotDeliveredError,
    LumoAuthConfigError,
    LumoAuthValidationError,
)

ApprovalImpact = Literal["low", "medium", "high", "critical"]
ApprovalStatus = Literal["pending", "approved", "denied", "expired"]

#: Status of a 202 answer to the create call: no push prompt was sent.
EMAIL_FALLBACK_SENT = "email_fallback_sent"
#: Error code of a 428 answer: no device, and the email notice failed.
NO_ENROLLED_DEVICE = "no_enrolled_device"


def is_not_delivered(created: Any) -> bool:
    """True when a create response is the 202 ``email_fallback_sent`` answer."""
    return isinstance(created, dict) and created.get("status") == EMAIL_FALLBACK_SENT


def not_delivered_error(
    reason: str, body: Any = None, status_code: Optional[int] = None
) -> LumoAuthApprovalNotDeliveredError:
    """Build the error for a 202 ``email_fallback_sent`` or a 428 answer."""
    body_dict = body if isinstance(body, dict) else {}
    message = body_dict.get("message")
    if not isinstance(message, str) or not message:
        message = (
            "No push prompt was sent: the user has no enrolled device. "
            "LumoAuth emailed them a notice instead."
            if reason == EMAIL_FALLBACK_SENT
            else "No push prompt was sent: the user has no enrolled device."
        )
    task_id = body_dict.get("task_id")
    return LumoAuthApprovalNotDeliveredError(
        message,
        reason=reason,
        task_id=task_id if isinstance(task_id, str) else None,
        status_code=status_code,
        body=body,
    )


@dataclass(frozen=True)
class ApprovalResult:
    """Outcome of a resolved (or timed-out) approval request.

    ``approved_by`` is ``{"user_id": <int>}`` when the status is
    ``"approved"`` and ``None`` otherwise. LumoAuth does not return the
    approver's email.
    """

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
        raise LumoAuthValidationError("task_id is required")
    if not reason:
        raise LumoAuthValidationError("reason is required")
    if impact not in ("low", "medium", "high", "critical"):
        raise LumoAuthValidationError(f"invalid impact: {impact!r}")

    org_id = getattr(agent, "org_id", None)
    if not org_id:
        raise LumoAuthConfigError("agent has no org_id; call agent.authenticate() first")

    _, create_path = format_path("approvals.create", org_id=org_id)
    create_resp = agent.api_request(
        "POST",
        create_path,
        json={
            "task_id": task_id,
            "reason": reason,
            "impact": impact,
            "on_behalf_of": on_behalf_of,
            "meta": dict(meta) if meta else None,
        },
    )
    if create_resp.status_code == 428:
        raise not_delivered_error(NO_ENROLLED_DEVICE, _json_or_none(create_resp), 428)
    create_resp.raise_for_status()
    created = create_resp.json()
    if create_resp.status_code == 202 or is_not_delivered(created):
        raise not_delivered_error(EMAIL_FALLBACK_SENT, created, create_resp.status_code)
    token = created.get("approval_token") if isinstance(created, dict) else None
    if not token:
        raise LumoAuthValidationError("approval response has no approval_token")

    deadline = time.monotonic() + timeout_s
    last: Dict[str, Any] = {"status": "pending"}
    while time.monotonic() < deadline:
        time.sleep(poll_interval_s)
        _, status_path = format_path("approvals.status", org_id=org_id, token=token)
        status_resp = agent.api_request(
            "GET",
            status_path,
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


def _json_or_none(resp: Any) -> Any:
    try:
        return resp.json()
    except ValueError:
        return None

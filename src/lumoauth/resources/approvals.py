"""Push approvals — human sign-off for irreversible agent actions."""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, Mapping, Optional

from lumoauth._http import HttpClient
from lumoauth.approval import ApprovalResult
from lumoauth.errors import LumoAuthValidationError

logger = logging.getLogger("lumoauth.approvals")

__all__ = ["ApprovalsResource"]

_VALID_IMPACTS = ("low", "medium", "high", "critical")


class ApprovalsResource:
    """Create, poll, and await push-approval requests."""

    def __init__(self, http: HttpClient) -> None:
        self._http = http

    def create(
        self,
        *,
        task_id: str,
        reason: str,
        on_behalf_of: str,
        impact: str = "medium",
        meta: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Create an approval request; returns the server dict (``approval_token``…)."""
        if not task_id:
            raise LumoAuthValidationError("task_id is required")
        if not reason:
            raise LumoAuthValidationError("reason is required")
        if impact not in _VALID_IMPACTS:
            raise LumoAuthValidationError(f"invalid impact: {impact!r}")
        return self._http.call(
            "approvals.create",
            json={
                "task_id": task_id,
                "reason": reason,
                "impact": impact,
                "on_behalf_of": on_behalf_of,
                "meta": dict(meta) if meta else None,
            },
        )

    def get_status(self, token: str) -> Dict[str, Any]:
        """Fetch the current status of an approval request by its token."""
        return self._http.call("approvals.status", path_params={"token": token})

    def wait(
        self,
        token: str,
        *,
        poll_interval_s: float = 1.5,
        timeout_s: float = 90.0,
    ) -> Dict[str, Any]:
        """Poll until the approval resolves or *timeout_s* elapses.

        Returns the last status dict (``status`` stays ``"pending"`` on timeout).
        """
        deadline = time.monotonic() + timeout_s
        last: Dict[str, Any] = {"status": "pending"}
        while time.monotonic() < deadline:
            time.sleep(poll_interval_s)
            last = self.get_status(token)
            if last.get("status") != "pending":
                break
        return last

    def require(
        self,
        *,
        task_id: str,
        reason: str,
        on_behalf_of: str,
        impact: str = "medium",
        meta: Optional[Mapping[str, Any]] = None,
        poll_interval_s: float = 1.5,
        timeout_s: float = 90.0,
    ) -> ApprovalResult:
        """Create an approval request and block until it resolves or expires."""
        created = self.create(
            task_id=task_id,
            reason=reason,
            on_behalf_of=on_behalf_of,
            impact=impact,
            meta=meta,
        )
        token = created["approval_token"]
        last = self.wait(token, poll_interval_s=poll_interval_s, timeout_s=timeout_s)
        return ApprovalResult(
            status=last.get("status", "expired"),
            token=last.get("approval_token", token),
            task_id=last.get("task_id", task_id),
            impact=last.get("impact"),
            reason=last.get("reason"),
            responded_at=last.get("responded_at"),
            approved_by=last.get("approved_by"),
        )

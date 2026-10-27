"""Push approvals — human sign-off for irreversible agent actions."""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, Mapping, Optional

from lumoauth._http import HttpClient
from lumoauth.approval import (
    EMAIL_FALLBACK_SENT,
    NO_ENROLLED_DEVICE,
    ApprovalResult,
    is_not_delivered,
    not_delivered_error,
)
from lumoauth.errors import LumoAuthApiError, LumoAuthValidationError

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
        """Create an approval request; returns the server dict.

        When a push prompt was sent, the dict has ``approval_token`` and
        ``status`` ``"pending"``; poll it with :meth:`get_status` or
        :meth:`wait`.

        When the user has no enrolled push device, LumoAuth emails them a
        plain notice (no approval link) and answers 202. The dict then has
        ``status`` ``"email_fallback_sent"`` and ``approval_token`` ``None``.
        Nothing can be polled, and the approval cannot happen in this call.
        LumoAuth gives the same answer when the user does not exist.

        Raises:
            LumoAuthApprovalNotDeliveredError: 428, with ``reason``
                ``"no_enrolled_device"``: no device, and the email failed.
            LumoAuthPermissionDeniedError: 403, for example
                ``test_token_not_accepted`` for a portal test token.
        """
        if not task_id:
            raise LumoAuthValidationError("task_id is required")
        if not reason:
            raise LumoAuthValidationError("reason is required")
        if impact not in _VALID_IMPACTS:
            raise LumoAuthValidationError(f"invalid impact: {impact!r}")
        try:
            created = self._http.call(
                "approvals.create",
                json={
                    "task_id": task_id,
                    "reason": reason,
                    "impact": impact,
                    "on_behalf_of": on_behalf_of,
                    "meta": dict(meta) if meta else None,
                },
            )
        except LumoAuthApiError as exc:
            if exc.status_code == 428:
                raise not_delivered_error(NO_ENROLLED_DEVICE, exc.body, 428) from exc
            raise
        if is_not_delivered(created):
            created = dict(created)
            created["approval_token"] = None
        return created

    def get_status(self, token: str) -> Dict[str, Any]:
        """Fetch the current status of an approval request by its token.

        ``approved_by`` is ``{"user_id": <int>}`` once the request is
        approved, and ``None`` before that.
        """
        if not token:
            raise LumoAuthValidationError(
                "approval token is required (a 202 email_fallback_sent answer has none)"
            )
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
        if not token:
            raise LumoAuthValidationError(
                "approval token is required (a 202 email_fallback_sent answer has none)"
            )
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
        """Create an approval request and block until it resolves or expires.

        Raises:
            LumoAuthApprovalNotDeliveredError: no push prompt was sent, so
                there is nothing to wait for. ``reason`` is
                ``"email_fallback_sent"`` (202) or ``"no_enrolled_device"``
                (428). The request is never treated as approved.
        """
        created = self.create(
            task_id=task_id,
            reason=reason,
            on_behalf_of=on_behalf_of,
            impact=impact,
            meta=meta,
        )
        if is_not_delivered(created):
            raise not_delivered_error(EMAIL_FALLBACK_SENT, created, 202)
        token = created.get("approval_token") if isinstance(created, dict) else None
        if not token:
            raise LumoAuthValidationError("approval response has no approval_token")
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

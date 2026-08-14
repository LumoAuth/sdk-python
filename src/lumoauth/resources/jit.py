"""JIT permission endpoints — ephemeral tasks and RFC 9396 requests.

The ergonomic context-manager wrapper lives in
:class:`lumoauth.jit.JITContext`; this resource exposes the raw endpoint
operations it delegates to.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Mapping, Optional

from lumoauth._http import HttpClient

logger = logging.getLogger("lumoauth.jit")

__all__ = ["JitResource"]


class JitResource:
    """Just-in-Time permission operations."""

    # Maximum TTL the server will honour (15 min).
    MAX_TTL: int = 900

    def __init__(self, http: HttpClient) -> None:
        self._http = http

    # ── Task lifecycle ────────────────────────────────────────────────

    def create_task(
        self,
        *,
        name: Optional[str] = None,
        task_type: Optional[str] = None,
        on_behalf_of: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create an ephemeral task (isolated sub-identity)."""
        body: Dict[str, Any] = {}
        if name:
            body["name"] = name
        if task_type:
            body["type"] = task_type
        if on_behalf_of:
            body["on_behalf_of"] = on_behalf_of
        return self._http.call("jit.task.create", json=body)

    def complete_task(self, task_id: str) -> Any:
        """Complete a task and revoke all associated JIT tokens."""
        return self._http.call(
            "jit.task.complete", path_params={"task_id": task_id}
        )

    def evaluate_task(
        self,
        task_id: str,
        *,
        result: str = "completed",
        notes: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Close a task with an outcome (``completed``/``failed``/``cancelled``)."""
        body: Dict[str, Any] = {"result": result}
        if notes:
            body["notes"] = notes
        return self._http.call(
            "jit.task.evaluate", path_params={"task_id": task_id}, json=body
        )

    # ── Permission requests (RFC 9396) ────────────────────────────────

    def request(
        self,
        task_id: str,
        authorization_details: Mapping[str, Any],
        *,
        justification: Optional[str] = None,
        ttl: int = 300,
    ) -> Dict[str, Any]:
        """Request a JIT permission via RFC 9396 ``authorization_details``."""
        body: Dict[str, Any] = {
            "task_id": task_id,
            "authorization_details": dict(authorization_details),
            "requested_ttl": min(ttl, self.MAX_TTL),
        }
        if justification:
            body["justification"] = justification
        return self._http.call("jit.request.create", json=body)

    def get_status(self, request_id: str) -> Dict[str, Any]:
        """Current status of a JIT permission request."""
        return self._http.call(
            "jit.request.status", path_params={"request_id": request_id}
        )

    def get_token(self, request_id: str) -> Dict[str, Any]:
        """Exchange an approved request for a short-lived JIT token response."""
        return self._http.call(
            "jit.request.token", path_params={"request_id": request_id}
        )

    def pending(self) -> List[Dict[str, Any]]:
        """List pending HITL approval requests."""
        data = self._http.call("jit.pending")
        if isinstance(data, dict):
            return data.get("requests", [])
        return data if isinstance(data, list) else []

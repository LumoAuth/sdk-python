"""Just-in-Time (JIT) permissions — ephemeral tasks, RFC 9396 permission requests, and HITL support."""

from __future__ import annotations

import base64
import json
import logging
import time
from typing import Any, Protocol, runtime_checkable

import requests

logger = logging.getLogger("lumoauth.jit")

__all__ = ["JITContext"]


# ---------------------------------------------------------------------------
# Minimal protocol so JITContext works with *any* authenticated agent object
# that exposes a bearer token and the usual base_url / tenant pair.
# ---------------------------------------------------------------------------

@runtime_checkable
class _TokenBearer(Protocol):
    base_url: str
    tenant: str

    @property
    def access_token(self) -> str | None: ...


class JITContext:
    """Manage an ephemeral JIT task with scoped permission requests.

    ``JITContext`` wraps a :class:`~lumoauth.LumoAuthAgent` (or any
    object satisfying the token-bearer protocol) and provides helpers for
    the full JIT lifecycle:

    1. **Create a task** — isolated sub-identity (ephemeral persona).
    2. **Request permissions** — RFC 9396 ``authorization_details``, with
       automatic HITL polling when approval is required.
    3. **Exchange for JIT token** — short-lived, narrowly scoped token.
    4. **Complete the task** — revoke all associated tokens.

    Use as a context manager to guarantee cleanup::

        from lumoauth import LumoAuthAgent
        from lumoauth.jit import JITContext

        agent = LumoAuthAgent()
        agent.authenticate()

        with JITContext(agent) as jit:
            jit.create_task(name="Analyse Q4 report")
            result = jit.request_permission({
                "type": "file_access",
                "actions": ["read"],
                "identifier": "report_q4.pdf",
            })
            if result["status"] == "approved":
                token = jit.get_token(result["request_id"])
                resp = jit.call(token, "GET",
                    "https://storage.example.com/report_q4.pdf")
    """

    # Maximum TTL the server will honour (15 min).
    MAX_TTL: int = 900

    def __init__(
        self,
        agent: _TokenBearer,
        *,
        delegated_token: str | None = None,
    ) -> None:
        """Initialise from an authenticated agent.

        Args:
            agent: Any object that exposes ``base_url``, ``tenant`` and an
                ``access_token`` property (e.g. :class:`LumoAuthAgent`).
            delegated_token: Optional on-behalf-of token (from
                :meth:`delegate_on_behalf_of`).  When set, JIT requests
                are made with this token instead of the agent's own.
        """
        self._agent = agent
        self._delegated_token = delegated_token
        self.task_id: str | None = None
        self.caep_session_id: str | None = None
        self._verify_tls: bool = getattr(agent, "_verify_tls", True)

    # -- context manager ------------------------------------------------------

    def __enter__(self) -> JITContext:
        return self

    def __exit__(self, *exc: object) -> None:
        self.complete_task()

    # -- helpers --------------------------------------------------------------

    def _bearer(self) -> str:
        token = self._delegated_token or self._agent.access_token
        if not token:
            raise RuntimeError("No access token available — authenticate first.")
        return token

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._bearer()}"}

    def _api(self, path: str) -> str:
        return f"{self._agent.base_url}/t/{self._agent.tenant}/api/v1{path}"

    # =========================================================================
    # Delegation (on-behalf-of)
    # =========================================================================

    def delegate_on_behalf_of(self, user_token: str) -> bool:
        """Exchange the agent + user tokens for a delegated token (RFC 8693).

        The resulting token represents *"agent acting as user"* and carries
        an ``act`` (actor) claim for full audit.

        Args:
            user_token: The user's access token obtained through OAuth.

        Returns:
            ``True`` on success.
        """
        logger.info("Exchanging tokens for on-behalf-of delegation")

        resp = requests.post(
            self._api("/oauth/token"),
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "subject_token": user_token,
                "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "actor_token": self._agent.access_token,
                "actor_token_type": "urn:ietf:params:oauth:token-type:access_token",
            },
            timeout=30,
            verify=self._verify_tls,
        )

        if resp.status_code != 200:
            logger.error("Delegation failed: HTTP %d — %s", resp.status_code, resp.text)
            return False

        self._delegated_token = resp.json()["access_token"]
        logger.info("Delegation successful — agent can now act on behalf of user")
        return True

    # =========================================================================
    # Task lifecycle
    # =========================================================================

    def create_task(
        self,
        *,
        name: str | None = None,
        task_type: str | None = None,
        on_behalf_of: str | None = None,
    ) -> str:
        """Create an ephemeral task (isolated sub-identity).

        Args:
            name: Human-readable task label.
            task_type: Category (e.g. ``"research"``, ``"analysis"``).
            on_behalf_of: User email when acting on their behalf.

        Returns:
            The ``task_id`` string.
        """
        body: dict[str, Any] = {}
        if name:
            body["name"] = name
        if task_type:
            body["type"] = task_type
        if on_behalf_of:
            body["on_behalf_of"] = on_behalf_of

        resp = requests.post(
            self._api("/jit/task"),
            headers=self._headers(),
            json=body,
            timeout=30,
            verify=self._verify_tls,
        )
        resp.raise_for_status()

        data = resp.json()
        self.task_id = data["task_id"]
        self.caep_session_id = data.get("caep_session_id")
        logger.info(
            "Task created: task_id=%s caep=%s expires=%s",
            self.task_id,
            self.caep_session_id,
            data.get("expires_at"),
        )
        return self.task_id

    def complete_task(self) -> bool:
        """Complete the task and revoke all associated JIT tokens.

        Safe to call multiple times or when no task exists.
        """
        if not self.task_id:
            return True

        logger.info("Completing task %s", self.task_id)
        try:
            resp = requests.post(
                self._api(f"/jit/task/{self.task_id}/complete"),
                headers=self._headers(),
                timeout=30,
                verify=self._verify_tls,
            )
            ok = resp.status_code == 200
            if ok:
                logger.info("Task %s completed — all JIT tokens revoked", self.task_id)
            else:
                logger.warning("Task completion returned HTTP %d", resp.status_code)
            return ok
        finally:
            self.task_id = None
            self.caep_session_id = None

    # =========================================================================
    # Permission requests (RFC 9396)
    # =========================================================================

    def request_permission(
        self,
        authorization_details: dict[str, Any],
        *,
        justification: str | None = None,
        ttl: int = 300,
        wait_for_approval: bool = True,
        poll_interval: int = 5,
        poll_timeout: int = 300,
    ) -> dict[str, Any]:
        """Request a JIT permission using RFC 9396 authorization details.

        Low-risk requests are auto-approved.  High-risk requests enter
        a human-in-the-loop (HITL) approval flow; when *wait_for_approval*
        is ``True`` this method polls until the request is resolved or
        *poll_timeout* is reached.

        Args:
            authorization_details: RFC 9396 structured object, e.g.
                ``{"type": "file_access", "actions": ["read"],
                "identifier": "report.pdf"}``.
            justification: Human-readable reason for the request.
            ttl: Requested token lifetime in seconds (capped at 900).
            wait_for_approval: Block on HITL approval.
            poll_interval: Seconds between status polls.
            poll_timeout: Maximum seconds to wait for approval.

        Returns:
            Server response dict.  Key fields: ``request_id``,
            ``status`` (``"approved"`` / ``"pending"`` / ``"denied"``),
            ``risk_level``, and ``token_url`` (when approved).
        """
        if not self.task_id:
            raise RuntimeError("No active task — call create_task() first.")

        body: dict[str, Any] = {
            "task_id": self.task_id,
            "authorization_details": authorization_details,
            "requested_ttl": min(ttl, self.MAX_TTL),
        }
        if justification:
            body["justification"] = justification

        resp = requests.post(
            self._api("/jit/request"),
            headers=self._headers(),
            json=body,
            timeout=30,
            verify=self._verify_tls,
        )
        resp.raise_for_status()
        result = resp.json()

        logger.info(
            "JIT request %s — status=%s risk=%s",
            result.get("request_id"),
            result.get("status"),
            result.get("risk_level"),
        )

        if result["status"] == "pending" and wait_for_approval:
            result = self._poll_status(result, poll_interval, poll_timeout)

        return result

    def _poll_status(
        self,
        initial: dict[str, Any],
        interval: int,
        timeout: int,
    ) -> dict[str, Any]:
        status_url = initial["status_url"]
        deadline = time.time() + timeout

        logger.info("Waiting for HITL approval (timeout=%ds)…", timeout)
        while time.time() < deadline:
            time.sleep(interval)
            resp = requests.get(
                f"{self._agent.base_url}{status_url}"
                if not status_url.startswith("http")
                else status_url,
                headers=self._headers(),
                timeout=30,
                verify=self._verify_tls,
            )
            resp.raise_for_status()
            result = resp.json()
            if result["status"] != "pending":
                logger.info("HITL resolved: %s", result["status"])
                return result

        logger.warning("HITL approval timed out after %ds", timeout)
        return initial  # still pending

    def get_token(self, request_id: str) -> str:
        """Exchange an approved permission request for a short-lived JIT token.

        Args:
            request_id: The ``request_id`` from :meth:`request_permission`.

        Returns:
            JIT access token string.
        """
        resp = requests.post(
            self._api(f"/jit/request/{request_id}/token"),
            headers=self._headers(),
            timeout=30,
            verify=self._verify_tls,
        )
        resp.raise_for_status()
        data = resp.json()
        logger.info(
            "JIT token issued (expires_in=%ds, request=%s)",
            data.get("expires_in", 0),
            request_id,
        )
        return data["access_token"]

    # =========================================================================
    # Convenience: call with automatic JIT escalation
    # =========================================================================

    def call(
        self,
        jit_token: str,
        method: str,
        url: str,
        *,
        data: dict[str, Any] | None = None,
        timeout: int = 30,
    ) -> requests.Response:
        """Make an API call using a JIT token.

        Args:
            jit_token: Short-lived access token from :meth:`get_token`.
            method: HTTP verb.
            url: Target URL.
            data: JSON body for POST/PUT.
            timeout: HTTP timeout.
        """
        return requests.request(
            method,
            url,
            headers={"Authorization": f"Bearer {jit_token}"},
            json=data,
            timeout=timeout,
            verify=self._verify_tls,
        )

    # =========================================================================
    # Admin / oversight helpers
    # =========================================================================

    def list_pending_requests(self) -> list[dict[str, Any]]:
        """List all pending HITL approval requests for the current task.

        Returns:
            List of pending request dicts, each with ``request_id``,
            ``status``, ``risk_level``, ``authorization_details``, etc.

        Raises:
            RuntimeError: If the request fails.
        """
        resp = requests.get(
            self._api("/jit/pending"),
            headers=self._headers(),
            timeout=30,
            verify=self._verify_tls,
        )
        resp.raise_for_status()
        data = resp.json()
        logger.info("Listed %d pending JIT requests", len(data.get("requests", [])))
        return data.get("requests", data if isinstance(data, list) else [])

    def evaluate_task(
        self,
        task_id: str | None = None,
        *,
        result: str = "completed",
        notes: str | None = None,
    ) -> dict[str, Any]:
        """Evaluate and close a task with an outcome.

        Allows supervisors or orchestrators to mark a task as
        ``"completed"``, ``"failed"``, or ``"cancelled"`` and attach audit
        notes.  Uses the current task if *task_id* is omitted.

        Args:
            task_id: Task to evaluate.  Defaults to ``self.task_id``.
            result: Outcome label — ``"completed"``, ``"failed"``, or
                ``"cancelled"``.
            notes: Human-readable notes attached to the audit record.

        Returns:
            Server response dict.

        Raises:
            RuntimeError: If no task is active or the request fails.
        """
        tid = task_id or self.task_id
        if not tid:
            raise RuntimeError("No active task — call create_task() first.")

        body: dict[str, Any] = {"result": result}
        if notes:
            body["notes"] = notes

        resp = requests.post(
            self._api(f"/jit/task/{tid}/evaluate"),
            headers=self._headers(),
            json=body,
            timeout=30,
            verify=self._verify_tls,
        )
        resp.raise_for_status()
        data = resp.json()
        logger.info("Task %s evaluated as '%s'", tid, result)
        return data

    def call_with_escalation(
        self,
        method: str,
        url: str,
        *,
        justification: str = "Required for user request",
        data: dict[str, Any] | None = None,
        timeout: int = 30,
    ) -> requests.Response:
        """Call an API, automatically requesting JIT permission on 403.

        When the server returns ``403`` with an
        ``Insufficient-Authorization-Details`` header, this method
        automatically requests the missing permission, obtains a JIT
        token, and retries the request once.

        Args:
            method: HTTP verb.
            url: Target URL.
            justification: Passed to :meth:`request_permission`.
            data: JSON body for POST/PUT.
            timeout: HTTP timeout.
        """
        # First attempt with the base bearer token
        resp = requests.request(
            method,
            url,
            headers=self._headers(),
            json=data,
            timeout=timeout,
            verify=self._verify_tls,
        )

        if resp.status_code != 403:
            return resp

        header = resp.headers.get("Insufficient-Authorization-Details")
        if not header:
            return resp

        # Decode the required authorization_details
        required_authz = json.loads(base64.b64decode(header))
        logger.info("Auto-escalating: requesting JIT for %s", required_authz)

        result = self.request_permission(
            required_authz, justification=justification
        )
        if result.get("status") != "approved":
            logger.warning("JIT escalation not approved: %s", result.get("status"))
            return resp  # return original 403

        jit_token = self.get_token(result["request_id"])
        return self.call(jit_token, method, url, data=data, timeout=timeout)

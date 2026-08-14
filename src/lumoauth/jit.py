"""Just-in-Time (JIT) permissions — ephemeral tasks, RFC 9396 permission requests, and HITL support."""

from __future__ import annotations

import base64
import json
import logging
import time
from typing import Any, Protocol, runtime_checkable

import requests

from lumoauth._http import HttpClient
from lumoauth.errors import LumoAuthApiError, LumoAuthConfigError
from lumoauth.resources.auth import AuthResource
from lumoauth.resources.jit import JitResource

logger = logging.getLogger("lumoauth.jit")

__all__ = ["JITContext"]


# ---------------------------------------------------------------------------
# Minimal protocol so JITContext works with *any* authenticated agent object
# that exposes a bearer token and the usual base_url / org_id pair.
# ---------------------------------------------------------------------------

@runtime_checkable
class _TokenBearer(Protocol):
    base_url: str
    org_id: str

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
    MAX_TTL: int = JitResource.MAX_TTL

    def __init__(
        self,
        agent: _TokenBearer,
        *,
        delegated_token: str | None = None,
    ) -> None:
        """Initialise from an authenticated agent.

        Args:
            agent: Any object that exposes ``base_url``, ``org_id`` and an
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

        # JIT calls always use the current bearer (delegated wins), which
        # the token provider resolves per request.
        self._http = HttpClient(
            agent.base_url,
            org_id=agent.org_id,
            token_provider=self._bearer,
            verify_tls=self._verify_tls,
        )
        self._resource = JitResource(self._http)
        self._auth = AuthResource(self._http)

    # -- context manager ------------------------------------------------------

    def __enter__(self) -> JITContext:
        return self

    def __exit__(self, *exc: object) -> None:
        self.complete_task()

    # -- helpers --------------------------------------------------------------

    def _bearer(self) -> str:
        token = self._delegated_token or self._agent.access_token
        if not token:
            raise LumoAuthConfigError(
                "No access token available — authenticate first."
            )
        return token

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._bearer()}"}

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

        try:
            body = self._auth.token_exchange(
                user_token, actor_token=self._agent.access_token or ""
            )
        except LumoAuthApiError as exc:
            logger.error("Delegation failed: HTTP %s — %s", exc.status_code, exc)
            return False

        self._delegated_token = body["access_token"]
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
        data = self._resource.create_task(
            name=name, task_type=task_type, on_behalf_of=on_behalf_of
        )
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
            self._resource.complete_task(self.task_id)
            logger.info("Task %s completed — all JIT tokens revoked", self.task_id)
            return True
        except LumoAuthApiError as exc:
            logger.warning("Task completion returned HTTP %s", exc.status_code)
            return False
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
            raise LumoAuthConfigError("No active task — call create_task() first.")

        result = self._resource.request(
            self.task_id,
            authorization_details,
            justification=justification,
            ttl=ttl,
        )

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
            result = self._http.request("GET", status_url)
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
        data = self._resource.get_token(request_id)
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
        return self._http.request(
            method,
            url,
            json=data,
            timeout=timeout,
            headers={"Authorization": f"Bearer {jit_token}"},
            raw=True,
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
            LumoAuthApiError: If the request fails.
        """
        pending = self._resource.pending()
        logger.info("Listed %d pending JIT requests", len(pending))
        return pending

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
            LumoAuthConfigError: If no task is active.
            LumoAuthApiError: If the request fails.
        """
        tid = task_id or self.task_id
        if not tid:
            raise LumoAuthConfigError("No active task — call create_task() first.")

        data = self._resource.evaluate_task(tid, result=result, notes=notes)
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
        resp = self._http.request(
            method,
            url,
            json=data,
            timeout=timeout,
            headers=self._headers(),
            raw=True,
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

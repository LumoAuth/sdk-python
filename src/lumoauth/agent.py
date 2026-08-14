"""LumoAuth Agent client — OAuth 2.0 authentication, capability checks, and token exchange."""

from __future__ import annotations

import logging
import os
import time
from typing import Any, Dict, List, Optional

import requests

from lumoauth.client import LumoAuth
from lumoauth.errors import LumoAuthApiError, LumoAuthConfigError
from lumoauth.resources.approvals import ApprovalsResource
from lumoauth.resources.delegation import DelegationResource
from lumoauth.resources.jit import JitResource
from lumoauth.resources.mcp import McpResource

logger = logging.getLogger("lumoauth")

__all__ = ["LumoAuthAgent"]


class LumoAuthAgent:
    """LumoAuth Agent client with OAuth 2.0 authentication and capability management.

    A thin, ergonomic layer over :class:`lumoauth.LumoAuth` that owns a
    client-credentials token manager.  Handles the full agent lifecycle:

    - Client-credentials authentication
    - Automatic token refresh (with configurable safety buffer)
    - Capability and budget introspection via the UserInfo endpoint
    - Authenticated API requests
    - RFC 8693 token exchange for secured MCP servers

    Example::

        from lumoauth import LumoAuthAgent

        agent = LumoAuthAgent()          # reads env vars by default
        agent.authenticate()
        info = agent.get_agent_info()
        print(info["capabilities"])
    """

    # Default safety margin (seconds) subtracted from ``expires_in`` so we
    # refresh *before* the token actually expires.
    _TOKEN_REFRESH_BUFFER: int = 60

    def __init__(
        self,
        base_url: str | None = None,
        org_id: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        skip_cert_validation: bool = False,
    ) -> None:
        """Initialise the agent client.

        All parameters fall back to environment variables when not provided:

        ===============  ========================
        Parameter        Environment variable
        ===============  ========================
        ``base_url``     ``LUMOAUTH_URL``
        ``org_id``       ``LUMOAUTH_ORG_ID``
        ``client_id``    ``AGENT_CLIENT_ID``
        ``client_secret`` ``AGENT_CLIENT_SECRET``
        ===============  ========================

        Raises:
            LumoAuthConfigError: If ``client_id`` or ``client_secret`` cannot
                be resolved (subclasses ``ValueError`` for compatibility).
        """
        self.base_url: str = (
            base_url or os.environ.get("LUMOAUTH_URL", "https://app.lumoauth.dev")
        )
        self.org_id: str = (
            org_id or os.environ.get("LUMOAUTH_ORG_ID", "")
        )
        self.client_id: str = client_id or os.environ.get("AGENT_CLIENT_ID", "")
        self.client_secret: str = client_secret or os.environ.get("AGENT_CLIENT_SECRET", "")

        if not self.client_id or not self.client_secret:
            raise LumoAuthConfigError(
                "Agent credentials required. Set AGENT_CLIENT_ID and AGENT_CLIENT_SECRET "
                "environment variables or pass client_id/client_secret to the constructor."
            )

        # TLS verification (set to False only for local / dev environments)
        self._verify_tls: bool = not skip_cert_validation

        # Token state
        self._access_token: str | None = None
        self._token_expires_at: float = 0.0
        self._token_scopes: list[str] = []

        # Cached agent info (populated by :meth:`get_agent_info`)
        self._agent_info: dict[str, Any] | None = None

        # Internal general-purpose client; every request pulls a fresh
        # bearer token through the auto-refreshing token provider.
        self._client = LumoAuth(
            base_url=self.base_url,
            org_id=self.org_id or None,
            token_provider=self._provide_token,
            skip_cert_validation=skip_cert_validation,
        )

    # -- helpers exposed as read-only properties ------------------------------

    @property
    def access_token(self) -> str | None:
        """The current access token, or *None* if not yet authenticated."""
        return self._access_token

    @property
    def token_scopes(self) -> list[str]:
        """Scopes granted by the last successful authentication."""
        return list(self._token_scopes)

    @property
    def agent_info(self) -> dict[str, Any] | None:
        """Cached agent info dict, or *None* if :meth:`get_agent_info` hasn't been called."""
        return self._agent_info

    # -- resource namespaces --------------------------------------------------

    @property
    def jit(self) -> JitResource:
        """Raw JIT endpoint operations (see also :class:`lumoauth.JITContext`)."""
        return self._client.jit

    @property
    def delegation(self) -> DelegationResource:
        """Raw delegation operations (see also :class:`lumoauth.DelegationChain`)."""
        return self._client.delegation

    @property
    def mcp(self) -> McpResource:
        """MCP token exchange operations."""
        return self._client.mcp

    @property
    def approvals(self) -> ApprovalsResource:
        """Push-approval operations."""
        return self._client.approvals

    # =========================================================================
    # Authentication — OAuth 2.0 Client Credentials
    # =========================================================================

    def authenticate(self, scopes: list[str] | None = None) -> bool:
        """Authenticate using the OAuth 2.0 client-credentials flow.

        Args:
            scopes: Optional scopes to request.  When *None* the server returns
                the agent's default registered capabilities.

        Returns:
            ``True`` on success, ``False`` on failure (details are logged).
        """
        logger.info(
            "Authenticating agent (base_url=%s, org_id=%s, client_id=%s…)",
            self.base_url,
            self.org_id,
            self.client_id[:12],
        )

        try:
            body = self._client.auth.client_credentials(
                self.client_id, self.client_secret, scopes=scopes
            )
        except LumoAuthApiError as exc:
            logger.error("Authentication failed: HTTP %s — %s", exc.status_code, exc)
            return False

        self._access_token = body["access_token"]
        self._token_scopes = body.get("scope", "").split()
        expires_in = body.get("expires_in", 3600)
        self._token_expires_at = time.time() + expires_in - self._TOKEN_REFRESH_BUFFER
        logger.info(
            "Authentication successful (expires_in=%ds, scopes=%s)",
            expires_in,
            self._token_scopes or "default",
        )
        return True

    def ensure_authenticated(self) -> bool:
        """Ensure a valid access token exists, refreshing transparently if needed.

        Returns:
            ``True`` when a valid token is available.
        """
        if self._access_token and time.time() < self._token_expires_at:
            return True
        logger.debug("Token expired or missing — re-authenticating")
        return self.authenticate(self._token_scopes or None)

    # =========================================================================
    # Agent info & capabilities
    # =========================================================================

    def get_agent_info(self) -> dict[str, Any]:
        """Fetch agent identity and capabilities from the UserInfo endpoint.

        The response includes ``sub``, ``name``, ``agent_id``,
        ``capabilities``, ``budget_policy``, and more.

        Returns:
            Agent info dictionary.

        Raises:
            LumoAuthApiError: If the request fails (subclasses ``RuntimeError``).
        """
        self.ensure_authenticated()

        try:
            self._agent_info = self._client.agents.info()
        except LumoAuthApiError as exc:
            _reraise_with_prefix(exc, "Failed to get agent info")

        logger.info(
            "Agent info: name=%s, capabilities=%s",
            self._agent_info.get("name"),
            self._agent_info.get("capabilities"),
        )
        return self._agent_info

    def has_capability(self, capability: str) -> bool:
        """Check whether the agent has a specific capability.

        Lazily fetches agent info on the first call.

        Args:
            capability: Capability string (e.g. ``"read:documents"``).
        """
        if self._agent_info is None:
            self.get_agent_info()
        return capability in (self._agent_info or {}).get("capabilities", [])

    def get_budget_status(self) -> dict[str, Any]:
        """Return the agent's current budget status.

        Lazily fetches agent info on the first call.

        Returns:
            Budget policy dict (may be empty if no policy is set).
        """
        if self._agent_info is None:
            self.get_agent_info()
        return (self._agent_info or {}).get("budget_policy", {})

    def is_budget_exhausted(self) -> bool:
        """Return ``True`` if the daily token budget has been reached."""
        budget = self.get_budget_status()
        if not budget:
            return False
        return budget.get("tokens_used_today", 0) >= budget.get(
            "max_tokens_per_day", float("inf")
        )

    # =========================================================================
    # Ask API — preflight capability checks & self-inspection
    # =========================================================================

    def ask(self, action: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
        """Check whether the agent is authorised to perform *action*.

        This calls the ``/agents/ask`` endpoint which is optimised for
        LLM tool-calling patterns — use it as a preflight check before
        executing a tool.

        Args:
            action: Permission or action slug (e.g. ``"document.read"``).
            context: Optional context dict (e.g. ``{"id": "doc_99"}``).

        Returns:
            Dict with ``allowed`` (bool), ``action``, ``reason``,
            ``audit_id`` and the original ``context``.

        Raises:
            LumoAuthApiError: If the request fails (subclasses ``RuntimeError``).
        """
        self.ensure_authenticated()

        try:
            result = self._client.agents.ask(action, context)
        except LumoAuthApiError as exc:
            _reraise_with_prefix(exc, "Ask API failed")

        logger.info(
            "ask(%s) → allowed=%s reason=%s",
            action,
            result.get("allowed"),
            result.get("reason"),
        )
        return result

    def is_allowed(self, action: str, context: dict[str, Any] | None = None) -> bool:
        """Convenience wrapper: return ``True`` when *action* is allowed."""
        return self.ask(action, context).get("allowed", False)

    def get_identity(self) -> dict[str, Any]:
        """Return the agent's own identity, capabilities and workspace info.

        Calls ``GET /agents/me``.

        Returns:
            Dict with ``identity``, ``capabilities``, and ``workspace`` keys.

        Raises:
            LumoAuthApiError: If the request fails (subclasses ``RuntimeError``).
        """
        self.ensure_authenticated()

        try:
            data = self._client.agents.me()
        except LumoAuthApiError as exc:
            _reraise_with_prefix(exc, "Identity request failed")

        logger.info(
            "Agent identity: id=%s capabilities=%s",
            data.get("identity", {}).get("id"),
            data.get("capabilities"),
        )
        return data

    # =========================================================================
    # Generic API requests
    # =========================================================================

    def api_request(
        self,
        method: str,
        endpoint: str,
        *,
        data: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        timeout: int = 30,
    ) -> requests.Response:
        """Make an authenticated API request.

        Automatically ensures a valid token before sending.

        Args:
            method: HTTP verb (``GET``, ``POST``, ``PUT``, ``DELETE``, …).
            endpoint: Full URL **or** a path (which is appended to ``base_url``).
            data: JSON request body.
            json: Alias for ``data`` (kept for keyword compatibility).
            params: Query-string parameters.
            timeout: Request timeout in seconds.

        Returns:
            The :class:`requests.Response` object.
        """
        self.ensure_authenticated()

        body = json if json is not None else data
        return self._client._http.request(
            method,
            endpoint,
            json=body,
            params=params,
            timeout=timeout,
            raw=True,
        )

    # =========================================================================
    # Agent registration
    # =========================================================================

    def register(
        self,
        name: str,
        description: str | None = None,
        capabilities: list[str] | None = None,
        jwks_uri: str | None = None,
    ) -> dict[str, Any]:
        """Register this agent with LumoAuth.

        Creates or updates the agent record in the organization directory.
        The ``client_id`` / ``client_secret`` on this instance are used
        for identification.

        Args:
            name: Human-readable agent name (e.g. ``"Document Analyser"``).
            description: Optional description of the agent's purpose.
            capabilities: List of capability slugs the agent declares
                (e.g. ``["read:documents", "tool:search_web"]``).
            jwks_uri: Optional HTTPS URL to the agent's public JWKS
                (required for AAuth / proof-of-possession flows).

        Returns:
            Registration response dict (includes ``agent_id``).

        Raises:
            LumoAuthApiError: If registration fails (subclasses ``RuntimeError``).
        """
        self.ensure_authenticated()

        try:
            data = self._client.agents.register(
                name,
                client_id=self.client_id,
                description=description,
                capabilities=capabilities,
                jwks_uri=jwks_uri,
            )
        except LumoAuthApiError as exc:
            _reraise_with_prefix(exc, "Agent registration failed")

        logger.info(
            "Agent registered: name=%s agent_id=%s",
            name,
            data.get("agent_id"),
        )
        return data

    # =========================================================================
    # MCP token exchange (RFC 8693)
    # =========================================================================

    def get_mcp_token(self, mcp_server_id: str) -> str | None:
        """Exchange the agent's token for one scoped to a secured MCP server.

        Uses the RFC 8693 Token Exchange grant type.

        Args:
            mcp_server_id: The audience identifier of the target MCP server
                (e.g. ``"urn:mcp:financial-data"``).

        Returns:
            An access token string, or *None* on failure.
        """
        self.ensure_authenticated()

        logger.info("Exchanging token for MCP server %s", mcp_server_id)

        try:
            token = self._client.mcp.get_token(
                mcp_server_id, subject_token=self._access_token
            )
        except (LumoAuthApiError, LumoAuthConfigError) as exc:
            status = getattr(exc, "status_code", None)
            logger.error("Token exchange failed: HTTP %s — %s", status, exc)
            return None

        logger.info("Token exchange successful for MCP server %s", mcp_server_id)
        return token

    # -- private helpers ------------------------------------------------------

    def _provide_token(self) -> str | None:
        """Token provider for the internal client — refreshes transparently."""
        self.ensure_authenticated()
        return self._access_token

    def _auth_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._access_token}"}


def _reraise_with_prefix(exc: LumoAuthApiError, prefix: str) -> None:
    """Re-raise a typed API error with a human-readable prefix, in place."""
    exc.message = f"{prefix}: HTTP {exc.status_code} — {exc.message}"
    exc.args = (exc.message,)
    raise exc

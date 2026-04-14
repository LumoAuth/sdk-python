"""LumoAuth Agent client — OAuth 2.0 authentication, capability checks, and token exchange."""

from __future__ import annotations

import logging
import os
import time
from typing import Any, Dict, List, Optional

import requests

logger = logging.getLogger("lumoauth")

__all__ = ["LumoAuthAgent"]


class LumoAuthAgent:
    """LumoAuth Agent client with OAuth 2.0 authentication and capability management.

    Handles the full agent lifecycle:
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
            ValueError: If ``client_id`` or ``client_secret`` cannot be resolved.
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
            raise ValueError(
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

        data: dict[str, str] = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }
        if scopes:
            data["scope"] = " ".join(scopes)

        resp = requests.post(
            f"{self.base_url}/orgs/{self.org_id}/api/v1/oauth/token",
            data=data,
            timeout=30,
            verify=self._verify_tls,
        )

        if resp.status_code == 200:
            body = resp.json()
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

        # Log structured error information
        logger.error("Authentication failed: HTTP %d — %s", resp.status_code, resp.text)
        return False

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
            RuntimeError: If the request fails.
        """
        self.ensure_authenticated()

        resp = requests.get(
            f"{self.base_url}/orgs/{self.org_id}/api/v1/oauth/userinfo",
            headers=self._auth_headers(),
            timeout=30,
            verify=self._verify_tls,
        )

        if resp.status_code != 200:
            raise RuntimeError(f"Failed to get agent info: HTTP {resp.status_code} — {resp.text}")

        self._agent_info = resp.json()
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
            RuntimeError: If the request fails.
        """
        self.ensure_authenticated()

        body: dict[str, Any] = {"action": action}
        if context:
            body["context"] = context

        resp = requests.post(
            f"{self.base_url}/orgs/{self.org_id}/api/v1/agents/ask",
            headers=self._auth_headers(),
            json=body,
            timeout=30,
            verify=self._verify_tls,
        )
        if resp.status_code != 200:
            raise RuntimeError(f"Ask API failed: HTTP {resp.status_code} — {resp.text}")

        result = resp.json()
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
            RuntimeError: If the request fails.
        """
        self.ensure_authenticated()

        resp = requests.get(
            f"{self.base_url}/orgs/{self.org_id}/api/v1/agents/me",
            headers=self._auth_headers(),
            timeout=30,
            verify=self._verify_tls,
        )
        if resp.status_code != 200:
            raise RuntimeError(f"Identity request failed: HTTP {resp.status_code} — {resp.text}")

        data = resp.json()
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
        params: dict[str, Any] | None = None,
        timeout: int = 30,
    ) -> requests.Response:
        """Make an authenticated API request.

        Automatically ensures a valid token before sending.

        Args:
            method: HTTP verb (``GET``, ``POST``, ``PUT``, ``DELETE``, …).
            endpoint: Full URL **or** a path (which is appended to ``base_url``).
            data: JSON request body.
            params: Query-string parameters.
            timeout: Request timeout in seconds.

        Returns:
            The :class:`requests.Response` object.
        """
        self.ensure_authenticated()

        url = endpoint if endpoint.startswith("http") else f"{self.base_url}{endpoint}"

        return requests.request(
            method,
            url,
            headers=self._auth_headers(),
            json=data,
            params=params,
            timeout=timeout,
            verify=self._verify_tls,
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
            RuntimeError: If registration fails.
        """
        self.ensure_authenticated()

        body: dict[str, Any] = {
            "client_id": self.client_id,
            "name": name,
        }
        if description:
            body["description"] = description
        if capabilities:
            body["capabilities"] = capabilities
        if jwks_uri:
            body["jwks_uri"] = jwks_uri

        resp = requests.post(
            f"{self.base_url}/orgs/{self.org_id}/api/v1/agents/register",
            headers=self._auth_headers(),
            json=body,
            timeout=30,
            verify=self._verify_tls,
        )

        if resp.status_code not in (200, 201):
            raise RuntimeError(
                f"Agent registration failed: HTTP {resp.status_code} — {resp.text}"
            )

        data = resp.json()
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

        data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": self._access_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "audience": mcp_server_id,
        }

        resp = requests.post(
            f"{self.base_url}/orgs/{self.org_id}/api/v1/oauth/token",
            data=data,
            timeout=30,
            verify=self._verify_tls,
        )

        if resp.status_code == 200:
            token = resp.json()["access_token"]
            logger.info("Token exchange successful for MCP server %s", mcp_server_id)
            return token

        logger.error("Token exchange failed: HTTP %d — %s", resp.status_code, resp.text)
        return None

    # -- private helpers ------------------------------------------------------

    def _auth_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._access_token}"}

"""LumoAuth Agent client — OAuth 2.0 authentication, capability checks, and token exchange."""

from __future__ import annotations

import logging
import os
import time
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Union

import requests

from lumoauth.capabilities import any_capability_covers
from lumoauth.client import LumoAuth
from lumoauth.errors import LumoAuthApiError, LumoAuthConfigError
from lumoauth.resources.agents import AgentMcpToolDecision
from lumoauth.resources.approvals import ApprovalsResource
from lumoauth.resources.delegation import DelegationResource
from lumoauth.resources.jit import JitResource
from lumoauth.resources.mcp import McpResource, McpToken, validate_mcp_server_id

if TYPE_CHECKING:  # pragma: no cover
    from lumoauth.client_assertion import ClientAssertionSigner
    from lumoauth.dpop import DpopKey, DpopProofSigner

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
    - Optional DPoP (RFC 9449): with ``dpop=`` every token the agent obtains
      is bound to its key, and each request carries a proof

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
        dpop: Union["DpopProofSigner", "DpopKey", bool, None] = None,
        private_key: Union["ClientAssertionSigner", str, bytes, None] = None,
        key_id: str | None = None,
        issuer: str | None = None,
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
        ``private_key``  ``AGENT_PRIVATE_KEY`` (PEM)
        ``key_id``       ``AGENT_KEY_ID``
        ===============  ========================

        Args:
            dpop: Turn on DPoP (RFC 9449). ``True`` generates an ephemeral
                ES256 key; a :class:`~lumoauth.dpop.DpopKey` (for example
                one loaded from PEM) or a ready
                :class:`~lumoauth.dpop.DpopProofSigner` uses that key. The
                client-credentials token, MCP token exchanges and every
                API request then carry a DPoP proof. Needs the
                ``cryptography`` package (``pip install "lumoauth[dpop]"``).
            private_key: For an agent registered with the **Private key JWT**
                identity type: its PEM private key, or a ready
                :class:`~lumoauth.ClientAssertionSigner`. The agent then
                authenticates with a signed client assertion (RFC 7523)
                instead of a secret, so ``client_secret`` is not needed.
                Needs the ``cryptography`` package.
            key_id: The ``kid`` of the registered public key, used with a PEM
                ``private_key``. Required when the agent has several keys.
            issuer: The organization's issuer identifier, the assertion's
                ``aud``. Defaults to ``{base_url}/orgs/{org_id}/api/v1``;
                set it on a custom domain.

        Raises:
            LumoAuthConfigError: If ``client_id``, or both ``client_secret``
                and ``private_key``, cannot be resolved (subclasses
                ``ValueError`` for compatibility).
        """
        self.base_url: str = (
            base_url or os.environ.get("LUMOAUTH_URL", "https://app.lumoauth.dev")
        )
        self.org_id: str = (
            org_id or os.environ.get("LUMOAUTH_ORG_ID", "")
        )
        self.client_id: str = client_id or os.environ.get("AGENT_CLIENT_ID", "")
        self.client_secret: str = client_secret or os.environ.get("AGENT_CLIENT_SECRET", "")
        self.client_assertion_signer: "ClientAssertionSigner | None" = _coerce_assertion_signer(
            private_key if private_key is not None else os.environ.get("AGENT_PRIVATE_KEY") or None,
            key_id or os.environ.get("AGENT_KEY_ID") or None,
        )
        self.issuer: str | None = issuer
        if self.client_assertion_signer is not None and client_secret is None:
            # A private_key_jwt agent has no secret; an AGENT_CLIENT_SECRET
            # left in the environment must not turn into a second method.
            self.client_secret = ""

        if not self.client_id or (not self.client_secret and self.client_assertion_signer is None):
            raise LumoAuthConfigError(
                "Agent credentials required. Set AGENT_CLIENT_ID and AGENT_CLIENT_SECRET "
                "(or AGENT_PRIVATE_KEY for a private key JWT agent), or pass client_id with "
                "client_secret or private_key to the constructor."
            )
        if self.client_secret and self.client_assertion_signer is not None:
            raise LumoAuthConfigError(
                "Pass client_secret or private_key, not both: an agent authenticates with one method."
            )

        # TLS verification (set to False only for local / dev environments)
        self._verify_tls: bool = not skip_cert_validation

        # Token state
        self._access_token: str | None = None
        self._token_type: str = "Bearer"
        self._token_expires_at: float = 0.0
        self._token_scopes: list[str] = []

        # DPoP signer (None when the agent uses plain bearer tokens)
        self.dpop: "DpopProofSigner | None" = _coerce_dpop(dpop)

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
    def token_type(self) -> str:
        """``"Bearer"``, or ``"DPoP"`` when the current token is DPoP-bound."""
        return self._token_type

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
            if self.client_assertion_signer is not None:
                body = self._client.auth.client_credentials(
                    self.client_id,
                    scopes=scopes,
                    dpop=self.dpop,
                    client_assertion=self.client_assertion(),
                )
            else:
                body = self._client.auth.client_credentials(
                    self.client_id, self.client_secret, scopes=scopes, dpop=self.dpop
                )
        except LumoAuthApiError as exc:
            logger.error("Authentication failed: HTTP %s — %s", exc.status_code, exc)
            return False

        self._access_token = body["access_token"]
        self._token_type = str(body.get("token_type") or "Bearer")
        self._token_scopes = body.get("scope", "").split()
        expires_in = body.get("expires_in", 3600)
        self._token_expires_at = time.time() + expires_in - self._TOKEN_REFRESH_BUFFER
        # A DPoP-bound token must travel as `Authorization: DPoP` with a
        # proof on every request; a Bearer answer (server without DPoP)
        # keeps the plain bearer scheme.
        self._client._http.dpop = (
            self.dpop if self.dpop is not None and self._token_type.lower() == "dpop" else None
        )
        logger.info(
            "Authentication successful (expires_in=%ds, scopes=%s, token_type=%s)",
            expires_in,
            self._token_scopes or "default",
            self._token_type,
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

        Lazily fetches agent info on the first call. Names match as on the
        server: ``"read:documents"`` matches the stored ``read.documents``,
        and a held ``read.*`` covers ``read.documents``
        (see :func:`lumoauth.capability_covers`).

        This checks only the agent's registered capabilities. The Ask API
        (:meth:`ask`) also applies your policies and the token's scope.

        Args:
            capability: Capability string (e.g. ``"read:documents"``).
        """
        if self._agent_info is None:
            self.get_agent_info()
        held = (self._agent_info or {}).get("capabilities") or []
        return isinstance(held, list) and any_capability_covers(held, capability)

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
        """Return ``True`` if the agent's budget is spent.

        The server reports ``exhausted`` in ``budget_policy``: true when any
        limit (calls, tokens or cost, per hour, day or month) is reached, so
        the next metered call would get ``429``. Without that field (older
        servers), the daily token cap is compared with today's usage.
        Uses the cached agent info; call :meth:`get_agent_info` for a live
        reading.
        """
        budget = self.get_budget_status()
        if not budget:
            return False
        reported = budget.get("exhausted")
        if isinstance(reported, bool):
            return reported
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

    def authorize_mcp_tool(self, server_id: str, tool: str) -> AgentMcpToolDecision:
        """Ask whether this agent may run *tool* on a registered MCP server.

        Calls ``POST /agents/me/mcp/authorize`` with the agent's own token.

        Args:
            server_id: The registered MCP server id (``mcp_…``), not its URL.
            tool: The tool name, at most 80 characters.

        Returns:
            :class:`lumoauth.AgentMcpToolDecision`. A deny returns
            ``allowed=False`` and does not raise.

        Raises:
            LumoAuthValidationError: An argument is empty or malformed.
            LumoAuthApiError: Any other error, for example
                ``LumoAuthNotFoundError`` for an unknown server.
        """
        self.ensure_authenticated()

        try:
            decision = self._client.agents.authorize_mcp_tool(server_id, tool)
        except LumoAuthApiError as exc:
            _reraise_with_prefix(exc, "MCP tool authorization failed")

        logger.info(
            "authorize_mcp_tool(%s, %s) → allowed=%s",
            server_id,
            tool,
            decision.allowed,
        )
        return decision

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

        The new token names exactly one MCP server. The server id is sent
        as the RFC 8707 ``resource`` parameter, so the token's ``aud`` is
        that MCP server. Pass the server's registered Resource URI. The
        token works only at that MCP server, and LumoAuth's own API rejects
        it. When the agent was created with ``dpop=``, the exchange carries
        a DPoP proof and the token is DPoP-bound: send it as
        ``Authorization: DPoP`` with a proof (see :meth:`dpop_headers`), or
        use :meth:`get_mcp_credential`, whose result builds those headers.

        Args:
            mcp_server_id: The MCP server's https URL, its RFC 8707 resource
                identifier (e.g. ``"https://mcp.example.com/mcp"``).

        Returns:
            An access token string, or *None* when the exchange fails.

        Raises:
            LumoAuthValidationError: *mcp_server_id* is not an absolute
                http(s) URL (a programming error, so it is not swallowed).
        """
        validate_mcp_server_id(mcp_server_id)
        try:
            return self.get_mcp_credential(mcp_server_id).access_token
        except (LumoAuthApiError, LumoAuthConfigError) as exc:
            status = getattr(exc, "status_code", None)
            logger.error("Token exchange failed: HTTP %s — %s", status, exc)
            return None

    def get_mcp_credential(self, mcp_server_id: str) -> McpToken:
        """Like :meth:`get_mcp_token`, but returns an :class:`McpToken` and raises.

        The result carries ``token_type`` (``"Bearer"`` or ``"DPoP"``) and
        ``headers(method, url)``, which builds the ``Authorization`` header
        and, for a DPoP-bound token, a fresh ``DPoP`` proof with ``ath``::

            cred = agent.get_mcp_credential("https://mcp.example.com/mcp")
            requests.post(url, headers=cred.headers("POST", url), json=body)

        Raises:
            LumoAuthValidationError: *mcp_server_id* is not an absolute
                http(s) URL.
            LumoAuthApiError: LumoAuth refused the exchange.
            LumoAuthConfigError: The agent could not authenticate.
        """
        validate_mcp_server_id(mcp_server_id)
        if not self.ensure_authenticated():
            raise LumoAuthConfigError("Agent authentication failed; see the log")

        logger.info("Exchanging token for MCP server %s", mcp_server_id)
        credential = self._client.mcp.exchange(
            mcp_server_id, subject_token=self._access_token, dpop=self.dpop
        )
        logger.info(
            "Token exchange successful for MCP server %s (token_type=%s)",
            mcp_server_id,
            credential.token_type,
        )
        return credential

    # =========================================================================
    # DPoP helpers (RFC 9449)
    # =========================================================================

    def client_assertion(self) -> str:
        """A new ``private_key_jwt`` client assertion for this agent (single-use).

        Its ``aud`` is :attr:`issuer`, or ``{base_url}/orgs/{org_id}/api/v1``.

        Raises:
            LumoAuthConfigError: The agent was created without ``private_key``.
        """
        if self.client_assertion_signer is None:
            raise LumoAuthConfigError(
                "This agent signs no client assertions: create it with private_key=..."
            )
        from lumoauth.client_assertion import issuer_for

        if not self.issuer and not self.org_id:
            raise LumoAuthConfigError(
                "org_id (LUMOAUTH_ORG_ID) or issuer is needed to address a client assertion"
            )
        audience = self.issuer or issuer_for(self.base_url, self.org_id)
        return self.client_assertion_signer.create(self.client_id, audience)

    def dpop_proof(self, method: str, url: str, *, access_token: str | None = None) -> str:
        """A DPoP proof JWT for one request (``htm``/``htu``, plus ``ath`` with a token).

        Use it for endpoints the SDK does not wrap, such as the attestation
        endpoint (``POST {issuer}/agents/{agent_id}/attest``): pass the full
        request URL. The remembered ``DPoP-Nonce`` of that origin is included.

        Raises:
            LumoAuthConfigError: The agent was created without ``dpop=``.
        """
        return self._require_dpop().create_proof(method, url, access_token=access_token)

    def dpop_headers(
        self, method: str, url: str, *, access_token: str | None = None
    ) -> dict[str, str]:
        """``Authorization: DPoP <token>`` plus a ``DPoP`` proof for one request.

        Without ``access_token`` the agent's own token is used (after
        :meth:`ensure_authenticated`). Each call makes a new proof; call it
        once per request.

        Raises:
            LumoAuthConfigError: The agent was created without ``dpop=``.
        """
        signer = self._require_dpop()
        token = access_token
        if token is None:
            self.ensure_authenticated()
            token = self._access_token
        return signer.headers(method, url, token)

    def _require_dpop(self) -> "DpopProofSigner":
        if self.dpop is None:
            raise LumoAuthConfigError(
                "DPoP is not enabled on this agent: create it with "
                "LumoAuthAgent(dpop=True) or dpop=DpopKey.from_pem(...)."
            )
        return self.dpop

    # -- private helpers ------------------------------------------------------

    def _provide_token(self) -> str | None:
        """Token provider for the internal client — refreshes transparently."""
        self.ensure_authenticated()
        return self._access_token

    def _auth_headers(self) -> dict[str, str]:
        return {"Authorization": f"{self._token_type} {self._access_token}"}


def _coerce_assertion_signer(
    private_key: Union["ClientAssertionSigner", str, bytes, None], key_id: Optional[str]
) -> "ClientAssertionSigner | None":
    if private_key is None or private_key == "":
        return None
    from lumoauth.client_assertion import ClientAssertionSigner

    if isinstance(private_key, ClientAssertionSigner):
        return private_key
    if isinstance(private_key, (str, bytes)):
        return ClientAssertionSigner.from_pem(private_key, key_id=key_id)
    raise LumoAuthConfigError(
        "private_key must be a PEM string or a ClientAssertionSigner, "
        f"not {type(private_key).__name__}"
    )


def _coerce_dpop(
    value: Union["DpopProofSigner", "DpopKey", bool, None]
) -> "DpopProofSigner | None":
    if value is None or value is False:
        return None
    from lumoauth.dpop import DpopKey, DpopProofSigner

    if isinstance(value, DpopProofSigner):
        return value
    if isinstance(value, DpopKey):
        return DpopProofSigner(value)
    if value is True:
        return DpopProofSigner()
    raise LumoAuthConfigError(
        "dpop must be True, a DpopKey or a DpopProofSigner, "
        f"not {type(value).__name__}"
    )


def _reraise_with_prefix(exc: LumoAuthApiError, prefix: str) -> None:
    """Re-raise a typed API error with a human-readable prefix, in place."""
    exc.message = f"{prefix}: HTTP {exc.status_code} — {exc.message}"
    exc.args = (exc.message,)
    raise exc

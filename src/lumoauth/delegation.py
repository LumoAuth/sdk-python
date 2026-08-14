"""Chain of Agency — RFC 8693 token exchange for delegated actions and nested agent chains."""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable

import requests

from lumoauth._http import HttpClient
from lumoauth.errors import (
    LumoAuthApiError,
    LumoAuthPermissionDeniedError,
)
from lumoauth.resources.delegation import MAX_DELEGATION_DEPTH, DelegationResource

logger = logging.getLogger("lumoauth.delegation")

__all__ = ["DelegationChain", "MAX_DELEGATION_DEPTH"]


# ---------------------------------------------------------------------------
# Minimal protocol so DelegationChain works with any authenticated agent.
# ---------------------------------------------------------------------------

@runtime_checkable
class _AgentLike(Protocol):
    base_url: str
    org_id: str
    client_id: str
    client_secret: str

    @property
    def access_token(self) -> str | None: ...

    def ensure_authenticated(self) -> bool: ...


class DelegationChain:
    """Manage RFC 8693 token exchange for acting on behalf of users and nested agent delegation.

    ``DelegationChain`` wraps a :class:`~lumoauth.LumoAuthAgent` and provides
    the full delegation lifecycle:

    1. **User consent** — generate an authorization URL and exchange the
       callback code for user tokens.
    2. **Token exchange** — combine the agent's token (actor) with the
       user's token (subject) to produce a delegated token carrying an
       ``act`` claim.
    3. **Delegated requests** — make API calls using the delegated token
       so every action is attributed to both agent and user.
    4. **Nested delegation** — pass authority down to sub-agents, each
       level adding to the ``act`` chain.
    5. **Revocation** — invalidate all tokens for a delegation session.

    Example::

        from lumoauth import LumoAuthAgent
        from lumoauth.delegation import DelegationChain

        agent = LumoAuthAgent()
        agent.authenticate()

        chain = DelegationChain(agent, redirect_uri="https://agent.example.com/callback")

        # After user completes consent flow:
        chain.handle_consent_callback("session_1", authorization_code)
        token = chain.exchange("session_1", scopes=["read:documents"])

        # Make delegated API calls
        resp = chain.request("session_1", "GET", "/orgs/acme/api/v1/documents")
    """

    def __init__(
        self,
        agent: _AgentLike,
        *,
        redirect_uri: str | None = None,
    ) -> None:
        """Initialise from an authenticated agent.

        Args:
            agent: An authenticated :class:`~lumoauth.LumoAuthAgent` instance.
            redirect_uri: OAuth callback URL for the user consent flow.
        """
        self._agent = agent
        self._redirect_uri = redirect_uri or ""
        self._verify_tls: bool = getattr(agent, "_verify_tls", True)

        self._http = HttpClient(
            agent.base_url,
            org_id=agent.org_id,
            verify_tls=self._verify_tls,
        )
        self._resource = DelegationResource(self._http)

        # User consent tokens, keyed by session id
        self._user_tokens: Dict[str, _UserTokens] = {}

        # Cached delegated tokens, keyed by session id
        self._delegated_tokens: Dict[str, str] = {}

    # =========================================================================
    # Step 1: User consent flow
    # =========================================================================

    def get_consent_url(
        self,
        session_id: str,
        scopes: List[str] | None = None,
        state: str | None = None,
    ) -> str:
        """Generate a URL where the user can grant the agent permission to act on their behalf.

        This initiates an OAuth 2.0 authorization-code flow.  Redirect the
        user to the returned URL; after they grant consent they will be
        sent back to ``redirect_uri`` with an authorization code.

        Args:
            session_id: Caller-defined identifier to correlate the consent
                with later token-exchange calls.
            scopes: Permissions the agent is requesting on behalf of the user
                (e.g. ``["read:documents", "write:documents"]``).
            state: CSRF-protection value.  Defaults to ``session:<session_id>``.

        Returns:
            The full authorization URL to redirect the user to.

        Raises:
            ValueError: If no ``redirect_uri`` was configured.
        """
        if not self._redirect_uri:
            raise ValueError(
                "redirect_uri is required for the consent flow. "
                "Pass it to the DelegationChain constructor."
            )

        scopes = scopes or ["read:documents"]
        state = state or f"session:{session_id}"

        url = self._resource.consent_url(
            client_id=self._agent.client_id,
            redirect_uri=self._redirect_uri,
            scopes=scopes,
            state=state,
        )
        logger.info(
            "Consent URL generated (session=%s, scopes=%s)",
            session_id,
            scopes,
        )
        return url

    def handle_consent_callback(
        self,
        session_id: str,
        authorization_code: str,
    ) -> bool:
        """Exchange an authorization code from the consent callback for user tokens.

        Call this when the user is redirected back to your ``redirect_uri``
        with an authorization code.

        Args:
            session_id: The same identifier used in :meth:`get_consent_url`.
            authorization_code: The ``code`` query-string parameter from the
                callback URL.

        Returns:
            ``True`` on success, ``False`` on failure (details logged).
        """
        logger.info("Exchanging authorization code for user tokens (session=%s)", session_id)

        try:
            body = self._resource.exchange_code(
                authorization_code,
                self._redirect_uri,
                client_id=self._agent.client_id,
                client_secret=self._agent.client_secret,
            )
        except LumoAuthApiError as exc:
            logger.error(
                "Consent code exchange failed: HTTP %s — %s",
                exc.status_code,
                exc,
            )
            return False

        self._user_tokens[session_id] = _UserTokens(
            access_token=body["access_token"],
            refresh_token=body.get("refresh_token"),
            expires_at=time.time() + body.get("expires_in", 3600),
            scopes=body.get("scope", "").split(),
        )
        logger.info(
            "User consent obtained (session=%s, scopes=%s, refresh=%s)",
            session_id,
            self._user_tokens[session_id].scopes,
            self._user_tokens[session_id].refresh_token is not None,
        )
        return True

    def set_user_token(self, session_id: str, access_token: str) -> None:
        """Register a pre-existing user access token for delegation.

        Use this when you already have a user's token (e.g. from an
        existing OAuth session) and don't need the consent redirect flow.

        Args:
            session_id: Caller-defined session identifier.
            access_token: The user's valid access token.
        """
        self._user_tokens[session_id] = _UserTokens(
            access_token=access_token,
            refresh_token=None,
            expires_at=0,  # unknown — server will reject if expired
            scopes=[],
        )
        logger.info("User token registered directly (session=%s)", session_id)

    # =========================================================================
    # Step 2: RFC 8693 Token Exchange
    # =========================================================================

    def exchange(
        self,
        session_id: str,
        scopes: List[str] | None = None,
    ) -> str:
        """Perform an RFC 8693 token exchange to get a delegated token.

        Combines the user's token (subject) with the agent's token (actor)
        to produce a delegated access token.  The resulting JWT carries an
        ``act`` (actor) claim that records the delegation chain for audit.

        Args:
            session_id: Session whose user token to use as the subject.
            scopes: Optional scope reduction — must be a subset of the
                scopes the user consented to.

        Returns:
            The delegated access token string.

        Raises:
            LookupError: If no user token exists for *session_id*.
            LumoAuthApiError: If the token exchange request fails
                (subclasses ``RuntimeError``).
        """
        self._agent.ensure_authenticated()

        user = self._ensure_user_token(session_id)

        logger.info("Performing RFC 8693 token exchange (session=%s)", session_id)

        body = self._exchange_tokens(
            subject_token=user.access_token,
            actor_token=self._agent.access_token or "",
            scopes=scopes,
            forbidden_message=(
                "Token exchange forbidden — agent may lack 'delegate:on_behalf' capability"
            ),
            failed_prefix="Token exchange failed",
        )

        token = body["access_token"]
        self._delegated_tokens[session_id] = token
        logger.info(
            "Token exchange successful (session=%s, expires_in=%s)",
            session_id,
            body.get("expires_in"),
        )
        return token

    # =========================================================================
    # Step 3: Delegated API requests
    # =========================================================================

    def request(
        self,
        session_id: str,
        method: str,
        endpoint: str,
        *,
        data: Dict[str, Any] | None = None,
        params: Dict[str, Any] | None = None,
        timeout: int = 30,
    ) -> requests.Response:
        """Make an API request using the delegated token for a session.

        The delegated token is obtained automatically via :meth:`exchange`
        if one hasn't been cached yet.

        Args:
            session_id: Session identifying the delegation.
            method: HTTP verb (``GET``, ``POST``, etc.).
            endpoint: Full URL or path appended to the agent's ``base_url``.
            data: JSON request body.
            params: Query-string parameters.
            timeout: Request timeout in seconds.

        Returns:
            The :class:`requests.Response` object.
        """
        token = self._delegated_tokens.get(session_id)
        if not token:
            token = self.exchange(session_id)

        return self._http.request(
            method,
            endpoint,
            json=data,
            params=params,
            timeout=timeout,
            headers={"Authorization": f"Bearer {token}"},
            raw=True,
        )

    # =========================================================================
    # Step 4: Nested delegation (agent → sub-agent)
    # =========================================================================

    def delegate_to_sub_agent(
        self,
        session_id: str,
        sub_agent_token: str,
        scopes: List[str] | None = None,
    ) -> str:
        """Create a nested delegation token for a sub-agent.

        The resulting token represents the chain:
        **user → this agent → sub-agent**.

        Each level of delegation reduces available scopes.  LumoAuth
        enforces a maximum depth of ``MAX_DELEGATION_DEPTH`` levels.

        Args:
            session_id: Session with the original user delegation.
            sub_agent_token: The sub-agent's own access token (obtained
                via its client-credentials flow).
            scopes: Optional scope reduction for the sub-agent (must be
                a subset of the current delegation's scopes).

        Returns:
            A delegated access token for the sub-agent.

        Raises:
            LumoAuthApiError: If the nested exchange fails or the delegation
                chain is too deep (subclasses ``RuntimeError``).
        """
        our_token = self._delegated_tokens.get(session_id)
        if not our_token:
            our_token = self.exchange(session_id)

        logger.info("Creating nested delegation to sub-agent (session=%s)", session_id)

        body = self._exchange_tokens(
            subject_token=our_token,
            actor_token=sub_agent_token,
            scopes=scopes,
            forbidden_message="Nested delegation forbidden",
            failed_prefix="Nested delegation failed",
        )

        token = body["access_token"]
        logger.info("Nested delegation successful (session=%s)", session_id)
        return token

    # =========================================================================
    # Introspection
    # =========================================================================

    @staticmethod
    def parse_actor_chain(token: str) -> List[str]:
        """Decode a delegated JWT and return the list of actors in the chain.

        The chain is returned **outermost-first**: the first element is the
        direct actor, subsequent elements are progressively deeper
        sub-agents.

        Args:
            token: A delegated JWT (decoded without signature verification
                — use only for display / debugging).

        Returns:
            List of ``sub`` values from the nested ``act`` claims,
            e.g. ``["agent:orchestrator", "agent:search-tool"]``.

        Example::

            chain = DelegationChain.parse_actor_chain(delegated_token)
            # ["agent:orchestrator", "agent:search-tool", "agent:web-scraper"]
        """
        return DelegationResource.parse_actor_chain(token)

    @staticmethod
    def get_subject(token: str) -> str | None:
        """Extract the ``sub`` (subject / principal) from a delegated JWT.

        Args:
            token: A JWT string.

        Returns:
            The ``sub`` claim value, or ``None`` if decoding fails.
        """
        return DelegationResource.get_subject(token)

    # =========================================================================
    # Revocation
    # =========================================================================

    def revoke(self, session_id: str) -> bool:
        """Revoke the delegation for a session.

        Invalidates the refresh token at the LumoAuth server (which also
        invalidates all derived tokens) and clears local state.

        Args:
            session_id: The session to revoke.

        Returns:
            ``True`` on success or if nothing to revoke.
        """
        user = self._user_tokens.get(session_id)
        if not user:
            self._delegated_tokens.pop(session_id, None)
            return True

        logger.info("Revoking delegation (session=%s)", session_id)

        if user.refresh_token:
            try:
                self._resource.revoke(
                    user.refresh_token,
                    token_type_hint="refresh_token",
                    client_id=self._agent.client_id,
                    client_secret=self._agent.client_secret,
                )
            except LumoAuthApiError as exc:
                logger.warning(
                    "Revocation request returned HTTP %s (session=%s)",
                    exc.status_code,
                    session_id,
                )
            else:
                logger.info("Delegation revoked at server (session=%s)", session_id)

        self._user_tokens.pop(session_id, None)
        self._delegated_tokens.pop(session_id, None)
        return True

    def revoke_all(self) -> None:
        """Revoke all active delegation sessions."""
        for session_id in list(self._user_tokens):
            self.revoke(session_id)

    # =========================================================================
    # Active session info
    # =========================================================================

    @property
    def active_sessions(self) -> List[str]:
        """Return the list of session IDs with active delegations."""
        return list(self._user_tokens)

    def has_delegation(self, session_id: str) -> bool:
        """Return ``True`` if a delegation token exists for *session_id*."""
        return session_id in self._delegated_tokens

    # -- private helpers ------------------------------------------------------

    def _exchange_tokens(
        self,
        *,
        subject_token: str,
        actor_token: str,
        scopes: List[str] | None,
        forbidden_message: str,
        failed_prefix: str,
    ) -> Dict[str, Any]:
        """Run a token exchange, translating errors to the legacy messages."""
        try:
            return self._resource.exchange(subject_token, actor_token, scopes=scopes)
        except LumoAuthPermissionDeniedError as exc:
            error = exc.body if isinstance(exc.body, dict) else {}
            if error.get("error") == "delegation_depth_exceeded":
                raise LumoAuthPermissionDeniedError(
                    f"Delegation chain too deep (max depth: "
                    f"{error.get('max_depth', MAX_DELEGATION_DEPTH)})",
                    body=exc.body,
                ) from exc
            raise LumoAuthPermissionDeniedError(
                f"{forbidden_message}: {error.get('error_description', exc.message)}",
                body=exc.body,
            ) from exc
        except LumoAuthApiError as exc:
            raise LumoAuthApiError(
                f"{failed_prefix} (HTTP {exc.status_code}): {exc.message}",
                code=exc.code,
                status_code=exc.status_code,
                body=exc.body,
            ) from exc

    def _ensure_user_token(self, session_id: str) -> _UserTokens:
        """Return the user tokens for *session_id*, refreshing if needed."""
        user = self._user_tokens.get(session_id)
        if not user:
            raise LookupError(
                f"No user token for session '{session_id}'. "
                "Complete the consent flow first (get_consent_url → handle_consent_callback) "
                "or register a token with set_user_token()."
            )

        if user.expires_at and time.time() >= user.expires_at:
            if user.refresh_token:
                self._refresh_user_token(session_id, user)
                user = self._user_tokens[session_id]
            else:
                logger.warning(
                    "User token expired and no refresh token available (session=%s)",
                    session_id,
                )

        return user

    def _refresh_user_token(self, session_id: str, user: _UserTokens) -> None:
        """Refresh the user's access token."""
        logger.info("Refreshing user token (session=%s)", session_id)

        try:
            body = self._resource.refresh_user_token(
                user.refresh_token or "",
                client_id=self._agent.client_id,
                client_secret=self._agent.client_secret,
            )
        except LumoAuthApiError as exc:
            logger.error(
                "User token refresh failed: HTTP %s — %s (session=%s)",
                exc.status_code,
                exc,
                session_id,
            )
            return

        self._user_tokens[session_id] = _UserTokens(
            access_token=body["access_token"],
            refresh_token=body.get("refresh_token", user.refresh_token),
            expires_at=time.time() + body.get("expires_in", 3600),
            scopes=body.get("scope", "").split(),
        )
        # Invalidate cached delegated token since the underlying user token changed
        self._delegated_tokens.pop(session_id, None)
        logger.info("User token refreshed (session=%s)", session_id)


class _UserTokens:
    """Internal holder for a user's consent tokens."""

    __slots__ = ("access_token", "refresh_token", "expires_at", "scopes")

    def __init__(
        self,
        access_token: str,
        refresh_token: str | None,
        expires_at: float,
        scopes: List[str],
    ) -> None:
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.expires_at = expires_at
        self.scopes = scopes

"""Chain of Agency — RFC 8693 token exchange for delegated actions and nested agent chains."""

from __future__ import annotations

import base64
import hashlib
import logging
import secrets
import time
import warnings
from typing import Any, Dict, List, Optional, Protocol, Tuple, runtime_checkable

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

    1. **User consent** — the person consents to an *application* of the
       organization (never to the agent): :meth:`get_consent_url` builds the
       authorization URL with the application's client ID and PKCE, and
       :meth:`handle_consent_callback` redeems the code as the application.
       Or register a token that your application already holds with
       :meth:`set_user_token`.
    2. **Token exchange** — combine the agent's token (actor) with the
       user's token (subject) to produce a delegated token carrying an
       ``act`` claim.
    3. **Delegated requests** — make API calls using the delegated token
       so every action is attributed to both agent and user.
    4. **Nested delegation** — pass authority down to sub-agents, each
       level adding to the ``act`` chain.
    5. **Revocation** — revoke the person's refresh token as the
       application, which ends every delegated token of that grant.

    Example::

        from lumoauth import LumoAuthAgent
        from lumoauth.delegation import DelegationChain

        agent = LumoAuthAgent()
        agent.authenticate()

        chain = DelegationChain(
            agent,
            redirect_uri="https://app.example.com/callback",   # registered on the application
            app_client_id="client_…",                          # the application, not the agent
            app_client_secret="…",                             # for a confidential application
        )
        url = chain.get_consent_url("session_1", scopes=["documents:read"], offline_access=True)

        # After the person consented and came back to redirect_uri:
        chain.handle_consent_callback("session_1", authorization_code, state=returned_state)
        token = chain.exchange("session_1", scopes=["documents:read"])

        # Make delegated API calls
        resp = chain.request("session_1", "GET", "/orgs/acme/api/v1/documents")
    """

    def __init__(
        self,
        agent: _AgentLike,
        *,
        redirect_uri: str | None = None,
        app_client_id: str | None = None,
        app_client_secret: str | None = None,
    ) -> None:
        """Initialise from an authenticated agent.

        Args:
            agent: An authenticated :class:`~lumoauth.LumoAuthAgent` instance.
            redirect_uri: A redirect URI registered on the application, for
                the consent flow.
            app_client_id: The client ID of the APPLICATION that the person
                consents to (``client_…``), never the agent's ID. The consent
                flow, the refresh of the person's token and :meth:`revoke`
                use it.
            app_client_secret: The application's secret, for a confidential
                application. A public application has none (PKCE only).
        """
        self._agent = agent
        self._redirect_uri = redirect_uri or ""
        self._app_client_id = app_client_id or None
        self._app_client_secret = app_client_secret or None
        # PKCE verifier and state of each consent in progress, by session id.
        self._pending_consents: Dict[str, Tuple[str, str]] = {}
        self._verify_tls: bool = getattr(agent, "_verify_tls", True)

        self._http = HttpClient(
            agent.base_url,
            org_id=agent.org_id,
            verify_tls=self._verify_tls,
            # The agent's custom domain, when it has one: same host, same paths.
            custom_domain=getattr(agent, "custom_domain", None),
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
        *,
        offline_access: bool = False,
    ) -> str:
        """Build the URL where the person consents, for the agent to act for them.

        The person consents to the application (``app_client_id``): an
        agent never starts a sign-in. The URL asks for ``openid`` plus
        *scopes* (and ``offline_access`` when asked), with a PKCE challenge
        (S256) and a random ``state``. Redirect the person there; LumoAuth
        sends them back to ``redirect_uri`` with a code for
        :meth:`handle_consent_callback`.

        Args:
            session_id: Caller-defined identifier to correlate the consent
                with later token-exchange calls.
            scopes: Scopes for the agent (``<resource>:<action>``, such as
                ``["documents:read"]``; the default). The application must be
                allowed them, and the agent must hold them as capabilities,
                or the exchange later issues no scope.
            state: CSRF-protection value. Defaults to a random value.
            offline_access: Ask for a refresh token as well. It renews the
                person's token, and :meth:`revoke` needs it.

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

        scopes = scopes or ["documents:read"]
        if not self._app_client_id:
            warnings.warn(
                "DelegationChain.get_consent_url() without app_client_id builds the URL with "
                "the agent's ID, which LumoAuth refuses (an agent never starts a sign-in). "
                "Pass app_client_id (and app_client_secret for a confidential application) "
                "of the application that the person consents to.",
                FutureWarning,
                stacklevel=2,
            )
            url = self._resource.consent_url(
                client_id=self._agent.client_id,
                redirect_uri=self._redirect_uri,
                scopes=scopes,
                state=state or f"session:{session_id}",
            )
            logger.info("Consent URL generated (session=%s, scopes=%s)", session_id, scopes)
            return url

        state = state or secrets.token_urlsafe(24)
        verifier = secrets.token_urlsafe(48)
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        )
        self._pending_consents[session_id] = (verifier, state)
        requested = ["openid", *[s for s in scopes if s != "openid"]]
        if offline_access and "offline_access" not in requested:
            requested.append("offline_access")
        url = self._resource.consent_url(
            client_id=self._app_client_id,
            redirect_uri=self._redirect_uri,
            scopes=requested,
            state=state,
            code_challenge=challenge,
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
        *,
        state: str | None = None,
    ) -> bool:
        """Redeem the code of the consent callback as the application.

        Call this when the person comes back to your ``redirect_uri`` with a
        code. The application redeems it (its client ID, its secret when it
        is confidential, and the PKCE verifier of :meth:`get_consent_url`);
        the agent's credentials play no part. The person's tokens are the
        application's tokens.

        Args:
            session_id: The same identifier used in :meth:`get_consent_url`.
            authorization_code: The ``code`` query-string parameter from the
                callback URL.
            state: The ``state`` query-string parameter. When given, it must
                be the value of :meth:`get_consent_url`.

        Returns:
            ``True`` on success, ``False`` on failure (details logged).
        """
        logger.info("Exchanging authorization code for user tokens (session=%s)", session_id)

        if self._app_client_id:
            pending = self._pending_consents.pop(session_id, None)
            if pending is None:
                logger.error("No consent in progress for session %s", session_id)
                return False
            verifier, expected_state = pending
            if state is not None and not secrets.compare_digest(state, expected_state):
                logger.error("Consent callback state does not match (session=%s)", session_id)
                return False
            redeem = dict(
                client_id=self._app_client_id,
                client_secret=self._app_client_secret,
                code_verifier=verifier,
            )
        else:
            warnings.warn(
                "DelegationChain.handle_consent_callback() without app_client_id redeems the "
                "code with the agent's credentials, which LumoAuth refuses. Pass app_client_id.",
                FutureWarning,
                stacklevel=2,
            )
            redeem = dict(client_id=self._agent.client_id, client_secret=self._agent.client_secret)

        try:
            body = self._resource.exchange_code(authorization_code, self._redirect_uri, **redeem)
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
        *,
        resource: Optional[str] = None,
    ) -> str:
        """Perform an RFC 8693 token exchange to get a delegated token.

        Combines the user's token (subject) with the agent's token (actor)
        to produce a delegated access token.  The resulting JWT carries an
        ``act`` (actor) claim that records the delegation chain for audit.

        Args:
            session_id: Session whose user token to use as the subject.
            scopes: Optional scope reduction — must be a subset of the
                scopes the user consented to.
            resource: RFC 8707 resource indicator — the https URL of the
                API the delegated token is for. It becomes its ``aud``;
                without it the token is bound to this agent's id.

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
            resource=resource,
            forbidden_message=(
                "Token exchange forbidden — the agent may not be allowed to act on "
                "behalf of users"
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
                On a custom domain give the path without the
                ``/orgs/{org_id}`` segment.
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
        *,
        resource: Optional[str] = None,
    ) -> str:
        """Create a nested delegation token for a sub-agent.

        The resulting token represents the chain:
        **user → this agent → sub-agent**.

        Each level of delegation reduces available scopes. A chain holds at
        most ``MAX_DELEGATION_DEPTH`` (5) actors; LumoAuth refuses a deeper
        one with 400 ``invalid_request``.

        Args:
            session_id: Session with the original user delegation.
            sub_agent_token: The sub-agent's own access token (obtained
                via its client-credentials flow).
            scopes: Optional scope reduction for the sub-agent (must be
                a subset of the current delegation's scopes).
            resource: RFC 8707 resource indicator for the sub-agent's
                token (its ``aud``), as for :meth:`exchange`.

        Returns:
            A delegated access token for the sub-agent.

        Raises:
            LumoAuthApiError: If the nested exchange fails, or the delegation
                chain would hold more than ``MAX_DELEGATION_DEPTH`` actors
                (status 400, code ``invalid_request``, message starting with
                "Delegation chain too deep"). Subclasses ``RuntimeError``.
        """
        our_token = self._delegated_tokens.get(session_id)
        if not our_token:
            our_token = self.exchange(session_id)

        logger.info("Creating nested delegation to sub-agent (session=%s)", session_id)

        body = self._exchange_tokens(
            subject_token=our_token,
            actor_token=sub_agent_token,
            scopes=scopes,
            resource=resource,
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
        """End the delegation of a session.

        With ``app_client_id`` and a refresh token of the person (from a
        consent with ``offline_access``), the application revokes that
        refresh token at LumoAuth (``/oauth/revoke``). That ends the whole
        grant, including every delegated token that the agent got from it.

        Otherwise nothing can be revoked at LumoAuth by this SDK: the agent's
        own credentials cannot revoke the application's token. The method
        then only forgets the session's tokens here, logs a warning and
        returns ``False``. The delegated token stays valid until it expires
        (at most the lifetime of the person's token). The person can end it
        on their account page ("AI agents acting for you"), or your
        application can revoke the person's refresh token.

        Args:
            session_id: The session to revoke.

        Returns:
            ``True`` when LumoAuth revoked the grant, or when the session is
            unknown; ``False`` when only local state was forgotten, or the
            revocation request failed.
        """
        user = self._user_tokens.get(session_id)
        if not user:
            self._delegated_tokens.pop(session_id, None)
            self._pending_consents.pop(session_id, None)
            return True

        logger.info("Revoking delegation (session=%s)", session_id)
        self._user_tokens.pop(session_id, None)
        self._delegated_tokens.pop(session_id, None)

        if not user.refresh_token or not self._app_client_id:
            logger.warning(
                "Delegation of session %s was only forgotten locally: %s. Delegated tokens "
                "stay valid until they expire.",
                session_id,
                "no refresh token of the person is held (consent without offline_access, "
                "or set_user_token())" if not user.refresh_token
                else "app_client_id is not set, and the agent cannot revoke the application's token",
            )
            return False

        try:
            self._resource.revoke(
                user.refresh_token,
                token_type_hint="refresh_token",
                client_id=self._app_client_id,
                client_secret=self._app_client_secret,
            )
        except LumoAuthApiError as exc:
            logger.warning(
                "Revocation request returned HTTP %s (session=%s)",
                exc.status_code,
                session_id,
            )
            return False
        logger.info("Delegation revoked at server (session=%s)", session_id)
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
        resource: Optional[str],
        forbidden_message: str,
        failed_prefix: str,
    ) -> Dict[str, Any]:
        """Run a token exchange, translating errors to the legacy messages."""
        try:
            return self._resource.exchange(
                subject_token, actor_token, scopes=scopes, resource=resource
            )
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
            if exc.status_code == 400 and exc.message.startswith("Delegation chain too deep"):
                # LumoAuth: 400 invalid_request "Delegation chain too deep: act
                # nesting depth 6 exceeds the maximum of 5".
                raise LumoAuthApiError(
                    f"Delegation chain too deep (max depth: {MAX_DELEGATION_DEPTH}): {exc.message}",
                    code=exc.code,
                    status_code=exc.status_code,
                    body=exc.body,
                ) from exc
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

        # The person's tokens belong to the application: it refreshes them.
        try:
            body = self._resource.refresh_user_token(
                user.refresh_token or "",
                client_id=self._app_client_id or self._agent.client_id,
                client_secret=self._app_client_secret if self._app_client_id else self._agent.client_secret,
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

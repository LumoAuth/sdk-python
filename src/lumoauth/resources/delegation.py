"""Delegation primitives — RFC 8693 token exchange building blocks.

The ergonomic session-tracking wrapper lives in
:class:`lumoauth.delegation.DelegationChain`; this resource exposes the raw
operations it delegates to.
"""

from __future__ import annotations

import base64
import json
import logging
from typing import Any, Dict, List, Optional

from lumoauth._http import HttpClient
from lumoauth.resources.auth import AuthResource

logger = logging.getLogger("lumoauth.delegation")

__all__ = ["DelegationResource", "MAX_DELEGATION_DEPTH"]

# The most actors that a delegation chain can hold: LumoAuth refuses a token
# exchange whose `act` chain would be deeper (400 invalid_request,
# "Delegation chain too deep: ...").
MAX_DELEGATION_DEPTH = 5


class DelegationResource:
    """RFC 8693 delegation operations (user → agent → sub-agent chains)."""

    def __init__(self, http: HttpClient) -> None:
        self._http = http
        self._auth = AuthResource(http)

    # ── Consent flow helpers ──────────────────────────────────────────

    def consent_url(
        self,
        *,
        client_id: str,
        redirect_uri: str,
        scopes: Optional[List[str]] = None,
        state: Optional[str] = None,
        code_challenge: Optional[str] = None,
    ) -> str:
        """Authorization URL where a person consents to delegated access.

        *client_id* is the client ID of an APPLICATION of the organization
        and *redirect_uri* one of its registered redirect URIs: an agent's ID
        is refused. Pass a PKCE ``code_challenge`` (S256); a public
        application needs one. Without *scopes* it asks for
        ``documents:read``; add ``offline_access`` to *scopes* for a refresh
        token.
        """
        return self._auth.authorization_url(
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=" ".join(scopes or ["documents:read"]),
            state=state,
            code_challenge=code_challenge,
            prompt=None if code_challenge else "consent",
            access_type=None if code_challenge else "offline",
        )

    def exchange_code(
        self,
        code: str,
        redirect_uri: str,
        *,
        client_id: str,
        client_secret: Optional[str] = None,
        code_verifier: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Redeem a consent callback code as the application (its client ID and secret)."""
        return self._auth.exchange_code(
            code, redirect_uri, client_id=client_id, client_secret=client_secret,
            code_verifier=code_verifier,
        )

    def refresh_user_token(
        self,
        refresh_token: str,
        *,
        client_id: str,
        client_secret: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Refresh a user's delegated access token."""
        return self._auth.refresh_token(
            refresh_token, client_id=client_id, client_secret=client_secret
        )

    # ── Token exchange ────────────────────────────────────────────────

    def exchange(
        self,
        subject_token: str,
        actor_token: str,
        scopes: Optional[List[str]] = None,
        *,
        resource: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Combine subject (user) + actor (agent) tokens into a delegated token.

        Returns the full token response; the delegated JWT carries an ``act``
        claim recording the chain. ``resource`` (RFC 8707 https URL) becomes
        its ``aud``; without it the token is bound to the acting agent.
        """
        return self._auth.token_exchange(
            subject_token, actor_token=actor_token, scopes=scopes, resource=resource
        )

    def revoke(
        self,
        token: str,
        *,
        token_type_hint: str = "refresh_token",
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
    ) -> Any:
        """Revoke a delegation's refresh token (invalidates derived tokens)."""
        return self._auth.revoke(
            token,
            token_type_hint=token_type_hint,
            client_id=client_id,
            client_secret=client_secret,
        )

    # ── JWT introspection (no signature verification) ─────────────────

    @staticmethod
    def parse_actor_chain(token: str) -> List[str]:
        """Return the ``sub`` values of the nested ``act`` claims, outermost first."""
        payload = _decode_jwt_payload(token)
        actors: List[str] = []
        act = payload.get("act") if payload else None
        while isinstance(act, dict):
            sub = act.get("sub")
            if sub:
                actors.append(sub)
            act = act.get("act")
        return actors

    @staticmethod
    def get_subject(token: str) -> Optional[str]:
        """Extract the ``sub`` (principal) claim from a JWT, or ``None``."""
        payload = _decode_jwt_payload(token)
        return payload.get("sub") if payload else None


def _decode_jwt_payload(token: str) -> Optional[Dict[str, Any]]:
    parts = token.split(".")
    if len(parts) < 2:
        return None
    payload_b64 = parts[1]
    payload_b64 += "=" * (-len(payload_b64) % 4)
    try:
        decoded = json.loads(base64.urlsafe_b64decode(payload_b64))
    except Exception:
        return None
    return decoded if isinstance(decoded, dict) else None

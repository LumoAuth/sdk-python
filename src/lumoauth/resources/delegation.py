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

# Maximum delegation depth enforced by LumoAuth.
MAX_DELEGATION_DEPTH = 3


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
    ) -> str:
        """Authorization URL where a user grants the agent delegated access."""
        return self._auth.authorization_url(
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=" ".join(scopes or ["read:documents"]),
            state=state,
            prompt="consent",
            access_type="offline",
        )

    def exchange_code(
        self,
        code: str,
        redirect_uri: str,
        *,
        client_id: str,
        client_secret: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Exchange a consent callback code for user tokens."""
        return self._auth.exchange_code(
            code, redirect_uri, client_id=client_id, client_secret=client_secret
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
    ) -> Dict[str, Any]:
        """Combine subject (user) + actor (agent) tokens into a delegated token.

        Returns the full token response; the delegated JWT carries an ``act``
        claim recording the chain.
        """
        return self._auth.token_exchange(
            subject_token, actor_token=actor_token, scopes=scopes
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

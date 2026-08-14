"""OAuth 2.1 flows — authorization URL, code exchange, refresh, revoke, userinfo."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Mapping, Optional
from urllib.parse import urlencode

from lumoauth._http import HttpClient

logger = logging.getLogger("lumoauth.auth")

__all__ = ["AuthResource"]

# RFC 8693 constants
TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"


class AuthResource:
    """OAuth 2.1 endpoints (org-scoped): authorize, token, userinfo, revoke."""

    def __init__(self, http: HttpClient) -> None:
        self._http = http

    # ── Authorization URL ─────────────────────────────────────────────

    def authorization_url(
        self,
        *,
        client_id: str,
        redirect_uri: str,
        scope: str = "openid profile email",
        state: Optional[str] = None,
        response_type: str = "code",
        code_challenge: Optional[str] = None,
        code_challenge_method: Optional[str] = None,
        prompt: Optional[str] = None,
        access_type: Optional[str] = None,
        extra: Optional[Mapping[str, str]] = None,
    ) -> str:
        """Build the URL to redirect a user to for the authorization-code flow."""
        _, path = self._http._fill_route("oauth.authorize", None)
        params: Dict[str, str] = {
            "response_type": response_type,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
        }
        if state is not None:
            params["state"] = state
        if code_challenge:
            params["code_challenge"] = code_challenge
            params["code_challenge_method"] = code_challenge_method or "S256"
        if prompt:
            params["prompt"] = prompt
        if access_type:
            params["access_type"] = access_type
        if extra:
            params.update(extra)
        return f"{self._http.base_url}{path}?{urlencode(params)}"

    # ── Token endpoint flows (form-encoded) ───────────────────────────

    def exchange_code(
        self,
        code: str,
        redirect_uri: str,
        *,
        client_id: str,
        client_secret: Optional[str] = None,
        code_verifier: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Exchange an authorization code for tokens."""
        data: Dict[str, str] = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": client_id,
        }
        if client_secret:
            data["client_secret"] = client_secret
        if code_verifier:
            data["code_verifier"] = code_verifier
        return self._token_request(data)

    def refresh_token(
        self,
        refresh_token: str,
        *,
        client_id: str,
        client_secret: Optional[str] = None,
        scopes: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Refresh an access token."""
        data: Dict[str, str] = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": client_id,
        }
        if client_secret:
            data["client_secret"] = client_secret
        if scopes:
            data["scope"] = " ".join(scopes)
        return self._token_request(data)

    def client_credentials(
        self,
        client_id: str,
        client_secret: str,
        scopes: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """OAuth 2.0 client-credentials grant (machine-to-machine)."""
        data: Dict[str, str] = {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
        }
        if scopes:
            data["scope"] = " ".join(scopes)
        return self._token_request(data)

    def token_exchange(
        self,
        subject_token: str,
        *,
        actor_token: Optional[str] = None,
        audience: Optional[str] = None,
        scopes: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """RFC 8693 token exchange (delegation, MCP audience scoping)."""
        data: Dict[str, str] = {
            "grant_type": TOKEN_EXCHANGE_GRANT,
            "subject_token": subject_token,
            "subject_token_type": ACCESS_TOKEN_TYPE,
        }
        if actor_token:
            data["actor_token"] = actor_token
            data["actor_token_type"] = ACCESS_TOKEN_TYPE
        if audience:
            data["audience"] = audience
        if scopes:
            data["scope"] = " ".join(scopes)
        return self._token_request(data)

    def revoke(
        self,
        token: str,
        *,
        token_type_hint: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
    ) -> Any:
        """Revoke an access or refresh token."""
        data: Dict[str, str] = {"token": token}
        if token_type_hint:
            data["token_type_hint"] = token_type_hint
        if client_id:
            data["client_id"] = client_id
        if client_secret:
            data["client_secret"] = client_secret
        return self._http.call("oauth.revoke", data=data, auth=False)

    # ── UserInfo ──────────────────────────────────────────────────────

    def userinfo(self, access_token: Optional[str] = None) -> Dict[str, Any]:
        """Fetch OIDC UserInfo.

        Uses the client's default credentials unless *access_token* is given.
        """
        headers = (
            {"Authorization": f"Bearer {access_token}"} if access_token else None
        )
        return self._http.call("oauth.userinfo", headers=headers)

    # ── Internal ──────────────────────────────────────────────────────

    def _token_request(self, data: Dict[str, str]) -> Dict[str, Any]:
        # Token endpoints authenticate via the form body — never inject the
        # client's default credentials.
        return self._http.call("oauth.token", data=data, auth=False)

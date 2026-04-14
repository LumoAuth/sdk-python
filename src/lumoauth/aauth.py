"""AAuth (Agent Auth) protocol client — cryptographic identity, HTTP signing, and token flows."""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import math
import time
from typing import Any
from urllib.parse import urlencode

import requests

logger = logging.getLogger("lumoauth.aauth")

__all__ = ["AAuthClient"]


def _b64url(data: bytes) -> str:
    """Base64url-encode *data* without padding (RFC 7515 §2)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class AAuthClient:
    """Client for the AAuth (Agent Auth) protocol.

    AAuth extends OAuth 2.1 with cryptographic agent identity,
    proof-of-possession tokens and HTTP message signing (RFC 9421).

    Example::

        from lumoauth.aauth import AAuthClient

        client = AAuthClient(
            agent_identifier="https://my-agent.example.com",
            private_key_pem=open("agent-key.pem").read(),
            org_id="acme-corp",
        )

        # Direct authorisation (no user interaction)
        tokens = client.request_authorization(
            resource_token=resource_tok,
            scope="read write",
        )
        resp = client.signed_request("GET", "https://api.example.com/v1/data",
                                     auth_token=tokens["access_token"])
    """

    def __init__(
        self,
        agent_identifier: str,
        private_key_pem: str,
        *,
        base_url: str | None = None,
        org_id: str | None = None,
        kid: str = "key-1",
        skip_cert_validation: bool = False,
    ) -> None:
        """Create an AAuth client.

        Args:
            agent_identifier: HTTPS URL uniquely identifying the agent
                (e.g. ``"https://my-agent.example.com"``).
            private_key_pem: PEM-encoded Ed25519 **private** key.
            base_url: LumoAuth instance URL.
            org_id: Organization ID.
            kid: Key ID matching the JWKS entry registered with LumoAuth.
        """
        import os

        self.agent_identifier = agent_identifier
        self.kid = kid
        self.base_url: str = base_url or os.environ.get(
            "LUMOAUTH_URL", "https://app.lumoauth.dev"
        )
        self.tenant: str = org_id or os.environ.get("LUMOAUTH_ORG_ID", "")
        self._verify_tls: bool = not skip_cert_validation

        # Import cryptography lazily so the rest of the SDK works without it.
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import load_pem_private_key

        key = load_pem_private_key(private_key_pem.encode(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise TypeError("AAuth requires an Ed25519 private key.")
        self._private_key: Ed25519PrivateKey = key

    # =========================================================================
    # Key helpers
    # =========================================================================

    @staticmethod
    def generate_keypair() -> tuple[str, dict[str, Any]]:
        """Generate an Ed25519 key pair suitable for AAuth.

        Returns:
            ``(private_key_pem, jwks)`` where *jwks* is a dict ready to
            be published at ``/.well-known/jwks.json``.

        Example::

            private_pem, jwks = AAuthClient.generate_keypair()
            print(json.dumps(jwks, indent=2))
        """
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
            PublicFormat,
        )

        private_key = Ed25519PrivateKey.generate()
        public_bytes = private_key.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
        private_pem = private_key.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        ).decode()

        jwks = {
            "keys": [
                {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": _b64url(public_bytes),
                    "use": "sig",
                    "kid": "key-1",
                }
            ]
        }
        return private_pem, jwks

    # =========================================================================
    # HTTP Message Signing (RFC 9421)
    # =========================================================================

    def sign_request(
        self,
        method: str,
        url: str,
        *,
        body: bytes | None = None,
        content_type: str = "application/json",
    ) -> dict[str, str]:
        """Create RFC 9421 signature headers for an HTTP request.

        Returns a dict of headers to merge into the outgoing request
        (``Agent-Auth`` and optionally ``Content-Digest``).

        Args:
            method: HTTP verb (uppercased).
            url: Full target URI.
            body: Raw request body bytes (required for POST/PUT).
            content_type: Media type of the body.
        """
        components: list[str] = [
            f'"@method": {method.upper()}',
            f'"@target-uri": {url}',
        ]
        extra_headers: dict[str, str] = {}

        if body is not None:
            digest_b64 = base64.b64encode(hashlib.sha256(body).digest()).decode()
            content_digest = f"sha-256=:{digest_b64}:"
            components.append(f'"content-type": {content_type}')
            components.append(f'"content-digest": {content_digest}')
            extra_headers["Content-Digest"] = content_digest

        sig_base = "\n".join(components)
        signature = self._private_key.sign(sig_base.encode())
        sig_b64 = base64.b64encode(signature).decode()

        covered = " ".join(c.split('"')[1] for c in components)
        created = math.floor(time.time())

        agent_auth = (
            f'sig1=:{sig_b64}:; label="sig1"; alg="ed25519"; '
            f'keyid="{self.agent_identifier}#{self.kid}"; '
            f"created={created}; "
            f'covered="{covered}"'
        )
        extra_headers["Agent-Auth"] = agent_auth
        return extra_headers

    # =========================================================================
    # Token flows
    # =========================================================================

    def _token_url(self) -> str:
        return f"{self.base_url}/orgs/{self.tenant}/api/v1/aauth/agent/token"

    def request_authorization(
        self,
        resource_token: str,
        scope: str,
        *,
        agent_token: str | None = None,
        redirect_uri: str | None = None,
        timeout: int = 30,
    ) -> dict[str, Any]:
        """Request an auth token (AAuth Flow 2 — direct authorisation).

        If the server requires user consent it returns a ``401`` with an
        ``auth_url``.  In that case this method returns a dict with
        ``"authorization_required": True`` and the ``auth_url`` to redirect
        the user to.

        Args:
            resource_token: Resource token obtained from the target resource.
            scope: Space-separated scopes.
            agent_token: Agent JWT (e.g. from delegation).  When *None* the
                request is self-signed.
            redirect_uri: Redirect URI for user-consent flows.
            timeout: HTTP timeout.

        Returns:
            Token response dict **or** ``{"authorization_required": True,
            "auth_url": "…", "request_token": "…"}`` when user consent is
            needed.
        """
        body_dict: dict[str, Any] = {
            "request_type": "auth",
            "resource_token": resource_token,
            "scope": scope,
        }
        if agent_token:
            body_dict["agent_token"] = agent_token
        if redirect_uri:
            body_dict["redirect_uri"] = redirect_uri

        url = self._token_url()
        body_bytes = json.dumps(body_dict).encode()
        sig_headers = self.sign_request("POST", url, body=body_bytes)

        headers = {"Content-Type": "application/json", **sig_headers}
        resp = requests.post(url, headers=headers, data=body_bytes, timeout=timeout,
                             verify=self._verify_tls)

        if resp.status_code == 200:
            logger.info("AAuth authorization granted (scope=%s)", scope)
            return resp.json()

        if resp.status_code == 401:
            data = resp.json()
            logger.info("AAuth user consent required: %s", data.get("auth_url"))
            return {
                "authorization_required": True,
                "auth_url": data.get("auth_url", ""),
                "request_token": data.get("request_token", ""),
            }

        raise RuntimeError(
            f"AAuth authorization failed: HTTP {resp.status_code} — {resp.text}"
        )

    def exchange_code(
        self,
        code: str,
        request_token: str,
        *,
        timeout: int = 30,
    ) -> dict[str, Any]:
        """Exchange an authorisation code for tokens (AAuth Flow 3, step 6).

        Args:
            code: Authorisation code from the consent redirect.
            request_token: Request token returned in the original 401.
        """
        body_dict = {
            "request_type": "code",
            "code": code,
            "request_token": request_token,
        }
        url = self._token_url()
        body_bytes = json.dumps(body_dict).encode()
        sig_headers = self.sign_request("POST", url, body=body_bytes)

        headers = {"Content-Type": "application/json", **sig_headers}
        resp = requests.post(url, headers=headers, data=body_bytes, timeout=timeout,
                             verify=self._verify_tls)

        if resp.status_code != 200:
            raise RuntimeError(
                f"AAuth code exchange failed: HTTP {resp.status_code} — {resp.text}"
            )
        logger.info("AAuth code exchange successful")
        return resp.json()

    def refresh(
        self,
        refresh_token: str,
        scope: str | None = None,
        *,
        timeout: int = 30,
    ) -> dict[str, Any]:
        """Refresh an auth token.

        Args:
            refresh_token: The refresh token from a prior token response.
            scope: Optional scope to narrow the refreshed token.
        """
        body_dict: dict[str, Any] = {
            "request_type": "refresh",
            "refresh_token": refresh_token,
        }
        if scope:
            body_dict["scope"] = scope

        url = self._token_url()
        body_bytes = json.dumps(body_dict).encode()
        sig_headers = self.sign_request("POST", url, body=body_bytes)

        headers = {"Content-Type": "application/json", **sig_headers}
        resp = requests.post(url, headers=headers, data=body_bytes, timeout=timeout,
                             verify=self._verify_tls)

        if resp.status_code != 200:
            raise RuntimeError(
                f"AAuth refresh failed: HTTP {resp.status_code} — {resp.text}"
            )
        logger.info("AAuth token refreshed")
        return resp.json()

    # =========================================================================
    # Signed requests to protected resources
    # =========================================================================

    def signed_request(
        self,
        method: str,
        url: str,
        *,
        auth_token: str,
        data: dict[str, Any] | None = None,
        timeout: int = 30,
    ) -> requests.Response:
        """Make a signed, authenticated request to a protected resource.

        The request carries both a ``Bearer`` token **and** an
        ``Agent-Auth`` HTTP message signature.

        Args:
            method: HTTP verb.
            url: Full target URL.
            auth_token: AAuth access token.
            data: JSON body (for POST/PUT).
            timeout: HTTP timeout.
        """
        body_bytes = json.dumps(data).encode() if data else None
        sig_headers = self.sign_request(method, url, body=body_bytes)

        headers: dict[str, str] = {
            "Authorization": f"Bearer {auth_token}",
            **sig_headers,
        }
        if body_bytes is not None:
            headers["Content-Type"] = "application/json"

        return requests.request(
            method, url, headers=headers, data=body_bytes, timeout=timeout,
            verify=self._verify_tls,
        )

    # =========================================================================
    # Discovery
    # =========================================================================

    def discover_issuer(self, *, timeout: int = 10) -> dict[str, Any]:
        """Fetch ``/.well-known/aauth-issuer`` from the authorisation server."""
        resp = requests.get(
            f"{self.base_url}/.well-known/aauth-issuer", timeout=timeout,
            verify=self._verify_tls,
        )
        resp.raise_for_status()
        return resp.json()

    def discover_resource(self, resource_url: str, *, timeout: int = 10) -> dict[str, Any]:
        """Fetch ``/.well-known/aauth-resource`` from a resource server."""
        # Strip trailing slash so we don't double up
        base = resource_url.rstrip("/")
        resp = requests.get(f"{base}/.well-known/aauth-resource", timeout=timeout,
                            verify=self._verify_tls)
        resp.raise_for_status()
        return resp.json()

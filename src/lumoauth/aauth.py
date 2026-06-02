"""AAuth (Agent Auth) protocol client — cryptographic identity, HTTP signing, and token flows."""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import math
import os
import time
from typing import Any
from urllib.parse import urlencode, urlsplit

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
            agent_token=agent_tok,
        )
        resp = client.signed_request("GET", "https://api.example.com/v1/data",
                                     auth_token=tokens["auth_token"])
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
        self.org_id: str = org_id or os.environ.get("LUMOAUTH_ORG_ID", "")
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

    # Covered components the AAuth agent token endpoint requires, in order.
    _COVERED = (
        "@method", "@authority", "@path",
        "signature-key", "content-digest", "content-type", "authorization",
    )

    def sign_request(
        self,
        method: str,
        url: str,
        *,
        body: bytes | None = None,
        content_type: str = "application/json",
        agent_token: str | None = None,
        authorization: str = "",
        signature_key: str = "",
    ) -> dict[str, str]:
        """Create RFC 9421 signature headers for the AAuth agent token endpoint.

        Builds the standard ``Signature-Input`` / ``Signature`` headers per the
        AAuth profile the server enforces: the covered components are exactly
        ``@method @authority @path signature-key content-digest content-type
        authorization`` with both ``created`` (within ±60 s) and a fresh
        ``nonce`` (≥ 12 bytes of entropy). The Ed25519 signature is base64url
        encoded. The agent's credential travels in ``Agent-Auth`` as
        ``agent_token=<JWT>`` — not inside the signature.

        Args:
            method: HTTP verb.
            url: Full target URI.
            body: Raw request body bytes.
            content_type: Media type of the body.
            agent_token: The ``agent+jwt`` to present in ``Agent-Auth``.
            authorization: Value of a covered ``Authorization`` header, if any.
            signature_key: Value of a covered ``Signature-Key`` header, if any.
        """
        parsed = urlsplit(url)
        authority = parsed.netloc
        path = parsed.path or "/"

        body_bytes = body if body is not None else b""
        # Content-Digest uses STANDARD base64 (the server base64-decodes it).
        digest_b64 = base64.b64encode(hashlib.sha256(body_bytes).digest()).decode()
        content_digest = f"sha-256=:{digest_b64}:"

        created = math.floor(time.time())
        nonce = _b64url(os.urandom(16))  # >= 12 bytes of entropy

        values = {
            "@method": method.upper(),
            "@authority": authority,
            "@path": path,
            "signature-key": signature_key,
            "content-digest": content_digest,
            "content-type": content_type,
            "authorization": authorization,
        }
        lines = [f'"{c}": {values[c]}' for c in self._COVERED]
        covered_list = " ".join(f'"{c}"' for c in self._COVERED)
        # The @signature-params line carries ONLY created + nonce.
        params = f'({covered_list});created={created};nonce="{nonce}"'
        lines.append(f'"@signature-params": {params}')
        sig_base = "\n".join(lines)

        signature = self._private_key.sign(sig_base.encode())
        sig_b64url = _b64url(signature)  # base64url, per RFC 9421

        headers: dict[str, str] = {
            "Content-Digest": content_digest,
            "Content-Type": content_type,
            "Signature-Input": f"sig1=({covered_list});created={created};nonce=\"{nonce}\"",
            "Signature": f"sig1=:{sig_b64url}:",
        }
        if agent_token:
            headers["Agent-Auth"] = f"agent_token={agent_token}"
        return headers

    # =========================================================================
    # Token flows
    # =========================================================================

    def _token_url(self) -> str:
        return f"{self.base_url}/orgs/{self.org_id}/api/v1/aauth/agent/token"

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
        if not agent_token:
            raise ValueError(
                "agent_token is required — the /agent/token endpoint authenticates "
                "the agent via the Agent-Auth header, not the request body."
            )

        body_dict: dict[str, Any] = {
            "request_type": "auth",
            "resource_token": resource_token,
            "scope": scope,
        }
        if redirect_uri:
            body_dict["redirect_uri"] = redirect_uri

        url = self._token_url()
        body_bytes = json.dumps(body_dict).encode()
        # agent_token rides in Agent-Auth; sign_request also emits Content-Type.
        headers = self.sign_request("POST", url, body=body_bytes, agent_token=agent_token)
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
        agent_token: str,
        timeout: int = 30,
    ) -> dict[str, Any]:
        """Exchange an authorisation code for tokens (AAuth Flow 3, step 6).

        Args:
            code: Authorisation code from the consent redirect.
            request_token: Request token returned in the original 401.
            agent_token: The ``agent+jwt`` presented in ``Agent-Auth``.
        """
        body_dict = {
            "request_type": "code",
            "code": code,
            "request_token": request_token,
        }
        url = self._token_url()
        body_bytes = json.dumps(body_dict).encode()
        headers = self.sign_request("POST", url, body=body_bytes, agent_token=agent_token)
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
        agent_token: str,
        timeout: int = 30,
    ) -> dict[str, Any]:
        """Refresh an auth token.

        Args:
            refresh_token: The refresh token from a prior token response.
            scope: Optional scope to narrow the refreshed token.
            agent_token: The ``agent+jwt`` presented in ``Agent-Auth``.
        """
        body_dict: dict[str, Any] = {
            "request_type": "refresh",
            "refresh_token": refresh_token,
        }
        if scope:
            body_dict["scope"] = scope

        url = self._token_url()
        body_bytes = json.dumps(body_dict).encode()
        headers = self.sign_request("POST", url, body=body_bytes, agent_token=agent_token)
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

        The request carries the ``Bearer`` access token **and** an RFC 9421
        HTTP Message Signature that provides proof-of-possession of the key
        bound to the token's ``cnf.jwk``. Because the signature covers the
        ``authorization`` component, it is computed over the *actual* Bearer
        header so a resource server can verify it.

        Args:
            method: HTTP verb.
            url: Full target URL.
            auth_token: AAuth access token.
            data: JSON body (for POST/PUT).
            timeout: HTTP timeout.
        """
        body_bytes = json.dumps(data).encode() if data else b""
        authorization = f"Bearer {auth_token}"
        sig_headers = self.sign_request(method, url, body=body_bytes, authorization=authorization)

        headers: dict[str, str] = {"Authorization": authorization, **sig_headers}

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

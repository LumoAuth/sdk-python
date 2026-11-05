"""Client assertions for ``private_key_jwt`` (RFC 7523 §2.2, OpenID Connect Core §9).

A LumoAuth agent registered with the **Private key JWT** identity type has no
client secret. Whenever it needs a token, it signs a short-lived JWT with its
private key and sends that instead::

    from lumoauth import ClientAssertionSigner, LumoAuthAgent

    agent = LumoAuthAgent(
        client_id="agt_0123456789abcdef",
        private_key=open("agent-private-key.pem").read(),
        key_id="agent-2026-11",
    )
    agent.authenticate()

Register :meth:`ClientAssertionSigner.jwks` (the public key only) on the agent.

What the server checks, and what :meth:`ClientAssertionSigner.create` produces:

- header ``alg`` (ES256, ES384, ES512, EdDSA, RS256 to RS512 or PS256 to PS512),
  ``kid`` and ``typ: client-authentication+jwt``;
- ``iss`` = ``sub`` = the agent ID, ``aud`` = the organization's issuer
  identifier alone (not the token endpoint URL);
- ``iat`` now, ``exp`` at most 10 minutes later (60 seconds by default), and a
  random ``jti``: every assertion is single-use, so sign a new one per request.

Needs the ``cryptography`` package (``pip install "lumoauth[dpop]"``).
"""

from __future__ import annotations

import json
import secrets
import time
from typing import Any, Callable, Dict, Optional

from lumoauth._jose import (
    b64url_encode,
    load_private_key,
    private_key_alg,
    public_jwk,
    require_cryptography,
    sign,
)
from lumoauth.errors import LumoAuthValidationError

__all__ = ["CLIENT_ASSERTION_TYPE", "ClientAssertionSigner", "issuer_for"]

#: ``client_assertion_type`` for a JWT client assertion (RFC 7523 §2.2).
CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

#: The ``typ`` header that marks a client-authentication JWT.
CLIENT_ASSERTION_TYP = "client-authentication+jwt"

#: The longest validity that LumoAuth accepts for an assertion, in seconds.
MAX_LIFETIME_SECONDS = 600

_RSA_ALGS = ("RS256", "RS384", "RS512", "PS256", "PS384", "PS512")


def issuer_for(base_url: str, org_id: str) -> str:
    """The issuer identifier of an organization on ``base_url``.

    This is the ``issuer`` of ``/orgs/{org_id}/api/v1/.well-known/openid-configuration``
    and the ``aud`` that a client assertion must carry. On a custom domain the
    issuer is different; pass it explicitly there.
    """
    return f"{base_url.rstrip('/')}/orgs/{org_id}/api/v1"


class ClientAssertionSigner:
    """Signs ``private_key_jwt`` client assertions with one private key."""

    def __init__(
        self,
        private_key: Any,
        *,
        key_id: Optional[str] = None,
        alg: Optional[str] = None,
        lifetime: int = 60,
        clock: Optional[Callable[[], float]] = None,
    ) -> None:
        """
        Args:
            private_key: A ``cryptography`` private key (EC P-256/P-384/P-521,
                Ed25519 or RSA of at least 2048 bits).
            key_id: The ``kid`` of the registered public key. Required by the
                server when the agent has more than one key.
            alg: The JWS algorithm. Defaults to the key's natural algorithm
                (ES256/ES384/ES512, EdDSA, RS256); for an RSA key, ``PS256``,
                ``PS384``, ``PS512``, ``RS384`` and ``RS512`` are also allowed.
            lifetime: Seconds until ``exp``, 1 to 600. Default 60.
        """
        require_cryptography("Client assertions")
        from cryptography.hazmat.primitives.asymmetric import rsa

        natural = private_key_alg(private_key)
        chosen = alg or natural
        if isinstance(private_key, rsa.RSAPrivateKey):
            if chosen not in _RSA_ALGS:
                raise LumoAuthValidationError(f"{chosen!r} does not fit an RSA key; use one of {', '.join(_RSA_ALGS)}")
            if private_key.key_size < 2048:
                raise LumoAuthValidationError("RSA keys must be at least 2048 bits")
        elif chosen != natural:
            raise LumoAuthValidationError(f"{chosen!r} does not fit this key; it signs with {natural}")
        if not 1 <= int(lifetime) <= MAX_LIFETIME_SECONDS:
            raise LumoAuthValidationError(f"lifetime must be 1 to {MAX_LIFETIME_SECONDS} seconds")

        self._private_key = private_key
        self.alg: str = chosen
        self.key_id: Optional[str] = key_id
        self.lifetime: int = int(lifetime)
        self._clock = clock or time.time

    @classmethod
    def from_pem(
        cls,
        pem: str | bytes,
        *,
        key_id: Optional[str] = None,
        password: str | bytes | None = None,
        alg: Optional[str] = None,
        lifetime: int = 60,
    ) -> "ClientAssertionSigner":
        """Load a PEM private key (PKCS#8, SEC 1 or PKCS#1)."""
        return cls(load_private_key(pem, password), key_id=key_id, alg=alg, lifetime=lifetime)

    @classmethod
    def generate(cls, alg: str = "ES256", *, key_id: Optional[str] = None) -> "ClientAssertionSigner":
        """Generate a new key: ``ES256`` (default), ``ES384``, ``ES512``, ``EdDSA``, ``RS256`` or ``PS256``."""
        require_cryptography("Client assertions")
        from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

        if alg in ("ES256", "ES384", "ES512"):
            curve = {"ES256": ec.SECP256R1, "ES384": ec.SECP384R1, "ES512": ec.SECP521R1}[alg]()
            key: Any = ec.generate_private_key(curve)
        elif alg == "EdDSA":
            key = ed25519.Ed25519PrivateKey.generate()
        elif alg in _RSA_ALGS:
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        else:
            raise LumoAuthValidationError(f"unsupported algorithm {alg!r}")
        return cls(key, key_id=key_id, alg=alg)

    def create(self, client_id: str, audience: str) -> str:
        """Sign one assertion for ``client_id`` (the agent ID) and ``audience`` (the issuer)."""
        if not client_id or not audience:
            raise LumoAuthValidationError("client_id and audience are required for a client assertion")
        now = int(self._clock())
        header: Dict[str, Any] = {"alg": self.alg, "typ": CLIENT_ASSERTION_TYP}
        if self.key_id:
            header["kid"] = self.key_id
        claims = {
            "iss": client_id,
            "sub": client_id,
            "aud": audience,
            "iat": now,
            "exp": now + self.lifetime,
            "jti": secrets.token_urlsafe(24),
        }
        signing_input = f"{_b64json(header)}.{_b64json(claims)}"
        signature = sign(self._private_key, self.alg, signing_input.encode("ascii"))
        return f"{signing_input}.{b64url_encode(signature)}"

    def public_jwk(self) -> Dict[str, Any]:
        """The public key as a JWK with ``kid`` (when set), ``alg`` and ``use: sig``."""
        jwk = public_jwk(self._private_key.public_key())
        if self.key_id:
            jwk["kid"] = self.key_id
        jwk["alg"] = self.alg
        jwk["use"] = "sig"
        return jwk

    def jwks(self) -> Dict[str, Any]:
        """``{"keys": [public_jwk]}``: what to register on the agent."""
        return {"keys": [self.public_jwk()]}

    def to_pem(self) -> str:
        """The private key as unencrypted PKCS#8 PEM, for your secret store."""
        from cryptography.hazmat.primitives import serialization

        return self._private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode("ascii")

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return f"ClientAssertionSigner(alg={self.alg!r}, key_id={self.key_id!r})"


def _b64json(value: Dict[str, Any]) -> str:
    return b64url_encode(json.dumps(value, separators=(",", ":")).encode("utf-8"))

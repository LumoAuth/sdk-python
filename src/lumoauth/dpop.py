"""RFC 9449 DPoP — proof signing for sender-constrained access tokens.

A :class:`DpopKey` is a private EC P-256 (``ES256``, the default) or Ed25519
(``EdDSA``) key. A :class:`DpopProofSigner` turns it into ``DPoP`` proof
JWTs for the token endpoint, the attestation endpoint and resource requests,
and remembers the latest ``DPoP-Nonce`` per origin.

Example::

    from lumoauth import LumoAuthAgent
    from lumoauth.dpop import DpopKey

    key = DpopKey.generate()                    # or DpopKey.from_pem(open("dpop.pem").read())
    agent = LumoAuthAgent(dpop=key)             # dpop=True generates a key for you
    agent.authenticate()                        # token_type is now "DPoP"
    mcp = agent.get_mcp_credential("https://mcp.example.com/mcp")
    requests.post("https://mcp.example.com/mcp", headers=mcp.headers("POST", "https://mcp.example.com/mcp"), ...)

The JWS is built here with ``cryptography`` only; no JWT library is needed.
Install the extra: ``pip install "lumoauth[dpop]"``.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import threading
import time
from typing import Any, Dict, Mapping, Optional
from urllib.parse import urlsplit

from lumoauth._jose import (
    b64url_encode,
    jwk_thumbprint,
    load_private_key,
    private_key_alg,
    public_jwk,
    require_cryptography,
    sign,
)
from lumoauth.errors import LumoAuthValidationError

__all__ = [
    "DPOP_SCHEME",
    "DpopKey",
    "DpopProofSigner",
    "access_token_hash",
    "canonical_htu",
    "nonce_origin",
    "wants_new_nonce",
]

DPOP_SCHEME = "DPoP"
# The server requires at least 16 characters; 24 random bytes give 32.
_JTI_BYTES = 24


def canonical_htu(url: str) -> str:
    """The ``htu`` value for *url*: ``scheme://host[:port]/path`` with no query or fragment."""
    parts = urlsplit(url)
    if parts.scheme.lower() not in ("http", "https") or not parts.netloc:
        raise LumoAuthValidationError(f"DPoP htu needs an absolute http(s) URL, got {url!r}")
    return f"{parts.scheme.lower()}://{parts.netloc.lower()}{parts.path or '/'}"


def nonce_origin(url: str) -> str:
    """The key under which a ``DPoP-Nonce`` is remembered: ``scheme://host[:port]``."""
    parts = urlsplit(url)
    return f"{parts.scheme.lower()}://{parts.netloc.lower()}"


def access_token_hash(access_token: str) -> str:
    """The ``ath`` claim: base64url(SHA-256(access_token))."""
    return b64url_encode(hashlib.sha256(access_token.encode("ascii")).digest())


def _header(headers: Mapping[str, str], name: str) -> Optional[str]:
    """Case-insensitive header lookup that also works on plain dicts."""
    getter = getattr(headers, "get", None)
    value = getter(name) if getter else None
    if value is not None:
        return value
    lowered = name.lower()
    for key, val in headers.items():
        if key.lower() == lowered:
            return val
    return None


def wants_new_nonce(status_code: int, headers: Mapping[str, str], body: Any) -> bool:
    """``True`` when a response asks for a fresh nonce (``use_dpop_nonce``).

    The token endpoint answers HTTP 400 with ``{"error": "use_dpop_nonce"}``;
    a resource server answers HTTP 401 with ``WWW-Authenticate: DPoP
    error="use_dpop_nonce"``. Both carry the nonce in ``DPoP-Nonce``.
    """
    if _header(headers, "DPoP-Nonce") is None:
        return False
    if status_code == 400 and isinstance(body, dict) and body.get("error") == "use_dpop_nonce":
        return True
    if status_code == 401:
        challenge = _header(headers, "WWW-Authenticate") or ""
        return "use_dpop_nonce" in challenge
    return False


class DpopKey:
    """A private key for DPoP proofs, with its public JWK and RFC 7638 thumbprint."""

    def __init__(self, private_key: Any, *, alg: Optional[str] = None) -> None:
        require_cryptography("DPoP")
        self._private_key = private_key
        self.alg: str = alg or private_key_alg(private_key)
        # Validate alg/key pairing eagerly: sign() raises on a mismatch.
        self.public_jwk: Dict[str, Any] = public_jwk(private_key.public_key())
        self.thumbprint: str = jwk_thumbprint(self.public_jwk)

    @classmethod
    def generate(cls, alg: str = "ES256") -> "DpopKey":
        """Generate a fresh key: ``ES256`` (P-256, default) or ``EdDSA`` (Ed25519)."""
        require_cryptography("DPoP")
        from cryptography.hazmat.primitives.asymmetric import ec, ed25519

        if alg == "ES256":
            return cls(ec.generate_private_key(ec.SECP256R1()), alg=alg)
        if alg == "ES384":
            return cls(ec.generate_private_key(ec.SECP384R1()), alg=alg)
        if alg == "ES512":
            return cls(ec.generate_private_key(ec.SECP521R1()), alg=alg)
        if alg == "EdDSA":
            return cls(ed25519.Ed25519PrivateKey.generate(), alg=alg)
        raise LumoAuthValidationError(
            f"unsupported DPoP algorithm {alg!r}: use ES256, ES384, ES512 or EdDSA"
        )

    @classmethod
    def from_pem(cls, pem: str | bytes, password: str | bytes | None = None) -> "DpopKey":
        """Load a PEM-encoded EC, Ed25519 or RSA private key."""
        return cls(load_private_key(pem, password))

    def to_pem(self) -> str:
        """The private key as unencrypted PKCS#8 PEM, for storing it between runs."""
        from cryptography.hazmat.primitives import serialization

        return self._private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode("ascii")

    def sign(self, data: bytes) -> bytes:
        """Raw JWS signature (``r || s`` for ES*)."""
        return sign(self._private_key, self.alg, data)

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return f"DpopKey(alg={self.alg!r}, thumbprint={self.thumbprint!r})"


class DpopProofSigner:
    """Creates DPoP proofs and remembers server nonces.

    Args:
        key: The :class:`DpopKey` to sign with. ``None`` generates an
            ephemeral ES256 key.
    """

    def __init__(self, key: Optional[DpopKey] = None) -> None:
        self.key: DpopKey = key if key is not None else DpopKey.generate()
        self._nonces: Dict[str, str] = {}
        self._lock = threading.Lock()

    # ── Nonce memory ───────────────────────────────────────────────────

    def remember_nonce(self, url: str, nonce: Optional[str]) -> None:
        """Store the latest ``DPoP-Nonce`` for the origin of *url*."""
        if not nonce:
            return
        with self._lock:
            self._nonces[nonce_origin(url)] = nonce

    def nonce_for(self, url: str) -> Optional[str]:
        """The remembered nonce for the origin of *url*, if any."""
        with self._lock:
            return self._nonces.get(nonce_origin(url))

    def observe_response(self, url: str, headers: Mapping[str, str]) -> None:
        """Remember the ``DPoP-Nonce`` header of a response to *url*."""
        self.remember_nonce(url, _header(headers, "DPoP-Nonce"))

    # ── Proofs ─────────────────────────────────────────────────────────

    @property
    def thumbprint(self) -> str:
        """RFC 7638 thumbprint of the public key (what ``cnf.jkt`` will hold)."""
        return self.key.thumbprint

    def create_proof(
        self,
        method: str,
        url: str,
        *,
        access_token: Optional[str] = None,
        nonce: Optional[str] = None,
        now: Optional[float] = None,
        extra_claims: Optional[Mapping[str, Any]] = None,
    ) -> str:
        """Build a ``dpop+jwt`` proof for one request.

        Args:
            method: HTTP method; sent upper-case as ``htm``.
            url: Request URL; query and fragment are dropped for ``htu``.
            access_token: When the proof accompanies an access token, its
                hash goes out as ``ath``.
            nonce: Explicit ``nonce`` claim. Defaults to the nonce last seen
                from this origin, if any.
            now: Override the clock (seconds since the epoch) for tests.
            extra_claims: Additional claims to merge in.
        """
        if not isinstance(method, str) or not method.strip():
            raise LumoAuthValidationError("DPoP proof needs an HTTP method")
        header = {"typ": "dpop+jwt", "alg": self.key.alg, "jwk": self.key.public_jwk}
        claims: Dict[str, Any] = {
            "jti": secrets.token_urlsafe(_JTI_BYTES),
            "htm": method.upper(),
            "htu": canonical_htu(url),
            "iat": int(now if now is not None else time.time()),
        }
        if access_token:
            claims["ath"] = access_token_hash(access_token)
        effective_nonce = nonce if nonce is not None else self.nonce_for(url)
        if effective_nonce:
            claims["nonce"] = effective_nonce
        if extra_claims:
            claims.update(extra_claims)
        signing_input = f"{_b64json(header)}.{_b64json(claims)}"
        return f"{signing_input}.{b64url_encode(self.key.sign(signing_input.encode('ascii')))}"

    def headers(
        self,
        method: str,
        url: str,
        access_token: Optional[str] = None,
        *,
        nonce: Optional[str] = None,
    ) -> Dict[str, str]:
        """Headers for a request: ``DPoP`` and, with a token, ``Authorization: DPoP …``."""
        headers = {"DPoP": self.create_proof(method, url, access_token=access_token, nonce=nonce)}
        if access_token:
            headers["Authorization"] = f"{DPOP_SCHEME} {access_token}"
        return headers


def _b64json(value: Mapping[str, Any]) -> str:
    return b64url_encode(json.dumps(value, separators=(",", ":"), sort_keys=False).encode("utf-8"))

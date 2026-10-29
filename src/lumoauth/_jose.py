"""Internal JOSE helpers shared by :mod:`lumoauth.dpop` and :mod:`lumoauth.verify`.

Compact JWS encoding and decoding, JWK conversion for EC / OKP / RSA keys,
RFC 7638 thumbprints and raw signatures. ``cryptography`` is imported
lazily so that ``import lumoauth`` keeps working without it.
"""

from __future__ import annotations

import base64
import hashlib
import importlib
import json
from typing import Any, Dict, Tuple

from lumoauth.errors import LumoAuthConfigError, LumoAuthValidationError

__all__ = [
    "ASYMMETRIC_ALGS",
    "b64url_decode",
    "b64url_encode",
    "jwk_thumbprint",
    "load_private_key",
    "private_key_alg",
    "public_jwk",
    "public_key_from_jwk",
    "require_cryptography",
    "sign",
    "split_jws",
    "verify",
]

# Algorithms the LumoAuth server accepts on DPoP proofs and uses on access tokens.
ASYMMETRIC_ALGS = frozenset(
    {
        "ES256",
        "ES384",
        "ES512",
        "RS256",
        "RS384",
        "RS512",
        "PS256",
        "PS384",
        "PS512",
        "EdDSA",
    }
)

_CURVES = {"P-256": "secp256r1", "P-384": "secp384r1", "P-521": "secp521r1"}
_CURVE_ALG = {"P-256": "ES256", "P-384": "ES384", "P-521": "ES512"}
_CURVE_NAMES = {v: k for k, v in _CURVES.items()}
_HASHES = {"256": "SHA256", "384": "SHA384", "512": "SHA512"}
# Members that must never appear in a public JWK (RFC 7518 §6).
_PRIVATE_MEMBERS = ("d", "p", "q", "dp", "dq", "qi", "oth", "k")


def require_cryptography(feature: str) -> None:
    """Raise a clear error when ``cryptography`` is not installed."""
    try:
        importlib.import_module("cryptography")
    except ImportError as exc:  # pragma: no cover - depends on the environment
        raise LumoAuthConfigError(
            f"{feature} needs the 'cryptography' package: "
            'pip install "lumoauth[dpop]"'
        ) from exc


def b64url_encode(data: bytes) -> str:
    """Base64url without padding (RFC 7515 §2)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    if not isinstance(text, str):
        raise LumoAuthValidationError("base64url value must be a string")
    padded = text + "=" * (-len(text) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise LumoAuthValidationError("invalid base64url value") from exc


def _json_part(raw: bytes, what: str) -> Dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise LumoAuthValidationError(f"JWS {what} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise LumoAuthValidationError(f"JWS {what} must be a JSON object")
    return value


def split_jws(token: str) -> Tuple[Dict[str, Any], Dict[str, Any], bytes, bytes]:
    """Return ``(header, payload, signing_input, signature)`` of a compact JWS.

    Nothing is verified here.
    """
    if not isinstance(token, str) or token.count(".") != 2:
        raise LumoAuthValidationError("not a compact JWS (expected three segments)")
    h, p, s = token.split(".")
    if not h or not p or not s:
        raise LumoAuthValidationError("not a compact JWS (empty segment)")
    header = _json_part(b64url_decode(h), "header")
    payload = _json_part(b64url_decode(p), "payload")
    return header, payload, f"{h}.{p}".encode("ascii"), b64url_decode(s)


# ── Keys ─────────────────────────────────────────────────────────────


def load_private_key(pem: str | bytes, password: str | bytes | None = None) -> Any:
    """Load a PEM private key (EC, Ed25519 or RSA)."""
    require_cryptography("DPoP")
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    data = pem.encode("utf-8") if isinstance(pem, str) else pem
    pw = password.encode("utf-8") if isinstance(password, str) else password
    try:
        return load_pem_private_key(data, password=pw)
    except (ValueError, TypeError) as exc:
        raise LumoAuthValidationError(f"cannot load private key: {exc}") from exc


def private_key_alg(key: Any) -> str:
    """The JWS ``alg`` that fits a private key (ES256 for P-256, EdDSA, RS256)."""
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

    if isinstance(key, ec.EllipticCurvePrivateKey):
        crv = _CURVE_NAMES.get(key.curve.name)
        if crv is None:
            raise LumoAuthValidationError(f"unsupported EC curve {key.curve.name}")
        return _CURVE_ALG[crv]
    if isinstance(key, ed25519.Ed25519PrivateKey):
        return "EdDSA"
    if isinstance(key, rsa.RSAPrivateKey):
        return "RS256"
    raise LumoAuthValidationError(
        "unsupported key type: use an EC P-256/P-384/P-521, Ed25519 or RSA key"
    )


def _int_bytes(value: int, length: int) -> bytes:
    return value.to_bytes(length, "big")


def public_jwk(public_key: Any) -> Dict[str, Any]:
    """Public JWK (members only, no ``kid``/``alg``) for an EC, Ed25519 or RSA key."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

    if isinstance(public_key, ec.EllipticCurvePublicKey):
        crv = _CURVE_NAMES.get(public_key.curve.name)
        if crv is None:
            raise LumoAuthValidationError(f"unsupported EC curve {public_key.curve.name}")
        size = (public_key.curve.key_size + 7) // 8
        nums = public_key.public_numbers()
        return {
            "kty": "EC",
            "crv": crv,
            "x": b64url_encode(_int_bytes(nums.x, size)),
            "y": b64url_encode(_int_bytes(nums.y, size)),
        }
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        raw = public_key.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return {"kty": "OKP", "crv": "Ed25519", "x": b64url_encode(raw)}
    if isinstance(public_key, rsa.RSAPublicKey):
        nums = public_key.public_numbers()
        n_len = (nums.n.bit_length() + 7) // 8
        e_len = (nums.e.bit_length() + 7) // 8
        return {
            "kty": "RSA",
            "n": b64url_encode(_int_bytes(nums.n, n_len)),
            "e": b64url_encode(_int_bytes(nums.e, e_len)),
        }
    raise LumoAuthValidationError("unsupported public key type")


def public_key_from_jwk(jwk: Dict[str, Any]) -> Any:
    """Build a ``cryptography`` public key from a public JWK (EC, OKP, RSA)."""
    require_cryptography("Token verification")
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

    if not isinstance(jwk, dict):
        raise LumoAuthValidationError("JWK must be a JSON object")
    for member in _PRIVATE_MEMBERS:
        if member in jwk:
            raise LumoAuthValidationError(f"JWK carries the private member {member!r}")
    kty = jwk.get("kty")
    try:
        if kty == "EC":
            crv = jwk.get("crv")
            if crv not in _CURVES:
                raise LumoAuthValidationError(f"unsupported EC curve {crv!r}")
            curve = getattr(ec, _CURVES[crv].upper())()
            x = int.from_bytes(b64url_decode(jwk["x"]), "big")
            y = int.from_bytes(b64url_decode(jwk["y"]), "big")
            return ec.EllipticCurvePublicNumbers(x, y, curve).public_key()
        if kty == "OKP":
            if jwk.get("crv") != "Ed25519":
                raise LumoAuthValidationError("unsupported OKP curve")
            return ed25519.Ed25519PublicKey.from_public_bytes(b64url_decode(jwk["x"]))
        if kty == "RSA":
            n = int.from_bytes(b64url_decode(jwk["n"]), "big")
            e = int.from_bytes(b64url_decode(jwk["e"]), "big")
            return rsa.RSAPublicNumbers(e, n).public_key()
    except KeyError as exc:
        raise LumoAuthValidationError(f"JWK is missing the member {exc.args[0]!r}") from exc
    except ValueError as exc:
        raise LumoAuthValidationError(f"invalid JWK: {exc}") from exc
    raise LumoAuthValidationError(f"unsupported JWK key type {kty!r}")


def jwk_thumbprint(jwk: Dict[str, Any]) -> str:
    """RFC 7638 SHA-256 thumbprint, base64url encoded.

    Canonical members: ``crv, kty, x, y`` (EC), ``crv, kty, x`` (OKP),
    ``e, kty, n`` (RSA); lexicographic order, no whitespace.
    """
    kty = jwk.get("kty") if isinstance(jwk, dict) else None
    members = {"EC": ("crv", "kty", "x", "y"), "OKP": ("crv", "kty", "x"), "RSA": ("e", "kty", "n")}.get(kty)
    if members is None:
        raise LumoAuthValidationError(f"cannot thumbprint a JWK of type {kty!r}")
    try:
        canonical = {m: jwk[m] for m in members}
    except KeyError as exc:
        raise LumoAuthValidationError(f"JWK is missing the member {exc.args[0]!r}") from exc
    for value in canonical.values():
        if not isinstance(value, str):
            raise LumoAuthValidationError("JWK members must be strings")
    encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return b64url_encode(hashlib.sha256(encoded).digest())


# ── Signatures ───────────────────────────────────────────────────────


def _hash_for(alg: str) -> Any:
    from cryptography.hazmat.primitives import hashes

    return getattr(hashes, _HASHES[alg[2:]])()


def _check_alg(alg: str) -> None:
    if alg not in ASYMMETRIC_ALGS:
        raise LumoAuthValidationError(f"unsupported or forbidden JWS algorithm {alg!r}")


def _check_key_matches_alg(key: Any, alg: str) -> None:
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

    if alg.startswith("ES"):
        if not isinstance(key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
            raise LumoAuthValidationError(f"{alg} needs an EC key")
        expected = _CURVE_ALG.get(_CURVE_NAMES.get(key.curve.name, ""), None)
        if expected != alg:
            raise LumoAuthValidationError(f"{alg} needs a {_curve_for_alg(alg)} key")
    elif alg == "EdDSA":
        if not isinstance(key, (ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey)):
            raise LumoAuthValidationError("EdDSA needs an Ed25519 key")
    else:
        if not isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
            raise LumoAuthValidationError(f"{alg} needs an RSA key")


def _curve_for_alg(alg: str) -> str:
    return {v: k for k, v in _CURVE_ALG.items()}[alg]


def sign(private_key: Any, alg: str, data: bytes) -> bytes:
    """Sign *data* with the JWS algorithm *alg*. ES* signatures are raw ``r || s``."""
    _check_alg(alg)
    _check_key_matches_alg(private_key, alg)
    from cryptography.hazmat.primitives.asymmetric import ec, padding
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    if alg.startswith("ES"):
        der = private_key.sign(data, ec.ECDSA(_hash_for(alg)))
        r, s = decode_dss_signature(der)
        size = (private_key.curve.key_size + 7) // 8
        return _int_bytes(r, size) + _int_bytes(s, size)
    if alg == "EdDSA":
        return private_key.sign(data)
    if alg.startswith("PS"):
        h = _hash_for(alg)
        return private_key.sign(data, padding.PSS(padding.MGF1(h), h.digest_size), h)
    return private_key.sign(data, padding.PKCS1v15(), _hash_for(alg))


def verify(public_key: Any, alg: str, data: bytes, signature: bytes) -> bool:
    """Return ``True`` when *signature* over *data* is valid for *alg*."""
    _check_alg(alg)
    _check_key_matches_alg(public_key, alg)
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import ec, padding
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

    try:
        if alg.startswith("ES"):
            size = (public_key.curve.key_size + 7) // 8
            if len(signature) != 2 * size:
                return False
            r = int.from_bytes(signature[:size], "big")
            s = int.from_bytes(signature[size:], "big")
            public_key.verify(encode_dss_signature(r, s), data, ec.ECDSA(_hash_for(alg)))
        elif alg == "EdDSA":
            public_key.verify(signature, data)
        elif alg.startswith("PS"):
            h = _hash_for(alg)
            public_key.verify(
                signature, data, padding.PSS(padding.MGF1(h), h.digest_size), h
            )
        else:
            public_key.verify(signature, data, padding.PKCS1v15(), _hash_for(alg))
    except InvalidSignature:
        return False
    return True

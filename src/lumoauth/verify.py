"""Local verification of LumoAuth ``at+jwt`` access tokens.

This is what an MCP server or any resource server built with this SDK
calls on the token it receives. It checks the signature against the
organization's JWKS (found through the issuer's discovery document), the
``typ`` header, ``iss``, ``aud`` (= your resource URI), ``exp`` / ``nbf``,
refuses test tokens, and, for a DPoP-bound token (``cnf.jkt``), checks the
``DPoP`` proof of the request.

Three lines::

    from lumoauth.verify import verify_access_token

    claims = verify_access_token(token, issuer="https://app.lumoauth.dev/orgs/acme/api/v1",
                                 resource="https://mcp.example.com/mcp")
    if not claims.has_scope("tools:read"): ...

Every failure raises :class:`lumoauth.errors.LumoAuthTokenError`, whose
``code`` is stable (``TOKEN_EXPIRED``, ``TOKEN_WRONG_AUDIENCE``,
``DPOP_REQUIRED``, ``DPOP_REPLAYED``, …).

Needs ``cryptography``: ``pip install "lumoauth[verify]"``.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Mapping, Optional, Protocol, Tuple

from lumoauth._http import HttpClient
from lumoauth._jose import (
    ASYMMETRIC_ALGS,
    jwk_thumbprint,
    public_key_from_jwk,
    split_jws,
    verify as verify_signature,
)
from lumoauth.dpop import DPOP_SCHEME, access_token_hash, canonical_htu
from lumoauth.errors import (
    LumoAuthApiError,
    LumoAuthConfigError,
    LumoAuthNetworkError,
    LumoAuthTokenError,
    LumoAuthValidationError,
)

__all__ = [
    "AccessTokenClaims",
    "AccessTokenVerifier",
    "DpopRequest",
    "InMemoryReplayCache",
    "JwksCache",
    "ReplayCache",
    "verify_access_token",
]

_AT_JWT_TYPES = ("at+jwt", "application/at+jwt")
_TOKEN_ALGS = frozenset(a for a in ASYMMETRIC_ALGS if a != "EdDSA")
_DEFAULT_PROOF_MAX_AGE = 300  # seconds a DPoP proof may be old (server uses 300)
_DEFAULT_JWKS_TTL = 3600
_MIN_REFETCH_INTERVAL = 30  # unknown-kid refetch rate limit (seconds)

Fetch = Callable[[str], Any]


# ── Results ──────────────────────────────────────────────────────────


@dataclass(frozen=True)
class AccessTokenClaims:
    """The verified claims of a LumoAuth access token."""

    sub: str
    iss: str
    aud: Tuple[str, ...]
    exp: int
    scopes: Tuple[str, ...]
    is_agent: bool
    capabilities: Tuple[str, ...]
    jti: Optional[str] = None
    nbf: Optional[int] = None
    iat: Optional[int] = None
    client_id: Optional[str] = None
    act: Optional[Dict[str, Any]] = None
    cnf: Optional[Dict[str, Any]] = None
    token_use: Optional[str] = None
    claims: Dict[str, Any] = field(default_factory=dict, repr=False, compare=False)
    header: Dict[str, Any] = field(default_factory=dict, repr=False, compare=False)

    # ── scopes ─────────────────────────────────────────────────────────

    @property
    def scope(self) -> str:
        """The ``scope`` claim as LumoAuth sent it (space separated)."""
        return " ".join(self.scopes)

    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes

    def has_scopes(self, *scopes: str) -> bool:
        """``True`` when every listed scope was granted."""
        return all(s in self.scopes for s in scopes)

    def missing_scopes(self, scopes: Any) -> List[str]:
        return [s for s in scopes if s not in self.scopes]

    def has_capability(self, capability: str) -> bool:
        return capability in self.capabilities

    # ── identity ───────────────────────────────────────────────────────

    @property
    def agent_id(self) -> Optional[str]:
        """``agt_…`` for an agent token (``sub`` is ``agent_agt_…``), else ``None``."""
        if self.is_agent and self.sub.startswith("agent_"):
            return self.sub[len("agent_"):]
        return None

    @property
    def is_delegated(self) -> bool:
        """``True`` when the token carries an ``act`` claim (someone acts for ``sub``)."""
        return self.act is not None

    @property
    def act_chain(self) -> List[Dict[str, Any]]:
        """The ``act`` claims from the outermost actor inwards (RFC 8693 §4.1)."""
        chain: List[Dict[str, Any]] = []
        current = self.act
        while isinstance(current, dict):
            chain.append({k: v for k, v in current.items() if k != "act"})
            current = current.get("act")
        return chain

    @property
    def actor(self) -> Optional[str]:
        """The ``sub`` of the immediate actor, if the token is delegated."""
        return self.act.get("sub") if isinstance(self.act, dict) else None

    # ── DPoP ───────────────────────────────────────────────────────────

    @property
    def dpop_thumbprint(self) -> Optional[str]:
        """``cnf.jkt`` for a DPoP-bound token, else ``None``."""
        if isinstance(self.cnf, dict) and isinstance(self.cnf.get("jkt"), str):
            return self.cnf["jkt"]
        return None

    @property
    def is_dpop_bound(self) -> bool:
        return self.dpop_thumbprint is not None


@dataclass(frozen=True)
class DpopRequest:
    """What the resource server saw on the incoming request, for the DPoP check.

    Args:
        method: The request's HTTP method.
        url: The request URL as the client addressed it (query is ignored).
            Behind a proxy, rebuild the public URL.
        proof: The ``DPoP`` header, or ``None`` when absent.
        scheme: The ``Authorization`` scheme the client used (``Bearer``
            or ``DPoP``).
        nonce: The nonce the resource server expects, if it issues nonces.
    """

    method: str
    url: str
    proof: Optional[str]
    scheme: str = DPOP_SCHEME
    nonce: Optional[str] = None


# ── Caches ───────────────────────────────────────────────────────────


class ReplayCache(Protocol):
    """Remembers DPoP ``jti`` values. Plug in Redis or similar for several workers."""

    def check_and_add(self, key: str, ttl: float) -> bool:
        """Return ``True`` when *key* was already present; otherwise add it for *ttl* seconds."""
        ...


class InMemoryReplayCache:
    """Process-local :class:`ReplayCache` with lazy expiry."""

    def __init__(self, max_entries: int = 100_000) -> None:
        self._entries: Dict[str, float] = {}
        self._lock = threading.Lock()
        self._max_entries = max_entries

    def check_and_add(self, key: str, ttl: float, *, now: Optional[float] = None) -> bool:
        current = time.time() if now is None else now
        with self._lock:
            expires = self._entries.get(key)
            if expires is not None and expires > current:
                return True
            if len(self._entries) >= self._max_entries:
                self._prune(current)
            self._entries[key] = current + ttl
            return False

    def _prune(self, now: float) -> None:
        for k in [k for k, exp in self._entries.items() if exp <= now]:
            del self._entries[k]
        if len(self._entries) >= self._max_entries:
            # Still full with live entries: drop the oldest half.
            for k in sorted(self._entries, key=self._entries.get)[: self._max_entries // 2]:
                del self._entries[k]


class JwksCache:
    """Fetches and caches an issuer's JWKS, refetching once on an unknown ``kid``."""

    def __init__(
        self,
        issuer: str,
        *,
        jwks: Optional[Mapping[str, Any]] = None,
        fetch: Optional[Fetch] = None,
        jwks_uri: Optional[str] = None,
        ttl: float = _DEFAULT_JWKS_TTL,
        verify_tls: bool = True,
    ) -> None:
        self.issuer = issuer.rstrip("/")
        self._fetch = fetch
        self._verify_tls = verify_tls
        self._jwks_uri = jwks_uri
        self._ttl = ttl
        self._keys: Dict[str, Dict[str, Any]] = {}
        self._fetched_at: float = 0.0
        self._static = jwks is not None
        self._lock = threading.Lock()
        if jwks is not None:
            self._load(jwks)

    # -- public ------------------------------------------------------------

    @property
    def jwks_uri(self) -> Optional[str]:
        return self._jwks_uri

    def key_for(self, kid: Optional[str], *, now: Optional[float] = None) -> Dict[str, Any]:
        current = time.time() if now is None else now
        with self._lock:
            if not self._static and (not self._keys or current - self._fetched_at > self._ttl):
                self._refresh(current)
            key = self._lookup(kid)
            if key is None and not self._static and current - self._fetched_at >= _MIN_REFETCH_INTERVAL:
                self._refresh(current)
                key = self._lookup(kid)
        if key is None:
            raise LumoAuthTokenError(
                f"no signing key with kid {kid!r} in the issuer's JWKS", "TOKEN_UNKNOWN_KEY"
            )
        return key

    # -- internal ----------------------------------------------------------

    def _lookup(self, kid: Optional[str]) -> Optional[Dict[str, Any]]:
        if kid is not None:
            return self._keys.get(kid)
        if len(self._keys) == 1:
            return next(iter(self._keys.values()))
        return None

    def _load(self, jwks: Mapping[str, Any]) -> None:
        keys = jwks.get("keys") if isinstance(jwks, Mapping) else None
        if not isinstance(keys, list):
            raise LumoAuthConfigError("JWKS document has no 'keys' list")
        loaded: Dict[str, Dict[str, Any]] = {}
        for index, key in enumerate(keys):
            if not isinstance(key, dict):
                continue
            if key.get("use") not in (None, "sig"):
                continue
            kid = key.get("kid")
            loaded[kid if isinstance(kid, str) else f"#{index}"] = key
        self._keys = loaded

    def _get(self, url: str) -> Any:
        if self._fetch is not None:
            return self._fetch(url)
        return HttpClient("", timeout=10, verify_tls=self._verify_tls).request(
            "GET", url, auth=False
        )

    def _refresh(self, now: float) -> None:
        self._fetched_at = now
        try:
            if self._jwks_uri is None:
                self._jwks_uri = self._discover()
            document = self._get(self._jwks_uri)
        except (LumoAuthApiError, LumoAuthNetworkError) as exc:
            raise LumoAuthTokenError(
                f"cannot fetch the issuer's signing keys: {exc}", "TOKEN_KEYS_UNAVAILABLE"
            ) from exc
        self._load(document)

    def _discover(self) -> str:
        discovery_url = f"{self.issuer}/.well-known/openid-configuration"
        fallback = f"{self.issuer}/.well-known/jwks.json"
        try:
            document = self._get(discovery_url)
        except (LumoAuthApiError, LumoAuthNetworkError):
            return fallback
        if isinstance(document, dict):
            if isinstance(document.get("issuer"), str) and document["issuer"].rstrip("/") != self.issuer:
                raise LumoAuthConfigError(
                    f"discovery document issuer {document['issuer']!r} does not match {self.issuer!r}"
                )
            uri = document.get("jwks_uri")
            if isinstance(uri, str) and uri:
                return uri
        return fallback


# ── Verifier ─────────────────────────────────────────────────────────


class AccessTokenVerifier:
    """Verifies LumoAuth ``at+jwt`` access tokens for one resource.

    Args:
        issuer: The organization issuer, for example
            ``https://app.lumoauth.dev/orgs/acme/api/v1``.
        resource: Your resource URI; the token's ``aud`` must contain it.
        jwks: A JWKS document to use instead of fetching (tests, pinning).
        fetch: ``fetch(url) -> dict`` used for discovery and the JWKS;
            defaults to the SDK's HTTP client.
        jwks_uri: Skip discovery and fetch this URL.
        clock_skew: Seconds of leeway on ``exp`` / ``nbf`` and on a proof's
            ``iat`` in the future (default 60).
        require_dpop: Refuse tokens that are not DPoP-bound.
        replay_cache: Where DPoP ``jti`` values are remembered; defaults to
            a process-local cache.
        proof_max_age: Seconds a DPoP proof's ``iat`` may lie in the past
            (default 300).
        clock: Time source for tests.
    """

    def __init__(
        self,
        issuer: str,
        resource: str,
        *,
        jwks: Optional[Mapping[str, Any]] = None,
        fetch: Optional[Fetch] = None,
        jwks_uri: Optional[str] = None,
        clock_skew: float = 60,
        require_dpop: bool = False,
        replay_cache: Optional[ReplayCache] = None,
        proof_max_age: float = _DEFAULT_PROOF_MAX_AGE,
        jwks_ttl: float = _DEFAULT_JWKS_TTL,
        verify_tls: bool = True,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not isinstance(issuer, str) or not issuer.startswith(("https://", "http://")):
            raise LumoAuthConfigError("issuer must be the organization's https issuer URL")
        if not isinstance(resource, str) or not resource:
            raise LumoAuthConfigError("resource is required (your resource URI, the token's aud)")
        self.issuer = issuer.rstrip("/")
        self.resource = resource
        self.clock_skew = float(clock_skew)
        self.require_dpop = require_dpop
        self.proof_max_age = float(proof_max_age)
        self._clock = clock
        self._replay: ReplayCache = replay_cache if replay_cache is not None else InMemoryReplayCache()
        self.jwks = JwksCache(
            self.issuer,
            jwks=jwks,
            fetch=fetch,
            jwks_uri=jwks_uri,
            ttl=jwks_ttl,
            verify_tls=verify_tls,
        )

    def verify(
        self,
        token: str,
        *,
        dpop: Optional[DpopRequest] = None,
        now: Optional[float] = None,
    ) -> AccessTokenClaims:
        """Verify *token*; return its claims or raise :class:`LumoAuthTokenError`."""
        current = self._clock() if now is None else now
        if not isinstance(token, str) or not token:
            raise LumoAuthTokenError("no access token", "TOKEN_MISSING")

        try:
            header, payload, signing_input, signature = split_jws(token)
        except LumoAuthValidationError as exc:
            raise LumoAuthTokenError(f"malformed access token: {exc.message}", "TOKEN_MALFORMED") from exc

        self._check_header(header)
        key = self.jwks.key_for(header.get("kid"), now=current)
        self._check_signature(header, key, signing_input, signature)
        claims = self._check_claims(payload, header, current)

        if dpop is not None and dpop.scheme.lower() == DPOP_SCHEME.lower() and not claims.is_dpop_bound:
            raise LumoAuthTokenError(
                "the token is not DPoP-bound but was presented with the DPoP scheme",
                "DPOP_NOT_BOUND",
                scheme=DPOP_SCHEME,
            )
        if claims.is_dpop_bound:
            self._check_dpop(claims, token, dpop, current)
        elif self.require_dpop:
            raise LumoAuthTokenError(
                "this resource requires a DPoP-bound token (cnf.jkt)",
                "DPOP_REQUIRED",
                scheme=DPOP_SCHEME,
            )
        return claims

    # -- steps -------------------------------------------------------------

    @staticmethod
    def _check_header(header: Dict[str, Any]) -> None:
        typ = header.get("typ")
        if not isinstance(typ, str) or typ.lower() not in _AT_JWT_TYPES:
            raise LumoAuthTokenError(
                f"token typ must be at+jwt, got {typ!r}", "TOKEN_WRONG_TYPE"
            )
        alg = header.get("alg")
        if alg not in _TOKEN_ALGS:
            raise LumoAuthTokenError(
                f"token alg {alg!r} is not allowed (RS*/PS*/ES* only)", "TOKEN_BAD_ALG"
            )

    @staticmethod
    def _check_signature(
        header: Dict[str, Any], key: Dict[str, Any], signing_input: bytes, signature: bytes
    ) -> None:
        alg = header["alg"]
        key_alg = key.get("alg")
        if isinstance(key_alg, str) and key_alg != alg:
            raise LumoAuthTokenError(
                f"token alg {alg!r} does not match the key's alg {key_alg!r}", "TOKEN_BAD_ALG"
            )
        try:
            public_key = public_key_from_jwk(key)
            valid = verify_signature(public_key, alg, signing_input, signature)
        except LumoAuthValidationError as exc:
            raise LumoAuthTokenError(f"cannot verify the signature: {exc.message}", "TOKEN_BAD_SIGNATURE") from exc
        if not valid:
            raise LumoAuthTokenError("the token signature is invalid", "TOKEN_BAD_SIGNATURE")

    def _check_claims(self, payload: Dict[str, Any], header: Dict[str, Any], now: float) -> AccessTokenClaims:
        iss = payload.get("iss")
        if not isinstance(iss, str) or iss.rstrip("/") != self.issuer:
            raise LumoAuthTokenError(
                f"token issuer {iss!r} is not {self.issuer!r}", "TOKEN_WRONG_ISSUER"
            )

        aud_raw = payload.get("aud")
        aud: Tuple[str, ...]
        if isinstance(aud_raw, str):
            aud = (aud_raw,)
        elif isinstance(aud_raw, list) and all(isinstance(a, str) for a in aud_raw):
            aud = tuple(aud_raw)
        else:
            aud = ()
        if self.resource not in aud:
            raise LumoAuthTokenError(
                f"token audience {list(aud)!r} does not include {self.resource!r}",
                "TOKEN_WRONG_AUDIENCE",
            )

        exp = payload.get("exp")
        if not isinstance(exp, (int, float)) or isinstance(exp, bool):
            raise LumoAuthTokenError("token has no exp claim", "TOKEN_MISSING_CLAIM")
        if now - self.clock_skew >= exp:
            raise LumoAuthTokenError("the token has expired", "TOKEN_EXPIRED")

        nbf = payload.get("nbf")
        if nbf is not None:
            if not isinstance(nbf, (int, float)) or isinstance(nbf, bool):
                raise LumoAuthTokenError("token nbf is not a number", "TOKEN_MISSING_CLAIM")
            if nbf > now + self.clock_skew:
                raise LumoAuthTokenError("the token is not valid yet (nbf)", "TOKEN_NOT_YET_VALID")

        sub = payload.get("sub")
        if not isinstance(sub, str) or not sub:
            raise LumoAuthTokenError("token has no sub claim", "TOKEN_MISSING_CLAIM")

        token_use = payload.get("token_use")
        if token_use == "test":
            raise LumoAuthTokenError(
                "test tokens (token_use=test) are not accepted by resource servers",
                "TOKEN_TEST_TOKEN",
            )

        scope = payload.get("scope")
        if isinstance(scope, str):
            scopes = tuple(s for s in scope.split() if s)
        elif isinstance(scope, list):
            scopes = tuple(s for s in scope if isinstance(s, str))
        else:
            scopes = ()

        capabilities_raw = payload.get("capabilities")
        capabilities = (
            tuple(c for c in capabilities_raw if isinstance(c, str))
            if isinstance(capabilities_raw, list)
            else ()
        )
        act = payload.get("act") if isinstance(payload.get("act"), dict) else None
        cnf = payload.get("cnf") if isinstance(payload.get("cnf"), dict) else None
        iat = payload.get("iat")
        jti = payload.get("jti")
        client_id = payload.get("client_id")

        return AccessTokenClaims(
            sub=sub,
            iss=iss,
            aud=aud,
            exp=int(exp),
            scopes=scopes,
            is_agent=payload.get("is_agent") is True,
            capabilities=capabilities,
            jti=jti if isinstance(jti, str) else None,
            nbf=int(nbf) if isinstance(nbf, (int, float)) else None,
            iat=int(iat) if isinstance(iat, (int, float)) and not isinstance(iat, bool) else None,
            client_id=client_id if isinstance(client_id, str) else None,
            act=act,
            cnf=cnf,
            token_use=token_use if isinstance(token_use, str) else None,
            claims=dict(payload),
            header=dict(header),
        )

    def _check_dpop(
        self, claims: AccessTokenClaims, token: str, dpop: Optional[DpopRequest], now: float
    ) -> None:
        if dpop is not None and dpop.scheme.lower() != DPOP_SCHEME.lower():
            raise LumoAuthTokenError(
                f"a DPoP-bound token must use the DPoP authorization scheme, not {dpop.scheme!r}",
                "DPOP_WRONG_SCHEME",
                scheme=DPOP_SCHEME,
            )
        if dpop is None or not dpop.proof:
            raise LumoAuthTokenError(
                "the token is DPoP-bound but the request carries no DPoP proof",
                "DPOP_REQUIRED",
                scheme=DPOP_SCHEME,
            )

        def bad(message: str, code: str = "DPOP_INVALID") -> LumoAuthTokenError:
            return LumoAuthTokenError(message, code, scheme=DPOP_SCHEME, error="invalid_dpop_proof")

        try:
            header, proof_claims, signing_input, signature = split_jws(dpop.proof)
        except LumoAuthValidationError as exc:
            raise bad(f"malformed DPoP proof: {exc.message}") from exc

        if str(header.get("typ", "")).lower() != "dpop+jwt":
            raise bad("DPoP proof typ must be dpop+jwt")
        alg = header.get("alg")
        if alg not in ASYMMETRIC_ALGS:
            raise bad(f"DPoP proof alg {alg!r} is not allowed")
        jwk = header.get("jwk")
        if not isinstance(jwk, dict):
            raise bad("DPoP proof has no jwk header")
        try:
            thumbprint = jwk_thumbprint(jwk)
            public_key = public_key_from_jwk(jwk)
            valid = verify_signature(public_key, alg, signing_input, signature)
        except LumoAuthValidationError as exc:
            raise bad(f"DPoP proof key is not usable: {exc.message}") from exc
        if thumbprint != claims.dpop_thumbprint:
            raise bad("the DPoP proof key does not match the token's cnf.jkt", "DPOP_KEY_MISMATCH")
        if not valid:
            raise bad("the DPoP proof signature is invalid")

        jti = proof_claims.get("jti")
        if not isinstance(jti, str) or not jti:
            raise bad("DPoP proof has no jti")
        htm = proof_claims.get("htm")
        if not isinstance(htm, str) or htm.upper() != dpop.method.upper():
            raise bad(f"DPoP proof htm {htm!r} does not match the request method")
        htu = proof_claims.get("htu")
        try:
            expected_htu = canonical_htu(dpop.url)
        except LumoAuthValidationError as exc:
            raise LumoAuthConfigError(f"DpopRequest.url is not an absolute URL: {exc.message}") from exc
        if not isinstance(htu, str) or htu.rstrip("/") != expected_htu.rstrip("/"):
            raise bad(f"DPoP proof htu {htu!r} does not match the request URL")
        iat = proof_claims.get("iat")
        if not isinstance(iat, (int, float)) or isinstance(iat, bool):
            raise bad("DPoP proof has no iat")
        if iat > now + self.clock_skew:
            raise bad("DPoP proof iat is in the future")
        if iat < now - self.proof_max_age:
            raise bad("DPoP proof is too old")
        if proof_claims.get("ath") != access_token_hash(token):
            raise bad("DPoP proof ath does not match the presented token")
        if dpop.nonce is not None and proof_claims.get("nonce") != dpop.nonce:
            raise bad("DPoP proof nonce is missing or stale", "DPOP_USE_NONCE")

        if self._replay.check_and_add(f"{thumbprint}:{jti}", self.proof_max_age + self.clock_skew):
            raise bad("DPoP proof jti was already used", "DPOP_REPLAYED")


# ── Convenience function ─────────────────────────────────────────────

_verifiers: Dict[Tuple[str, str, bool], AccessTokenVerifier] = {}
_verifiers_lock = threading.Lock()


def verify_access_token(
    token: str,
    *,
    issuer: str,
    resource: str,
    jwks: Optional[Mapping[str, Any]] = None,
    fetch: Optional[Fetch] = None,
    clock_skew: float = 60,
    require_dpop: bool = False,
    dpop: Optional[DpopRequest] = None,
    replay_cache: Optional[ReplayCache] = None,
    now: Optional[float] = None,
) -> AccessTokenClaims:
    """Verify a LumoAuth access token for *resource*.

    A shortcut over :class:`AccessTokenVerifier`. With the default fetcher
    and no ``jwks``, a verifier (and its JWKS cache) is kept per
    ``(issuer, resource, require_dpop)``, so repeated calls do not refetch
    the keys. Pass ``jwks`` or ``fetch`` to build a fresh verifier each
    time (tests), or hold an :class:`AccessTokenVerifier` yourself.

    Args:
        token: The access token from the ``Authorization`` header.
        issuer: ``https://app.lumoauth.dev/orgs/{org}/api/v1``.
        resource: Your resource URI (the MCP server's URL).
        jwks: Static JWKS instead of discovery.
        fetch: Custom ``fetch(url) -> dict`` for discovery and the JWKS.
        clock_skew: Leeway in seconds (default 60).
        require_dpop: Refuse tokens without ``cnf.jkt``.
        dpop: The request's DPoP details; required when the token is
            DPoP-bound.
        replay_cache: A :class:`ReplayCache` for DPoP ``jti`` values.
        now: Override the clock (tests).

    Raises:
        LumoAuthTokenError: The token or its DPoP proof is not acceptable;
            ``code`` says why.
    """
    if jwks is not None or fetch is not None or replay_cache is not None:
        verifier = AccessTokenVerifier(
            issuer,
            resource,
            jwks=jwks,
            fetch=fetch,
            clock_skew=clock_skew,
            require_dpop=require_dpop,
            replay_cache=replay_cache,
        )
    else:
        key = (issuer.rstrip("/"), resource, require_dpop)
        with _verifiers_lock:
            verifier = _verifiers.get(key)
            if verifier is None:
                verifier = AccessTokenVerifier(
                    issuer, resource, clock_skew=clock_skew, require_dpop=require_dpop
                )
                _verifiers[key] = verifier
        verifier.clock_skew = float(clock_skew)
    return verifier.verify(token, dpop=dpop, now=now)

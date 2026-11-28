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

import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Mapping, Optional, Protocol, Tuple
from urllib.parse import unquote

from lumoauth._http import HttpClient
from lumoauth._routes import normalize_custom_domain, org_api_base
from lumoauth._jose import (
    ASYMMETRIC_ALGS,
    jwk_thumbprint,
    public_key_from_jwk,
    split_jws,
    verify as verify_signature,
)
from lumoauth.capabilities import any_capability_covers
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
    "JitTokenClaims",
    "JitTokenVerifier",
    "JwksCache",
    "ReplayCache",
    "org_id_from_issuer",
    "verify_access_token",
    "verify_jit_token",
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
        """Whether the agent's ``capabilities`` claim covers *capability*.

        Names match as on the server (``web.search`` matches
        ``web:search``; ``invoices:*`` covers ``invoices:read``). Scopes
        are different: :meth:`has_scope` compares them exactly.
        """
        return any_capability_covers(self.capabilities, capability)

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

    # ── JIT / RAR & Trace context ──────────────────────────────────────

    @property
    def authorization_details(self) -> Tuple[Dict[str, Any], ...]:
        """RFC 9396 Rich Authorization Requests details granted to this token."""
        items: List[Dict[str, Any]] = []
        top = self.claims.get("authorization_details")
        if isinstance(top, list):
            items.extend(entry for entry in top if isinstance(entry, dict))
        perms = self.claims.get("permissions")
        if isinstance(perms, dict):
            nested = perms.get("authorization_details")
            if isinstance(nested, list):
                items.extend(entry for entry in nested if isinstance(entry, dict))
        return tuple(items)

    @property
    def is_jit(self) -> bool:
        """``True`` when the token is a task-bound JIT token or carries RAR details."""
        if self.claims.get("jit") is True:
            return True
        perms = self.claims.get("permissions")
        if isinstance(perms, dict) and isinstance(perms.get("jit_request_id"), str):
            return True
        return len(self.authorization_details) > 0

    @property
    def traceparent(self) -> Optional[str]:
        """W3C ``traceparent`` associated with the request or token, if present."""
        val = self.claims.get("_traceparent") or self.claims.get("traceparent")
        return val if isinstance(val, str) and val else None

    @property
    def trace_id(self) -> Optional[str]:
        """32-hex W3C trace ID extracted from ``traceparent`` or token claims."""
        val = self.claims.get("_trace_id") or self.claims.get("trace_id")
        if isinstance(val, str) and val:
            return val
        act = self.act
        if isinstance(act, dict) and isinstance(act.get("trace_id"), str):
            return act["trace_id"]
        return None


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
    """Fetches and caches an issuer's JWKS, refetching once on an unknown ``kid``.

    The discovery document and the key set are read below ``metadata_base``.
    It defaults to the issuer, which is right on the platform host. On a
    custom domain the issuer is the bare domain and the documents are below
    ``{domain}/api/v1``: :class:`AccessTokenVerifier` passes that address.
    """

    def __init__(
        self,
        issuer: str,
        *,
        jwks: Optional[Mapping[str, Any]] = None,
        fetch: Optional[Fetch] = None,
        jwks_uri: Optional[str] = None,
        ttl: float = _DEFAULT_JWKS_TTL,
        verify_tls: bool = True,
        metadata_base: Optional[str] = None,
    ) -> None:
        self.issuer = issuer.rstrip("/")
        self.metadata_base = (metadata_base or self.issuer).rstrip("/")
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
        discovery_url = f"{self.metadata_base}/.well-known/openid-configuration"
        fallback = f"{self.metadata_base}/.well-known/jwks.json"
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


def resolve_issuer(issuer: Optional[str], custom_domain: Optional[str] = None) -> Tuple[str, str]:
    """The issuer that a token must name, and the address of its metadata.

    Returns ``(issuer, metadata_base)``. Without a custom domain both are
    the given issuer. With a custom domain the issuer is the bare domain
    and the metadata is below ``{domain}/api/v1``; an *issuer* that is also
    given must be that domain, so that exactly one issuer is accepted.

    Raises:
        LumoAuthConfigError: Neither value is given, a value is malformed,
            or the two name different issuers.
    """
    domain = normalize_custom_domain(custom_domain)
    if domain is not None:
        if issuer is not None and (not isinstance(issuer, str) or issuer.rstrip("/") != domain):
            raise LumoAuthConfigError(
                "issuer and custom_domain disagree: on a custom domain the issuer is the "
                f"domain itself ({domain}). Pass custom_domain alone."
            )
        return domain, org_api_base("", None, domain)
    if not isinstance(issuer, str) or not issuer.startswith(("https://", "http://")):
        raise LumoAuthConfigError("issuer must be the organization's https issuer URL")
    return issuer.rstrip("/"), issuer.rstrip("/")


# ── Verifier ─────────────────────────────────────────────────────────


class AccessTokenVerifier:
    """Verifies LumoAuth ``at+jwt`` access tokens for one resource.

    Args:
        issuer: The organization issuer, for example
            ``https://app.lumoauth.dev/orgs/acme/api/v1``. Leave it out
            with ``custom_domain``.
        resource: Your resource URI; the token's ``aud`` must contain it.
        custom_domain: The organization's own domain, as a host name or an
            ``https://`` origin (``"auth.acme.com"``). The issuer is then
            the bare domain, and a token that names the platform issuer is
            refused. The discovery document and the key set are read below
            ``{domain}/api/v1``.
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
        issuer: Optional[str] = None,
        resource: Optional[str] = None,
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
        custom_domain: Optional[str] = None,
    ) -> None:
        issuer, metadata_base = resolve_issuer(issuer, custom_domain)
        if not isinstance(resource, str) or not resource:
            raise LumoAuthConfigError("resource is required (your resource URI, the token's aud)")
        self.issuer = issuer
        #: The custom domain as ``https://<host>[:port]``, or ``None``.
        self.custom_domain: Optional[str] = normalize_custom_domain(custom_domain)
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
            metadata_base=metadata_base,
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

_verifiers: Dict[Tuple[str, str, str, bool], AccessTokenVerifier] = {}
_verifiers_lock = threading.Lock()


def verify_access_token(
    token: str,
    *,
    issuer: Optional[str] = None,
    resource: str,
    jwks: Optional[Mapping[str, Any]] = None,
    fetch: Optional[Fetch] = None,
    clock_skew: float = 60,
    require_dpop: bool = False,
    dpop: Optional[DpopRequest] = None,
    replay_cache: Optional[ReplayCache] = None,
    now: Optional[float] = None,
    custom_domain: Optional[str] = None,
) -> AccessTokenClaims:
    """Verify a LumoAuth access token for *resource*.

    A shortcut over :class:`AccessTokenVerifier`. With the default fetcher
    and no ``jwks``, a verifier (and its JWKS cache) is kept per
    ``(issuer, resource, require_dpop)``, so repeated calls do not refetch
    the keys. Pass ``jwks`` or ``fetch`` to build a fresh verifier each
    time (tests), or hold an :class:`AccessTokenVerifier` yourself.

    Args:
        token: The access token from the ``Authorization`` header.
        issuer: ``https://app.lumoauth.dev/orgs/{org}/api/v1``. Leave it
            out with ``custom_domain``.
        resource: Your resource URI (the MCP server's URL).
        custom_domain: The organization's own domain (``"auth.acme.com"``).
            The token must then name the bare domain as its issuer.
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
            custom_domain=custom_domain,
        )
    else:
        key = (*resolve_issuer(issuer, custom_domain), resource, require_dpop)
        with _verifiers_lock:
            verifier = _verifiers.get(key)
            if verifier is None:
                verifier = AccessTokenVerifier(
                    issuer,
                    resource,
                    clock_skew=clock_skew,
                    require_dpop=require_dpop,
                    custom_domain=custom_domain,
                )
                _verifiers[key] = verifier
        verifier.clock_skew = float(clock_skew)
    return verifier.verify(token, dpop=dpop, now=now)


# ── JIT tokens ───────────────────────────────────────────────────────
#
# A JIT token is the approval of one Just-in-Time request
# (POST /jit/request/{id}/token). It is not an access token: its header typ
# is JWT, its aud is the organization slug, and the approval is in
# permissions.authorization_details. The rules are the same as in
# lumoauth-fastmcp and @lumoauth/mcp (X-LumoAuth-Jit-Token):
#
#  1. A compact JWS whose header and payload are JSON objects.
#  2. Header typ is JWT (any case); at+jwt, another value or none is refused.
#  3. Header alg is RS256/384/512, PS256/384/512 or ES256/384/512; kid is set.
#  4. The key with that kid comes from the organization's JWKS; its use is sig
#     or absent, its kty (and crv) fit the alg, its alg (when set) is the
#     header's; the signature verifies.
#  5. iss is the organization issuer (a trailing / ignored on both sides).
#  6. aud is the organization slug, or a list that contains it.
#  7. jit is the JSON boolean true.
#  8. exp is a number and now - skew < exp; nbf and iat, when present, are
#     numbers and not later than now + skew.
#  9. sub is a non-empty string; permissions is an object with a non-empty
#     string agent_id and authorization_details holding at least one object
#     with a string type. Those objects are the approval.
# 10. With a caller (the verified access token of the same request): sub is
#     the caller's sub, and "agent_" + permissions.agent_id is the caller's
#     agent (act.sub of a delegated token, else its sub); permissions.act.sub,
#     when present, is that agent too.
#
# Not checked locally: revocation before exp. Introspect the token for that
# (docs: agents/jit, "Validate a JIT token in your API").

_JIT_ALGS: Dict[str, Tuple[str, Optional[str]]] = {
    "RS256": ("RSA", None),
    "RS384": ("RSA", None),
    "RS512": ("RSA", None),
    "PS256": ("RSA", None),
    "PS384": ("RSA", None),
    "PS512": ("RSA", None),
    "ES256": ("EC", "P-256"),
    "ES384": ("EC", "P-384"),
    "ES512": ("EC", "P-521"),
}
_ISSUER_SLUG = re.compile(r"/orgs/([^/]+)/api/v1/?$")


def _jit_entry_covers(required: Mapping[str, Any], granted: Mapping[str, Any]) -> bool:
    """One approved entry covers one required entry (RFC 9396 matching)."""
    req_type = required.get("type")
    if not isinstance(req_type, str) or granted.get("type") not in (req_type, "*"):
        return False
    for member in ("actions", "locations"):
        wanted = required.get(member)
        if isinstance(wanted, list) and wanted:
            have = granted.get(member)
            if not isinstance(have, list):
                return False
            have_set = {str(v) for v in have}
            if "*" not in have_set and not all(str(v) in have_set for v in wanted):
                return False
    req_id = required.get("identifier")
    if isinstance(req_id, str) and req_id and granted.get("identifier") not in (req_id, "*"):
        return False
    return True


@dataclass(frozen=True)
class JitTokenClaims:
    """A verified LumoAuth JIT token (the approval of one JIT request)."""

    #: The approved RFC 9396 entries (``permissions.authorization_details``).
    authorization_details: Tuple[Dict[str, Any], ...]
    #: ``sub``: the user, or ``agent_agt_…`` for an agent that acts on its own.
    subject: str
    #: The agent that the approval was issued to (``agt_…``).
    agent_id: str
    exp: int
    jti: Optional[str] = None
    task_id: Optional[str] = None
    request_id: Optional[str] = None
    claims: Dict[str, Any] = field(default_factory=dict)

    def covers(
        self,
        type: str,
        *,
        actions: Optional[List[str]] = None,
        locations: Optional[List[str]] = None,
        identifier: Optional[str] = None,
    ) -> bool:
        """Whether the approval allows this action.

        An approved entry covers the request when its ``type`` is the same
        (or ``*``), its ``actions`` and ``locations`` hold every requested
        value (or ``*``), and its ``identifier`` is the same (or ``*``).
        """
        required: Dict[str, Any] = {"type": type}
        if actions:
            required["actions"] = list(actions)
        if locations:
            required["locations"] = list(locations)
        if identifier:
            required["identifier"] = identifier
        return any(_jit_entry_covers(required, entry) for entry in self.authorization_details)


def org_id_from_issuer(issuer: str) -> Optional[str]:
    """The organization slug of an issuer of the form ``…/orgs/{slug}/api/v1``."""
    match = _ISSUER_SLUG.search(issuer or "")
    return unquote(match.group(1)) if match else None


class JitTokenVerifier:
    """Verifies LumoAuth JIT tokens of one organization.

    Args:
        issuer: ``https://app.lumoauth.dev/orgs/{org}/api/v1``. Leave it out
            with ``custom_domain``.
        org_id: The organization slug, the ``aud`` of its JIT tokens. Read
            from *issuer* when it is left out; required with ``custom_domain``.
        custom_domain: The organization's own domain (``"auth.acme.com"``).
        jwks: Static JWKS instead of discovery.
        fetch: Custom ``fetch(url) -> dict`` for discovery and the JWKS.
        clock_skew: Leeway in seconds (default 60).

    Raises:
        LumoAuthConfigError: The issuer is missing or malformed, or the
            organization slug is unknown.
    """

    def __init__(
        self,
        issuer: Optional[str] = None,
        *,
        org_id: Optional[str] = None,
        custom_domain: Optional[str] = None,
        jwks: Optional[Mapping[str, Any]] = None,
        fetch: Optional[Fetch] = None,
        clock_skew: float = 60,
        verify_tls: bool = True,
    ) -> None:
        self.issuer, metadata_base = resolve_issuer(issuer, custom_domain)
        slug = org_id or org_id_from_issuer(self.issuer)
        if not slug:
            raise LumoAuthConfigError(
                "org_id is required to verify JIT tokens: their aud is the organization slug. "
                "Pass org_id (LUMOAUTH_ORG_ID)."
            )
        self.org_id: str = slug
        self.clock_skew = float(clock_skew)
        self.jwks = JwksCache(
            self.issuer, jwks=jwks, fetch=fetch, verify_tls=verify_tls, metadata_base=metadata_base
        )

    def verify(
        self,
        token: str,
        *,
        caller: Optional[AccessTokenClaims] = None,
        now: Optional[float] = None,
    ) -> JitTokenClaims:
        """Verify *token*; raise :class:`LumoAuthTokenError` when it is not acceptable.

        Pass *caller* (the verified access token of the same request) to
        check that the approval belongs to the caller. ``code`` of a refusal
        is ``JIT_TOKEN_INVALID``, ``JIT_TOKEN_NOT_FOR_CALLER``, or the code of
        the key lookup (``TOKEN_KEYS_UNAVAILABLE``).
        """

        def refuse(message: str, code: str = "JIT_TOKEN_INVALID") -> LumoAuthTokenError:
            return LumoAuthTokenError(message, code)

        if not isinstance(token, str):
            raise refuse("the JIT token is not a JWT")
        try:
            header, payload, signing_input, signature = split_jws(token)
        except LumoAuthValidationError as exc:
            raise refuse("the JIT token is not a JWT") from exc

        typ = header.get("typ")
        if not isinstance(typ, str) or typ.lower() != "jwt":
            raise refuse(f"the JIT token's typ must be JWT, got {typ!r}")
        alg = header.get("alg")
        spec = _JIT_ALGS.get(alg) if isinstance(alg, str) else None
        if spec is None:
            raise refuse(f"the JIT token's alg {alg!r} is not allowed")
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise refuse("the JIT token has no kid")

        iss = payload.get("iss")
        if not isinstance(iss, str) or iss.rstrip("/") != self.issuer:
            raise refuse("the JIT token comes from another issuer")

        try:
            key = self.jwks.key_for(kid, now=now)
        except LumoAuthTokenError as exc:
            if exc.code == "TOKEN_UNKNOWN_KEY":
                raise refuse(f"no signing key with kid {kid!r} in the organization's keys") from exc
            raise refuse(f"cannot read the organization's signing keys: {exc.message}", exc.code) from exc
        if key.get("use") not in (None, "sig"):
            raise refuse("the signing key is not a signature key")
        kty, crv = spec
        if key.get("kty") != kty or (crv is not None and key.get("crv") != crv):
            raise refuse(f"the signing key does not fit alg {alg}")
        if key.get("alg") is not None and key.get("alg") != alg:
            raise refuse(f"the signing key is for alg {key.get('alg')}")
        try:
            valid = verify_signature(public_key_from_jwk(key), alg, signing_input, signature)
        except LumoAuthValidationError as exc:
            raise refuse("the signing key cannot be read") from exc
        if not valid:
            raise refuse("the JIT token signature is invalid")

        aud = payload.get("aud")
        audiences = (aud,) if isinstance(aud, str) else tuple(aud) if isinstance(aud, list) else ()
        if self.org_id not in audiences:
            raise refuse("the JIT token is for another organization")
        if payload.get("jit") is not True:
            raise refuse("the token is not a JIT token (jit is not true)")

        current = time.time() if now is None else now
        exp = payload.get("exp")
        if not _is_number(exp) or current - self.clock_skew >= exp:
            raise refuse("the JIT token has expired")
        for name in ("nbf", "iat"):
            value = payload.get(name)
            if value is not None and (not _is_number(value) or value > current + self.clock_skew):
                raise refuse(f"the JIT token is not valid yet ({name})")

        sub = payload.get("sub")
        if not isinstance(sub, str) or not sub:
            raise refuse("the JIT token has no sub")
        permissions = payload.get("permissions")
        if not isinstance(permissions, dict):
            raise refuse("the JIT token has no permissions")
        agent_id = permissions.get("agent_id")
        if not isinstance(agent_id, str) or not agent_id:
            raise refuse("the JIT token names no agent")
        raw_details = permissions.get("authorization_details")
        details = tuple(
            dict(item)
            for item in (raw_details if isinstance(raw_details, list) else [])
            if isinstance(item, dict) and isinstance(item.get("type"), str)
        )
        if not details:
            raise refuse("the JIT token approves nothing (no authorization_details)")

        if caller is not None:
            act = caller.act
            caller_agent = (
                str(act["sub"])
                if isinstance(act, Mapping) and isinstance(act.get("sub"), str) and act.get("sub")
                else caller.sub
            )
            bound = permissions.get("act")
            delegated_agent = bound.get("sub") if isinstance(bound, dict) else None
            if (
                sub != caller.sub
                or f"agent_{agent_id}" != caller_agent
                or (delegated_agent is not None and delegated_agent != caller_agent)
            ):
                raise refuse("the JIT token was issued to another caller", "JIT_TOKEN_NOT_FOR_CALLER")

        jti = payload.get("jti")
        task_id = permissions.get("task_id")
        request_id = permissions.get("jit_request_id")
        return JitTokenClaims(
            authorization_details=details,
            subject=sub,
            agent_id=agent_id,
            exp=int(exp),
            jti=jti if isinstance(jti, str) else None,
            task_id=task_id if isinstance(task_id, str) else None,
            request_id=request_id if isinstance(request_id, str) else None,
            claims=dict(payload),
        )


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


_jit_verifiers: Dict[Tuple[str, str], JitTokenVerifier] = {}


def verify_jit_token(
    token: str,
    *,
    issuer: Optional[str] = None,
    org_id: Optional[str] = None,
    custom_domain: Optional[str] = None,
    caller: Optional[AccessTokenClaims] = None,
    jwks: Optional[Mapping[str, Any]] = None,
    fetch: Optional[Fetch] = None,
    clock_skew: float = 60,
    now: Optional[float] = None,
) -> JitTokenClaims:
    """Verify a LumoAuth JIT token locally. A shortcut over :class:`JitTokenVerifier`.

    With the default fetcher and no ``jwks``, one verifier (and its JWKS
    cache) is kept per issuer and organization. The token is not checked
    for revocation: introspect it for an action with consequences.

    Raises:
        LumoAuthTokenError: The token is not acceptable; ``code`` says why.
        LumoAuthConfigError: The issuer or the organization is unknown.
    """
    if jwks is not None or fetch is not None:
        verifier = JitTokenVerifier(
            issuer, org_id=org_id, custom_domain=custom_domain, jwks=jwks, fetch=fetch, clock_skew=clock_skew
        )
    else:
        resolved, _ = resolve_issuer(issuer, custom_domain)
        key = (resolved, org_id or org_id_from_issuer(resolved) or "")
        with _verifiers_lock:
            verifier = _jit_verifiers.get(key)
            if verifier is None:
                verifier = JitTokenVerifier(
                    issuer, org_id=org_id, custom_domain=custom_domain, clock_skew=clock_skew
                )
                _jit_verifiers[key] = verifier
        verifier.clock_skew = float(clock_skew)
    return verifier.verify(token, caller=caller, now=now)

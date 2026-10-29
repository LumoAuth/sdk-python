"""Local verification of LumoAuth at+jwt access tokens, including DPoP binding."""

from __future__ import annotations

import json
import time
from typing import Any, Dict, Optional

import pytest

pytest.importorskip(
    "cryptography",
    reason="Verifier tests need the 'cryptography' package (pip install -e '.[dev]')",
)

from cryptography.hazmat.primitives.asymmetric import ec, rsa  # noqa: E402

from lumoauth import verify_access_token  # noqa: E402
from lumoauth._jose import b64url_encode, public_jwk, sign  # noqa: E402
from lumoauth.dpop import DpopKey, DpopProofSigner  # noqa: E402
from lumoauth.errors import LumoAuthTokenError  # noqa: E402
from lumoauth.verify import (  # noqa: E402
    AccessTokenVerifier,
    DpopRequest,
    InMemoryReplayCache,
    JwksCache,
)

ISSUER = "https://app.lumoauth.dev/orgs/acme/api/v1"
RESOURCE = "https://mcp.example.com/mcp"
NOW = 1_800_000_000

RSA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
EC_KEY = ec.generate_private_key(ec.SECP256R1())
JWKS = {
    "keys": [
        dict(public_jwk(RSA_KEY.public_key()), kid="rsa-1", alg="RS256", use="sig"),
        dict(public_jwk(EC_KEY.public_key()), kid="ec-1", use="sig"),
    ]
}


def make_token(
    claims: Optional[Dict[str, Any]] = None,
    *,
    header: Optional[Dict[str, Any]] = None,
    key: Any = RSA_KEY,
    alg: str = "RS256",
    kid: str = "rsa-1",
    drop: tuple = (),
) -> str:
    hdr = {"typ": "at+jwt", "alg": alg, "kid": kid}
    hdr.update(header or {})
    body: Dict[str, Any] = {
        "iss": ISSUER,
        "sub": "agent_agt_0123",
        "aud": RESOURCE,
        "exp": NOW + 600,
        "nbf": NOW - 5,
        "iat": NOW - 5,
        "jti": "jti-1",
        "scope": "tools:read tools:write",
        "is_agent": True,
        "capabilities": ["tool:search_web"],
    }
    body.update(claims or {})
    for name in drop:
        body.pop(name, None)
    h = b64url_encode(json.dumps(hdr, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(body, separators=(",", ":")).encode())
    sig = sign(key, alg, f"{h}.{p}".encode())
    return f"{h}.{p}.{b64url_encode(sig)}"


def verify(token: str, **kw: Any):
    kw.setdefault("jwks", JWKS)
    kw.setdefault("now", NOW)
    return verify_access_token(token, issuer=ISSUER, resource=RESOURCE, **kw)


def code_of(exc_info) -> str:
    return exc_info.value.code


# ── Happy paths ───────────────────────────────────────────────────────


def test_happy_path_rs256():
    claims = verify(make_token())
    assert claims.sub == "agent_agt_0123"
    assert claims.agent_id == "agt_0123"
    assert claims.is_agent is True
    assert claims.aud == (RESOURCE,)
    assert claims.scopes == ("tools:read", "tools:write")
    assert claims.scope == "tools:read tools:write"
    assert claims.has_scope("tools:read") and not claims.has_scope("admin")
    assert claims.has_scopes("tools:read", "tools:write")
    assert claims.missing_scopes(["tools:read", "x"]) == ["x"]
    assert claims.has_capability("tool:search_web")
    assert claims.jti == "jti-1" and claims.exp == NOW + 600 and claims.nbf == NOW - 5
    assert not claims.is_dpop_bound and not claims.is_delegated
    assert claims.header["kid"] == "rsa-1"


def test_happy_path_es256_and_list_audience_and_application_typ():
    token = make_token(
        {"aud": ["https://other", RESOURCE]},
        header={"typ": "application/at+jwt"},
        key=EC_KEY,
        alg="ES256",
        kid="ec-1",
    )
    claims = verify(token)
    assert claims.aud == ("https://other", RESOURCE)


def test_ps256_signature():
    claims = verify(make_token(alg="PS256", kid="rsa-1", key=RSA_KEY), jwks={"keys": [
        dict(public_jwk(RSA_KEY.public_key()), kid="rsa-1")
    ]})
    assert claims.sub


def test_delegated_token_act_chain():
    act = {"sub": "agent_agt_outer", "iss": ISSUER, "sub_profile": "agent", "name": "Outer",
           "act": {"sub": "agent_agt_inner", "iss": ISSUER, "sub_profile": "agent"}}
    claims = verify(make_token({"sub": "usr_42", "is_agent": False, "act": act}))
    assert claims.is_delegated and claims.actor == "agent_agt_outer"
    assert [a["sub"] for a in claims.act_chain] == ["agent_agt_outer", "agent_agt_inner"]
    assert "act" not in claims.act_chain[0]
    assert claims.agent_id is None


def test_clock_skew_is_honoured():
    verify(make_token({"exp": NOW - 30}))            # within the 60 s default
    verify(make_token({"nbf": NOW + 30}))
    with pytest.raises(LumoAuthTokenError) as e:
        verify(make_token({"exp": NOW - 30}), clock_skew=0)
    assert code_of(e) == "TOKEN_EXPIRED"


# ── Rejections ────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "kwargs, code",
    [
        ({"claims": {"aud": "https://someone-else.example"}}, "TOKEN_WRONG_AUDIENCE"),
        ({"claims": {"aud": ["https://a", "https://b"]}}, "TOKEN_WRONG_AUDIENCE"),
        ({"drop": ("aud",)}, "TOKEN_WRONG_AUDIENCE"),
        ({"header": {"typ": "JWT"}}, "TOKEN_WRONG_TYPE"),
        ({"header": {"typ": None}}, "TOKEN_WRONG_TYPE"),
        ({"claims": {"exp": NOW - 120}}, "TOKEN_EXPIRED"),
        ({"claims": {"nbf": NOW + 120}}, "TOKEN_NOT_YET_VALID"),
        ({"claims": {"token_use": "test"}}, "TOKEN_TEST_TOKEN"),
        ({"claims": {"iss": "https://app.lumoauth.dev/orgs/other/api/v1"}}, "TOKEN_WRONG_ISSUER"),
        ({"drop": ("sub",)}, "TOKEN_MISSING_CLAIM"),
        ({"drop": ("exp",)}, "TOKEN_MISSING_CLAIM"),
        ({"kid": "nope"}, "TOKEN_UNKNOWN_KEY"),
    ],
)
def test_rejections(kwargs, code):
    with pytest.raises(LumoAuthTokenError) as e:
        verify(make_token(**kwargs))
    assert code_of(e) == code
    assert isinstance(e.value, ValueError)  # LumoAuthValidationError compatibility


def test_wrong_signature_and_key_confusion():
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(LumoAuthTokenError) as e:
        verify(make_token(key=other))
    assert code_of(e) == "TOKEN_BAD_SIGNATURE"

    # Tampered payload.
    token = make_token()
    h, p, s = token.split(".")
    tampered = b64url_encode(json.dumps({**json.loads(_b64d(p)), "scope": "admin"}).encode())
    with pytest.raises(LumoAuthTokenError) as e:
        verify(f"{h}.{tampered}.{s}")
    assert code_of(e) == "TOKEN_BAD_SIGNATURE"

    # alg says ES256 but the kid points at an RSA key.
    with pytest.raises(LumoAuthTokenError) as e:
        verify(make_token(key=EC_KEY, alg="ES256", kid="rsa-1"))
    assert code_of(e) in ("TOKEN_BAD_ALG", "TOKEN_BAD_SIGNATURE")


def _b64d(s: str) -> bytes:
    import base64

    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


@pytest.mark.parametrize("alg", ["none", "HS256"])
def test_none_and_hmac_are_rejected(alg):
    hdr = b64url_encode(json.dumps({"typ": "at+jwt", "alg": alg, "kid": "rsa-1"}).encode())
    body = b64url_encode(json.dumps({"iss": ISSUER, "sub": "x", "aud": RESOURCE, "exp": NOW + 60}).encode())
    with pytest.raises(LumoAuthTokenError) as e:
        verify(f"{hdr}.{body}.{b64url_encode(b'sig')}")
    assert code_of(e) == "TOKEN_BAD_ALG"


def test_malformed_tokens():
    for bad in ("", "a.b", "not-a-jwt", "a.b.c"):
        with pytest.raises(LumoAuthTokenError) as e:
            verify(bad)
        assert code_of(e) in ("TOKEN_MISSING", "TOKEN_MALFORMED")


# ── JWKS fetching ─────────────────────────────────────────────────────


def test_discovery_and_jwks_fetch_with_refetch_on_unknown_kid():
    calls = []
    new_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    documents = {
        f"{ISSUER}/.well-known/openid-configuration": {"issuer": ISSUER, "jwks_uri": f"{ISSUER}/.well-known/jwks.json"},
    }
    served = {"keys": [JWKS["keys"][0]]}

    def fetch(url):
        calls.append(url)
        if url.endswith("jwks.json"):
            return json.loads(json.dumps(served))
        return documents[url]

    verifier = AccessTokenVerifier(ISSUER, RESOURCE, fetch=fetch, clock=lambda: NOW)
    verifier.verify(make_token())
    assert calls == [f"{ISSUER}/.well-known/openid-configuration", f"{ISSUER}/.well-known/jwks.json"]
    assert verifier.jwks.jwks_uri == f"{ISSUER}/.well-known/jwks.json"

    # Cached: no refetch for a known kid.
    verifier.verify(make_token())
    assert len(calls) == 2

    # Rotated key: unknown kid triggers exactly one refetch.
    served["keys"].append(dict(public_jwk(new_key.public_key()), kid="rsa-2"))
    verifier.verify(make_token(key=new_key, kid="rsa-2"), now=NOW + 60)
    assert calls[-1].endswith("jwks.json") and len(calls) == 3

    # Still unknown after refetch: rate limited, one more fetch at most.
    with pytest.raises(LumoAuthTokenError) as e:
        verifier.verify(make_token(kid="ghost"), now=NOW + 120)
    assert code_of(e) == "TOKEN_UNKNOWN_KEY"
    assert len(calls) == 4


def test_discovery_falls_back_to_jwks_json_and_rejects_foreign_issuer():
    def fetch(url):
        if url.endswith("openid-configuration"):
            from lumoauth.errors import LumoAuthNotFoundError

            raise LumoAuthNotFoundError()
        assert url == f"{ISSUER}/.well-known/jwks.json"
        return JWKS

    cache = JwksCache(ISSUER, fetch=fetch)
    assert cache.key_for("rsa-1", now=NOW)["kid"] == "rsa-1"

    from lumoauth.errors import LumoAuthConfigError

    bad = JwksCache(ISSUER, fetch=lambda url: {"issuer": "https://evil", "jwks_uri": "https://evil/jwks"})
    with pytest.raises(LumoAuthConfigError):
        bad.key_for("rsa-1", now=NOW)


# ── DPoP binding ──────────────────────────────────────────────────────


def dpop_token(signer: DpopProofSigner, **claims: Any) -> str:
    return make_token({"cnf": {"jkt": signer.thumbprint}, **claims})


def test_dpop_bound_token_happy_path():
    signer = DpopProofSigner(DpopKey.generate())
    token = dpop_token(signer)
    proof = signer.create_proof("POST", f"{RESOURCE}?page=2", access_token=token, now=NOW - 10)
    claims = verify(token, dpop=DpopRequest("post", f"{RESOURCE}?page=2", proof))
    assert claims.is_dpop_bound and claims.dpop_thumbprint == signer.thumbprint


def test_dpop_bound_token_with_eddsa_key():
    signer = DpopProofSigner(DpopKey.generate("EdDSA"))
    token = dpop_token(signer)
    proof = signer.create_proof("POST", RESOURCE, access_token=token, now=NOW)
    assert verify(token, dpop=DpopRequest("POST", RESOURCE, proof)).is_dpop_bound


def test_dpop_bound_token_without_proof_or_with_bearer_scheme_is_rejected():
    signer = DpopProofSigner()
    token = dpop_token(signer)
    with pytest.raises(LumoAuthTokenError) as e:
        verify(token)
    assert code_of(e) == "DPOP_REQUIRED"
    assert e.value.www_authenticate.startswith('DPoP error="invalid_token"')

    with pytest.raises(LumoAuthTokenError) as e:
        verify(token, dpop=DpopRequest("POST", RESOURCE, None, scheme="DPoP"))
    assert code_of(e) == "DPOP_REQUIRED"

    proof = signer.create_proof("POST", RESOURCE, access_token=token, now=NOW)
    with pytest.raises(LumoAuthTokenError) as e:
        verify(token, dpop=DpopRequest("POST", RESOURCE, proof, scheme="Bearer"))
    assert code_of(e) == "DPOP_WRONG_SCHEME"


def test_require_dpop_rejects_unbound_tokens_and_dpop_scheme_on_bearer_token():
    with pytest.raises(LumoAuthTokenError) as e:
        verify(make_token(), require_dpop=True)
    assert code_of(e) == "DPOP_REQUIRED"
    with pytest.raises(LumoAuthTokenError) as e:
        verify(make_token(), dpop=DpopRequest("POST", RESOURCE, None, scheme="DPoP"))
    assert code_of(e) == "DPOP_NOT_BOUND"
    # A Bearer token presented as Bearer is fine even when the dependency passes request details.
    verify(make_token(), dpop=DpopRequest("POST", RESOURCE, None, scheme="Bearer"))


def test_dpop_proof_mismatches():
    signer = DpopProofSigner()
    token = dpop_token(signer)

    def check(proof: str, method="POST", url=RESOURCE, nonce=None):
        with pytest.raises(LumoAuthTokenError) as e:
            verify(token, dpop=DpopRequest(method, url, proof, nonce=nonce))
        return e.value

    # Wrong key.
    other = DpopProofSigner()
    assert check(other.create_proof("POST", RESOURCE, access_token=token, now=NOW)).code == "DPOP_KEY_MISMATCH"
    # htm / htu mismatch.
    assert check(signer.create_proof("GET", RESOURCE, access_token=token, now=NOW)).code == "DPOP_INVALID"
    assert check(signer.create_proof("POST", "https://mcp.example.com/other", access_token=token, now=NOW)).code == "DPOP_INVALID"
    # ath for a different token, or missing.
    assert check(signer.create_proof("POST", RESOURCE, access_token="other-token", now=NOW)).code == "DPOP_INVALID"
    assert check(signer.create_proof("POST", RESOURCE, now=NOW)).code == "DPOP_INVALID"
    # iat outside the window.
    assert check(signer.create_proof("POST", RESOURCE, access_token=token, now=NOW - 400)).code == "DPOP_INVALID"
    assert check(signer.create_proof("POST", RESOURCE, access_token=token, now=NOW + 120)).code == "DPOP_INVALID"
    # Expected nonce missing / stale.
    assert check(signer.create_proof("POST", RESOURCE, access_token=token, now=NOW), nonce="n1").code == "DPOP_USE_NONCE"
    assert check(signer.create_proof("POST", RESOURCE, access_token=token, now=NOW, nonce="old"), nonce="n1").code == "DPOP_USE_NONCE"
    ok = signer.create_proof("POST", RESOURCE, access_token=token, now=NOW, nonce="n1")
    verify(token, dpop=DpopRequest("POST", RESOURCE, ok, nonce="n1"))
    # Wrong typ, and a proof whose jwk leaks a private member.
    bad_typ = signer.create_proof("POST", RESOURCE, access_token=token, now=NOW)
    h, p, s = bad_typ.split(".")
    hdr = json.loads(_b64d(h))
    hdr["typ"] = "JWT"
    assert check(f"{b64url_encode(json.dumps(hdr).encode())}.{p}.{s}").code == "DPOP_INVALID"
    hdr = json.loads(_b64d(h))
    hdr["jwk"]["d"] = "secret"
    assert check(f"{b64url_encode(json.dumps(hdr).encode())}.{p}.{s}").code == "DPOP_INVALID"
    garbage = check("garbage")
    assert garbage.code == "DPOP_INVALID" and garbage.error == "invalid_dpop_proof"
    assert garbage.www_authenticate.startswith('DPoP error="invalid_dpop_proof"')


def test_replayed_jti_is_rejected_and_cache_is_pluggable():
    signer = DpopProofSigner()
    token = dpop_token(signer)
    proof = signer.create_proof("POST", RESOURCE, access_token=token, now=NOW)
    cache = InMemoryReplayCache()
    verifier = AccessTokenVerifier(ISSUER, RESOURCE, jwks=JWKS, replay_cache=cache, clock=lambda: NOW)
    verifier.verify(token, dpop=DpopRequest("POST", RESOURCE, proof))
    with pytest.raises(LumoAuthTokenError) as e:
        verifier.verify(token, dpop=DpopRequest("POST", RESOURCE, proof))
    assert code_of(e) == "DPOP_REPLAYED"

    # A fresh proof from the same key passes.
    verifier.verify(token, dpop=DpopRequest("POST", RESOURCE, signer.create_proof("POST", RESOURCE, access_token=token, now=NOW)))

    # Custom cache that never remembers anything: the same proof passes twice.
    class Forgetful:
        def check_and_add(self, key, ttl):
            return False

    loose = AccessTokenVerifier(ISSUER, RESOURCE, jwks=JWKS, replay_cache=Forgetful(), clock=lambda: NOW)
    loose.verify(token, dpop=DpopRequest("POST", RESOURCE, proof))
    loose.verify(token, dpop=DpopRequest("POST", RESOURCE, proof))


def test_in_memory_replay_cache_expires_entries():
    cache = InMemoryReplayCache()
    assert cache.check_and_add("a", 10, now=100) is False
    assert cache.check_and_add("a", 10, now=105) is True
    assert cache.check_and_add("a", 10, now=111) is False


def test_module_level_function_caches_verifier_per_issuer_and_resource(monkeypatch):
    from lumoauth import verify as verify_module

    monkeypatch.setattr(verify_module, "_verifiers", {})
    fetches = []

    def fake_get(self, url, *a, **k):
        fetches.append(url)
        return {"keys": JWKS["keys"]} if url.endswith("jwks.json") else {"jwks_uri": f"{ISSUER}/.well-known/jwks.json"}

    monkeypatch.setattr(verify_module.JwksCache, "_get", fake_get)
    verify_access_token(make_token(), issuer=ISSUER, resource=RESOURCE, now=NOW)
    verify_access_token(make_token(), issuer=ISSUER, resource=RESOURCE, now=NOW)
    assert len(fetches) == 2
    assert len(verify_module._verifiers) == 1


def test_real_clock_default_works():
    token = make_token({"exp": int(time.time()) + 300, "nbf": int(time.time()) - 5, "iat": int(time.time()) - 5})
    assert verify_access_token(token, issuer=ISSUER, resource=RESOURCE, jwks=JWKS).sub

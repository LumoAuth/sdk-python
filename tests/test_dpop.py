"""DPoP proof signing (RFC 9449): proof shape, thumbprints, nonce retry, agent wiring."""

from __future__ import annotations

import base64
import hashlib
import json

import pytest

pytest.importorskip(
    "cryptography",
    reason="DPoP tests need the 'cryptography' package (pip install -e '.[dev]')",
)

from lumoauth import LumoAuth, LumoAuthAgent  # noqa: E402
from lumoauth._jose import jwk_thumbprint, public_key_from_jwk, split_jws, verify  # noqa: E402
from lumoauth.dpop import (  # noqa: E402
    DpopKey,
    DpopProofSigner,
    access_token_hash,
    canonical_htu,
    wants_new_nonce,
)
from lumoauth.errors import LumoAuthApiError, LumoAuthConfigError, LumoAuthValidationError  # noqa: E402
from conftest import FakeResponse, FakeSession  # noqa: E402

BASE_URL = "https://auth.example.com"
ORG = "acme-corp"
TOKEN_URL = f"{BASE_URL}/orgs/{ORG}/api/v1/oauth/token"
MCP_URL = "https://mcp.example.com/mcp"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


# ── Thumbprints ───────────────────────────────────────────────────────


def test_rfc7638_rsa_vector():
    # RFC 7638 §3.1 example key and its thumbprint.
    jwk = {
        "kty": "RSA",
        "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
        "e": "AQAB",
        "alg": "RS256",
        "kid": "2011-04-29",
    }
    assert jwk_thumbprint(jwk) == "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"


def test_ec_thumbprint_uses_canonical_members_only():
    key = DpopKey.generate()
    jwk = dict(key.public_jwk, kid="ignored", alg="ES256", use="sig")
    canonical = json.dumps(
        {"crv": "P-256", "kty": "EC", "x": jwk["x"], "y": jwk["y"]},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    assert jwk_thumbprint(jwk) == _b64url(hashlib.sha256(canonical).digest())
    assert key.thumbprint == jwk_thumbprint(jwk)


def test_ed25519_thumbprint_members():
    key = DpopKey.generate("EdDSA")
    assert set(key.public_jwk) == {"kty", "crv", "x"}
    assert key.public_jwk["crv"] == "Ed25519"
    canonical = json.dumps(
        {"crv": "Ed25519", "kty": "OKP", "x": key.public_jwk["x"]},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    assert key.thumbprint == _b64url(hashlib.sha256(canonical).digest())


# ── Proof shape ───────────────────────────────────────────────────────


@pytest.mark.parametrize("alg", ["ES256", "EdDSA"])
def test_proof_shape_and_signature(alg):
    signer = DpopProofSigner(DpopKey.generate(alg))
    proof = signer.create_proof("post", f"{MCP_URL}?x=1#frag", access_token="tok", now=1_700_000_000)
    header, claims, signing_input, signature = split_jws(proof)

    assert header["typ"] == "dpop+jwt"
    assert header["alg"] == alg
    assert header["jwk"] == signer.key.public_jwk
    assert "d" not in header["jwk"]
    assert len(claims["jti"]) >= 16
    assert claims["htm"] == "POST"
    assert claims["htu"] == MCP_URL
    assert claims["iat"] == 1_700_000_000
    assert claims["ath"] == _b64url(hashlib.sha256(b"tok").digest())
    assert "nonce" not in claims
    assert verify(public_key_from_jwk(header["jwk"]), alg, signing_input, signature)


def test_es256_signature_is_raw_r_s_not_der():
    signer = DpopProofSigner(DpopKey.generate("ES256"))
    _, _, _, signature = split_jws(signer.create_proof("GET", MCP_URL))
    assert len(signature) == 64
    assert signature[0] != 0x30 or len(signature) == 64  # not a DER SEQUENCE of variable length


def test_proof_without_token_has_no_ath_and_each_proof_has_fresh_jti():
    signer = DpopProofSigner()
    a = split_jws(signer.create_proof("POST", TOKEN_URL))[1]
    b = split_jws(signer.create_proof("POST", TOKEN_URL))[1]
    assert "ath" not in a
    assert a["jti"] != b["jti"]


def test_nonce_memory_is_per_origin():
    signer = DpopProofSigner()
    signer.remember_nonce(TOKEN_URL, "n-auth")
    assert signer.nonce_for(f"{BASE_URL}/other/path") == "n-auth"
    assert signer.nonce_for(MCP_URL) is None
    claims = split_jws(signer.create_proof("POST", TOKEN_URL))[1]
    assert claims["nonce"] == "n-auth"
    claims = split_jws(signer.create_proof("POST", TOKEN_URL, nonce="explicit"))[1]
    assert claims["nonce"] == "explicit"
    signer.observe_response(MCP_URL, {"dpop-nonce": "n-mcp"})
    assert signer.nonce_for(MCP_URL) == "n-mcp"


def test_headers_helper():
    signer = DpopProofSigner()
    headers = signer.headers("POST", MCP_URL, "tok")
    assert headers["Authorization"] == "DPoP tok"
    assert split_jws(headers["DPoP"])[1]["ath"] == access_token_hash("tok")
    assert "Authorization" not in signer.headers("POST", TOKEN_URL)


def test_canonical_htu():
    assert canonical_htu("HTTPS://MCP.Example.com:8443/a/b?x=1#f") == "https://mcp.example.com:8443/a/b"
    assert canonical_htu("https://mcp.example.com") == "https://mcp.example.com/"
    with pytest.raises(LumoAuthValidationError):
        canonical_htu("/relative")


def test_key_round_trips_through_pem():
    key = DpopKey.generate()
    again = DpopKey.from_pem(key.to_pem())
    assert again.thumbprint == key.thumbprint
    assert again.alg == "ES256"
    with pytest.raises(LumoAuthValidationError):
        DpopKey.generate("HS256")


def test_wants_new_nonce():
    assert wants_new_nonce(400, {"DPoP-Nonce": "n"}, {"error": "use_dpop_nonce"})
    assert wants_new_nonce(401, {"dpop-nonce": "n", "WWW-Authenticate": 'DPoP error="use_dpop_nonce"'}, None)
    assert not wants_new_nonce(400, {}, {"error": "use_dpop_nonce"})
    assert not wants_new_nonce(400, {"DPoP-Nonce": "n"}, {"error": "invalid_client"})


# ── Token endpoint: nonce retry through the fake transport ────────────


@pytest.fixture()
def agent(fake_session: FakeSession) -> LumoAuthAgent:
    return LumoAuthAgent(
        base_url=BASE_URL, org_id=ORG, client_id="agt_1", client_secret="s", dpop=True
    )


def test_client_credentials_sends_dpop_proof_and_retries_once_on_use_dpop_nonce(agent, fake_session):
    fake_session.queue(
        FakeResponse(400, {"error": "use_dpop_nonce"}, headers={"DPoP-Nonce": "server-nonce-1"}),
        FakeResponse(
            200,
            {"access_token": "at", "token_type": "DPoP", "expires_in": 3600, "scope": "a b"},
            headers={"DPoP-Nonce": "server-nonce-2"},
        ),
    )
    assert agent.authenticate() is True
    assert agent.token_type == "DPoP"
    assert len(fake_session.calls) == 2

    first, second = fake_session.calls
    assert first[1] == TOKEN_URL and second[1] == TOKEN_URL
    assert "Authorization" not in first[2]["headers"]
    c1 = split_jws(first[2]["headers"]["DPoP"])[1]
    c2 = split_jws(second[2]["headers"]["DPoP"])[1]
    assert c1["htu"] == TOKEN_URL and c1["htm"] == "POST" and "ath" not in c1
    assert "nonce" not in c1
    assert c2["nonce"] == "server-nonce-1"
    assert c1["jti"] != c2["jti"]
    # The latest nonce is remembered for the next proof to that origin.
    assert agent.dpop.nonce_for(TOKEN_URL) == "server-nonce-2"


def test_use_dpop_nonce_is_retried_only_once(agent, fake_session):
    fake_session.queue(
        FakeResponse(400, {"error": "use_dpop_nonce"}, headers={"DPoP-Nonce": "n1"}),
        FakeResponse(400, {"error": "use_dpop_nonce"}, headers={"DPoP-Nonce": "n2"}),
    )
    assert agent.authenticate() is False
    assert len(fake_session.calls) == 2


def test_api_requests_use_dpop_scheme_with_ath_after_dpop_authentication(agent, fake_session):
    fake_session.queue(
        FakeResponse(200, {"access_token": "at", "token_type": "DPoP", "expires_in": 3600}),
        FakeResponse(200, {"allowed": True, "action": "x"}),
    )
    agent.authenticate()
    agent.ask("x")
    method, url, kwargs = fake_session.last
    assert kwargs["headers"]["Authorization"] == "DPoP at"
    claims = split_jws(kwargs["headers"]["DPoP"])[1]
    assert claims["htm"] == "POST"
    assert claims["htu"] == url
    assert claims["ath"] == access_token_hash("at")


def test_bearer_answer_keeps_bearer_scheme(agent, fake_session):
    fake_session.queue(
        FakeResponse(200, {"access_token": "at", "token_type": "Bearer", "expires_in": 3600}),
        FakeResponse(200, {"allowed": True}),
    )
    agent.authenticate()
    assert agent.token_type == "Bearer"
    agent.ask("x")
    assert fake_session.last[2]["headers"]["Authorization"] == "Bearer at"
    assert "DPoP" not in fake_session.last[2]["headers"]


def test_mcp_exchange_sends_proof_and_surfaces_token_type(agent, fake_session):
    fake_session.queue(
        FakeResponse(200, {"access_token": "at", "token_type": "DPoP", "expires_in": 3600}),
        FakeResponse(
            200,
            {"access_token": "mcp-at", "token_type": "DPoP", "expires_in": 600, "scope": "tools:read"},
        ),
    )
    agent.authenticate()
    cred = agent.get_mcp_credential(MCP_URL)
    assert cred.access_token == "mcp-at"
    assert cred.token_type == "DPoP" and cred.is_dpop
    assert cred.expires_in == 600 and cred.scope == "tools:read" and cred.resource == MCP_URL

    method, url, kwargs = fake_session.last
    assert url == TOKEN_URL
    assert kwargs["data"]["grant_type"] == "urn:ietf:params:oauth:grant-type:token-exchange"
    assert kwargs["data"]["subject_token"] == "at"
    assert kwargs["data"]["resource"] == MCP_URL
    assert "Authorization" not in kwargs["headers"]
    proof = split_jws(kwargs["headers"]["DPoP"])[1]
    assert proof["htu"] == TOKEN_URL and "ath" not in proof

    headers = cred.headers("POST", MCP_URL)
    assert headers["Authorization"] == "DPoP mcp-at"
    assert split_jws(headers["DPoP"])[1]["ath"] == access_token_hash("mcp-at")
    assert split_jws(headers["DPoP"])[0]["jwk"] == agent.dpop.key.public_jwk


def test_get_mcp_token_still_returns_the_string_or_none(agent, fake_session):
    fake_session.queue(
        FakeResponse(200, {"access_token": "at", "token_type": "DPoP", "expires_in": 3600}),
        FakeResponse(200, {"access_token": "mcp-at", "token_type": "DPoP"}),
        FakeResponse(400, {"error": "invalid_target"}),
        FakeResponse(400, {"error": "invalid_target"}),
    )
    agent.authenticate()
    assert agent.get_mcp_token(MCP_URL) == "mcp-at"
    assert agent.get_mcp_token(MCP_URL) is None
    with pytest.raises(LumoAuthApiError):
        agent.get_mcp_credential(MCP_URL)


def test_dpop_headers_and_proof_for_unwrapped_endpoints(agent, fake_session):
    fake_session.queue(FakeResponse(200, {"access_token": "at", "token_type": "DPoP"}))
    attest_url = f"{BASE_URL}/orgs/{ORG}/api/v1/agents/agt_1/attest"
    headers = agent.dpop_headers("POST", attest_url)
    assert headers["Authorization"] == "DPoP at"
    claims = split_jws(headers["DPoP"])[1]
    assert claims["htu"] == attest_url and claims["ath"] == access_token_hash("at")
    bare = split_jws(agent.dpop_proof("POST", attest_url))[1]
    assert "ath" not in bare


def test_agent_without_dpop_refuses_dpop_helpers(fake_session):
    plain = LumoAuthAgent(base_url=BASE_URL, org_id=ORG, client_id="agt_1", client_secret="s")
    assert plain.dpop is None
    with pytest.raises(LumoAuthConfigError):
        plain.dpop_headers("POST", MCP_URL)
    with pytest.raises(LumoAuthConfigError):
        LumoAuthAgent(base_url=BASE_URL, org_id=ORG, client_id="a", client_secret="s", dpop="yes")


def test_agent_accepts_a_key_or_a_signer(fake_session):
    key = DpopKey.generate("EdDSA")
    a = LumoAuthAgent(base_url=BASE_URL, org_id=ORG, client_id="a", client_secret="s", dpop=key)
    assert a.dpop.key is key
    signer = DpopProofSigner(key)
    b = LumoAuthAgent(base_url=BASE_URL, org_id=ORG, client_id="a", client_secret="s", dpop=signer)
    assert b.dpop is signer


def test_plain_client_mcp_get_token_with_dpop_signer(fake_session):
    client = LumoAuth(base_url=BASE_URL, org_id=ORG, token_provider=lambda: "subject")
    signer = DpopProofSigner()
    fake_session.queue(FakeResponse(200, {"access_token": "mcp-at", "token_type": "DPoP"}))
    assert client.mcp.get_token(MCP_URL, dpop=signer) == "mcp-at"
    _, url, kwargs = fake_session.last
    assert url == TOKEN_URL
    assert split_jws(kwargs["headers"]["DPoP"])[0]["jwk"] == signer.key.public_jwk

    fake_session.queue(FakeResponse(200, {"access_token": "plain", "token_type": "Bearer"}))
    cred = client.mcp.exchange(MCP_URL)
    assert cred.token_type == "Bearer" and cred.headers("GET", MCP_URL) == {"Authorization": "Bearer plain"}
    assert "DPoP" not in fake_session.last[2]["headers"]

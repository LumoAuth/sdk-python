"""The FastAPI ``require_access_token`` dependency (skipped without fastapi)."""

from __future__ import annotations

import json
from typing import Any, Dict

import pytest

pytest.importorskip("cryptography", reason="needs cryptography")
pytest.importorskip("fastapi", reason="needs fastapi")
pytest.importorskip("httpx", reason="FastAPI's TestClient needs httpx")

from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from fastapi import Depends, FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from lumoauth._jose import b64url_encode, public_jwk, sign  # noqa: E402
from lumoauth.dpop import DpopProofSigner  # noqa: E402
from lumoauth.fastapi import AccessTokenClaims, parse_authorization, require_access_token  # noqa: E402

ISSUER = "https://app.lumoauth.dev/orgs/acme/api/v1"
RESOURCE = "http://testserver/mcp"
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
JWKS = {"keys": [dict(public_jwk(KEY.public_key()), kid="k1")]}


def make_token(**extra: Any) -> str:
    import time

    body: Dict[str, Any] = {
        "iss": ISSUER,
        "sub": "agent_agt_1",
        "aud": RESOURCE,
        "exp": int(time.time()) + 300,
        "scope": "tools:read",
        "is_agent": True,
    }
    body.update(extra)
    h = b64url_encode(json.dumps({"typ": "at+jwt", "alg": "RS256", "kid": "k1"}).encode())
    p = b64url_encode(json.dumps(body).encode())
    return f"{h}.{p}.{b64url_encode(sign(KEY, 'RS256', f'{h}.{p}'.encode()))}"


@pytest.fixture()
def client() -> TestClient:
    app = FastAPI()
    auth = require_access_token(issuer=ISSUER, resource=RESOURCE, jwks=JWKS)
    writer = require_access_token(issuer=ISSUER, resource=RESOURCE, jwks=JWKS, scopes=["tools:write"])

    @app.post("/mcp")
    def mcp(claims: AccessTokenClaims = Depends(auth)):
        return {"sub": claims.sub, "scopes": list(claims.scopes), "dpop": claims.is_dpop_bound}

    @app.post("/write")
    def write(claims: AccessTokenClaims = Depends(writer)):
        return {"ok": True}

    return TestClient(app)


def test_parse_authorization():
    assert parse_authorization("Bearer abc") == ("Bearer", "abc")
    assert parse_authorization("dpop abc") == ("DPoP", "abc")
    assert parse_authorization("Basic abc") == (None, None)
    assert parse_authorization(None) == (None, None)


def test_bearer_token_is_accepted(client):
    r = client.post("/mcp", headers={"Authorization": f"Bearer {make_token()}"})
    assert r.status_code == 200, r.text
    assert r.json() == {"sub": "agent_agt_1", "scopes": ["tools:read"], "dpop": False}


def test_missing_and_invalid_tokens_answer_401_with_challenge(client):
    r = client.post("/mcp")
    assert r.status_code == 401
    assert r.headers["WWW-Authenticate"].startswith("Bearer ")

    r = client.post("/mcp", headers={"Authorization": f"Bearer {make_token(aud='https://other')}"})
    assert r.status_code == 401
    assert r.json()["detail"]["code"] == "TOKEN_WRONG_AUDIENCE"
    assert 'error="invalid_token"' in r.headers["WWW-Authenticate"]

    r = client.post("/mcp", headers={"Authorization": f"Bearer {make_token(token_use='test')}"})
    assert r.status_code == 401
    assert r.json()["detail"]["code"] == "TOKEN_TEST_TOKEN"


def test_missing_scope_answers_403(client):
    r = client.post("/write", headers={"Authorization": f"Bearer {make_token()}"})
    assert r.status_code == 403
    assert r.json()["detail"]["error"] == "insufficient_scope"


def test_dpop_bound_token_needs_a_matching_proof(client):
    signer = DpopProofSigner()
    token = make_token(cnf={"jkt": signer.thumbprint})

    # Presented as Bearer without a proof: refused with a DPoP challenge.
    r = client.post("/mcp", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401
    assert r.headers["WWW-Authenticate"].startswith("DPoP ")
    assert r.json()["detail"]["code"] == "DPOP_WRONG_SCHEME"

    # Proper DPoP request.
    headers = signer.headers("POST", RESOURCE, token)
    r = client.post("/mcp", headers=headers)
    assert r.status_code == 200, r.text
    assert r.json()["dpop"] is True

    # Replaying the same proof fails.
    r = client.post("/mcp", headers=headers)
    assert r.status_code == 401
    assert r.json()["detail"]["code"] == "DPOP_REPLAYED"

    # A proof for another URL fails.
    r = client.post("/mcp", headers=signer.headers("POST", "http://testserver/other", token))
    assert r.status_code == 401
    assert r.json()["detail"]["code"] == "DPOP_INVALID"

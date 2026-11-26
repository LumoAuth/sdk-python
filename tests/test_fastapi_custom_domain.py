"""Custom domains in the FastAPI integration (skipped without fastapi)."""

from __future__ import annotations

import json
from typing import Any, Dict
from urllib.parse import parse_qs, urlsplit

import pytest

pytest.importorskip("fastapi", reason="needs fastapi")
pytest.importorskip("httpx", reason="FastAPI's TestClient needs httpx")

from fastapi import Depends, FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from conftest import FakeResponse, FakeSession  # noqa: E402
from lumoauth import LumoAuth, PoppyVerification  # noqa: E402
from lumoauth.errors import LumoAuthConfigError  # noqa: E402
from lumoauth.fastapi import (  # noqa: E402
    AccessTokenClaims,
    LumoAuthFastAPI,
    LumoAuthPoppy,
    lumo_auth_router,
    require_access_token,
)

DOMAIN = "https://auth.acme.com"
PLATFORM = "https://app.lumoauth.dev"
ORG = "acme-corp"
PLATFORM_ISSUER = f"{PLATFORM}/orgs/{ORG}/api/v1"
RESOURCE = "http://testserver/mcp"


class MemorySession:
    """Stands in for Starlette's SessionMiddleware: one session, kept in memory."""

    def __init__(self, app: Any) -> None:
        self.app = app
        self.store: Dict[str, Any] = {}

    async def __call__(self, scope: Dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] == "http":
            scope["session"] = self.store
        await self.app(scope, receive, send)


def _sign_in_app(**router_options: Any) -> TestClient:
    app = FastAPI()
    app.include_router(lumo_auth_router(client_id="web-app", client_secret="s", **router_options), prefix="/auth")
    return TestClient(MemorySession(app), follow_redirects=False)


# ── Sign-in routes ────────────────────────────────────────────────────


def test_sign_in_flow_uses_the_custom_domain(fake_session: FakeSession):
    client = _sign_in_app(custom_domain="auth.acme.com")

    r = client.get("/auth/login")
    assert r.status_code == 302
    location = urlsplit(r.headers["location"])
    assert f"{location.scheme}://{location.netloc}{location.path}" == DOMAIN + "/api/v1/oauth/authorize"
    state = parse_qs(location.query)["state"][0]

    fake_session.queue(
        FakeResponse(200, {"access_token": "at", "token_type": "Bearer", "scope": "openid"}),
        FakeResponse(200, {"sub": "user-1", "email": "a@acme.com"}),
    )
    r = client.get(f"/auth/callback?code=abc&state={state}")
    assert r.status_code == 302, r.text
    assert [url for _, url, _ in fake_session.calls] == [
        DOMAIN + "/api/v1/oauth/token",
        DOMAIN + "/api/v1/oauth/userinfo",
    ]


def test_sign_in_flow_without_a_custom_domain_is_unchanged(fake_session: FakeSession):
    client = _sign_in_app(base_url=PLATFORM + "/", organization=ORG)
    r = client.get("/auth/login")
    location = urlsplit(r.headers["location"])
    assert f"{location.scheme}://{location.netloc}{location.path}" == PLATFORM_ISSUER + "/oauth/authorize"
    state = parse_qs(location.query)["state"][0]
    fake_session.queue(FakeResponse(200, {"access_token": "at"}), FakeResponse(200, {"sub": "user-1"}))
    assert client.get(f"/auth/callback?code=abc&state={state}").status_code == 302
    assert [url for _, url, _ in fake_session.calls] == [
        PLATFORM_ISSUER + "/oauth/token",
        PLATFORM_ISSUER + "/oauth/userinfo",
    ]


def test_configuration_addresses_in_both_forms():
    custom = LumoAuthFastAPI(client_id="web-app", custom_domain="https://Auth.Acme.com/")
    assert custom.custom_domain == DOMAIN and custom.base_url == DOMAIN
    assert custom.authorize_url() == DOMAIN + "/api/v1/oauth/authorize"
    assert custom.token_url() == DOMAIN + "/api/v1/oauth/token"
    assert custom.userinfo_url() == DOMAIN + "/api/v1/oauth/userinfo"

    # A base URL and an organization given too are not used.
    both = LumoAuthFastAPI(PLATFORM, ORG, "web-app", custom_domain="auth.acme.com")
    assert both.authorize_url() == DOMAIN + "/api/v1/oauth/authorize"

    platform = LumoAuthFastAPI(PLATFORM, ORG, "web-app")
    assert platform.custom_domain is None
    assert platform.authorize_url() == PLATFORM_ISSUER + "/oauth/authorize"
    assert platform.token_url() == PLATFORM_ISSUER + "/oauth/token"
    assert platform.userinfo_url() == PLATFORM_ISSUER + "/oauth/userinfo"


def test_configuration_errors_are_raised_when_the_helper_is_created():
    with pytest.raises(LumoAuthConfigError):
        lumo_auth_router(client_id="web-app", custom_domain="https://auth.acme.com/orgs/acme-corp")
    with pytest.raises(LumoAuthConfigError):
        lumo_auth_router(client_id="web-app")  # neither a custom domain nor base_url + organization
    with pytest.raises(LumoAuthConfigError):
        lumo_auth_router(client_id="web-app", base_url=PLATFORM)
    with pytest.raises(LumoAuthConfigError):
        LumoAuthFastAPI(PLATFORM, ORG, "")
    with pytest.raises(LumoAuthConfigError):
        require_access_token(resource=RESOURCE, custom_domain="http://auth.acme.com")
    with pytest.raises(LumoAuthConfigError):
        require_access_token(resource=RESOURCE)
    with pytest.raises(LumoAuthConfigError):
        require_access_token(issuer=PLATFORM_ISSUER, resource=RESOURCE, custom_domain="auth.acme.com")


# ── Resource server: require_access_token ─────────────────────────────


def test_require_access_token_accepts_only_the_custom_domain_issuer():
    pytest.importorskip("cryptography")
    import time

    from cryptography.hazmat.primitives.asymmetric import ec

    from lumoauth._jose import b64url_encode, public_jwk, sign

    key = ec.generate_private_key(ec.SECP256R1())
    jwks = {"keys": [dict(public_jwk(key.public_key()), kid="k1")]}

    def token(issuer: str) -> str:
        h = b64url_encode(json.dumps({"typ": "at+jwt", "alg": "ES256", "kid": "k1"}).encode())
        p = b64url_encode(
            json.dumps({"iss": issuer, "sub": "user-1", "aud": RESOURCE, "exp": int(time.time()) + 300}).encode()
        )
        return f"{h}.{p}.{b64url_encode(sign(key, 'ES256', f'{h}.{p}'.encode()))}"

    app = FastAPI()
    auth = require_access_token(resource=RESOURCE, custom_domain="auth.acme.com", jwks=jwks)

    @app.post("/mcp")
    def mcp(claims: AccessTokenClaims = Depends(auth)):
        return {"iss": claims.iss}

    client = TestClient(app)
    r = client.post("/mcp", headers={"Authorization": f"Bearer {token(DOMAIN)}"})
    assert r.status_code == 200 and r.json() == {"iss": DOMAIN}

    r = client.post("/mcp", headers={"Authorization": f"Bearer {token(PLATFORM_ISSUER)}"})
    assert r.status_code == 401
    assert r.json()["detail"]["code"] == "TOKEN_WRONG_ISSUER"


# ── Personal Agent Protocol helper ────────────────────────────────────


def test_poppy_helper_asks_lumoauth_on_the_custom_domain(fake_session: FakeSession):
    lumo = LumoAuth(custom_domain="auth.acme.com", client_id="shop-api", client_secret="s3cr3t")
    poppy = LumoAuthPoppy(lumo, public_origin="https://shop.example.com")
    app = FastAPI()
    poppy.install(app)

    @app.get("/api/catalog")
    def catalog(who: PoppyVerification = Depends(poppy.session())):
        return {"session": who.session.id}

    fake_session.queue(
        FakeResponse(
            200,
            {
                "active": True,
                "client_id": "https://agent.example/agent.json",
                "client_name": "Example Agent",
                "user_id": "usr_Q7c1vK",
                "agent_id": None,
                "session": {"id": 4821, "sid": "Yx2b", "new": True, "started_at": "2026-11-26T10:15:00+00:00"},
                "signed_in": False,
                "account": None,
                "version": "1.0",
                "extensions": {},
            },
        )
    )
    r = TestClient(app).get("/api/catalog", headers={"Poppy-Session": "s.jwt", "Poppy-Version": "1.0"})
    assert r.status_code == 200 and r.json() == {"session": 4821}
    method, url, kw = fake_session.last
    assert (method, url) == ("POST", DOMAIN + "/api/v1/poppy/sessions/verify")
    # The URL of the personal agent's request still comes from public_origin.
    assert kw["json"]["url"] == "https://shop.example.com/api/catalog"

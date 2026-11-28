"""Sign-in routes of the FastAPI integration: sign-out, session content, refresh.

Skipped without fastapi and httpx.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any, Dict
from urllib.parse import parse_qs, urlsplit

import pytest

pytest.importorskip("fastapi", reason="needs fastapi")
pytest.importorskip("httpx", reason="FastAPI's TestClient needs httpx")

from fastapi import Depends, FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from starlette.middleware.sessions import SessionMiddleware  # noqa: E402

from conftest import FakeResponse, FakeSession  # noqa: E402
from lumoauth import LumoAuth  # noqa: E402
from lumoauth.errors import LumoAuthNetworkError  # noqa: E402
from lumoauth.fastapi import LumoAuthFastAPI, lumo_auth_router  # noqa: E402

PLATFORM = "https://app.lumoauth.dev"
ORG = "acme-corp"
ISSUER = f"{PLATFORM}/orgs/{ORG}/api/v1"
END_SESSION = ISSUER + "/oauth/logout"


class MemorySession:
    """Stands in for Starlette's SessionMiddleware: one session, kept in memory."""

    def __init__(self, app: Any) -> None:
        self.app = app
        self.store: Dict[str, Any] = {}

    async def __call__(self, scope: Dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] in ("http", "websocket"):
            scope["session"] = self.store
        await self.app(scope, receive, send)


def _config(**options: Any) -> LumoAuthFastAPI:
    return LumoAuthFastAPI(
        base_url=PLATFORM, organization=ORG, client_id="web-app", client_secret="s3cr3t", **options
    )


def _app(cfg: LumoAuthFastAPI):
    app = FastAPI()
    app.include_router(cfg.router(), prefix="/auth")

    @app.get("/api/token")
    def token(access_token: str = Depends(cfg.access_token)):
        return {"access_token": access_token}

    session = MemorySession(app)
    return session, TestClient(session, follow_redirects=False)


TOKENS = {
    "access_token": "at-1",
    "refresh_token": "rt-1",
    "id_token": "id-1",
    "token_type": "Bearer",
    "scope": "openid profile email",
    "expires_in": 3600,
}


def _sign_in(client: TestClient, fake_session: FakeSession, tokens: Dict[str, Any] = TOKENS) -> None:
    r = client.get("/auth/login")
    state = parse_qs(urlsplit(r.headers["location"]).query)["state"][0]
    fake_session.queue(FakeResponse(200, tokens), FakeResponse(200, {"sub": "user-1", "email": "a@acme.com"}))
    r = client.get(f"/auth/callback?code=abc&state={state}")
    assert r.status_code == 302, r.text
    fake_session.calls.clear()


# ── End-session URL ───────────────────────────────────────────────────


def test_end_session_url_carries_the_hint_and_the_redirect():
    client = LumoAuth(base_url=PLATFORM, org_id=ORG, api_key="k")
    url = client.auth.end_session_url(
        id_token_hint="eyJ.id.token", post_logout_redirect_uri="https://app.example.com/bye", state="xyz"
    )
    parts = urlsplit(url)
    assert f"{parts.scheme}://{parts.netloc}{parts.path}" == END_SESSION
    assert parse_qs(parts.query) == {
        "id_token_hint": ["eyJ.id.token"],
        "post_logout_redirect_uri": ["https://app.example.com/bye"],
        "state": ["xyz"],
    }
    assert client.auth.end_session_url() == END_SESSION


def test_end_session_url_on_a_custom_domain():
    client = LumoAuth(custom_domain="auth.acme.com", api_key="k")
    assert client.auth.end_session_url(id_token_hint="t") == "https://auth.acme.com/api/v1/oauth/logout?id_token_hint=t"
    cfg = LumoAuthFastAPI(client_id="web-app", custom_domain="auth.acme.com")
    assert cfg.end_session_url() == "https://auth.acme.com/api/v1/oauth/logout"


# ── Sign-out ──────────────────────────────────────────────────────────


def test_logout_ends_the_lumoauth_session(fake_session: FakeSession):
    session, client = _app(_config())
    _sign_in(client, fake_session)
    session.store["other"] = "kept"

    r = client.get("/auth/logout")
    assert r.status_code == 302
    location = urlsplit(r.headers["location"])
    assert f"{location.scheme}://{location.netloc}{location.path}" == END_SESSION
    # A relative post_logout_redirect is made absolute with the request's address.
    assert parse_qs(location.query) == {
        "id_token_hint": ["id-1"],
        "post_logout_redirect_uri": ["http://testserver/"],
    }
    # The refresh token was revoked, with the client's credentials.
    method, url, kw = fake_session.last
    assert (method, url) == ("POST", ISSUER + "/oauth/revoke")
    assert kw["data"] == {
        "token": "rt-1",
        "token_type_hint": "refresh_token",
        "client_id": "web-app",
        "client_secret": "s3cr3t",
    }
    # Only the LumoAuth state is gone.
    assert session.store == {"other": "kept"}


def test_logout_by_post_keeps_an_absolute_redirect(fake_session: FakeSession):
    session, client = _app(_config(post_logout_redirect="https://app.example.com/signed-out"))
    _sign_in(client, fake_session)
    r = client.post("/auth/logout")
    assert r.status_code == 302
    query = parse_qs(urlsplit(r.headers["location"]).query)
    assert query["post_logout_redirect_uri"] == ["https://app.example.com/signed-out"]


def test_logout_survives_a_failed_revocation(fake_session: FakeSession):
    session, client = _app(_config())
    _sign_in(client, fake_session)
    fake_session.queue(FakeResponse(503, {"error": "unavailable"}))
    r = client.get("/auth/logout")
    assert r.status_code == 302 and r.headers["location"].startswith(END_SESSION + "?")
    assert "__lumoauth" not in session.store


def test_logout_can_clear_only_the_local_session(fake_session: FakeSession):
    session, client = _app(_config(end_session_on_logout=False, post_logout_redirect="/bye"))
    _sign_in(client, fake_session)
    # The ID token is not kept: nothing would use it.
    assert "id_token" not in session.store["__lumoauth"]["tokens"]
    r = client.get("/auth/logout")
    assert (r.status_code, r.headers["location"]) == (302, "/bye")
    assert fake_session.calls == []  # no revocation
    assert "__lumoauth" not in session.store

    # The router function takes the same option.
    app = FastAPI()
    app.include_router(
        lumo_auth_router(
            base_url=PLATFORM, organization=ORG, client_id="web-app", end_session_on_logout=False
        ),
        prefix="/auth",
    )
    r = TestClient(MemorySession(app), follow_redirects=False).get("/auth/logout")
    assert (r.status_code, r.headers["location"]) == (302, "/")


def test_logout_when_nobody_is_signed_in_stays_local(fake_session: FakeSession):
    session, client = _app(_config())
    r = client.get("/auth/logout")
    assert (r.status_code, r.headers["location"]) == (302, "/")
    assert fake_session.calls == []


# ── What the session keeps ────────────────────────────────────────────


def test_session_keeps_only_what_the_routes_use(fake_session: FakeSession):
    session, client = _app(_config())
    before = int(time.time())
    _sign_in(client, fake_session)
    state = session.store["__lumoauth"]
    assert set(state) == {"tokens", "user"}
    tokens = state["tokens"]
    assert set(tokens) == {"access_token", "refresh_token", "id_token", "scope", "expires_at"}
    assert before + 3600 <= tokens["expires_at"] <= int(time.time()) + 3600

    # Values that the server did not send are not stored.
    session, client = _app(_config())
    _sign_in(client, fake_session, {"access_token": "at-2", "scope": "profile"})
    assert session.store["__lumoauth"]["tokens"] == {"access_token": "at-2", "scope": "profile"}


def test_large_cookie_session_logs_a_warning(fake_session: FakeSession, caplog: pytest.LogCaptureFixture):
    def run(tokens: Dict[str, Any]) -> list:
        app = FastAPI()
        app.add_middleware(SessionMiddleware, secret_key="x" * 32)
        app.include_router(_config().router(), prefix="/auth")
        client = TestClient(app, follow_redirects=False)
        caplog.clear()
        with caplog.at_level(logging.WARNING, logger="lumoauth.fastapi"):
            _sign_in(client, fake_session, tokens)
        return [r.getMessage() for r in caplog.records if r.name == "lumoauth.fastapi"]

    assert run(TOKENS) == []
    big = dict(TOKENS, access_token="a" * 2000, id_token="i" * 1500)
    messages = run(big)
    assert len(messages) == 1 and "more than the 4096 bytes" in messages[0]


# ── The access token dependency ───────────────────────────────────────


def _expire(session: MemorySession, seconds_left: int = 10) -> None:
    state = session.store["__lumoauth"]
    state["tokens"]["expires_at"] = int(time.time()) + seconds_left


def test_access_token_needs_a_signed_in_user(fake_session: FakeSession):
    _, client = _app(_config())
    r = client.get("/api/token")
    assert r.status_code == 401 and r.json()["detail"] == {"error": "unauthenticated"}


def test_access_token_is_returned_while_it_is_valid(fake_session: FakeSession):
    session, client = _app(_config())
    _sign_in(client, fake_session)
    r = client.get("/api/token")
    assert r.json() == {"access_token": "at-1"}
    assert fake_session.calls == []


def test_access_token_is_refreshed_before_it_expires(fake_session: FakeSession):
    session, client = _app(_config())
    _sign_in(client, fake_session)
    _expire(session)
    fake_session.queue(
        FakeResponse(200, {"access_token": "at-2", "refresh_token": "rt-2", "expires_in": 3600, "scope": "openid"})
    )
    r = client.get("/api/token")
    assert r.json() == {"access_token": "at-2"}
    method, url, kw = fake_session.last
    assert (method, url) == ("POST", ISSUER + "/oauth/token")
    assert kw["data"] == {
        "grant_type": "refresh_token",
        "refresh_token": "rt-1",
        "client_id": "web-app",
        "client_secret": "s3cr3t",
    }
    tokens = session.store["__lumoauth"]["tokens"]
    assert tokens["access_token"] == "at-2" and tokens["refresh_token"] == "rt-2"
    assert tokens["id_token"] == "id-1"  # kept: the refresh answer had none
    assert tokens["expires_at"] > time.time() + 3000

    # The next request uses the new token without another refresh.
    fake_session.calls.clear()
    assert client.get("/api/token").json() == {"access_token": "at-2"}
    assert fake_session.calls == []


def test_an_old_refresh_token_is_never_presented_twice(fake_session: FakeSession):
    """A request that still carries the old refresh token gets the same answer."""
    cfg = _config()
    session, client = _app(cfg)
    _sign_in(client, fake_session)
    _expire(session)
    old_state = {"tokens": dict(session.store["__lumoauth"]["tokens"]), "user": session.store["__lumoauth"]["user"]}
    fake_session.queue(FakeResponse(200, {"access_token": "at-2", "refresh_token": "rt-2", "expires_in": 3600}))
    assert client.get("/api/token").json() == {"access_token": "at-2"}

    # The browser sends the old cookie once more (a request in parallel).
    session.store["__lumoauth"] = old_state
    assert client.get("/api/token").json() == {"access_token": "at-2"}
    assert [url for _, url, _ in fake_session.calls] == [ISSUER + "/oauth/token"]


def test_parallel_refreshes_make_one_request(fake_session: FakeSession):
    cfg = _config()
    release = threading.Event()
    calls = []

    def slow_refresh(refresh_token: str, **kw: Any) -> Dict[str, Any]:
        calls.append(refresh_token)
        release.wait(2)
        return {"access_token": "at-2", "refresh_token": "rt-2", "expires_in": 3600}

    cfg.auth_resource().refresh_token = slow_refresh  # type: ignore[method-assign]
    results = []
    threads = [threading.Thread(target=lambda: results.append(cfg._refresh("rt-1"))) for _ in range(4)]
    for t in threads:
        t.start()
    time.sleep(0.1)
    release.set()
    for t in threads:
        t.join(3)
    assert calls == ["rt-1"]
    assert [r["access_token"] for r in results] == ["at-2"] * 4


def test_a_refused_refresh_signs_the_user_out(fake_session: FakeSession):
    session, client = _app(_config())
    _sign_in(client, fake_session)
    _expire(session)
    fake_session.queue(FakeResponse(400, {"error": "invalid_grant"}))
    r = client.get("/api/token")
    assert r.status_code == 401 and r.json()["detail"]["error"] == "token_expired"
    assert "__lumoauth" not in session.store


def test_an_unreachable_server_keeps_the_session(fake_session: FakeSession, monkeypatch: pytest.MonkeyPatch):
    cfg = _config()
    session, client = _app(cfg)
    _sign_in(client, fake_session)
    _expire(session)

    def fail(*a: Any, **kw: Any) -> Any:
        raise LumoAuthNetworkError("down")

    monkeypatch.setattr(cfg.auth_resource(), "refresh_token", fail)
    r = client.get("/api/token")
    assert r.status_code == 503 and r.json()["detail"]["error"] == "token_refresh_failed"
    assert session.store["__lumoauth"]["tokens"]["refresh_token"] == "rt-1"


def test_an_expired_token_without_a_refresh_token_signs_the_user_out(fake_session: FakeSession):
    session, client = _app(_config())
    _sign_in(client, fake_session, {"access_token": "at-1", "expires_in": 3600, "scope": "openid"})
    # Still valid for 10 s, no refresh token: returned as it is.
    _expire(session, 10)
    assert client.get("/api/token").json() == {"access_token": "at-1"}
    _expire(session, -1)
    r = client.get("/api/token")
    assert r.status_code == 401 and r.json()["detail"]["error"] == "token_expired"
    assert "__lumoauth" not in session.store


def test_a_session_from_an_older_release_still_works(fake_session: FakeSession):
    """Sessions written before expires_at existed are used as they are."""
    session, client = _app(_config())
    session.store["__lumoauth"] = {
        "tokens": {"access_token": "old", "refresh_token": "rt", "id_token": "id", "token_type": "Bearer", "scope": ""},
        "user": {"sub": "user-1"},
    }
    assert client.get("/api/token").json() == {"access_token": "old"}
    r = client.get("/auth/logout")
    assert parse_qs(urlsplit(r.headers["location"]).query)["id_token_hint"] == ["id"]


# ── Sign-in parameters for one sign-in (step-up) ──────────────────────


def test_login_passes_the_allow_listed_parameters(fake_session: FakeSession):
    session, client = _app(_config())
    r = client.get(
        "/auth/login",
        params={
            "return_to": "/payouts",
            "acr_values": "urn:lumoauth:acr:mfa",
            "max_age": "300",
            "resource": "https://api.example.com",
            "login_hint": "maya@example.com",
            "prompt": "login",
            "client_id": "attacker",  # not on the allow-list: never passed on
            "scope": "admin",
        },
    )
    assert r.status_code == 302
    query = parse_qs(urlsplit(r.headers["location"]).query)
    assert query["acr_values"] == ["urn:lumoauth:acr:mfa"]
    assert query["max_age"] == ["300"]
    assert query["resource"] == ["https://api.example.com"]
    assert query["login_hint"] == ["maya@example.com"]
    assert query["prompt"] == ["login"]
    assert query["client_id"] == ["web-app"]
    assert query["scope"] == ["openid profile email"]
    assert session.store["__lumoauth"]["flow"]["return_to"] == "/payouts"


def test_login_without_parameters_is_unchanged(fake_session: FakeSession):
    _, client = _app(_config())
    query = parse_qs(urlsplit(client.get("/auth/login").headers["location"]).query)
    assert set(query) == {
        "response_type", "client_id", "redirect_uri", "scope", "state", "code_challenge", "code_challenge_method",
    }


@pytest.mark.parametrize(
    "params",
    [
        {"max_age": "-1"},
        {"max_age": "5 minutes"},
        {"acr_values": "urn:a  urn:b"},
        {"acr_values": 'urn:"quoted"'},
        {"resource": "http://api.example.com"},
        {"resource": "https://api.example.com/#frag"},
        {"resource": "api.example.com"},
        {"prompt": "none login"},
        {"prompt": "create"},
        {"login_hint": "maya\r\nX-Injected: 1"},
        {"login_hint": "m" * 1025},
    ],
)
def test_login_refuses_a_malformed_parameter(fake_session: FakeSession, params):
    session, client = _app(_config())
    r = client.get("/auth/login", params=params)
    assert r.status_code == 400 and r.json()["error"] == "invalid_request"
    assert "__lumoauth" not in session.store  # no sign-in was started


def test_login_accepts_a_local_http_resource(fake_session: FakeSession):
    _, client = _app(_config())
    r = client.get("/auth/login", params={"resource": "http://localhost:4116", "prompt": "login consent"})
    query = parse_qs(urlsplit(r.headers["location"]).query)
    assert query["resource"] == ["http://localhost:4116"] and query["prompt"] == ["login consent"]

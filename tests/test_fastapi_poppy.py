"""The FastAPI helper for Personal Agent Protocol requests (skipped without fastapi)."""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import Any, Dict, List

import pytest

pytest.importorskip("fastapi", reason="needs fastapi")
pytest.importorskip("httpx", reason="FastAPI's TestClient needs httpx")

import requests  # noqa: E402
from fastapi import APIRouter, Depends, FastAPI, Request  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from conftest import FakeResponse, FakeSession  # noqa: E402
from lumoauth import LumoAuth, PoppyVerification  # noqa: E402
from lumoauth.errors import LumoAuthConfigError, LumoAuthValidationError  # noqa: E402
from lumoauth.fastapi import (  # noqa: E402
    LumoAuthPoppy,
    PoppyRefusal,
    poppy_refusal_handler,
    poppy_refusal_response,
)

BASE = "https://auth.example.com"
ORG = "acme-corp"
CLIENT_ID = "shop-api"
CLIENT_SECRET = "s3cr3t"
VERIFY_URL = f"{BASE}/orgs/{ORG}/api/v1/poppy/sessions/verify"
EXPECTED_BASIC = "Basic " + base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()
PUBLIC_ORIGIN = "https://shop.example.com"

_CANDIDATES = [
    *([Path(os.environ["LUMO_SDK_CONTRACT"])] if os.environ.get("LUMO_SDK_CONTRACT") else []),
    Path(__file__).resolve().parents[2] / "sdk-contract",
]
_CONTRACT = next((c for c in _CANDIDATES if (c / "routes.json").is_file()), None)
_VECTOR_FILE = _CONTRACT / "vectors" / "poppy-verification.json" if _CONTRACT else None
VECTOR: Dict[str, Any] = (
    json.loads(_VECTOR_FILE.read_text()) if _VECTOR_FILE and _VECTOR_FILE.is_file() else {}
)
needs_vector = pytest.mark.skipif(not VECTOR, reason="sdk-contract not found")


def _answer_cases(outcome: str) -> list:
    return [
        pytest.param(c, id=c["name"])
        for c in VECTOR.get("answer_cases", [])
        if c["expect"]["outcome"] == outcome
    ]


ACCOUNT = {
    "sub": "0193a5c2-7d1e-7c7a-9a52-3f0f2b6c9e11",
    "scope": "orders:read orders:write",
    "aud": ["https://shop.example.com"],
    "exp": 1795000000,
    "token_type": "Bearer",
}
VERIFIED = {
    "active": True,
    "client_id": "https://agent.example/agent.json",
    "client_name": "Example Agent",
    "user_id": "usr_Q7c1vK",
    "agent_id": None,
    "session": {
        "id": 4821,
        "sid": "Yx2b7Qd_Kp8mR3vT1nWc4A",
        "new": False,
        "started_at": "2026-11-26T10:15:00+00:00",
    },
    "signed_in": True,
    "account": ACCOUNT,
    "version": "1.0",
    "extensions": {},
}
REFUSED = {
    "active": False,
    "error": "account_required",
    "error_description": "This operation needs the user's account.",
    "response": {
        "status": 401,
        "headers": {"Cache-Control": "no-store", "WWW-Authenticate": 'Bearer scope="orders:read"'},
        "body": None,
    },
    "scope": "orders:read",
}
AGENT_HEADERS = {
    "Poppy-Session": "session.jwt",
    "Poppy-Version": "1.0",
    "Authorization": "Bearer access.token",
}


@pytest.fixture(autouse=True)
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in ("LUMOAUTH_URL", "LUMOAUTH_ORG_ID", "LUMOAUTH_API_KEY"):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture()
def lumo(fake_session: FakeSession) -> LumoAuth:
    return LumoAuth(
        base_url=BASE,
        org_id=ORG,
        api_key="lmk_must_not_be_sent",
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
    )


class Shop:
    """A small application with routes that personal agents call."""

    def __init__(self, lumo: LumoAuth, public_origin: str = PUBLIC_ORIGIN, install: bool = True):
        self.app = FastAPI()
        self.poppy = LumoAuthPoppy(lumo, public_origin=public_origin)
        if install:
            self.poppy.install(self.app)
        self.seen: List[PoppyVerification] = []
        poppy = self.poppy
        seen = self.seen

        @self.app.get("/api/orders")
        def orders(
            request: Request,
            who: PoppyVerification = Depends(poppy.session(required_scope="orders:read")),
        ):
            seen.append(who)
            return {
                "client_id": who.client_id,
                "user_id": who.user_id,
                "session": who.session.id,
                "account": who.account.sub if who.account else None,
                "same_object_on_state": request.state.poppy is who,
            }

        @self.app.get("/api/catalog", dependencies=[Depends(poppy.session())])
        def catalog(request: Request):
            seen.append(request.state.poppy)
            return {"signed_in": request.state.poppy.signed_in}

        @self.app.post("/api/orders/{order_id}/return")
        def return_order(
            order_id: str,
            payload: Dict[str, Any],
            who: PoppyVerification = Depends(
                poppy.session(
                    ["orders:read", "orders:write"],
                    resource="https://shop.example.com",
                    allow_replay=True,
                )
            ),
        ):
            seen.append(who)
            return {"order": order_id, "reason": payload["reason"]}

        self.client = TestClient(self.app, raise_server_exceptions=False)


def sent_body(fake_session: FakeSession) -> Dict[str, Any]:
    method, url, kw = fake_session.last
    assert (method, url) == ("POST", VERIFY_URL)
    assert kw["headers"]["Authorization"] == EXPECTED_BASIC
    assert "X-API-Key" not in kw["headers"]
    return kw["json"]


# ── A verified request ────────────────────────────────────────────────


def test_verified_request_reaches_the_route_with_the_result(lumo, fake_session):
    shop = Shop(lumo)
    fake_session.queue(FakeResponse(200, VERIFIED))
    r = shop.client.get("/api/orders?page=2", headers=AGENT_HEADERS)

    assert r.status_code == 200, r.text
    assert r.json() == {
        "client_id": "https://agent.example/agent.json",
        "user_id": "usr_Q7c1vK",
        "session": 4821,
        "account": ACCOUNT["sub"],
        "same_object_on_state": True,
    }
    (who,) = shop.seen
    assert isinstance(who, PoppyVerification) and who.active is True
    assert who.account.scopes == ("orders:read", "orders:write")
    assert len(fake_session.calls) == 1
    assert sent_body(fake_session) == {
        "method": "GET",
        "url": "https://shop.example.com/api/orders",
        "headers": {
            "poppy-session": "session.jwt",
            "poppy-version": "1.0",
            "authorization": "Bearer access.token",
        },
        "required_scope": "orders:read",
    }


def test_url_comes_from_public_origin_and_ignores_hostile_headers(lumo, fake_session):
    shop = Shop(lumo)
    fake_session.queue(FakeResponse(200, VERIFIED))
    r = shop.client.get(
        "/api/orders",
        headers={
            **AGENT_HEADERS,
            "Host": "evil.example",
            "X-Forwarded-Host": "evil.example",
            "X-Forwarded-Proto": "http",
            "X-Forwarded-Prefix": "/evil",
            "Forwarded": "host=evil.example;proto=http",
            "Cookie": "sid=abc",
            "X-API-Key": "must-not-leave",
        },
    )
    assert r.status_code == 200, r.text
    body = sent_body(fake_session)
    assert body["url"] == "https://shop.example.com/api/orders"
    assert set(body["headers"]) == {"poppy-session", "poppy-version", "authorization"}
    assert "evil" not in json.dumps(body)
    assert "must-not-leave" not in json.dumps(body) and "sid=abc" not in json.dumps(body)


def test_public_origin_with_a_base_path(lumo, fake_session):
    shop = Shop(lumo, public_origin="https://example.com/shop/")
    fake_session.queue(FakeResponse(200, VERIFIED))
    assert shop.client.get("/api/orders", headers=AGENT_HEADERS).status_code == 200
    assert sent_body(fake_session)["url"] == "https://example.com/shop/api/orders"


def test_route_options_are_sent_and_the_body_is_left_for_the_route(lumo, fake_session):
    shop = Shop(lumo)
    fake_session.queue(FakeResponse(200, VERIFIED))
    r = shop.client.post(
        "/api/orders/ord_1042/return",
        json={"reason": "too small"},
        headers={**AGENT_HEADERS, "Authorization": "DPoP access.token", "DPoP": "dpop.proof"},
    )
    assert r.status_code == 200, r.text
    assert r.json() == {"order": "ord_1042", "reason": "too small"}
    assert sent_body(fake_session) == {
        "method": "POST",
        "url": "https://shop.example.com/api/orders/ord_1042/return",
        "headers": {
            "poppy-session": "session.jwt",
            "poppy-version": "1.0",
            "authorization": "DPoP access.token",
            "dpop": "dpop.proof",
        },
        "required_scope": "orders:read orders:write",
        "resource": "https://shop.example.com",
        "allow_replay": True,
    }


def test_route_without_a_scope_and_without_protocol_headers_is_still_asked(lumo, fake_session):
    shop = Shop(lumo)
    signed_out = {**VERIFIED, "signed_in": False, "account": None}
    fake_session.queue(FakeResponse(200, signed_out))
    r = shop.client.get("/api/catalog")
    assert r.status_code == 200 and r.json() == {"signed_in": False}
    assert sent_body(fake_session) == {
        "method": "GET",
        "url": "https://shop.example.com/api/catalog",
        "headers": {},
    }


def test_repeated_headers_are_joined(lumo, fake_session):
    shop = Shop(lumo)
    fake_session.queue(FakeResponse(200, VERIFIED))
    r = shop.client.get(
        "/api/orders",
        headers=[
            ("Poppy-Session", "session.jwt"),
            ("Poppy-Version", "1.0"),
            ("Poppy-Extensions", 'ext-one;v="1.0"'),
            ("poppy-extensions", 'ext-two;v="2.1"'),
        ],
    )
    assert r.status_code == 200, r.text
    assert sent_body(fake_session)["headers"]["poppy-extensions"] == (
        'ext-one;v="1.0", ext-two;v="2.1"'
    )


# ── The full path: router prefixes, mounts, percent-encoding ──────────


def _mounted(lumo: LumoAuth) -> TestClient:
    app = FastAPI()
    poppy = LumoAuthPoppy(lumo, public_origin=PUBLIC_ORIGIN)
    poppy.install(app)

    router = APIRouter(prefix="/v1")

    @router.get("/files/{name:path}")
    def files(name: str, who: PoppyVerification = Depends(poppy.session())):
        return {"name": name, "where": "router"}

    app.include_router(router, prefix="/api")

    sub = FastAPI()
    poppy.install(sub)  # a mounted application has its own handlers

    @sub.get("/items/{name:path}")
    def items(name: str, who: PoppyVerification = Depends(poppy.session("items:read"))):
        return {"name": name, "where": "mount"}

    app.mount("/shop", sub)
    return TestClient(app, raise_server_exceptions=False)


def test_prefixed_router_sends_the_full_raw_path(lumo, fake_session):
    client = _mounted(lumo)
    fake_session.queue(FakeResponse(200, VERIFIED))
    r = client.get("/api/v1/files/a%20b/..%2Fc//d?x=1", headers=AGENT_HEADERS)
    assert r.status_code == 200, r.text
    assert r.json()["where"] == "router"
    assert sent_body(fake_session)["url"] == (
        "https://shop.example.com/api/v1/files/a%20b/..%2Fc//d"
    )


def test_mounted_application_sends_the_full_raw_path(lumo, fake_session):
    client = _mounted(lumo)
    fake_session.queue(FakeResponse(200, VERIFIED))
    r = client.get("/shop/items/caf%C3%A9%2Fx?page=2", headers=AGENT_HEADERS)
    assert r.status_code == 200, r.text
    assert r.json() == {"name": "café/x", "where": "mount"}
    body = sent_body(fake_session)
    assert body["url"] == "https://shop.example.com/shop/items/caf%C3%A9%2Fx"
    assert body["required_scope"] == "items:read"


def test_mounted_application_relays_a_refusal(lumo, fake_session):
    client = _mounted(lumo)
    fake_session.queue(FakeResponse(200, REFUSED))
    r = client.get("/shop/items/x", headers=AGENT_HEADERS)
    assert r.status_code == 401
    assert r.headers["www-authenticate"] == 'Bearer scope="orders:read"'
    assert r.content == b""


class DropRawPath:
    """An ASGI server that gives no ``raw_path``."""

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: Dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] == "http":
            scope = {k: v for k, v in scope.items() if k != "raw_path"}
        await self.app(scope, receive, send)


def test_without_a_raw_path_the_decoded_path_is_encoded_again(lumo, fake_session):
    app = FastAPI()
    poppy = LumoAuthPoppy(lumo, public_origin=PUBLIC_ORIGIN)
    poppy.install(app)
    sub = FastAPI()
    poppy.install(sub)

    @sub.get("/items/{name:path}")
    def items(name: str, who: PoppyVerification = Depends(poppy.session())):
        return {"name": name}

    app.mount("/shop", sub)
    client = TestClient(DropRawPath(app), raise_server_exceptions=False)
    fake_session.queue(FakeResponse(200, VERIFIED))
    r = client.get("/shop/items/caf%C3%A9%20au%20lait?x=1", headers=AGENT_HEADERS)
    assert r.status_code == 200, r.text
    assert sent_body(fake_session)["url"] == (
        "https://shop.example.com/shop/items/caf%C3%A9%20au%20lait"
    )


# ── A refusal is relayed unchanged ────────────────────────────────────


def assert_relayed(r: Any, relay: Dict[str, Any]) -> None:
    assert r.status_code == relay["status"]
    for name, value in relay["headers"].items():
        assert r.headers.get_list(name) == [value], name
    if relay["body"] is None:
        assert r.content == b""
    else:
        assert r.json() == relay["body"]
    if relay["content_type"] is None:
        assert "content-type" not in r.headers
    else:
        assert r.headers.get_list("content-type") == [relay["content_type"]]
    # Nothing else is added. Content-Length is how the server frames the message.
    expected = {name.lower() for name in relay["headers"]} | {"content-length"}
    if relay["content_type"] is not None:
        expected.add("content-type")
    assert {name.lower() for name in r.headers} == expected
    assert int(r.headers["content-length"]) == len(r.content)


@needs_vector
@pytest.mark.parametrize("case", _answer_cases("refused"))
def test_vector_refusal_is_relayed_exactly(case, lumo, fake_session):
    shop = Shop(lumo)
    fake_session.queue(FakeResponse(200, case["answer"]["body"]))
    r = shop.client.get("/api/orders", headers=AGENT_HEADERS)
    assert_relayed(r, case["expect"]["relay"])
    assert shop.seen == []
    assert len(fake_session.calls) == 1


@needs_vector
@pytest.mark.parametrize("case", _answer_cases("refused"))
def test_vector_refusal_relayed_by_hand(case, lumo, fake_session):
    """An application that calls verify itself relays a refusal in one line."""
    app = FastAPI()
    poppy = LumoAuthPoppy(lumo, public_origin=PUBLIC_ORIGIN)  # no install()
    reached: List[PoppyVerification] = []

    @app.get("/api/orders")
    def orders(request: Request):
        who = poppy.verify(request, required_scope="orders:read")
        if not who.active:
            return poppy_refusal_response(who)
        reached.append(who)
        return {"ok": True}

    fake_session.queue(FakeResponse(200, case["answer"]["body"]))
    r = TestClient(app, raise_server_exceptions=False).get("/api/orders", headers=AGENT_HEADERS)
    assert_relayed(r, case["expect"]["relay"])
    assert reached == []


@needs_vector
@pytest.mark.parametrize("case", _answer_cases("verified"))
def test_vector_verified_answer_reaches_the_route(case, lumo, fake_session):
    shop = Shop(lumo)
    fake_session.queue(FakeResponse(200, case["answer"]["body"]))
    r = shop.client.get("/api/catalog", headers=AGENT_HEADERS)
    assert r.status_code == 200, r.text
    assert r.json() == {"signed_in": case["expect"]["signed_in"]}
    (who,) = shop.seen
    assert who.client_id == case["expect"]["client_id"]
    assert who.session.id == case["expect"]["session_id"]


def test_refusal_does_not_reach_the_route(lumo, fake_session):
    shop = Shop(lumo)
    fake_session.queue(FakeResponse(200, REFUSED))
    r = shop.client.get("/api/orders", headers={"Poppy-Session": "s", "Poppy-Version": "1.0"})
    assert_relayed(
        r,
        {
            "status": 401,
            "headers": REFUSED["response"]["headers"],
            "content_type": None,
            "body": None,
        },
    )
    assert shop.seen == []


def test_headers_that_the_server_writes_are_not_copied(lumo, fake_session):
    shop = Shop(lumo)
    refused = json.loads(json.dumps(REFUSED))
    refused["response"]["headers"].update(
        {"Content-Length": "999", "Content-Type": "text/html", "Transfer-Encoding": "chunked"}
    )
    fake_session.queue(FakeResponse(200, refused))
    r = shop.client.get("/api/orders", headers=AGENT_HEADERS)
    assert r.status_code == 401
    assert r.headers["content-length"] == "0"
    assert "content-type" not in r.headers and "transfer-encoding" not in r.headers


def test_refusal_response_needs_a_refusal(lumo, fake_session):
    fake_session.queue(FakeResponse(200, VERIFIED))
    who = lumo.poppy.verify_request("GET", "https://shop.example.com/x", [])
    with pytest.raises(LumoAuthValidationError):
        poppy_refusal_response(who)


# ── An SDK error is never relayed ─────────────────────────────────────


def assert_generic_500(r: Any, *secrets: str) -> None:
    assert r.status_code == 500
    assert r.text == "Internal Server Error"
    for name in ("www-authenticate", "retry-after", "cache-control"):
        assert name not in r.headers
    for secret in secrets:
        assert secret not in r.text


def assert_unavailable(r: Any, *secrets: str) -> None:
    """503 temporarily_unavailable: nothing of LumoAuth's answer, never a 500."""
    assert r.status_code == 503
    assert r.json() == {
        "error": "temporarily_unavailable",
        "error_description": "Requests from personal agents cannot be verified right now.",
    }
    assert r.headers["cache-control"] == "no-store"
    for name in ("www-authenticate", "retry-after"):
        assert name not in r.headers
    for secret in secrets:
        assert secret not in r.text


@needs_vector
@pytest.mark.parametrize("case", _answer_cases("error"))
def test_vector_sdk_error_becomes_503_unavailable(case, lumo, fake_session):
    shop = Shop(lumo)
    answer = case["answer"]
    fake_session.queue(FakeResponse(answer["status"], answer["body"], headers=answer["headers"]))
    r = shop.client.get("/api/orders", headers=AGENT_HEADERS)
    description = answer["body"].get("error_description") or "no-description"
    assert_unavailable(r, description, "poppy:verify", "invalid_client", "LumoAuth")
    assert shop.seen == []
    assert len(fake_session.calls) == 1


def test_network_error_becomes_503_unavailable(lumo, fake_session, monkeypatch):
    def unreachable(method: str, url: str, **kwargs: Any) -> FakeResponse:
        fake_session.calls.append((method, url, kwargs))
        raise requests.ConnectionError("connection refused: auth.example.com:443")

    monkeypatch.setattr(fake_session, "request", unreachable)
    shop = Shop(lumo)
    r = shop.client.get("/api/orders", headers=AGENT_HEADERS)
    assert_unavailable(r, "connection refused", "auth.example.com")
    assert shop.seen == []


def test_missing_credentials_become_503_unavailable(fake_session):
    shop = Shop(LumoAuth(base_url=BASE, org_id=ORG, api_key="lmk_x"))
    r = shop.client.get("/api/orders", headers=AGENT_HEADERS)
    assert_unavailable(r, "client_secret", "poppy:verify")
    assert shop.seen == [] and fake_session.calls == []


def test_sdk_error_is_logged_for_the_application(lumo, fake_session, caplog):
    """The cause goes to the application's log, never to the personal agent."""
    import logging

    shop = Shop(lumo)
    fake_session.queue(FakeResponse(403, {"error": "insufficient_scope"}))
    with caplog.at_level(logging.WARNING, logger="lumoauth.fastapi"):
        r = TestClient(shop.app).get("/api/orders", headers=AGENT_HEADERS)
    assert_unavailable(r, "insufficient_scope")
    assert shop.seen == []
    assert any("LumoAuthPermissionDeniedError" in rec.getMessage() for rec in caplog.records)


def test_switched_off_protocol_is_503_unavailable(lumo, fake_session):
    """LumoAuth answers 404 not_found while the organization has the protocol off."""
    shop = Shop(lumo)
    fake_session.queue(FakeResponse(404, {"error": "not_found"}))
    r = shop.client.get("/api/orders", headers=AGENT_HEADERS)
    assert_unavailable(r, "not_found")
    assert shop.seen == []


# ── Configuration ─────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "origin", [None, "", "  ", "shop.example.com", "https://shop.example.com?x=1"]
)
def test_missing_public_origin_is_an_error_when_the_helper_is_created(lumo, origin):
    with pytest.raises(LumoAuthConfigError):
        LumoAuthPoppy(lumo, public_origin=origin)


def test_public_origin_is_required_and_keyword_only(lumo):
    with pytest.raises(TypeError):
        LumoAuthPoppy(lumo)  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        LumoAuthPoppy(lumo, PUBLIC_ORIGIN)  # type: ignore[misc]


def test_helper_needs_a_lumoauth_client():
    with pytest.raises(LumoAuthConfigError):
        LumoAuthPoppy(object(), public_origin=PUBLIC_ORIGIN)


@pytest.mark.parametrize(
    "kwargs",
    [{"allow_replay": "yes"}, {"required_scope": 5}, {"resource": 5}, {"required_scope": ["a", None]}],
)
def test_malformed_route_options_fail_when_the_route_is_declared(lumo, kwargs):
    poppy = LumoAuthPoppy(lumo, public_origin=PUBLIC_ORIGIN)
    with pytest.raises(LumoAuthValidationError):
        poppy.session(**kwargs)


def test_without_install_every_request_fails_before_lumoauth_is_asked(lumo, fake_session):
    shop = Shop(lumo, install=False)
    fake_session.queue(FakeResponse(200, VERIFIED))
    r = shop.client.get("/api/orders", headers=AGENT_HEADERS)
    assert_generic_500(r, "install")
    assert shop.seen == [] and fake_session.calls == []


def test_install_registers_the_refusal_handler(lumo):
    app = FastAPI()
    LumoAuthPoppy(lumo, public_origin=PUBLIC_ORIGIN).install(app)
    assert app.exception_handlers[PoppyRefusal] is poppy_refusal_handler

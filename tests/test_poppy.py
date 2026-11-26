"""Personal Agent Protocol Session verification: ``client.poppy``.

The vector tests run every case of ``sdk-contract/vectors/poppy-verification.json``
against the core with a mocked transport. They are skipped when the contract
is not checked out next to ``sdk-python`` (``LUMO_SDK_CONTRACT`` overrides).
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import Any, Dict, Tuple

import pytest

from conftest import FakeResponse, FakeSession
from lumoauth import (
    POPPY_FORWARDED_HEADERS,
    LumoAuth,
    PoppyAccount,
    PoppyResponse,
    PoppySessionInfo,
    PoppySessionStatus,
    PoppyVerification,
    build_poppy_verify_body,
    errors,
)
from lumoauth.errors import (
    LumoAuthApiError,
    LumoAuthConfigError,
    LumoAuthError,
    LumoAuthValidationError,
)

BASE = "https://auth.example.com"
ORG = "acme-corp"
CLIENT_ID = "shop-api"
CLIENT_SECRET = "s3cr3t/with:colon+%41&é"
VERIFY_URL = f"{BASE}/orgs/{ORG}/api/v1/poppy/sessions/verify"
STATUS_URL = f"{BASE}/orgs/{ORG}/api/v1/poppy/sessions/status"
END_URL = f"{BASE}/orgs/{ORG}/api/v1/poppy/sessions/end"
EXPECTED_BASIC = "Basic " + base64.b64encode(
    f"{CLIENT_ID}:{CLIENT_SECRET}".encode("utf-8")
).decode("ascii")

AGENT = "https://agent.example/agent.json"
SID = "Yx2b7Qd_Kp8mR3vT1nWc4A"

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


def _cases(key: str) -> list:
    return [pytest.param(c, id=c["name"]) for c in VECTOR.get(key, [])]


VERIFIED = {
    "active": True,
    "client_id": AGENT,
    "client_name": "Example Agent",
    "user_id": "usr_Q7c1vK",
    "agent_id": None,
    "session": {"id": 4821, "sid": SID, "new": True, "started_at": "2026-11-26T10:15:00+00:00"},
    "signed_in": False,
    "account": None,
    "version": "1.0",
    "extensions": {},
}
ACCOUNT = {
    "sub": "0193a5c2-7d1e-7c7a-9a52-3f0f2b6c9e11",
    "scope": "orders:read orders:write",
    "aud": ["https://shop.example.com"],
    "exp": 1795000000,
    "token_type": "Bearer",
}
REFUSED = {
    "active": False,
    "error": "invalid_session",
    "error_description": "The Session JWT was signed for another URL (htu).",
    "response": {
        "status": 400,
        "headers": {"Cache-Control": "no-store"},
        "body": {"error": "invalid_session"},
    },
}
REQUEST: Tuple[str, str, list] = (
    "GET",
    "https://shop.example.com/api/orders",
    [("Poppy-Session", "session.jwt"), ("Poppy-Version", "1.0")],
)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in (
        "LUMOAUTH_URL",
        "LUMOAUTH_ORG_ID",
        "LUMOAUTH_API_KEY",
        "LUMOAUTH_CUSTOM_DOMAIN",
        "LUMOAUTH_CLIENT_ID",
        "LUMOAUTH_CLIENT_SECRET",
    ):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture()
def client(fake_session: FakeSession) -> LumoAuth:
    # The client also holds a bearer token and an API key. Neither may be
    # sent on a Personal Agent Protocol call.
    return LumoAuth(
        base_url=BASE,
        org_id=ORG,
        api_key="lmk_must_not_be_sent",
        token_provider=lambda: "bearer-must-not-be-sent",
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
    )


def assert_basic_only(call: Tuple[str, str, Dict[str, Any]], url: str) -> Dict[str, Any]:
    """The call is a POST with HTTP Basic and nothing else; returns its JSON body."""
    method, sent_url, kw = call
    assert (method, sent_url) == ("POST", url)
    headers = kw["headers"]
    assert headers["Authorization"] == EXPECTED_BASIC
    assert headers["Content-Type"] == "application/json"
    lowered = {name.lower() for name in headers}
    assert lowered == {"authorization", "content-type", "accept"}  # no X-API-Key, no DPoP
    assert "bearer-must-not-be-sent" not in json.dumps(headers)
    assert "lmk_must_not_be_sent" not in json.dumps(headers)
    assert kw["allow_redirects"] is False
    assert kw.get("data") is None and kw.get("params") is None
    body = kw["json"]
    assert isinstance(body, dict)
    assert "client_id" not in body and "client_secret" not in body
    assert CLIENT_SECRET not in json.dumps(body)
    return body


def _answer(spec: Dict[str, Any]) -> FakeResponse:
    return FakeResponse(spec["status"], spec.get("body"), headers=spec.get("headers") or {})


# ── Vector: request_cases ─────────────────────────────────────────────


@needs_vector
def test_forwarded_headers_match_the_vector():
    assert list(POPPY_FORWARDED_HEADERS) == VECTOR["forwarded_headers"]


@needs_vector
@pytest.mark.parametrize("case", _cases("request_cases"))
def test_vector_request_body_from_the_pure_function(case):
    incoming = case["incoming"]
    body = build_poppy_verify_body(
        case["public_origin"],
        incoming["method"],
        incoming["target"],
        [tuple(pair) for pair in incoming["headers"]],
        **case["options"],
    )
    assert body == case["expected_body"]
    # The same request with the headers as ASGI gives them: bytes pairs.
    as_bytes = build_poppy_verify_body(
        case["public_origin"],
        incoming["method"],
        incoming["target"].encode("ascii"),
        [(n.encode("latin-1"), v.encode("latin-1")) for n, v in incoming["headers"]],
        **case["options"],
    )
    assert as_bytes == case["expected_body"]


@needs_vector
@pytest.mark.parametrize("case", _cases("request_cases"))
def test_vector_request_body_sent_by_verify_request(case, client, fake_session):
    incoming = case["incoming"]
    fake_session.queue(FakeResponse(200, VERIFIED))
    # A caller that passes the whole URL (query included) and every header.
    target = incoming["target"]
    if "://" in target.split("?")[0]:
        # An absolute-form target is the builder's business. verify_request
        # takes the URL itself, so the caller passes the public one.
        url = case["expected_body"]["url"] + "?dropped=1"
    else:
        url = case["public_origin"].rstrip("/") + target
    client.poppy.verify_request(
        incoming["method"],
        url,
        [tuple(pair) for pair in incoming["headers"]],
        **case["options"],
    )
    assert len(fake_session.calls) == 1
    assert assert_basic_only(fake_session.last, VERIFY_URL) == case["expected_body"]


# ── Vector: answer_cases ──────────────────────────────────────────────


@needs_vector
@pytest.mark.parametrize("case", _cases("answer_cases"))
def test_vector_answer(case, client, fake_session):
    expect = case["expect"]
    fake_session.queue(_answer(case["answer"]))

    if expect["outcome"] == "error":
        cls = getattr(errors, expect["error_class"])
        with pytest.raises(cls) as info:
            client.poppy.verify_request(*REQUEST, required_scope="orders:read")
        if expect["error_class"] == "LumoAuthError":
            # A 200 answer of the wrong shape: an SDK error, not an API error.
            assert not isinstance(info.value, LumoAuthApiError)
        else:
            assert type(info.value) is cls
            assert info.value.status_code == case["answer"]["status"]
        if "retry_after" in expect:
            assert info.value.retry_after == expect["retry_after"]
    else:
        who = client.poppy.verify_request(*REQUEST, required_scope="orders:read")
        assert isinstance(who, PoppyVerification)
        assert who.raw == case["answer"]["body"]
        if expect["outcome"] == "verified":
            assert who.active is True
            assert who.client_id == expect["client_id"]
            assert who.client_name == expect["client_name"]
            assert who.user_id == expect["user_id"]
            assert who.agent_id == expect["agent_id"]
            assert who.session == PoppySessionInfo(
                id=expect["session_id"],
                sid=expect["sid"],
                is_new=expect["session_new"],
                started_at=expect["started_at"],
            )
            assert who.signed_in is expect["signed_in"]
            if expect["account"] is None:
                assert who.account is None
            else:
                assert isinstance(who.account, PoppyAccount)
                assert who.account.sub == expect["account"]["sub"]
                assert who.account.scope == expect["account"]["scope"]
                assert list(who.account.scopes) == expect["account"]["scopes"]
                assert list(who.account.aud) == expect["account"]["aud"]
                assert who.account.exp == expect["account"]["exp"]
                assert who.account.token_type == expect["account"]["token_type"]
            assert who.version == expect["version"]
            assert who.extensions == expect["extensions"]
            assert who.error is None and who.response is None
        else:
            assert expect["outcome"] == "refused"
            assert who.active is False
            assert who.error == expect["error"]
            assert who.error_description == expect["error_description"]
            assert who.scope == expect["scope"]
            relay = expect["relay"]
            assert who.response == PoppyResponse(
                status=relay["status"], headers=relay["headers"], body=relay["body"]
            )
            assert who.session is None and who.client_id is None and who.account is None

    assert len(fake_session.calls) == 1
    body = assert_basic_only(fake_session.last, VERIFY_URL)
    assert body["required_scope"] == "orders:read"


# ── Vector: session_status_cases and end_session_cases ────────────────


@needs_vector
@pytest.mark.parametrize("case", _cases("session_status_cases"))
def test_vector_session_status(case, client, fake_session):
    fake_session.queue(_answer(case["answer"]))
    status = client.poppy.get_session_status(
        case["request"]["personal_agent"], case["request"]["sid"]
    )
    expect = case["expect"]
    assert status == PoppySessionStatus(
        status=expect["status"],
        user_id=expect["user_id"],
        agent_id=expect["agent_id"],
        account=expect["account"],
        signed_in=expect["signed_in"],
        last_seen_at=expect["last_seen_at"],
    )
    assert status.raw == case["answer"]["body"]
    assert len(fake_session.calls) == 1
    assert assert_basic_only(fake_session.last, STATUS_URL) == case["request"]


@needs_vector
@pytest.mark.parametrize("case", _cases("end_session_cases"))
def test_vector_end_session(case, client, fake_session):
    fake_session.queue(_answer(case["answer"]))
    request = case["request"]
    expect = case["expect"]
    if "error_class" in expect:
        with pytest.raises(getattr(errors, expect["error_class"])) as info:
            client.poppy.end_session(request["personal_agent"], request["sid"])
        assert info.value.status_code == case["answer"]["status"]
    else:
        assert client.poppy.end_session(request["personal_agent"], request["sid"]) is expect["ended"]
    assert len(fake_session.calls) == 1
    assert assert_basic_only(fake_session.last, END_URL) == request


# ── Authentication ────────────────────────────────────────────────────


def test_basic_credentials_are_the_raw_values(client, fake_session):
    fake_session.queue(FakeResponse(200, VERIFIED))
    client.poppy.verify_request(*REQUEST)
    sent = fake_session.last[2]["headers"]["Authorization"]
    decoded = base64.b64decode(sent.split(" ", 1)[1]).decode("utf-8")
    assert decoded == f"{CLIENT_ID}:{CLIENT_SECRET}"  # no percent-encoding


def test_dpop_bound_client_sends_no_proof_and_no_token(client, fake_session):
    class Signer:
        def create_proof(self, *args, **kwargs):  # pragma: no cover - must not run
            raise AssertionError("a DPoP proof must not be made for this call")

        def observe_response(self, *args, **kwargs):  # pragma: no cover
            raise AssertionError("not a DPoP call")

    client._http.dpop = Signer()  # type: ignore[assignment]
    fake_session.queue(FakeResponse(200, VERIFIED))
    client.poppy.verify_request(*REQUEST)
    assert_basic_only(fake_session.last, VERIFY_URL)


def test_credentials_from_the_environment(fake_session, monkeypatch):
    monkeypatch.setenv("LUMOAUTH_CLIENT_ID", CLIENT_ID)
    monkeypatch.setenv("LUMOAUTH_CLIENT_SECRET", CLIENT_SECRET)
    lumo = LumoAuth(base_url=BASE, org_id=ORG)
    assert lumo.client_id == CLIENT_ID
    assert not hasattr(lumo, "client_secret")
    fake_session.queue(FakeResponse(200, {"ended": True}))
    assert lumo.poppy.end_session(AGENT, SID) is True
    assert fake_session.last[2]["headers"]["Authorization"] == EXPECTED_BASIC


@pytest.mark.parametrize(
    "kwargs",
    [
        {},
        {"client_id": CLIENT_ID},
        {"client_secret": CLIENT_SECRET},
        {"client_id": "", "client_secret": ""},
    ],
)
def test_missing_credentials_raise_before_any_request(fake_session, kwargs):
    lumo = LumoAuth(base_url=BASE, org_id=ORG, api_key="lmk_x", token_provider=lambda: "t", **kwargs)
    calls = (
        lambda: lumo.poppy.verify_request(*REQUEST),
        lambda: lumo.poppy.get_session_status(AGENT, SID),
        lambda: lumo.poppy.end_session(AGENT, SID),
    )
    for call in calls:
        with pytest.raises(LumoAuthConfigError) as info:
            call()
        assert "poppy:verify" in str(info.value)
    assert fake_session.calls == []


def test_other_calls_keep_their_credential_and_follow_redirects_as_before(client, fake_session):
    fake_session.queue(FakeResponse(200, {"allowed": True}))
    client.permissions.check("document.edit")
    _, _, kw = fake_session.last
    assert kw["headers"]["Authorization"] == "Bearer bearer-must-not-be-sent"
    assert "allow_redirects" not in kw


# ── Fail closed ───────────────────────────────────────────────────────


def _verified(**changes: Any) -> Dict[str, Any]:
    body = json.loads(json.dumps(VERIFIED))
    body.update(changes)
    return body


def _refused(**response_changes: Any) -> Dict[str, Any]:
    body = json.loads(json.dumps(REFUSED))
    body["response"].update(response_changes)
    return body


@pytest.mark.parametrize(
    "body",
    [
        None,
        [],
        "active",
        {"active": 1, **{k: v for k, v in VERIFIED.items() if k != "active"}},
        {"active": None},
        _verified(session=None),
        _verified(session={"id": "4821", "sid": SID, "new": True, "started_at": "x"}),
        _verified(session={"id": True, "sid": SID, "new": True, "started_at": "x"}),
        _verified(session={"id": 1, "sid": "", "new": True, "started_at": "x"}),
        _verified(session={"id": 1, "sid": SID, "new": "true", "started_at": "x"}),
        _verified(session={"id": 1, "sid": SID, "new": True}),
        _verified(client_id=None),
        _verified(client_id=""),
        _verified(user_id=7),
        _verified(agent_id=7),
        _verified(signed_in="false"),
        _verified(signed_in=True),  # signed in without an account
        _verified(account=ACCOUNT),  # an account while signed_in is false
        _verified(signed_in=True, account="0193a5c2"),
        _verified(signed_in=True, account={**ACCOUNT, "sub": ""}),
        _verified(signed_in=True, account={**ACCOUNT, "scope": ["orders:read"]}),
        _verified(signed_in=True, account={**ACCOUNT, "aud": "https://shop.example.com"}),
        _verified(signed_in=True, account={**ACCOUNT, "exp": "1795000000"}),
        _verified(signed_in=True, account={**ACCOUNT, "token_type": None}),
        _verified(version=None),
        _verified(extensions=["ext-one"]),
        _verified(extensions={"ext-one": 1}),
        {"active": False, "response": REFUSED["response"]},  # no error
        {**REFUSED, "error": ""},
        {**REFUSED, "error_description": 5},
        {**REFUSED, "scope": ["orders:read"]},
        {**REFUSED, "response": None},
        {**REFUSED, "response": "400"},
        _refused(status="400"),
        _refused(status=True),
        _refused(status=200),  # a refusal is never relayed as a success
        _refused(status=302),
        _refused(status=600),
        _refused(headers=None),
        _refused(headers=["Cache-Control: no-store"]),
        _refused(headers={"Retry-After": 42}),
        _refused(headers={"X-Injected": "a\r\nSet-Cookie: x=1"}),
        _refused(headers={"Bad Name": "x"}),
        _refused(body="invalid_session"),
        _refused(body=["invalid_session"]),
    ],
)
def test_a_200_answer_of_another_shape_is_an_error(client, fake_session, body):
    text = json.dumps(body)
    fake_session.queue(FakeResponse(200, body, text=text))
    with pytest.raises(LumoAuthError) as info:
        client.poppy.verify_request(*REQUEST)
    assert isinstance(info.value, LumoAuthValidationError)
    assert not isinstance(info.value, LumoAuthApiError)


def test_an_empty_header_map_written_as_a_list_is_accepted(client, fake_session):
    fake_session.queue(FakeResponse(200, _refused(headers=[], body=None)))
    who = client.poppy.verify_request(*REQUEST)
    assert who.active is False
    assert who.response == PoppyResponse(status=400, headers={}, body=None)


@pytest.mark.parametrize("status", [201, 202, 204])
def test_a_success_status_other_than_200_is_an_error(client, fake_session, status):
    fake_session.queue(FakeResponse(status, VERIFIED))
    with pytest.raises(LumoAuthApiError) as info:
        client.poppy.verify_request(*REQUEST)
    assert info.value.status_code == status


def test_a_redirect_is_an_error_and_is_not_followed(client, fake_session):
    fake_session.queue(
        FakeResponse(307, None, headers={"Location": "https://elsewhere.example/verify"}),
        FakeResponse(200, VERIFIED),
    )
    with pytest.raises(LumoAuthApiError) as info:
        client.poppy.verify_request(*REQUEST)
    assert info.value.status_code == 307
    assert len(fake_session.calls) == 1
    assert fake_session.last[2]["allow_redirects"] is False


@pytest.mark.parametrize("status", [400, 500, 502])
def test_other_error_statuses_raise_the_api_error(client, fake_session, status):
    fake_session.queue(FakeResponse(status, {"error": "invalid_request", "active": True}))
    with pytest.raises(LumoAuthApiError) as info:
        client.poppy.verify_request(*REQUEST)
    assert info.value.status_code == status


@pytest.mark.parametrize(
    "body",
    [
        None,
        {},
        {"status": "paused", "signed_in": False},
        {"status": "active", "signed_in": "true"},
        {"status": "active"},
        {"status": "active", "signed_in": True, "account": 7},
    ],
)
def test_session_status_of_another_shape_is_an_error(client, fake_session, body):
    fake_session.queue(FakeResponse(200, body, text=json.dumps(body)))
    with pytest.raises(LumoAuthValidationError):
        client.poppy.get_session_status(AGENT, SID)


@pytest.mark.parametrize("body", [None, {}, {"ended": "true"}, {"ended": 1}, [True]])
def test_end_session_of_another_shape_is_an_error(client, fake_session, body):
    fake_session.queue(FakeResponse(200, body, text=json.dumps(body)))
    with pytest.raises(LumoAuthValidationError):
        client.poppy.end_session(AGENT, SID)


def test_session_status_ended(client, fake_session):
    fake_session.queue(
        FakeResponse(
            200,
            {
                "status": "ended",
                "user_id": "usr_Q7c1vK",
                "agent_id": "travel-planner",
                "account": None,
                "signed_in": False,
                "last_seen_at": "2026-11-26T10:21:07+00:00",
            },
        )
    )
    status = client.poppy.get_session_status(AGENT, SID)
    assert (status.status, status.agent_id, status.signed_in) == ("ended", "travel-planner", False)


# ── Arguments ─────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "args",
    [("", SID), (AGENT, ""), ("   ", SID), (AGENT, "  "), (None, SID), (AGENT, None), (AGENT, 7)],
)
def test_session_calls_refuse_empty_arguments(client, fake_session, args):
    with pytest.raises(LumoAuthValidationError):
        client.poppy.get_session_status(*args)
    with pytest.raises(LumoAuthValidationError):
        client.poppy.end_session(*args)
    assert fake_session.calls == []


@pytest.mark.parametrize(
    "args,kwargs",
    [
        (("", "https://shop.example.com/x", []), {}),
        ((None, "https://shop.example.com/x", []), {}),
        (("GET", "", []), {}),
        (("GET", None, []), {}),
        (("GET", "https://shop.example.com/x", "Poppy-Session: x"), {}),
        (("GET", "https://shop.example.com/x", [("Poppy-Session",)]), {}),
        (("GET", "https://shop.example.com/x", [("Poppy-Session", 5)]), {}),
        (("GET", "https://shop.example.com/x", []), {"allow_replay": "false"}),
        (("GET", "https://shop.example.com/x", []), {"allow_replay": 1}),
        (("GET", "https://shop.example.com/x", []), {"required_scope": 5}),
        (("GET", "https://shop.example.com/x", []), {"required_scope": ["a", 5]}),
        (("GET", "https://shop.example.com/x", []), {"resource": 5}),
    ],
)
def test_verify_request_refuses_malformed_arguments(client, fake_session, args, kwargs):
    with pytest.raises(LumoAuthValidationError):
        client.poppy.verify_request(*args, **kwargs)
    assert fake_session.calls == []


def test_verify_request_accepts_a_header_mapping(client, fake_session):
    fake_session.queue(FakeResponse(200, VERIFIED))
    client.poppy.verify_request(
        "post",
        "https://shop.example.com/api/orders?page=2#top",
        {
            "POPPY-SESSION": "session.jwt",
            "Poppy-Version": "1.0",
            "Poppy-Extensions": ["ext-one;v=\"1.0\"", "ext-two;v=\"2.1\""],
            "Authorization": "Bearer access.token",
            "DPoP": None,
            "Cookie": "sid=abc",
            "X-API-Key": "must-not-leave",
            "Proxy-Authorization": "Basic must-not-leave",
        },
        required_scope=["orders:read", "orders:write"],
        resource="https://shop.example.com",
        allow_replay=True,
    )
    assert assert_basic_only(fake_session.last, VERIFY_URL) == {
        "method": "POST",
        "url": "https://shop.example.com/api/orders",
        "headers": {
            "poppy-session": "session.jwt",
            "poppy-version": "1.0",
            "poppy-extensions": "ext-one;v=\"1.0\", ext-two;v=\"2.1\"",
            "authorization": "Bearer access.token",
        },
        "required_scope": "orders:read orders:write",
        "resource": "https://shop.example.com",
        "allow_replay": True,
    }


# ── build_poppy_verify_body ───────────────────────────────────────────


@pytest.mark.parametrize(
    "origin",
    [
        None,
        "",
        "   ",
        "shop.example.com",
        "ftp://shop.example.com",
        "https://",
        "https://shop.example.com?x=1",
        "https://shop.example.com/#top",
        "https://user:pw@shop.example.com",
        "https://shop.example.com:port",
        "https://shop example.com",
        5,
    ],
)
def test_public_origin_must_be_a_configured_http_address(origin):
    with pytest.raises(LumoAuthConfigError):
        build_poppy_verify_body(origin, "GET", "/", [])


@pytest.mark.parametrize(
    "target,url",
    [
        ("/api/x", "https://shop.example.com/api/x"),
        ("", "https://shop.example.com/"),
        ("?page=2", "https://shop.example.com/"),
        ("#top", "https://shop.example.com/"),
        ("/a#b?c", "https://shop.example.com/a"),
        # absolute-form: the scheme and the authority of the request are dropped.
        ("http://evil.example/api/x?y=1", "https://shop.example.com/api/x"),
        ("https://evil.example", "https://shop.example.com/"),
        # The request can never change the host that the public origin names.
        ("@evil.example/x", "https://shop.example.com/@evil.example/x"),
        (".evil.example/x", "https://shop.example.com/.evil.example/x"),
        ("//evil.example/x", "https://shop.example.com//evil.example/x"),
        (b"/caf\xc3\xa9/a%20b c", "https://shop.example.com/caf%C3%A9/a%20b%20c"),
    ],
)
def test_url_is_the_public_origin_and_the_raw_path(target, url):
    body = build_poppy_verify_body("https://shop.example.com//", "GET", target, [])
    assert body == {"method": "GET", "url": url, "headers": {}}


def test_scope_strings_are_joined_with_one_space():
    def scope(value: Any) -> Any:
        return build_poppy_verify_body(
            "https://shop.example.com", "GET", "/", [], required_scope=value
        ).get("required_scope")

    assert scope("orders:read") == "orders:read"
    assert scope("  orders:read   orders:write ") == "orders:read orders:write"
    assert scope(["orders:read", "orders:write"]) == "orders:read orders:write"
    assert scope(("orders:read",)) == "orders:read"
    assert scope([]) is None
    assert scope("") is None
    assert scope(None) is None

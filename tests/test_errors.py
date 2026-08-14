"""HttpClient status → typed error mapping, auth injection, and body parsing."""

from __future__ import annotations

import pytest
import requests

from conftest import FakeResponse, FakeSession
from lumoauth._http import HttpClient
from lumoauth.errors import (
    LumoAuthApiError,
    LumoAuthAuthenticationError,
    LumoAuthConfigError,
    LumoAuthError,
    LumoAuthNetworkError,
    LumoAuthNotFoundError,
    LumoAuthPermissionDeniedError,
    LumoAuthRateLimitError,
)

BASE = "https://auth.example.com"


def make_client(**kwargs) -> tuple[HttpClient, FakeSession]:
    session = FakeSession()
    client = HttpClient(BASE, session=session, **kwargs)
    return client, session


# ── Status code mapping ───────────────────────────────────────────────


@pytest.mark.parametrize(
    "status,exc_type,default_code",
    [
        (401, LumoAuthAuthenticationError, "AUTH_ERROR"),
        (403, LumoAuthPermissionDeniedError, "PERMISSION_DENIED"),
        (404, LumoAuthNotFoundError, "NOT_FOUND"),
        (429, LumoAuthRateLimitError, "RATE_LIMITED"),
        (500, LumoAuthApiError, "API_ERROR"),
        (400, LumoAuthApiError, "API_ERROR"),
    ],
)
def test_status_maps_to_typed_error(status, exc_type, default_code):
    client, session = make_client()
    session.queue(FakeResponse(status, {}, text="{}"))
    with pytest.raises(exc_type) as exc_info:
        client.request("GET", "/thing")
    err = exc_info.value
    assert err.status_code == status
    assert err.code == default_code
    assert isinstance(err, LumoAuthApiError)
    assert isinstance(err, LumoAuthError)


def test_api_errors_are_also_runtime_errors():
    """Legacy code catching RuntimeError keeps working."""
    client, session = make_client()
    session.queue(FakeResponse(500, {"error": "boom"}))
    with pytest.raises(RuntimeError):
        client.request("GET", "/thing")


def test_error_message_and_code_parsed_from_json_body():
    client, session = make_client()
    session.queue(
        FakeResponse(
            403,
            {"error": "insufficient_scope", "error_description": "Missing scope: admin"},
        )
    )
    with pytest.raises(LumoAuthPermissionDeniedError) as exc_info:
        client.request("GET", "/thing")
    assert exc_info.value.code == "insufficient_scope"
    assert "Missing scope: admin" in str(exc_info.value)
    assert exc_info.value.body == {
        "error": "insufficient_scope",
        "error_description": "Missing scope: admin",
    }


def test_explicit_code_field_wins_over_error_field():
    client, session = make_client()
    session.queue(FakeResponse(404, {"error": "not_found", "code": "NOT_FOUND"}))
    with pytest.raises(LumoAuthNotFoundError) as exc_info:
        client.request("GET", "/thing")
    assert exc_info.value.code == "NOT_FOUND"


def test_rate_limit_error_parses_retry_after():
    client, session = make_client()
    session.queue(FakeResponse(429, {"error": "rate_limited"}, headers={"Retry-After": "12"}))
    with pytest.raises(LumoAuthRateLimitError) as exc_info:
        client.request("GET", "/thing")
    assert exc_info.value.retry_after == 12.0


# ── Success handling ──────────────────────────────────────────────────


def test_success_returns_parsed_json():
    client, session = make_client()
    session.queue(FakeResponse(200, {"ok": True}))
    assert client.request("GET", "/thing") == {"ok": True}


def test_204_returns_none():
    client, session = make_client()
    session.queue(FakeResponse(204, None, text=""))
    assert client.request("DELETE", "/thing") is None


def test_raw_returns_response_without_mapping():
    client, session = make_client()
    session.queue(FakeResponse(403, {"error": "nope"}))
    resp = client.request("GET", "/thing", raw=True)
    assert resp.status_code == 403


# ── Transport errors ──────────────────────────────────────────────────


def test_requests_exception_wrapped_in_network_error():
    class ExplodingSession:
        def request(self, *args, **kwargs):
            raise requests.ConnectionError("boom")

    client = HttpClient(BASE, session=ExplodingSession())
    with pytest.raises(LumoAuthNetworkError) as exc_info:
        client.request("GET", "/thing")
    assert isinstance(exc_info.value.cause, requests.ConnectionError)


# ── Auth injection ────────────────────────────────────────────────────


def test_token_provider_injects_bearer():
    client, session = make_client(token_provider=lambda: "tok-123")
    session.queue(FakeResponse(200, {}))
    client.request("GET", "/thing")
    _, _, kwargs = session.last
    assert kwargs["headers"]["Authorization"] == "Bearer tok-123"


def test_api_key_injects_x_api_key_header():
    client, session = make_client(api_key="lk_secret")
    session.queue(FakeResponse(200, {}))
    client.request("GET", "/thing")
    _, _, kwargs = session.last
    assert kwargs["headers"]["X-API-Key"] == "lk_secret"
    assert "Authorization" not in kwargs["headers"]


def test_token_provider_wins_over_api_key():
    client, session = make_client(api_key="lk_secret", token_provider=lambda: "tok-123")
    session.queue(FakeResponse(200, {}))
    client.request("GET", "/thing")
    _, _, kwargs = session.last
    assert kwargs["headers"]["Authorization"] == "Bearer tok-123"
    assert "X-API-Key" not in kwargs["headers"]


def test_explicit_authorization_header_is_not_overridden():
    client, session = make_client(token_provider=lambda: "tok-123")
    session.queue(FakeResponse(200, {}))
    client.request("GET", "/thing", headers={"Authorization": "Bearer other"})
    _, _, kwargs = session.last
    assert kwargs["headers"]["Authorization"] == "Bearer other"


def test_auth_false_sends_no_credentials():
    client, session = make_client(api_key="lk_secret", token_provider=lambda: "tok")
    session.queue(FakeResponse(200, {}))
    client.request("POST", "/oauth/token", data={"grant_type": "x"}, auth=False)
    _, _, kwargs = session.last
    assert "Authorization" not in kwargs["headers"]
    assert "X-API-Key" not in kwargs["headers"]


# ── URL building & org handling ───────────────────────────────────────


def test_path_joined_to_base_url_and_full_url_passthrough():
    client, session = make_client()
    session.queue(FakeResponse(200, {}), FakeResponse(200, {}))
    client.request("GET", "/a/b")
    assert session.calls[0][1] == f"{BASE}/a/b"
    client.request("GET", "https://elsewhere.example.com/c")
    assert session.calls[1][1] == "https://elsewhere.example.com/c"


def test_org_route_requires_org_id():
    client, _ = make_client()  # no org_id
    with pytest.raises(LumoAuthConfigError):
        client.call("agents.ask", json={"action": "x"})


def test_call_formats_route_with_org_id():
    client, session = make_client(org_id="acme")
    session.queue(FakeResponse(200, {"allowed": True}))
    client.call("agents.ask", json={"action": "x"})
    method, url, _ = session.last
    assert method == "POST"
    assert url == f"{BASE}/orgs/acme/api/v1/agents/ask"

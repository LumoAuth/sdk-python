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
    LumoAuthBudgetExceededError,
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
        (401, LumoAuthAuthenticationError, "AUTHENTICATION_ERROR"),
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
    assert not isinstance(exc_info.value, LumoAuthBudgetExceededError)


@pytest.mark.parametrize(
    "value,expected",
    [
        ("12", 12.0),
        (" 0 ", 0.0),
        ("1.5", 1.5),
        # RFC 9110: an HTTP date in each of its three forms; the time is 100 s ahead.
        ("Fri, 27 Nov 2026 18:01:40 GMT", 100.0),
        ("Friday, 27-Nov-26 18:01:40 GMT", 100.0),
        ("Fri Nov 27 18:01:40 2026", 100.0),
        # A date in the past means "now".
        ("Fri, 27 Nov 2026 17:00:00 GMT", 0.0),
        ("-5", None),
        ("soon", None),
        ("", None),
        (None, None),
        ("inf", None),
    ],
)
def test_retry_after_accepts_seconds_and_http_dates(value, expected):
    from lumoauth._http import _parse_retry_after

    now = 1795802400.0  # Fri, 27 Nov 2026 18:00:00 GMT
    assert _parse_retry_after(value, now=now) == expected


def test_rate_limit_error_reads_an_http_date():
    import email.utils
    import time

    client, session = make_client()
    later = email.utils.formatdate(time.time() + 120, usegmt=True)
    session.queue(FakeResponse(429, {"error": "rate_limit_exceeded"}, headers={"Retry-After": later}))
    with pytest.raises(LumoAuthRateLimitError) as exc_info:
        client.request("GET", "/thing")
    assert 110 <= exc_info.value.retry_after <= 120


@pytest.mark.parametrize(
    "body",
    [
        # The agent endpoints (Ask, token, JIT, attestation).
        {"error": "budget_exceeded", "error_description": "Agent budget exceeded"},
        # The Admin API envelope.
        {"error": "budget_exceeded", "message": "Agent budget exceeded", "status": 429},
    ],
)
def test_spent_budget_raises_the_budget_error(body):
    client, session = make_client()
    session.queue(FakeResponse(429, body, headers={"Retry-After": "3600"}))
    with pytest.raises(LumoAuthBudgetExceededError) as exc_info:
        client.request("POST", "/orgs/acme/api/v1/agents/ask")
    err = exc_info.value
    # Still a rate-limit error, so older except clauses keep catching it.
    assert isinstance(err, LumoAuthRateLimitError)
    assert (err.status_code, err.code, err.retry_after) == (429, "budget_exceeded", 3600.0)
    assert err.message == "Agent budget exceeded"
    assert err.body == body


def test_budget_code_on_another_status_is_not_the_budget_error():
    client, session = make_client()
    session.queue(FakeResponse(403, {"error": "budget_exceeded"}))
    with pytest.raises(LumoAuthPermissionDeniedError) as exc_info:
        client.request("GET", "/thing")
    assert not isinstance(exc_info.value, LumoAuthBudgetExceededError)


def test_budget_error_without_a_response_has_the_contract_defaults():
    err = LumoAuthBudgetExceededError()
    assert (err.code, err.status_code, err.retry_after) == ("BUDGET_EXCEEDED", 429, None)
    assert isinstance(err, LumoAuthRateLimitError)
    assert LumoAuthBudgetExceededError("spent").message == "spent"


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


def test_scope_refusal_exposes_required_scopes():
    client, session = make_client()
    session.queue(
        FakeResponse(
            403,
            {
                "error": "forbidden",
                "message": "Insufficient scope: this API key is missing a required scope",
                "status": 403,
                "details": {
                    "required_scopes": ["authz:read"],
                    "granted_scopes": ["admin:users:read"],
                },
            },
        )
    )
    with pytest.raises(LumoAuthPermissionDeniedError) as exc_info:
        client.request("GET", "/api/v1/authz/permissions")
    err = exc_info.value
    assert err.required_scopes == ["authz:read"]
    assert "Insufficient scope" in str(err)


def test_plain_permission_denial_has_no_required_scopes():
    client, session = make_client()
    session.queue(FakeResponse(403, {"error": "nope"}))
    with pytest.raises(LumoAuthPermissionDeniedError) as exc_info:
        client.request("GET", "/thing")
    assert exc_info.value.required_scopes == []
    assert LumoAuthPermissionDeniedError().required_scopes == []

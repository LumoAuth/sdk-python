"""Tests for the AAuth client token flows (mocked HTTP).

These assert the exact request shapes the LumoAuth server's AAuth 1.0
agent token endpoint (`request_type=code` / `request_type=refresh`)
requires.
"""

from __future__ import annotations

import base64
import hashlib
import json
from unittest import mock

import pytest

pytest.importorskip(
    "cryptography",
    reason="AAuth tests need the 'cryptography' package (pip install -e '.[dev]')",
)

from lumoauth.aauth import AAuthClient  # noqa: E402

BASE_URL = "https://auth.example.com"
ORG_ID = "acme-corp"
TOKEN_URL = f"{BASE_URL}/orgs/{ORG_ID}/api/v1/aauth/agent/token"
AGENT_TOKEN = "header.payload.signature"


@pytest.fixture()
def client() -> AAuthClient:
    private_pem, _jwks = AAuthClient.generate_keypair()
    return AAuthClient(
        agent_identifier="https://my-agent.example.com",
        private_key_pem=private_pem,
        base_url=BASE_URL,
        org_id=ORG_ID,
    )


def _mock_response(status_code: int = 200, payload: dict | None = None) -> mock.Mock:
    resp = mock.Mock()
    resp.status_code = status_code
    resp.json.return_value = payload if payload is not None else {}
    resp.text = json.dumps(payload or {})
    return resp


def _sent_body(post_mock: mock.Mock) -> dict:
    _, kwargs = post_mock.call_args
    return json.loads(kwargs["data"])


def _sent_headers(post_mock: mock.Mock) -> dict:
    _, kwargs = post_mock.call_args
    return kwargs["headers"]


# =============================================================================
# exchange_code — request_type=code
# =============================================================================


class TestExchangeCode:
    def test_sends_code_and_redirect_uri(self, client: AAuthClient) -> None:
        token_response = {
            "request_type": "code",
            "auth_token": "auth.jwt",
            "token_type": "auth+jwt",
            "expires_in": 300,
            "refresh_token": "rt-1",
        }
        with mock.patch("lumoauth.aauth.requests.post") as post:
            post.return_value = _mock_response(200, token_response)
            result = client.exchange_code(
                "auth-code-123",
                "https://my-agent.example.com/callback",
                agent_token=AGENT_TOKEN,
            )

        assert result == token_response
        assert post.call_args[0][0] == TOKEN_URL

        body = _sent_body(post)
        assert body == {
            "request_type": "code",
            "code": "auth-code-123",
            "redirect_uri": "https://my-agent.example.com/callback",
        }

    def test_does_not_send_request_token(self, client: AAuthClient) -> None:
        """Regression: the old client sent `request_token`, which the server
        never accepted for request_type=code."""
        with mock.patch("lumoauth.aauth.requests.post") as post:
            post.return_value = _mock_response(200, {"auth_token": "t"})
            client.exchange_code("c", "https://cb.example.com/", agent_token=AGENT_TOKEN)

        assert "request_token" not in _sent_body(post)

    def test_agent_token_travels_in_agent_auth_header(self, client: AAuthClient) -> None:
        with mock.patch("lumoauth.aauth.requests.post") as post:
            post.return_value = _mock_response(200, {"auth_token": "t"})
            client.exchange_code("c", "https://cb.example.com/", agent_token=AGENT_TOKEN)

        headers = _sent_headers(post)
        assert headers["Agent-Auth"] == f"agent_token={AGENT_TOKEN}"
        # RFC 9421 signature headers are present and the digest covers the body.
        assert headers["Signature-Input"].startswith("sig1=(")
        assert headers["Signature"].startswith("sig1=:")
        expected_digest = base64.b64encode(
            hashlib.sha256(post.call_args[1]["data"]).digest()
        ).decode()
        assert headers["Content-Digest"] == f"sha-256=:{expected_digest}:"

    def test_error_status_raises(self, client: AAuthClient) -> None:
        with mock.patch("lumoauth.aauth.requests.post") as post:
            post.return_value = _mock_response(400, {"error": "invalid_request"})
            with pytest.raises(RuntimeError, match="code exchange failed"):
                client.exchange_code("bad", "https://cb.example.com/", agent_token=AGENT_TOKEN)

    def test_redirect_uri_is_required(self, client: AAuthClient) -> None:
        with pytest.raises(TypeError):
            client.exchange_code("code-only", agent_token=AGENT_TOKEN)  # type: ignore[call-arg]


# =============================================================================
# refresh — request_type=refresh
# =============================================================================


class TestRefresh:
    def test_sends_refresh_and_resource_token(self, client: AAuthClient) -> None:
        token_response = {
            "request_type": "refresh",
            "auth_token": "auth.jwt2",
            "token_type": "auth+jwt",
            "expires_in": 300,
        }
        with mock.patch("lumoauth.aauth.requests.post") as post:
            post.return_value = _mock_response(200, token_response)
            result = client.refresh("refresh-tok", "resource.jwt", agent_token=AGENT_TOKEN)

        assert result == token_response
        assert post.call_args[0][0] == TOKEN_URL

        body = _sent_body(post)
        assert body == {
            "request_type": "refresh",
            "refresh_token": "refresh-tok",
            "resource_token": "resource.jwt",
        }

    def test_optional_scope_is_included(self, client: AAuthClient) -> None:
        with mock.patch("lumoauth.aauth.requests.post") as post:
            post.return_value = _mock_response(200, {"auth_token": "t"})
            client.refresh(
                "refresh-tok",
                "resource.jwt",
                scope="read",
                agent_token=AGENT_TOKEN,
            )

        body = _sent_body(post)
        assert body == {
            "request_type": "refresh",
            "refresh_token": "refresh-tok",
            "resource_token": "resource.jwt",
            "scope": "read",
        }

    def test_scope_omitted_when_not_given(self, client: AAuthClient) -> None:
        with mock.patch("lumoauth.aauth.requests.post") as post:
            post.return_value = _mock_response(200, {"auth_token": "t"})
            client.refresh("refresh-tok", "resource.jwt", agent_token=AGENT_TOKEN)

        assert "scope" not in _sent_body(post)

    def test_resource_token_is_required(self, client: AAuthClient) -> None:
        """Regression: the old client omitted resource_token entirely; the
        server rejects request_type=refresh without it."""
        with pytest.raises(TypeError):
            client.refresh("refresh-tok", agent_token=AGENT_TOKEN)  # type: ignore[call-arg]

    def test_agent_token_travels_in_agent_auth_header(self, client: AAuthClient) -> None:
        with mock.patch("lumoauth.aauth.requests.post") as post:
            post.return_value = _mock_response(200, {"auth_token": "t"})
            client.refresh("refresh-tok", "resource.jwt", agent_token=AGENT_TOKEN)

        assert _sent_headers(post)["Agent-Auth"] == f"agent_token={AGENT_TOKEN}"

    def test_error_status_raises(self, client: AAuthClient) -> None:
        with mock.patch("lumoauth.aauth.requests.post") as post:
            post.return_value = _mock_response(400, {"error": "invalid_request"})
            with pytest.raises(RuntimeError, match="refresh failed"):
                client.refresh("refresh-tok", "resource.jwt", agent_token=AGENT_TOKEN)

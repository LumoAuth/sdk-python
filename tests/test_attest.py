"""Workload attestation (``client.agents.attest``) and ``client_credentials(resource=)``."""

from __future__ import annotations

import base64
import json

import pytest

from conftest import FakeResponse, FakeSession
from lumoauth import LumoAuth, WorkloadAttestation
from lumoauth.errors import (
    LumoAuthAuthenticationError,
    LumoAuthBudgetExceededError,
    LumoAuthRateLimitError,
    LumoAuthValidationError,
)

BASE = "https://app.lumoauth.dev"
ORG = "acme-corp"
ATTEST = f"{BASE}/orgs/{ORG}/api/v1/agents/agt_7f3c2a19b84e5d60/attest"

ANSWER = {
    "access_token": "eyJ.agent.token",
    "token_type": "Bearer",
    "expires_in": 900,
    "scope": "invoices:read invoices:write",
    "identity": {"provider": "github", "subject": "repo:acme/agent:ref:refs/heads/main", "issuer": "https://token.actions.githubusercontent.com"},
}


def _client(fake_session: FakeSession, **options) -> LumoAuth:
    options.setdefault("base_url", BASE)
    options.setdefault("org_id", ORG)
    # An API key is configured, and attest() must not send it.
    return LumoAuth(api_key="lmk_secret", **options)


def test_attest_returns_the_typed_result(fake_session: FakeSession):
    fake_session.queue(FakeResponse(200, ANSWER))
    result = _client(fake_session).agents.attest("agt_7f3c2a19b84e5d60", "eyJ.oidc.token")

    assert isinstance(result, WorkloadAttestation)
    assert result.access_token == "eyJ.agent.token"
    assert (result.token_type, result.expires_in) == ("Bearer", 900)
    assert result.scopes == ["invoices:read", "invoices:write"]
    assert result.identity["provider"] == "github"
    assert result.raw == ANSWER

    method, url, kw = fake_session.last
    assert (method, url) == ("POST", ATTEST)
    assert kw["json"] == {"attestation_token": "eyJ.oidc.token"}
    # No credential of the client: the attestation token is the proof.
    assert "X-API-Key" not in kw["headers"] and "Authorization" not in kw["headers"]


@pytest.mark.parametrize(
    "scopes,sent",
    [
        (["invoices:read"], "invoices:read"),
        (["invoices:read", "", "invoices:write"], "invoices:read invoices:write"),
        ("invoices:read  invoices:write", "invoices:read invoices:write"),
        ([], None),
        (None, None),
    ],
)
def test_attest_narrows_the_scope(fake_session: FakeSession, scopes, sent):
    fake_session.queue(FakeResponse(200, ANSWER))
    _client(fake_session).agents.attest("agt_7f3c2a19b84e5d60", "eyJ.oidc.token", scopes=scopes)
    body = fake_session.last[2]["json"]
    assert body.get("scope") == sent


def test_attest_on_a_custom_domain(fake_session: FakeSession):
    fake_session.queue(FakeResponse(200, ANSWER))
    LumoAuth(custom_domain="auth.acme.com").agents.attest("agt_1", "t")
    assert fake_session.last[1] == "https://auth.acme.com/api/v1/agents/agt_1/attest"


def test_attest_with_dpop_sends_a_proof(fake_session: FakeSession):
    pytest.importorskip("cryptography")
    from lumoauth.dpop import DpopProofSigner

    fake_session.queue(FakeResponse(200, dict(ANSWER, token_type="DPoP")))
    result = _client(fake_session).agents.attest("agt_7f3c2a19b84e5d60", "t", dpop=DpopProofSigner())
    assert result.token_type == "DPoP"
    proof = fake_session.last[2]["headers"]["DPoP"]
    payload = proof.split(".")[1]
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    assert (claims["htm"], claims["htu"]) == ("POST", ATTEST)
    assert "ath" not in claims  # no access token yet


def test_attest_checks_its_arguments_before_any_request(fake_session: FakeSession):
    client = _client(fake_session)
    with pytest.raises(LumoAuthValidationError):
        client.agents.attest("", "t")
    with pytest.raises(LumoAuthValidationError):
        client.agents.attest("agt_1", "  ")
    assert fake_session.calls == []


def test_attest_refusals_are_typed(fake_session: FakeSession):
    client = _client(fake_session)
    fake_session.queue(FakeResponse(401, {"error": "attestation_rejected", "error_description": "Attestation rejected"}))
    with pytest.raises(LumoAuthAuthenticationError) as caught:
        client.agents.attest("agt_1", "t")
    assert caught.value.code == "attestation_rejected"

    fake_session.queue(
        FakeResponse(429, {"error": "budget_exceeded", "error_description": "Agent budget exceeded"}, headers={"Retry-After": "120"})
    )
    with pytest.raises(LumoAuthBudgetExceededError) as caught:
        client.agents.attest("agt_1", "t")
    assert isinstance(caught.value, LumoAuthRateLimitError) and caught.value.retry_after == 120.0

    fake_session.queue(FakeResponse(429, {"error": "rate_limit_exceeded"}, headers={"Retry-After": "60"}))
    with pytest.raises(LumoAuthRateLimitError) as caught:
        client.agents.attest("agt_1", "t")
    assert not isinstance(caught.value, LumoAuthBudgetExceededError)


def test_attest_refuses_an_answer_without_a_token(fake_session: FakeSession):
    fake_session.queue(FakeResponse(200, {"token_type": "Bearer"}))
    with pytest.raises(LumoAuthValidationError):
        _client(fake_session).agents.attest("agt_1", "t")


# ── client_credentials(resource=) ─────────────────────────────────────


def test_client_credentials_sends_the_resource(fake_session: FakeSession):
    fake_session.queue(FakeResponse(200, {"access_token": "at", "token_type": "Bearer"}))
    LumoAuth(base_url=BASE, org_id=ORG).auth.client_credentials(
        "client_1", "s3cr3t", scopes=["reports:read"], resource="https://api.example.com"
    )
    method, url, kw = fake_session.last
    assert url == f"{BASE}/orgs/{ORG}/api/v1/oauth/token"
    assert kw["data"] == {
        "grant_type": "client_credentials",
        "client_id": "client_1",
        "client_secret": "s3cr3t",
        "scope": "reports:read",
        "resource": "https://api.example.com",
    }


def test_client_credentials_without_a_resource_sends_none(fake_session: FakeSession):
    fake_session.queue(FakeResponse(200, {"access_token": "at"}))
    LumoAuth(base_url=BASE, org_id=ORG).auth.client_credentials("client_1", "s3cr3t")
    assert "resource" not in fake_session.last[2]["data"]

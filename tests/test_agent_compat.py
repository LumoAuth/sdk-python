"""LumoAuthAgent legacy surface — same methods, same endpoints, same payloads."""

from __future__ import annotations

import pytest

from conftest import FakeResponse, FakeSession
from lumoauth import LumoAuthAgent
from lumoauth.errors import LumoAuthApiError, LumoAuthConfigError

BASE = "https://auth.example.com"
ORG = "acme-corp"

TOKEN_RESPONSE = {
    "access_token": "at-1",
    "token_type": "Bearer",
    "expires_in": 3600,
    "scope": "read:documents tool:search_web",
}


@pytest.fixture()
def agent(fake_session: FakeSession, monkeypatch: pytest.MonkeyPatch) -> LumoAuthAgent:
    for var in ("LUMOAUTH_URL", "LUMOAUTH_ORG_ID", "AGENT_CLIENT_ID", "AGENT_CLIENT_SECRET"):
        monkeypatch.delenv(var, raising=False)
    return LumoAuthAgent(
        base_url=BASE,
        org_id=ORG,
        client_id="agt_client",
        client_secret="agt_secret",
    )


def authenticated(agent: LumoAuthAgent, session: FakeSession) -> LumoAuthAgent:
    session.queue(FakeResponse(200, TOKEN_RESPONSE))
    assert agent.authenticate() is True
    return agent


# ── Constructor ───────────────────────────────────────────────────────


def test_missing_credentials_raise_value_error_compatible(
    monkeypatch: pytest.MonkeyPatch,
):
    for var in ("AGENT_CLIENT_ID", "AGENT_CLIENT_SECRET"):
        monkeypatch.delenv(var, raising=False)
    with pytest.raises(ValueError):  # legacy contract
        LumoAuthAgent(base_url=BASE, org_id=ORG)
    with pytest.raises(LumoAuthConfigError):
        LumoAuthAgent(base_url=BASE, org_id=ORG)


def test_env_var_fallbacks(fake_session: FakeSession, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("LUMOAUTH_URL", BASE)
    monkeypatch.setenv("LUMOAUTH_ORG_ID", ORG)
    monkeypatch.setenv("AGENT_CLIENT_ID", "agt_env")
    monkeypatch.setenv("AGENT_CLIENT_SECRET", "sec_env")
    agent = LumoAuthAgent()
    assert agent.base_url == BASE
    assert agent.org_id == ORG
    assert agent.client_id == "agt_env"
    assert agent.client_secret == "sec_env"


def test_skip_cert_validation_flag(fake_session: FakeSession):
    agent = LumoAuthAgent(
        base_url=BASE, org_id=ORG, client_id="c", client_secret="s",
        skip_cert_validation=True,
    )
    assert agent._verify_tls is False
    fake_session.queue(FakeResponse(200, TOKEN_RESPONSE))
    agent.authenticate()
    _, _, kwargs = fake_session.last
    assert kwargs["verify"] is False


# ── authenticate / ensure_authenticated ───────────────────────────────


def test_authenticate_posts_client_credentials(agent, fake_session):
    fake_session.queue(FakeResponse(200, TOKEN_RESPONSE))
    assert agent.authenticate(scopes=["read:documents"]) is True

    method, url, kwargs = fake_session.last
    assert method == "POST"
    assert url == f"{BASE}/orgs/{ORG}/api/v1/oauth/token"
    assert kwargs["data"] == {
        "grant_type": "client_credentials",
        "client_id": "agt_client",
        "client_secret": "agt_secret",
        "scope": "read:documents",
    }
    # Token endpoint must not carry default auth headers
    assert "Authorization" not in (kwargs["headers"] or {})

    assert agent.access_token == "at-1"
    assert agent.token_scopes == ["read:documents", "tool:search_web"]


def test_authenticate_returns_false_on_http_error(agent, fake_session):
    fake_session.queue(FakeResponse(401, {"error": "invalid_client"}))
    assert agent.authenticate() is False
    assert agent.access_token is None


def test_ensure_authenticated_reuses_valid_token(agent, fake_session):
    authenticated(agent, fake_session)
    calls_before = len(fake_session.calls)
    assert agent.ensure_authenticated() is True
    assert len(fake_session.calls) == calls_before  # no extra HTTP call


# ── get_agent_info / capabilities / budget ────────────────────────────


def test_get_agent_info_calls_userinfo_with_bearer(agent, fake_session):
    authenticated(agent, fake_session)
    info = {"sub": "agent:1", "name": "Doc bot", "capabilities": ["read:documents"],
            "budget_policy": {"max_tokens_per_day": 100, "tokens_used_today": 100}}
    fake_session.queue(FakeResponse(200, info))

    assert agent.get_agent_info() == info
    method, url, kwargs = fake_session.last
    assert (method, url) == ("GET", f"{BASE}/orgs/{ORG}/api/v1/oauth/userinfo")
    assert kwargs["headers"]["Authorization"] == "Bearer at-1"

    # Cached info feeds capability & budget helpers with no extra requests
    calls = len(fake_session.calls)
    assert agent.has_capability("read:documents") is True
    assert agent.has_capability("write:documents") is False
    assert agent.get_budget_status() == info["budget_policy"]
    assert agent.is_budget_exhausted() is True
    assert len(fake_session.calls) == calls


def test_get_agent_info_failure_raises_runtime_error_compatible(agent, fake_session):
    authenticated(agent, fake_session)
    fake_session.queue(FakeResponse(500, {"error": "kaput"}))
    with pytest.raises(RuntimeError, match="Failed to get agent info"):
        agent.get_agent_info()


# ── ask / is_allowed / get_identity ───────────────────────────────────


def test_ask_posts_action_and_context(agent, fake_session):
    authenticated(agent, fake_session)
    fake_session.queue(FakeResponse(200, {"allowed": True, "action": "document.read"}))

    result = agent.ask("document.read", context={"id": "doc_99"})
    assert result["allowed"] is True

    method, url, kwargs = fake_session.last
    assert (method, url) == ("POST", f"{BASE}/orgs/{ORG}/api/v1/agents/ask")
    assert kwargs["json"] == {"action": "document.read", "context": {"id": "doc_99"}}
    assert kwargs["headers"]["Authorization"] == "Bearer at-1"


def test_is_allowed_shorthand(agent, fake_session):
    authenticated(agent, fake_session)
    fake_session.queue(FakeResponse(200, {"allowed": False}))
    assert agent.is_allowed("document.write") is False


def test_get_identity_calls_agents_me(agent, fake_session):
    authenticated(agent, fake_session)
    payload = {"identity": {"id": "agt_1"}, "capabilities": [], "workspace": {}}
    fake_session.queue(FakeResponse(200, payload))
    assert agent.get_identity() == payload
    method, url, _ = fake_session.last
    assert (method, url) == ("GET", f"{BASE}/orgs/{ORG}/api/v1/agents/me")


# ── register ──────────────────────────────────────────────────────────


def test_register_posts_full_payload(agent, fake_session):
    authenticated(agent, fake_session)
    fake_session.queue(FakeResponse(201, {"agent_id": "agt_1"}))

    result = agent.register(
        "Doc bot",
        description="Reads documents",
        capabilities=["read:documents"],
        jwks_uri="https://bot.example.com/.well-known/jwks.json",
    )
    assert result == {"agent_id": "agt_1"}

    method, url, kwargs = fake_session.last
    assert (method, url) == ("POST", f"{BASE}/orgs/{ORG}/api/v1/agents/register")
    assert kwargs["json"] == {
        "client_id": "agt_client",
        "name": "Doc bot",
        "description": "Reads documents",
        "capabilities": ["read:documents"],
        "jwks_uri": "https://bot.example.com/.well-known/jwks.json",
    }


def test_register_failure_raises(agent, fake_session):
    authenticated(agent, fake_session)
    fake_session.queue(FakeResponse(400, {"error": "invalid"}))
    with pytest.raises(RuntimeError, match="Agent registration failed"):
        agent.register("Doc bot")


# ── api_request ───────────────────────────────────────────────────────


def test_api_request_returns_raw_response(agent, fake_session):
    authenticated(agent, fake_session)
    fake_session.queue(FakeResponse(200, {"doc": 1}))

    resp = agent.api_request(
        "GET", f"/orgs/{ORG}/api/v1/documents/123", params={"full": 1}
    )
    assert resp.status_code == 200
    assert resp.json() == {"doc": 1}

    method, url, kwargs = fake_session.last
    assert (method, url) == ("GET", f"{BASE}/orgs/{ORG}/api/v1/documents/123")
    assert kwargs["params"] == {"full": 1}
    assert kwargs["headers"]["Authorization"] == "Bearer at-1"


def test_api_request_accepts_full_url_and_json_alias(agent, fake_session):
    authenticated(agent, fake_session)
    fake_session.queue(FakeResponse(200, {}))
    agent.api_request("POST", "https://api.other.example.com/x", json={"a": 1})
    method, url, kwargs = fake_session.last
    assert url == "https://api.other.example.com/x"
    assert kwargs["json"] == {"a": 1}


def test_api_request_error_status_does_not_raise(agent, fake_session):
    """Legacy contract: callers inspect resp.status_code themselves."""
    authenticated(agent, fake_session)
    fake_session.queue(FakeResponse(500, {"error": "boom"}))
    resp = agent.api_request("GET", "/x")
    assert resp.status_code == 500


# ── get_mcp_token ─────────────────────────────────────────────────────


def test_get_mcp_token_posts_rfc8693_exchange(agent, fake_session):
    authenticated(agent, fake_session)
    fake_session.queue(FakeResponse(200, {"access_token": "mcp-tok"}))

    assert agent.get_mcp_token("urn:mcp:financial-data") == "mcp-tok"

    method, url, kwargs = fake_session.last
    assert (method, url) == ("POST", f"{BASE}/orgs/{ORG}/api/v1/oauth/token")
    assert kwargs["data"] == {
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "subject_token": "at-1",
        "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "audience": "urn:mcp:financial-data",
    }


def test_get_mcp_token_returns_none_on_failure(agent, fake_session):
    authenticated(agent, fake_session)
    fake_session.queue(FakeResponse(403, {"error": "forbidden"}))
    assert agent.get_mcp_token("urn:mcp:x") is None


# ── namespaces ────────────────────────────────────────────────────────


def test_agent_exposes_resource_namespaces(agent):
    from lumoauth.resources import (
        ApprovalsResource,
        DelegationResource,
        JitResource,
        McpResource,
    )

    assert isinstance(agent.jit, JitResource)
    assert isinstance(agent.delegation, DelegationResource)
    assert isinstance(agent.mcp, McpResource)
    assert isinstance(agent.approvals, ApprovalsResource)


def test_namespace_calls_auto_authenticate(agent, fake_session):
    """Resource calls pull a token through the auto-refreshing provider."""
    fake_session.queue(
        FakeResponse(200, TOKEN_RESPONSE),          # client-credentials
        FakeResponse(200, {"task_id": "task-1"}),   # jit task create
    )
    data = agent.jit.create_task(name="t")
    assert data["task_id"] == "task-1"

    # First call was authentication, second the JIT create with the token.
    (m1, u1, _), (m2, u2, k2) = fake_session.calls
    assert u1.endswith("/oauth/token")
    assert (m2, u2) == ("POST", f"{BASE}/orgs/{ORG}/api/v1/jit/task")
    assert k2["headers"]["Authorization"] == "Bearer at-1"


# ── require_approval compatibility ────────────────────────────────────


def test_require_approval_flow(agent, fake_session, monkeypatch):
    from lumoauth import require_approval

    monkeypatch.setattr("lumoauth.approval.time.sleep", lambda s: None)
    authenticated(agent, fake_session)
    fake_session.queue(
        FakeResponse(200, {"approval_token": "apv-1", "status": "pending"}),
        FakeResponse(200, {
            "approval_token": "apv-1",
            "status": "approved",
            "task_id": "wire-1",
            "impact": "high",
            "reason": "Wire $1",
            "responded_at": "2026-08-14T00:00:00Z",
            "approved_by": {"email": "ada@acme.com"},
        }),
    )

    result = require_approval(
        agent,
        task_id="wire-1",
        reason="Wire $1",
        impact="high",
        on_behalf_of="ada@acme.com",
    )
    assert result.status == "approved"
    assert result.token == "apv-1"

    create = fake_session.calls[1]
    assert create[1] == f"{BASE}/orgs/{ORG}/api/v1/agents/me/approvals"
    status = fake_session.calls[2]
    assert status[1] == f"{BASE}/orgs/{ORG}/api/v1/agents/me/approvals/apv-1/status"

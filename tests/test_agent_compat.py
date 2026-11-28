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
    "scope": "documents:read web:search",
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
    assert agent.authenticate(scopes=["documents:read"]) is True

    method, url, kwargs = fake_session.last
    assert method == "POST"
    assert url == f"{BASE}/orgs/{ORG}/api/v1/oauth/token"
    assert kwargs["data"] == {
        "grant_type": "client_credentials",
        "client_id": "agt_client",
        "client_secret": "agt_secret",
        "scope": "documents:read",
    }
    # Token endpoint must not carry default auth headers
    assert "Authorization" not in (kwargs["headers"] or {})

    assert agent.access_token == "at-1"
    assert agent.token_scopes == ["documents:read", "web:search"]


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
    info = {"sub": "agent:1", "name": "Doc bot", "capabilities": ["documents:read"],
            "budget_policy": {"max_tokens_per_day": 100, "tokens_used_today": 100}}
    fake_session.queue(FakeResponse(200, info))

    assert agent.get_agent_info() == info
    method, url, kwargs = fake_session.last
    assert (method, url) == ("GET", f"{BASE}/orgs/{ORG}/api/v1/oauth/userinfo")
    assert kwargs["headers"]["Authorization"] == "Bearer at-1"

    # Cached info feeds capability & budget helpers with no extra requests
    calls = len(fake_session.calls)
    assert agent.has_capability("documents:read") is True
    assert agent.has_capability("documents:write") is False
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
    fake_session.queue(FakeResponse(200, {"allowed": True, "action": "document:read"}))

    result = agent.ask("document:read", context={"id": "doc_99"})
    assert result["allowed"] is True

    method, url, kwargs = fake_session.last
    assert (method, url) == ("POST", f"{BASE}/orgs/{ORG}/api/v1/agents/ask")
    assert kwargs["json"] == {"action": "document:read", "context": {"id": "doc_99"}}
    assert kwargs["headers"]["Authorization"] == "Bearer at-1"


def test_is_allowed_shorthand(agent, fake_session):
    authenticated(agent, fake_session)
    fake_session.queue(FakeResponse(200, {"allowed": False}))
    assert agent.is_allowed("document:write") is False


TRACEPARENT = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"


def test_ask_sends_the_traceparent(agent, fake_session):
    authenticated(agent, fake_session)
    fake_session.queue(FakeResponse(200, {"allowed": True}), FakeResponse(200, {"allowed": True}))

    agent.ask("document:read", traceparent=TRACEPARENT)
    headers = fake_session.last[2]["headers"]
    assert headers["traceparent"] == TRACEPARENT
    assert headers["Authorization"] == "Bearer at-1"  # the credential is still added

    assert agent.is_allowed("document:read", {"id": "doc_99"}, traceparent=TRACEPARENT) is True
    assert fake_session.last[2]["headers"]["traceparent"] == TRACEPARENT


def test_ask_without_a_traceparent_sends_none(agent, fake_session):
    authenticated(agent, fake_session)
    fake_session.queue(FakeResponse(200, {"allowed": True}))
    agent.ask("document:read")
    assert "traceparent" not in fake_session.last[2]["headers"]


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
        capabilities=["documents:read"],
        jwks_uri="https://bot.example.com/.well-known/jwks.json",
    )
    assert result == {"agent_id": "agt_1"}

    method, url, kwargs = fake_session.last
    assert (method, url) == ("POST", f"{BASE}/orgs/{ORG}/api/v1/agents/register")
    assert kwargs["json"] == {
        "client_id": "agt_client",
        "name": "Doc bot",
        "description": "Reads documents",
        "capabilities": ["documents:read"],
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

    assert agent.get_mcp_token("https://mcp.example.com/mcp") == "mcp-tok"

    method, url, kwargs = fake_session.last
    assert (method, url) == ("POST", f"{BASE}/orgs/{ORG}/api/v1/oauth/token")
    assert kwargs["data"] == {
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "subject_token": "at-1",
        "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "audience": "https://mcp.example.com/mcp",
        "resource": "https://mcp.example.com/mcp",
    }


def test_get_mcp_token_returns_none_on_failure(agent, fake_session):
    authenticated(agent, fake_session)
    fake_session.queue(FakeResponse(403, {"error": "forbidden"}))
    with pytest.warns(FutureWarning, match=r"HTTP 403 forbidden.*get_mcp_credential"):
        assert agent.get_mcp_token("https://mcp.example.com/x") is None


def test_get_mcp_credential_raises_the_same_failure(agent, fake_session):
    authenticated(agent, fake_session)
    fake_session.queue(FakeResponse(400, {"error": "invalid_target", "error_description": "Unknown resource"}))
    with pytest.raises(LumoAuthApiError) as caught:
        agent.get_mcp_credential("https://mcp.example.com/x")
    assert (caught.value.status_code, caught.value.code) == (400, "invalid_target")


def test_get_mcp_token_rejects_a_urn_server_id(agent, fake_session):
    from lumoauth.errors import LumoAuthValidationError

    with pytest.raises(LumoAuthValidationError, match="https URL"):
        agent.get_mcp_token("urn:mcp:financial-data")
    assert fake_session.calls == []


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
            "approved_by": {"user_id": 42},
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
    assert result.approved_by == {"user_id": 42}

    create = fake_session.calls[1]
    assert create[1] == f"{BASE}/orgs/{ORG}/api/v1/agents/me/approvals"
    status = fake_session.calls[2]
    assert status[1] == f"{BASE}/orgs/{ORG}/api/v1/agents/me/approvals/apv-1/status"


# ── delegation consent URL ────────────────────────────────────────────


def test_consent_url_defaults_to_documents_read(agent):
    from urllib.parse import parse_qs, urlparse

    from lumoauth import DelegationChain

    chain = DelegationChain(agent, redirect_uri="https://agent.example.com/callback")
    # Without the application's client ID the old URL is kept, with a warning: it cannot work.
    with pytest.warns(FutureWarning, match="app_client_id"):
        query = parse_qs(urlparse(chain.get_consent_url("session_1")).query)
    assert query["scope"] == ["documents:read"]
    assert query["prompt"] == ["consent"]
    assert query["client_id"] == [agent.client_id]


# ── delegation depth ──────────────────────────────────────────────────


def test_delegation_chain_holds_five_actors():
    from lumoauth import delegation

    assert delegation.MAX_DELEGATION_DEPTH == 5


def test_too_deep_chain_is_recognised(agent, fake_session):
    from lumoauth import DelegationChain

    authenticated(agent, fake_session)
    chain = DelegationChain(agent, redirect_uri="https://agent.example.com/callback")
    chain.set_user_token("s1", "user-at")
    too_deep = "Delegation chain too deep: act nesting depth 6 exceeds the maximum of 5"
    fake_session.queue(
        FakeResponse(200, {"access_token": "delegated", "token_type": "Bearer", "expires_in": 600}),
        FakeResponse(400, {"error": "invalid_request", "error_description": too_deep}),
    )
    with pytest.raises(LumoAuthApiError) as caught:
        chain.delegate_to_sub_agent("s1", "sub-agent-at")
    err = caught.value
    assert (err.status_code, err.code) == (400, "invalid_request")
    assert err.message == f"Delegation chain too deep (max depth: 5): {too_deep}"


# ── delegation consent as the application (SRV-47) ──────────────────


APP = "client_app123"


def _app_chain(agent, secret="app-secret"):
    from lumoauth import DelegationChain

    return DelegationChain(
        agent, redirect_uri="https://app.example.com/callback", app_client_id=APP, app_client_secret=secret
    )


def test_consent_url_names_the_application_with_pkce(agent):
    import base64
    import hashlib
    from urllib.parse import parse_qs, urlparse

    chain = _app_chain(agent)
    url = chain.get_consent_url("s1", scopes=["documents:read"], offline_access=True)
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    assert parsed.path == f"/orgs/{ORG}/api/v1/oauth/authorize"
    assert query["client_id"] == [APP]
    assert query["redirect_uri"] == ["https://app.example.com/callback"]
    assert query["scope"] == ["openid documents:read offline_access"]
    assert query["code_challenge_method"] == ["S256"]
    assert "prompt" not in query and "access_type" not in query
    verifier, state = chain._pending_consents["s1"]
    assert query["state"] == [state] and len(state) >= 24
    expected = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    assert query["code_challenge"] == [expected]
    # No refresh token asked for unless offline_access.
    plain = parse_qs(urlparse(chain.get_consent_url("s2")).query)
    assert plain["scope"] == ["openid documents:read"]


def test_consent_code_is_redeemed_by_the_application(agent, fake_session):
    from urllib.parse import parse_qs, urlparse

    chain = _app_chain(agent)
    state = parse_qs(urlparse(chain.get_consent_url("s1", offline_access=True)).query)["state"][0]
    verifier = chain._pending_consents["s1"][0]
    fake_session.queue(FakeResponse(200, {"access_token": "user-at", "refresh_token": "user-rt", "expires_in": 3600, "scope": "openid documents:read"}))
    assert chain.handle_consent_callback("s1", "the-code", state=state) is True
    method, url, kw = fake_session.last
    assert (method, url) == ("POST", f"{BASE}/orgs/{ORG}/api/v1/oauth/token")
    assert kw["data"] == {
        "grant_type": "authorization_code",
        "code": "the-code",
        "redirect_uri": "https://app.example.com/callback",
        "client_id": APP,
        "client_secret": "app-secret",
        "code_verifier": verifier,
    }
    # The agent's credentials play no part.
    assert agent.client_secret not in str(kw)


def test_consent_callback_refuses_a_wrong_state_or_an_unknown_session(agent, fake_session):
    chain = _app_chain(agent)
    chain.get_consent_url("s1")
    assert chain.handle_consent_callback("s1", "code", state="forged") is False
    assert chain.handle_consent_callback("never-started", "code") is False
    assert fake_session.calls == []


def test_a_public_application_redeems_without_a_secret(agent, fake_session):
    chain = _app_chain(agent, secret=None)
    chain.get_consent_url("s1")
    fake_session.queue(FakeResponse(200, {"access_token": "user-at"}))
    assert chain.handle_consent_callback("s1", "code") is True
    assert "client_secret" not in fake_session.last[2]["data"]


def test_revoke_revokes_the_refresh_token_as_the_application(agent, fake_session):
    chain = _app_chain(agent)
    chain.get_consent_url("s1", offline_access=True)
    fake_session.queue(FakeResponse(200, {"access_token": "user-at", "refresh_token": "user-rt"}))
    chain.handle_consent_callback("s1", "code")
    fake_session.queue(FakeResponse(200, {}))
    assert chain.revoke("s1") is True
    method, url, kw = fake_session.last
    assert (method, url) == ("POST", f"{BASE}/orgs/{ORG}/api/v1/oauth/revoke")
    assert kw["data"] == {"token": "user-rt", "token_type_hint": "refresh_token", "client_id": APP, "client_secret": "app-secret"}
    assert chain.active_sessions == []


def test_revoke_without_the_application_only_forgets_local_state(agent, fake_session, caplog):
    import logging

    from lumoauth import DelegationChain

    chain = DelegationChain(agent)
    chain.set_user_token("s1", "user-at")
    with caplog.at_level(logging.WARNING, logger="lumoauth.delegation"):
        assert chain.revoke("s1") is False
    assert fake_session.calls == []  # the agent's credentials never revoke the application's token
    assert any("only forgotten locally" in r.getMessage() for r in caplog.records)
    assert chain.active_sessions == []


def test_a_failed_revocation_returns_false(agent, fake_session):
    chain = _app_chain(agent)
    chain.get_consent_url("s1", offline_access=True)
    fake_session.queue(FakeResponse(200, {"access_token": "user-at", "refresh_token": "user-rt"}))
    chain.handle_consent_callback("s1", "code")
    fake_session.queue(FakeResponse(400, {"error": "invalid_client"}))
    assert chain.revoke("s1") is False


def test_the_application_refreshes_the_persons_token(agent, fake_session):
    authenticated(agent, fake_session)
    chain = _app_chain(agent)
    chain.get_consent_url("s1", offline_access=True)
    fake_session.queue(FakeResponse(200, {"access_token": "user-at", "refresh_token": "user-rt", "expires_in": -1}))
    chain.handle_consent_callback("s1", "code")
    fake_session.queue(
        FakeResponse(200, {"access_token": "user-at-2", "refresh_token": "user-rt-2", "expires_in": 3600}),
        FakeResponse(200, {"access_token": "delegated", "expires_in": 600}),
    )
    assert chain.exchange("s1") == "delegated"
    refresh = [kw["data"] for _, url, kw in fake_session.calls if kw.get("data", {}).get("grant_type") == "refresh_token"]
    assert refresh and refresh[-1]["client_id"] == APP and refresh[-1]["client_secret"] == "app-secret"

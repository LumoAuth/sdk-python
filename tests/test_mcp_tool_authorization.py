"""MCP per-tool checks: mcp.authorize_tool and agents.authorize_mcp_tool."""

from __future__ import annotations

import pytest

from conftest import FakeResponse, FakeSession
from lumoauth import (
    AgentMcpToolDecision,
    LumoAuth,
    LumoAuthAgent,
    McpToolDecision,
)
from lumoauth.errors import (
    LumoAuthApiError,
    LumoAuthAuthenticationError,
    LumoAuthNotFoundError,
    LumoAuthPermissionDeniedError,
    LumoAuthRateLimitError,
    LumoAuthValidationError,
)

BASE = "https://auth.example.com"
ORG = "acme-corp"
SERVER = "mcp_0123456789abcdef01234567"
TOOL = "send_payment_reminder"
TOOL_URL = f"{BASE}/orgs/{ORG}/api/v1/mcp/servers/{SERVER}/tools/authorize"
AGENT_URL = f"{BASE}/orgs/{ORG}/api/v1/agents/me/mcp/authorize"


def _decision(allowed: bool) -> dict:
    return {
        "allowed": allowed,
        "subject": {"type": "agent", "id": "agt_1"},
        "resource": {"type": "mcp_tool", "id": f"{SERVER}/{TOOL}"},
    }


def _agent_decision(allowed: bool) -> dict:
    return {
        "allowed": allowed,
        "agent_id": "agt_1",
        "resource": {"type": "mcp_tool", "id": f"{SERVER}/{TOOL}"},
    }


@pytest.fixture()
def server(fake_session: FakeSession) -> LumoAuth:
    return LumoAuth(base_url=BASE, org_id=ORG, token_provider=lambda: "server-cc-token")


@pytest.fixture()
def agent(fake_session: FakeSession, monkeypatch: pytest.MonkeyPatch) -> LumoAuthAgent:
    for var in ("LUMOAUTH_URL", "LUMOAUTH_ORG_ID", "AGENT_CLIENT_ID", "AGENT_CLIENT_SECRET"):
        monkeypatch.delenv(var, raising=False)
    a = LumoAuthAgent(base_url=BASE, org_id=ORG, client_id="c", client_secret="s")
    fake_session.queue(FakeResponse(200, {"access_token": "agent-at", "expires_in": 3600}))
    assert a.authenticate() is True
    return a


# ── mcp.authorize_tool ─────────────────────────────────────────────────


def test_authorize_tool_allow_sends_exact_request(server, fake_session):
    fake_session.queue(FakeResponse(200, _decision(True)))
    d = server.mcp.authorize_tool(SERVER, "agent", "agent_agt_1", TOOL)

    assert d == McpToolDecision(
        allowed=True,
        subject_type="agent",
        subject_id="agt_1",
        resource_type="mcp_tool",
        resource_id=f"{SERVER}/{TOOL}",
    )
    method, url, kw = fake_session.last
    assert method == "POST"
    assert url == TOOL_URL
    assert kw["json"] == {"subject": {"type": "agent", "id": "agent_agt_1"}, "tool": TOOL}
    assert kw["headers"]["Authorization"] == "Bearer server-cc-token"


def test_authorize_tool_url_encodes_server_id(server, fake_session):
    fake_session.queue(FakeResponse(200, _decision(True)))
    server.mcp.authorize_tool("mcp_a b?c", "user", "u-1", TOOL)
    _, url, _ = fake_session.last
    assert url == f"{BASE}/orgs/{ORG}/api/v1/mcp/servers/mcp_a%20b%3Fc/tools/authorize"


def test_authorize_tool_deny_is_a_result(server, fake_session):
    fake_session.queue(FakeResponse(403, _decision(False)))
    d = server.mcp.authorize_tool(SERVER, "user", "u-1", TOOL)
    assert d.allowed is False
    assert d.resource_id == f"{SERVER}/{TOOL}"


def test_authorize_tool_insufficient_scope_raises(server, fake_session):
    fake_session.queue(
        FakeResponse(403, {"error": "insufficient_scope", "error_description": "needs mcp:authorize"})
    )
    with pytest.raises(LumoAuthPermissionDeniedError) as info:
        server.mcp.authorize_tool(SERVER, "user", "u-1", TOOL)
    assert info.value.status_code == 403
    assert info.value.code == "insufficient_scope"


def test_authorize_tool_forbidden_raises(server, fake_session):
    fake_session.queue(FakeResponse(403, {"error": "forbidden"}))
    with pytest.raises(LumoAuthPermissionDeniedError):
        server.mcp.authorize_tool(SERVER, "user", "u-1", TOOL)


def test_authorize_tool_403_with_allowed_true_is_not_a_deny(server, fake_session):
    fake_session.queue(FakeResponse(403, {"allowed": True}))
    with pytest.raises(LumoAuthPermissionDeniedError):
        server.mcp.authorize_tool(SERVER, "user", "u-1", TOOL)


@pytest.mark.parametrize(
    "status,cls",
    [
        (400, LumoAuthApiError),
        (401, LumoAuthAuthenticationError),
        (404, LumoAuthNotFoundError),
    ],
)
def test_authorize_tool_error_mapping(server, fake_session, status, cls):
    fake_session.queue(FakeResponse(status, {"error": "x", "allowed": False}))
    with pytest.raises(cls) as info:
        server.mcp.authorize_tool(SERVER, "user", "u-1", TOOL)
    assert info.value.status_code == status


def test_authorize_tool_rate_limit(server, fake_session):
    fake_session.queue(
        FakeResponse(429, {"error": "too_many_requests"}, headers={"Retry-After": "7"})
    )
    with pytest.raises(LumoAuthRateLimitError) as info:
        server.mcp.authorize_tool(SERVER, "user", "u-1", TOOL)
    assert info.value.retry_after == 7


@pytest.mark.parametrize(
    "args",
    [
        ("", "user", "u-1", TOOL),
        ("https://mcp.example.com/mcp", "user", "u-1", TOOL),
        ("mcp_1#x", "user", "u-1", TOOL),
        (SERVER, "group", "u-1", TOOL),
        (SERVER, "user", "", TOOL),
        (SERVER, "user", "u-1", ""),
        (SERVER, "user", "u-1", "a/b"),
        (SERVER, "user", "u-1", "a:b"),
        (SERVER, "user", "u-1", "a#b"),
        (SERVER, "user", "u-1", "*"),
        (SERVER, "user", "u-1", "x" * 81),
    ],
)
def test_authorize_tool_validation(server, fake_session, args):
    with pytest.raises(LumoAuthValidationError):
        server.mcp.authorize_tool(*args)
    assert fake_session.calls == []


def test_authorize_tool_accepts_80_char_tool(server, fake_session):
    fake_session.queue(FakeResponse(200, _decision(True)))
    assert server.mcp.authorize_tool(SERVER, "user", "u-1", "x" * 80).allowed is True


# ── agents.authorize_mcp_tool ──────────────────────────────────────────


def test_agents_authorize_mcp_tool_allow(server, fake_session):
    fake_session.queue(FakeResponse(200, _agent_decision(True)))
    d = server.agents.authorize_mcp_tool(SERVER, TOOL)
    assert d == AgentMcpToolDecision(
        allowed=True,
        agent_id="agt_1",
        resource_type="mcp_tool",
        resource_id=f"{SERVER}/{TOOL}",
    )
    method, url, kw = fake_session.last
    assert method == "POST"
    assert url == AGENT_URL
    assert kw["json"] == {"server_id": SERVER, "tool": TOOL}
    assert kw["headers"]["Authorization"] == "Bearer server-cc-token"


def test_agents_authorize_mcp_tool_deny(server, fake_session):
    fake_session.queue(FakeResponse(403, _agent_decision(False)))
    d = server.agents.authorize_mcp_tool(SERVER, TOOL)
    assert d.allowed is False
    assert d.agent_id == "agt_1"


def test_agents_authorize_mcp_tool_agent_required_raises(server, fake_session):
    fake_session.queue(FakeResponse(403, {"error": "agent_required"}))
    with pytest.raises(LumoAuthPermissionDeniedError) as info:
        server.agents.authorize_mcp_tool(SERVER, TOOL)
    assert info.value.code == "agent_required"


def test_agents_authorize_mcp_tool_unknown_server(server, fake_session):
    fake_session.queue(FakeResponse(404, {"error": "unknown_server"}))
    with pytest.raises(LumoAuthNotFoundError) as info:
        server.agents.authorize_mcp_tool(SERVER, TOOL)
    assert info.value.code == "unknown_server"


def test_agents_authorize_mcp_tool_invalid_request(server, fake_session):
    fake_session.queue(FakeResponse(400, {"error": "invalid_request"}))
    with pytest.raises(LumoAuthApiError) as info:
        server.agents.authorize_mcp_tool(SERVER, TOOL)
    assert info.value.status_code == 400


@pytest.mark.parametrize(
    "server_id,tool",
    [("", TOOL), ("a/b", TOOL), (SERVER, ""), (SERVER, "t*"), (SERVER, "x" * 81)],
)
def test_agents_authorize_mcp_tool_validation(server, fake_session, server_id, tool):
    with pytest.raises(LumoAuthValidationError):
        server.agents.authorize_mcp_tool(server_id, tool)
    assert fake_session.calls == []


# ── LumoAuthAgent.authorize_mcp_tool ───────────────────────────────────


def test_agent_client_uses_its_own_token(agent, fake_session):
    fake_session.queue(FakeResponse(200, _agent_decision(True)))
    d = agent.authorize_mcp_tool(SERVER, TOOL)
    assert d.allowed is True
    method, url, kw = fake_session.last
    assert (method, url) == ("POST", AGENT_URL)
    assert kw["headers"]["Authorization"] == "Bearer agent-at"
    assert kw["json"] == {"server_id": SERVER, "tool": TOOL}


def test_agent_client_deny_does_not_raise(agent, fake_session):
    fake_session.queue(FakeResponse(403, _agent_decision(False)))
    assert agent.authorize_mcp_tool(SERVER, TOOL).allowed is False


def test_agent_client_unknown_server_raises(agent, fake_session):
    fake_session.queue(FakeResponse(404, {"error": "unknown_server"}))
    with pytest.raises(LumoAuthNotFoundError):
        agent.authorize_mcp_tool(SERVER, TOOL)

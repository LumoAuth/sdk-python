"""Approvals without a push prompt, MCP resource binding, JIT pending parsing."""

from __future__ import annotations

import pytest

from conftest import FakeResponse, FakeSession
from lumoauth import LumoAuth, LumoAuthAgent, require_approval
from lumoauth.errors import (
    LumoAuthApprovalNotDeliveredError,
    LumoAuthError,
    LumoAuthValidationError,
)

BASE = "https://auth.example.com"
ORG = "acme-corp"
APPROVALS = f"{BASE}/orgs/{ORG}/api/v1/agents/me/approvals"

FALLBACK_202 = {
    "status": "email_fallback_sent",
    "message": "The user has no enrolled push device. An approval email was sent to them.",
    "task_id": "wire-1",
    "impact": "high",
}
NO_DEVICE_428 = {
    "error": "no_enrolled_device",
    "message": "The user has no enrolled push device.",
}


@pytest.fixture()
def client(fake_session: FakeSession) -> LumoAuth:
    return LumoAuth(base_url=BASE, org_id=ORG, token_provider=lambda: "at-user")


@pytest.fixture()
def agent(fake_session: FakeSession, monkeypatch: pytest.MonkeyPatch) -> LumoAuthAgent:
    for var in ("LUMOAUTH_URL", "LUMOAUTH_ORG_ID", "AGENT_CLIENT_ID", "AGENT_CLIENT_SECRET"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr("lumoauth.approval.time.sleep", lambda s: None)
    monkeypatch.setattr("lumoauth.resources.approvals.time.sleep", lambda s: None)
    a = LumoAuthAgent(base_url=BASE, org_id=ORG, client_id="c", client_secret="s")
    fake_session.queue(FakeResponse(200, {"access_token": "at-1", "expires_in": 3600}))
    assert a.authenticate() is True
    return a


def _approval_kwargs():
    return dict(task_id="wire-1", reason="Wire $1", on_behalf_of="ada@acme.com", impact="high")


# ── Issue A: 202 email_fallback_sent / 428 no_enrolled_device ──────────


def test_error_class_shape():
    err = LumoAuthApprovalNotDeliveredError()
    assert isinstance(err, LumoAuthError)
    assert err.code == "APPROVAL_NOT_DELIVERED"
    assert err.reason is None


def test_create_202_returns_status_without_token(client, fake_session):
    fake_session.queue(FakeResponse(202, FALLBACK_202))
    created = client.approvals.create(**_approval_kwargs())
    assert created["status"] == "email_fallback_sent"
    assert created["approval_token"] is None
    assert created["task_id"] == "wire-1"
    assert len(fake_session.calls) == 1


def test_create_428_raises_no_enrolled_device(client, fake_session):
    fake_session.queue(FakeResponse(428, NO_DEVICE_428))
    with pytest.raises(LumoAuthApprovalNotDeliveredError) as info:
        client.approvals.create(**_approval_kwargs())
    assert info.value.reason == "no_enrolled_device"
    assert info.value.status_code == 428
    assert info.value.code == "APPROVAL_NOT_DELIVERED"


def test_require_202_raises_without_polling(client, fake_session, monkeypatch):
    monkeypatch.setattr("lumoauth.resources.approvals.time.sleep", lambda s: None)
    fake_session.queue(FakeResponse(202, FALLBACK_202))
    with pytest.raises(LumoAuthApprovalNotDeliveredError) as info:
        client.approvals.require(**_approval_kwargs())
    assert info.value.reason == "email_fallback_sent"
    assert info.value.task_id == "wire-1"
    assert [c[1] for c in fake_session.calls] == [APPROVALS], "no status request"


def test_require_428_raises_no_enrolled_device(client, fake_session):
    fake_session.queue(FakeResponse(428, NO_DEVICE_428))
    with pytest.raises(LumoAuthApprovalNotDeliveredError) as info:
        client.approvals.require(**_approval_kwargs())
    assert info.value.reason == "no_enrolled_device"
    assert len(fake_session.calls) == 1


def test_wait_without_token_is_rejected(client, fake_session):
    with pytest.raises(LumoAuthValidationError):
        client.approvals.wait(None)  # type: ignore[arg-type]
    assert fake_session.calls == []


def test_require_approval_helper_202_raises_without_polling(agent, fake_session):
    fake_session.queue(FakeResponse(202, FALLBACK_202))
    with pytest.raises(LumoAuthApprovalNotDeliveredError) as info:
        require_approval(agent, **_approval_kwargs())
    assert info.value.reason == "email_fallback_sent"
    assert [c[1] for c in fake_session.calls[1:]] == [APPROVALS]


def test_require_approval_helper_428_raises_no_enrolled_device(agent, fake_session):
    fake_session.queue(FakeResponse(428, NO_DEVICE_428))
    with pytest.raises(LumoAuthApprovalNotDeliveredError) as info:
        require_approval(agent, **_approval_kwargs())
    assert info.value.reason == "no_enrolled_device"
    assert len(fake_session.calls) == 2  # authenticate + create


def test_require_returns_approved_by_user_id(client, fake_session, monkeypatch):
    monkeypatch.setattr("lumoauth.resources.approvals.time.sleep", lambda s: None)
    fake_session.queue(
        FakeResponse(201, {"approval_token": "apv-1", "status": "pending", "task_id": "wire-1"}),
        FakeResponse(200, {
            "approval_token": "apv-1",
            "status": "approved",
            "task_id": "wire-1",
            "impact": "high",
            "reason": "Wire $1",
            "responded_at": "2026-10-26T00:00:00+00:00",
            "approved_by": {"user_id": 42},
        }),
    )
    result = client.approvals.require(**_approval_kwargs())
    assert result.status == "approved"
    assert result.approved_by == {"user_id": 42}
    assert isinstance(result.approved_by["user_id"], int)


# ── Issue B: MCP tokens bound via RFC 8707 resource ────────────────────


def test_mcp_get_token_sends_resource(client, fake_session):
    fake_session.queue(FakeResponse(200, {"access_token": "mcp-tok"}))
    assert client.mcp.get_token("https://mcp.example.com/mcp") == "mcp-tok"
    _, url, kwargs = fake_session.last
    assert url == f"{BASE}/orgs/{ORG}/api/v1/oauth/token"
    assert kwargs["data"]["resource"] == "https://mcp.example.com/mcp"
    assert kwargs["data"]["audience"] == "https://mcp.example.com/mcp"
    assert kwargs["data"]["subject_token"] == "at-user"


@pytest.mark.parametrize(
    "server_id",
    ["urn:mcp:financial-data", "financial-data", "", "ftp://mcp.example.com", "https://mcp.example.com/mcp#x", "https:///mcp"],
)
def test_mcp_get_token_rejects_non_url_server_ids(client, fake_session, server_id):
    with pytest.raises(LumoAuthValidationError, match="https URL"):
        client.mcp.get_token(server_id)
    assert fake_session.calls == []


# ── Issue C: JIT pending reads the list envelope ──────────────────────


def test_jit_pending_reads_data(client, fake_session):
    item = {"request_id": "r-1", "status": "pending"}
    fake_session.queue(FakeResponse(200, {
        "pending_requests": [item],
        "count": 1,
        "data": [item],
        "pagination": {"total": 1},
    }))
    assert client.jit.pending() == [item]
    method, url, _ = fake_session.last
    assert (method, url) == ("GET", f"{BASE}/orgs/{ORG}/api/v1/jit/pending")


def test_jit_pending_falls_back_to_pending_requests(client, fake_session):
    item = {"request_id": "r-2"}
    fake_session.queue(FakeResponse(200, {"pending_requests": [item], "count": 1}))
    assert client.jit.pending() == [item]

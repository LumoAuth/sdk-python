"""Token and cost usage reports (POST /agents/me/usage)."""

from __future__ import annotations

import pytest

from conftest import FakeResponse, FakeSession
from lumoauth import LumoAuthAgent

BASE = "https://auth.example.com"
ORG = "acme"


@pytest.fixture()
def agent(fake_session: FakeSession, monkeypatch: pytest.MonkeyPatch) -> LumoAuthAgent:
    for var in ("LUMOAUTH_URL", "LUMOAUTH_ORG_ID", "AGENT_CLIENT_ID", "AGENT_CLIENT_SECRET"):
        monkeypatch.delenv(var, raising=False)
    a = LumoAuthAgent(base_url=BASE, org_id=ORG, client_id="agt_1", client_secret="s")
    fake_session.queue(FakeResponse(200, {"access_token": "at-1", "token_type": "Bearer", "expires_in": 3600}))
    assert a.authenticate() is True
    return a


def test_report_usage_posts_and_refreshes_the_cached_budget(agent: LumoAuthAgent, fake_session: FakeSession) -> None:
    fake_session.queue(FakeResponse(200, {"sub": "agent_agt_1", "budget_policy": {
        "max_tokens_per_day": 1000, "tokens_used_today": 0, "exhausted": False}}))
    assert agent.is_budget_exhausted() is False

    fake_session.queue(FakeResponse(200, {
        "recorded": {"tokens": 1000, "cost_usd": 0.02},
        "budget": {"max_tokens_per_day": 1000, "tokens_used_today": 1000, "exhausted": True},
    }))
    result = agent.report_usage(tokens=1000, cost_usd=0.02)

    method, url, kwargs = fake_session.last
    assert (method, url) == ("POST", f"{BASE}/orgs/{ORG}/api/v1/agents/me/usage")
    assert kwargs["json"] == {"tokens": 1000, "cost_usd": 0.02}
    assert kwargs["headers"]["Authorization"] == "Bearer at-1"
    assert result["recorded"] == {"tokens": 1000, "cost_usd": 0.02}
    calls = len(fake_session.calls)
    assert agent.is_budget_exhausted() is True  # from the report, no extra request
    assert len(fake_session.calls) == calls


@pytest.mark.parametrize("tokens,cost", [(-1, 0.0), (0, 0.0), (0, -0.5), (1.5, 0.0), (True, 0.0)])
def test_report_usage_rejects_invalid_reports(agent: LumoAuthAgent, tokens: object, cost: object) -> None:
    with pytest.raises(ValueError):
        agent.report_usage(tokens=tokens, cost_usd=cost)  # type: ignore[arg-type]

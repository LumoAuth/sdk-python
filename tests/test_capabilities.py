"""Capability matching: the SDK must answer exactly as the server does.

The contract cases (``sdk-contract/vectors/agent-capabilities.json``) are
checked against the server's own matcher by the contract repo, and against
this SDK here. The inline cases below run even without the contract checkout.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from conftest import FakeResponse, FakeSession
from lumoauth import (
    AccessTokenClaims,
    LumoAuthAgent,
    any_capability_covers,
    capability_covers,
    normalize_capability,
    require_capability,
)

_CANDIDATES = [
    *([Path(os.environ["LUMO_SDK_CONTRACT"])] if os.environ.get("LUMO_SDK_CONTRACT") else []),
    Path(__file__).resolve().parents[2] / "sdk-contract",
]
_VECTOR = next(
    (c / "vectors/agent-capabilities.json" for c in _CANDIDATES if (c / "vectors/agent-capabilities.json").is_file()),
    None,
)
needs_contract = pytest.mark.skipif(_VECTOR is None, reason="sdk-contract not found")


def _vector() -> dict:
    assert _VECTOR is not None
    return json.loads(_VECTOR.read_text(encoding="utf-8"))


@needs_contract
def test_contract_normalize_cases() -> None:
    for case in _vector()["normalize"]:
        assert normalize_capability(case["input"]) == case["expected"], case


@needs_contract
def test_contract_covers_cases() -> None:
    for case in _vector()["covers"]:
        assert capability_covers(case["capability"], case["action"]) is case["expected"], case


@needs_contract
def test_contract_any_covers_cases() -> None:
    for case in _vector()["any_covers"]:
        assert any_capability_covers(case["capabilities"], case["action"]) is case["expected"], case


def test_inline_rules() -> None:
    assert normalize_capability(" Tool:Search-Web ") == "tool.search.web"
    assert normalize_capability("Ünits.Read") == "Ünits.read"  # ASCII only, as PHP strtolower
    assert capability_covers("tool:search_web", "tool.search_web")
    assert capability_covers("invoices.*", "invoices.read.draft")
    assert not capability_covers("invoices.*", "invoices")
    assert not capability_covers("*.read", "invoices.read")
    assert not capability_covers("*", "")
    assert any_capability_covers([1, None, "users.view"], "users:view")
    assert not any_capability_covers([], "users.view")


# ── The agent client ──────────────────────────────────────────────────

BASE = "https://auth.example.com"
ORG = "acme"


class Bot(LumoAuthAgent):
    @require_capability("tool:search_web")
    def search(self) -> str:
        return "ok"

    @require_capability("tool:send_email")
    def send(self) -> str:
        return "sent"


@pytest.fixture()
def bot(fake_session: FakeSession, monkeypatch: pytest.MonkeyPatch) -> Bot:
    for var in ("LUMOAUTH_URL", "LUMOAUTH_ORG_ID", "AGENT_CLIENT_ID", "AGENT_CLIENT_SECRET"):
        monkeypatch.delenv(var, raising=False)
    b = Bot(base_url=BASE, org_id=ORG, client_id="agt_1", client_secret="s")
    fake_session.queue(FakeResponse(200, {"access_token": "at-1", "token_type": "Bearer", "expires_in": 3600}))
    assert b.authenticate() is True
    # The server returns capabilities in their stored form.
    fake_session.queue(FakeResponse(200, {"sub": "agent_agt_1", "capabilities": ["tool.search_web", "invoices.*"]}))
    return b


def test_has_capability_matches_like_the_server(bot: Bot) -> None:
    assert bot.has_capability("tool:search_web") is True  # spelled as registered
    assert bot.has_capability("tool.search_web") is True  # stored form
    assert bot.has_capability("invoices.approve") is True  # through invoices.*
    assert bot.has_capability("Invoices:Read:Draft") is True
    assert bot.has_capability("invoices") is False  # a wildcard never covers its prefix
    assert bot.has_capability("tool:send_email") is False


def test_require_capability_uses_the_same_rules(bot: Bot) -> None:
    assert bot.search() == "ok"
    with pytest.raises(PermissionError, match="tool:send_email"):
        bot.send()


def test_budget_uses_the_servers_verdict(bot: Bot, fake_session: FakeSession) -> None:
    bot.get_agent_info()  # the fixture's queued UserInfo response
    # Any limit counts on the server (here calls per hour), not only the daily token cap.
    fake_session.queue(FakeResponse(200, {"sub": "agent_agt_1", "budget_policy": {
        "max_api_calls_per_hour": 10, "api_calls_this_hour": 10,
        "max_tokens_per_day": 1000, "tokens_used_today": 0, "exhausted": True}}))
    bot.get_agent_info()
    assert bot.is_budget_exhausted() is True

    fake_session.queue(FakeResponse(200, {"sub": "agent_agt_1", "budget_policy": {
        "max_tokens_per_day": 100, "tokens_used_today": 150, "exhausted": False}}))
    bot.get_agent_info()
    assert bot.is_budget_exhausted() is False

    # An older server without the verdict: the daily token cap decides.
    fake_session.queue(FakeResponse(200, {"sub": "agent_agt_1", "budget_policy": {
        "max_tokens_per_day": 100, "tokens_used_today": 100}}))
    bot.get_agent_info()
    assert bot.is_budget_exhausted() is True


def test_token_claims_match_like_the_server() -> None:
    claims = AccessTokenClaims(
        sub="agent_agt_1", iss="https://auth.example.com/orgs/acme/api/v1", aud=("https://mcp.example.com",),
        exp=0, scopes=("invoices.read",), is_agent=True, capabilities=("tool.search_web", "invoices.*"),
    )
    assert claims.has_capability("tool:search_web")
    assert claims.has_capability("invoices.approve")
    assert not claims.has_capability("payments.read")
    # Scopes stay exact, as in OAuth.
    assert claims.has_scope("invoices.read") and not claims.has_scope("invoices:read")

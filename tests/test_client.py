"""LumoAuth client — constructor/env fallbacks, namespace wiring, api escape hatch."""

from __future__ import annotations

import sys

import pytest

from lumoauth import LumoAuth
from lumoauth.errors import LumoAuthConfigError
from lumoauth.resources import (
    AbacResource,
    AgentsResource,
    ApprovalsResource,
    AuthResource,
    DelegationResource,
    JitResource,
    McpResource,
    PermissionsResource,
    ZanzibarResource,
)

ENV_VARS = ("LUMOAUTH_URL", "LUMOAUTH_ORG_ID", "LUMOAUTH_API_KEY")


@pytest.fixture(autouse=True)
def clean_env(monkeypatch: pytest.MonkeyPatch):
    for var in ENV_VARS:
        monkeypatch.delenv(var, raising=False)


# ── Constructor & environment fallbacks ───────────────────────────────


def test_defaults_without_env_or_args():
    client = LumoAuth()
    assert client.base_url == "https://app.lumoauth.dev"
    assert client.org_id is None
    assert client.api_key is None


def test_env_fallbacks(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("LUMOAUTH_URL", "https://lumo.internal.example.com/")
    monkeypatch.setenv("LUMOAUTH_ORG_ID", "acme-corp")
    monkeypatch.setenv("LUMOAUTH_API_KEY", "lk_env")
    client = LumoAuth()
    assert client.base_url == "https://lumo.internal.example.com"  # trailing / stripped
    assert client.org_id == "acme-corp"
    assert client.api_key == "lk_env"


def test_explicit_args_win_over_env(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("LUMOAUTH_URL", "https://env.example.com")
    monkeypatch.setenv("LUMOAUTH_ORG_ID", "env-org")
    monkeypatch.setenv("LUMOAUTH_API_KEY", "lk_env")
    client = LumoAuth(
        base_url="https://arg.example.com", org_id="arg-org", api_key="lk_arg"
    )
    assert client.base_url == "https://arg.example.com"
    assert client.org_id == "arg-org"
    assert client.api_key == "lk_arg"


def test_constructor_is_keyword_only():
    with pytest.raises(TypeError):
        LumoAuth("lk_key")  # type: ignore[misc]


def test_credentials_reach_http_client():
    provider = lambda: "tok"  # noqa: E731
    client = LumoAuth(api_key="lk_x", token_provider=provider, timeout=7)
    assert client._http.api_key == "lk_x"
    assert client._http.token_provider is provider
    assert client._http.timeout == 7


# ── Namespace wiring ──────────────────────────────────────────────────


def test_namespaces_are_wired():
    client = LumoAuth(org_id="acme")
    assert isinstance(client.auth, AuthResource)
    assert isinstance(client.permissions, PermissionsResource)
    assert isinstance(client.zanzibar, ZanzibarResource)
    assert isinstance(client.abac, AbacResource)
    assert isinstance(client.agents, AgentsResource)
    assert isinstance(client.delegation, DelegationResource)
    assert isinstance(client.jit, JitResource)
    assert isinstance(client.approvals, ApprovalsResource)
    assert isinstance(client.mcp, McpResource)


def test_namespaces_share_one_http_client():
    client = LumoAuth(org_id="acme")
    assert client.permissions._http is client._http
    assert client.zanzibar._http is client._http
    assert client.abac._http is client._http


# ── Generated-client escape hatch ─────────────────────────────────────


def test_api_property_raises_config_error_when_generated_client_missing(
    monkeypatch: pytest.MonkeyPatch,
):
    # Force `import lumoauth_api_client` to fail even if it were installed.
    monkeypatch.setitem(sys.modules, "lumoauth_api_client", None)
    client = LumoAuth(org_id="acme")
    with pytest.raises(LumoAuthConfigError) as exc_info:
        _ = client.api
    assert "pip install lumoauth-api-client" in str(exc_info.value)


# ── Legacy import path ────────────────────────────────────────────────


def test_legacy_import_of_agent_from_client_module():
    from lumoauth.client import LumoAuthAgent as FromClient
    from lumoauth.agent import LumoAuthAgent as FromAgent

    assert FromClient is FromAgent

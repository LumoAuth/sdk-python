"""Custom domains: an organization that serves LumoAuth on its own domain.

The vector tests run every entry of ``sdk-contract/vectors/custom-domain.json``
through the SDK's real resolution code. They are skipped when the contract is
not checked out next to ``sdk-python`` (``LUMO_SDK_CONTRACT`` overrides). The
behaviour tests below them need no contract.
"""

from __future__ import annotations

import json
import os
import re
import sys
import types
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from unittest import mock

import pytest

from conftest import FakeResponse, FakeSession
from lumoauth import LumoAuth, LumoAuthAgent
from lumoauth._http import HttpClient
from lumoauth._routes import (
    ROUTES,
    format_path,
    issuer_url,
    normalize_custom_domain,
    org_api_base,
    strip_org_segment,
)
from lumoauth.approval import require_approval
from lumoauth.client_assertion import issuer_for
from lumoauth.delegation import DelegationChain
from lumoauth.errors import LumoAuthConfigError
from lumoauth.jit import JITContext

_CANDIDATES = [
    *([Path(os.environ["LUMO_SDK_CONTRACT"])] if os.environ.get("LUMO_SDK_CONTRACT") else []),
    Path(__file__).resolve().parents[2] / "sdk-contract",
]
_CONTRACT = next((c for c in _CANDIDATES if (c / "routes.json").is_file()), None)
_VECTOR_FILE = _CONTRACT / "vectors" / "custom-domain.json" if _CONTRACT else None
VECTOR: Dict[str, Any] = (
    json.loads(_VECTOR_FILE.read_text()) if _VECTOR_FILE and _VECTOR_FILE.is_file() else {}
)
needs_vector = pytest.mark.skipif(not VECTOR, reason="sdk-contract not found")

DOMAIN = "https://auth.acme.com"
PLATFORM = "https://app.lumoauth.dev"
ORG = "acme-corp"
PLATFORM_ISSUER = f"{PLATFORM}/orgs/{ORG}/api/v1"
ENV_VARS = (
    "LUMOAUTH_URL",
    "LUMOAUTH_ORG_ID",
    "LUMOAUTH_API_KEY",
    "LUMOAUTH_CUSTOM_DOMAIN",
    "LUMOAUTH_CLIENT_ID",
    "LUMOAUTH_CLIENT_SECRET",
    "AGENT_CLIENT_ID",
    "AGENT_CLIENT_SECRET",
    "AGENT_PRIVATE_KEY",
    "AGENT_KEY_ID",
)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in ENV_VARS:
        monkeypatch.delenv(var, raising=False)


def _norm(path: str) -> str:
    return re.sub(r"\{[^}]+\}", "{}", path)


def _placeholders(path: str, organization: str) -> List[str]:
    return [name for name in re.findall(r"\{([^}]+)\}", path) if name != organization]


# ── The vector ────────────────────────────────────────────────────────


def _contract_json(name: str) -> Dict[str, Any]:
    assert _CONTRACT is not None
    return json.loads((_CONTRACT / name).read_text())


if VECTOR:
    _CONTRACT_ROUTES = {r["name"]: r for r in _contract_json("routes.json")["routes"]}
    _ME = _contract_json("features.json")["sdks"]["python"]
else:  # pragma: no cover - the vector tests are skipped
    _CONTRACT_ROUTES, _ME = {}, {"namespaces": [], "known_missing_routes": {}}

# The Python registry spells some route names in its own way, so a contract
# route is found by method and path, as tests/test_contract.py does.
_PYTHON_BY_PAIR = {(method, _norm(path)): name for name, (method, path) in ROUTES.items()}


def _python_route(entry: Dict[str, Any]) -> Optional[Tuple[str, str, Dict[str, str]]]:
    """``(python route name, method, path params)`` of a vector entry, or None."""
    contract = _CONTRACT_ROUTES[entry["route"]]
    name = _PYTHON_BY_PAIR.get((contract["method"], _norm(contract["path"])))
    if name is None:
        return None
    theirs = _placeholders(contract["path"], "orgId")
    ours = _placeholders(ROUTES[name][1], "org_id")
    assert len(theirs) == len(ours), f"{entry['route']}: placeholders differ"
    return name, contract["method"], {o: entry["params"][t] for t, o in zip(theirs, ours)}


def _route_cases() -> list:
    return [pytest.param(e, id=e["route"]) for e in VECTOR.get("routes", [])]


def _resolve(http: HttpClient, session: FakeSession, name: str, params: Dict[str, str]) -> Tuple[str, str]:
    """Send the route through the mocked transport; return ``(method, url)``."""
    session.calls.clear()
    http.call(name, path_params=params, auth=False)
    method, url, _ = session.last
    assert http.route_url(name, params) == url
    return method, url


@needs_vector
@pytest.mark.parametrize("entry", _route_cases())
def test_vector_route_in_both_forms(entry):
    found = _python_route(entry)
    if found is None:
        contract = _CONTRACT_ROUTES[entry["route"]]
        assert (
            entry["route"] in _ME["known_missing_routes"]
            or contract["namespace"] not in _ME["namespaces"]
        ), f"{entry['route']} is a claimed contract route but lumoauth._routes lacks it"
        pytest.skip("not a route of the Python SDK")
    name, method, params = found
    platform, custom = VECTOR["platform"], VECTOR["custom_domain"]["custom_domain"]

    # Without a custom domain: exactly the URL as before.
    session = FakeSession()
    http = HttpClient(platform["base_url"], org_id=platform["org_id"], session=session)
    assert _resolve(http, session, name, params) == (method, entry["platform_url"])

    # On the custom domain, with no organization ID and no base URL.
    session = FakeSession()
    http = HttpClient("", custom_domain=custom, session=session)
    assert _resolve(http, session, name, params) == (method, entry["custom_domain_url"])

    # The organization ID and a base URL given too: neither is used.
    session = FakeSession()
    http = HttpClient(
        platform["base_url"], org_id=platform["org_id"], custom_domain=custom, session=session
    )
    assert _resolve(http, session, name, params) == (method, entry["custom_domain_url"])
    assert "/orgs/" not in session.last[1]


@needs_vector
def test_vector_covers_every_route_of_the_registry():
    covered = {found[0] for e in VECTOR["routes"] if (found := _python_route(e)) is not None}
    assert covered == set(ROUTES), sorted(set(ROUTES) - covered)


def _value_cases(kind: str) -> list:
    values = VECTOR.get("custom_domain_values", {}).get(kind, [])
    return [pytest.param(v, id=repr(v["input"] if isinstance(v, dict) else v)) for v in values]


@needs_vector
@pytest.mark.parametrize("case", _value_cases("valid"))
def test_vector_valid_values_are_normalized(case):
    assert normalize_custom_domain(case["input"]) == case["normalized"]
    client = LumoAuth(custom_domain=case["input"])
    assert client.custom_domain == case["normalized"]
    assert client.base_url == case["normalized"]
    assert client.issuer == case["normalized"]


@needs_vector
@pytest.mark.parametrize("value", _value_cases("invalid"))
def test_vector_invalid_values_are_a_configuration_error(value, monkeypatch):
    with pytest.raises(LumoAuthConfigError):
        normalize_custom_domain(value)
    # Raised when the client is created, from the argument and from the environment.
    with pytest.raises(LumoAuthConfigError):
        LumoAuth(org_id=ORG, custom_domain=value)
    with pytest.raises(LumoAuthConfigError):
        LumoAuthAgent(client_id="c", client_secret="s", custom_domain=value)
    with pytest.raises(LumoAuthConfigError):
        HttpClient(PLATFORM, org_id=ORG, custom_domain=value, session=FakeSession())
    monkeypatch.setenv("LUMOAUTH_CUSTOM_DOMAIN", value)
    with pytest.raises(LumoAuthConfigError):
        LumoAuth(org_id=ORG)


@needs_vector
@pytest.mark.parametrize("value", _value_cases("not_set"))
def test_vector_blank_values_mean_not_set(value, monkeypatch):
    assert normalize_custom_domain(value) is None
    monkeypatch.setenv("LUMOAUTH_CUSTOM_DOMAIN", value)
    client = LumoAuth(org_id=ORG, custom_domain=value)
    assert client.custom_domain is None
    assert client.base_url == PLATFORM
    assert client.issuer == PLATFORM_ISSUER


# Derived addresses that this SDK does not build. A new entry of `derived`
# must be tested below or listed here with the reason.
_NOT_BUILT = {
    "authorization_server_metadata": "the SDK reads the OpenID configuration only",
    "end_session_endpoint": "the SDK has no sign-out redirect (known_missing_routes: oauth.logout)",
    "hosted_login_page": "the SDK never links to the hosted page; sign-in starts at the authorization endpoint",
}


def _platform_and_custom_clients() -> Tuple[LumoAuth, LumoAuth]:
    platform = VECTOR["platform"]
    return (
        LumoAuth(base_url=platform["base_url"], org_id=platform["org_id"]),
        LumoAuth(custom_domain=VECTOR["custom_domain"]["custom_domain"]),
    )


def _fetched_by_the_verifier(client: LumoAuth, with_discovery: bool) -> List[str]:
    """The addresses that the token verifier reads for *client*'s organization."""
    from lumoauth.errors import LumoAuthNetworkError
    from lumoauth.verify import AccessTokenVerifier

    fetched: List[str] = []

    def fetch(url: str) -> Any:
        fetched.append(url)
        if url.endswith("/openid-configuration"):
            if not with_discovery:
                raise LumoAuthNetworkError("no discovery document")
            return {"issuer": client.issuer}  # names no jwks_uri
        return {"keys": []}

    verifier = (
        AccessTokenVerifier(resource="https://api.example.com", custom_domain=client.custom_domain, fetch=fetch)
        if client.custom_domain
        else AccessTokenVerifier(client.issuer, "https://api.example.com", fetch=fetch)
    )
    assert verifier.issuer == client.issuer
    verifier.jwks._refresh(0.0)
    return fetched


def _derived(key: str, client: LumoAuth) -> str:
    if key == "issuer":
        assert issuer_for(client.base_url, client.org_id or "", client.custom_domain) == client.issuer
        assert issuer_url(client.base_url, client.org_id, client.custom_domain) == client.issuer
        return client.issuer
    if key == "openid_configuration":
        return _fetched_by_the_verifier(client, with_discovery=True)[0]
    if key == "jwks":
        return _fetched_by_the_verifier(client, with_discovery=False)[-1]
    if key == "authorization_endpoint":
        url = client.auth.authorization_url(client_id="app", redirect_uri="https://app.example/cb")
        return url.split("?", 1)[0]
    raise AssertionError(f"derived address {key!r} is neither tested nor listed in _NOT_BUILT")


@needs_vector
@pytest.mark.parametrize("key", [pytest.param(k, id=k) for k in VECTOR.get("derived", {})])
def test_vector_derived_addresses(key):
    if key in _NOT_BUILT:
        pytest.skip(_NOT_BUILT[key])
    platform, custom = _platform_and_custom_clients()
    assert _derived(key, platform) == VECTOR["derived"][key]["platform"]
    assert _derived(key, custom) == VECTOR["derived"][key]["custom_domain"]


# ── The rule itself ───────────────────────────────────────────────────


def test_format_path_drops_only_the_organization_segment():
    assert format_path("oauth.token", org_id=ORG) == ("POST", f"/orgs/{ORG}/api/v1/oauth/token")
    assert format_path("oauth.token", custom_domain=True) == ("POST", "/api/v1/oauth/token")
    assert format_path("oauth.token", custom_domain=True, org_id=ORG) == ("POST", "/api/v1/oauth/token")
    assert format_path("authz.check", custom_domain=True) == format_path("authz.check")
    assert format_path("approvals.status", custom_domain=True, token="a/b") == (
        "GET",
        "/api/v1/agents/me/approvals/a%2Fb/status",
    )
    with pytest.raises(KeyError):
        format_path("oauth.token")  # the platform form still needs the organization


def test_strip_org_segment_never_guesses():
    assert strip_org_segment("/orgs/{org_id}/api/v1/x") == "/api/v1/x"
    assert strip_org_segment("/orgs/acme-corp/api/v1/x", "acme-corp") == "/api/v1/x"
    assert strip_org_segment("/orgs/acme-corp", "acme-corp") == "/"
    assert strip_org_segment("/orgs/acme-corporation/api/v1/x", "acme-corp") == "/orgs/acme-corporation/api/v1/x"
    assert strip_org_segment("/orgs/other/api/v1/x", "acme-corp") == "/orgs/other/api/v1/x"
    assert strip_org_segment("/api/v1/authz/check", "acme-corp") == "/api/v1/authz/check"
    assert strip_org_segment("/orgs/acme-corp/api/v1/x", "") == "/orgs/acme-corp/api/v1/x"


@pytest.mark.parametrize(
    "value,expected",
    [
        (None, None),
        ("auth.acme.com", DOMAIN),
        ("AUTH.ACME.COM:8443/", "https://auth.acme.com:8443"),
        ("localhost:8000", "https://localhost:8000"),
        ("http://LOCALHOST:8000", "http://localhost:8000"),
        ("http://[::1]:8000/", "http://[::1]:8000"),
        ("https://[2001:db8::1]", "https://[2001:db8::1]"),
    ],
)
def test_normalize_custom_domain(value, expected):
    assert normalize_custom_domain(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        5,
        b"auth.acme.com",
        "auth.acme.com/login",
        "https://auth.acme.com//",
        "http://[2001:db8::1]",
        "https://auth.acme.com:port",
        "https://auth_acme.com",
        "https://-auth.acme.com",
        "//auth.acme.com",
        "https://auth.acme.com\\@evil.example",
        "https://@auth.acme.com",
    ],
)
def test_normalize_custom_domain_refuses(value):
    with pytest.raises(LumoAuthConfigError):
        normalize_custom_domain(value)


def test_org_api_base_and_issuer():
    assert org_api_base(PLATFORM + "/", ORG) == PLATFORM_ISSUER
    assert issuer_url(PLATFORM, ORG) == PLATFORM_ISSUER
    assert org_api_base(PLATFORM, ORG, "auth.acme.com") == DOMAIN + "/api/v1"
    assert issuer_url(PLATFORM, ORG, "auth.acme.com") == DOMAIN
    assert issuer_url("", None, DOMAIN) == DOMAIN
    for build in (org_api_base, issuer_url):
        with pytest.raises(LumoAuthConfigError):
            build(PLATFORM, None)
    # The older helper keeps its platform form and gains the custom domain.
    assert issuer_for(PLATFORM, ORG) == PLATFORM_ISSUER
    assert issuer_for(PLATFORM, ORG, "auth.acme.com") == DOMAIN


# ── The client ────────────────────────────────────────────────────────


@pytest.fixture()
def custom(fake_session: FakeSession) -> LumoAuth:
    """A client on a custom domain, with no organization ID."""
    return LumoAuth(
        custom_domain="auth.acme.com",
        token_provider=lambda: "tok",
        client_id="shop-api",
        client_secret="s3cr3t",
    )


def _urls(session: FakeSession) -> List[str]:
    return [url for _, url, _ in session.calls]


def test_custom_domain_wins_over_base_url_and_needs_no_org_id(fake_session):
    client = LumoAuth(base_url="https://eu.app.lumoauth.dev", custom_domain="Auth.Acme.com", api_key="lmk_x")
    assert client.custom_domain == DOMAIN
    assert client.base_url == DOMAIN
    assert client.org_id is None
    assert client.issuer == DOMAIN
    fake_session.queue(FakeResponse(200, {"allowed": True}))
    client.abac.check("document", "read", "doc-1")  # an organization route, without org_id
    assert _urls(fake_session) == [DOMAIN + "/api/v1/abac/check"]


def test_environment_variable_is_the_fallback(fake_session, monkeypatch):
    monkeypatch.setenv("LUMOAUTH_URL", "https://eu.app.lumoauth.dev")
    monkeypatch.setenv("LUMOAUTH_ORG_ID", ORG)
    monkeypatch.setenv("LUMOAUTH_CUSTOM_DOMAIN", "auth.acme.com")
    client = LumoAuth()
    assert (client.custom_domain, client.base_url, client.org_id) == (DOMAIN, DOMAIN, ORG)
    # An explicit argument wins over the environment.
    assert LumoAuth(custom_domain="https://login.acme.com").base_url == "https://login.acme.com"


def test_without_a_custom_domain_nothing_changes(fake_session):
    client = LumoAuth(base_url=PLATFORM, org_id=ORG, api_key="lmk_x")
    assert client.custom_domain is None and client.base_url == PLATFORM
    assert client.issuer == PLATFORM_ISSUER
    fake_session.queue(FakeResponse(200, {"allowed": True}), FakeResponse(200, {"allowed": True}))
    client.abac.check("document", "read", "doc-1")
    client.permissions.check("document.edit")
    assert _urls(fake_session) == [
        f"{PLATFORM}/orgs/{ORG}/api/v1/abac/check",
        f"{PLATFORM}/api/v1/authz/check",
    ]
    with pytest.raises(LumoAuthConfigError):
        LumoAuth(base_url=PLATFORM).abac.check("document", "read", "doc-1")
    with pytest.raises(LumoAuthConfigError):
        _ = LumoAuth(base_url=PLATFORM).issuer


def test_every_namespace_sends_the_prefix_less_url(custom, fake_session):
    token = {"access_token": "at", "token_type": "Bearer", "expires_in": 60}
    calls = [
        # (expected path, answer, call)
        ("/api/v1/oauth/token", token, lambda: custom.auth.client_credentials("c", "s")),
        ("/api/v1/oauth/userinfo", {"sub": "u"}, lambda: custom.auth.userinfo("at")),
        ("/api/v1/oauth/revoke", {}, lambda: custom.auth.revoke("at")),
        ("/api/v1/authz/check", {"allowed": True}, lambda: custom.permissions.check("document.edit")),
        ("/api/v1/authz/permissions", {"permissions": []}, lambda: custom.permissions.list()),
        ("/api/v1/authz/zanzibar/check", {"allowed": True}, lambda: custom.zanzibar.check("document:1", "viewer", "user:1")),
        ("/api/v1/abac/check", {"allowed": True}, lambda: custom.abac.check("document", "read", "doc-1")),
        ("/api/v1/agents/ask", {"allowed": True}, lambda: custom.agents.ask("document:read")),
        ("/api/v1/agents/me", {"agent_id": "agt_1"}, lambda: custom.agents.me()),
        (
            "/api/v1/agents/me/approvals",
            {"approval_token": "tok_abc", "status": "pending"},
            lambda: custom.approvals.create(task_id="t", reason="r", on_behalf_of="u"),
        ),
        ("/api/v1/agents/me/approvals/tok_abc/status", {"status": "approved"}, lambda: custom.approvals.get_status("tok_abc")),
        ("/api/v1/jit/task", {"task_id": "task_7"}, lambda: custom.jit.create_task(name="n")),
        ("/api/v1/jit/pending", {"data": []}, lambda: custom.jit.pending()),
        ("/api/v1/oauth/token", token, lambda: custom.delegation.exchange("user-token", "agent-token")),
        ("/api/v1/oauth/token", token, lambda: custom.mcp.get_token("https://mcp.example.com/mcp")),
        (
            "/api/v1/mcp/servers/srv_orders/tools/authorize",
            {"allowed": True},
            lambda: custom.mcp.authorize_tool("srv_orders", "user", "u-1", "list_orders"),
        ),
        (
            "/api/v1/poppy/sessions/status",
            {"status": "unknown", "signed_in": False},
            lambda: custom.poppy.get_session_status("https://agent.example/agent.json", "sid"),
        ),
        ("/api/v1/poppy/sessions/end", {"ended": True}, lambda: custom.poppy.end_session("https://agent.example/agent.json", "sid")),
        (
            "/api/v1/poppy/sessions/verify",
            {
                "active": False,
                "error": "invalid_session",
                "response": {"status": 400, "headers": {}, "body": {"error": "invalid_session"}},
            },
            lambda: custom.poppy.verify_request("GET", "https://shop.example.com/x", []),
        ),
    ]
    for path, answer, call in calls:
        fake_session.queue(FakeResponse(200, answer))
        call()
        assert fake_session.last[1] == DOMAIN + path, path
    namespaces = {"auth", "permissions", "zanzibar", "abac", "agents", "approvals", "jit", "delegation", "mcp", "poppy"}
    assert namespaces <= {name for name in vars(custom) if not name.startswith("_")}
    assert all(url.startswith(DOMAIN + "/api/v1/") and "/orgs/" not in url for url in _urls(fake_session))


def test_sign_in_url_is_on_the_custom_domain(custom):
    url = custom.auth.authorization_url(client_id="app", redirect_uri="https://app.example/cb", state="s")
    assert url.startswith(DOMAIN + "/api/v1/oauth/authorize?")
    assert "/orgs/" not in url
    consent = custom.delegation.consent_url(client_id="app", redirect_uri="https://app.example/cb")
    assert consent.startswith(DOMAIN + "/api/v1/oauth/authorize?")


def test_org_path_helper_follows_the_rule(custom):
    assert custom._http.org_path("/x") == "/api/v1/x"
    assert custom._http.api_base == DOMAIN + "/api/v1"
    platform = HttpClient(PLATFORM, org_id=ORG, session=FakeSession())
    assert platform.org_path("/x") == f"/orgs/{ORG}/api/v1/x"
    assert platform.api_base == PLATFORM_ISSUER


def test_dpop_proof_names_the_custom_domain_url(fake_session):
    pytest.importorskip("cryptography")
    from lumoauth._jose import split_jws
    from lumoauth.dpop import DpopProofSigner

    client = LumoAuth(custom_domain="auth.acme.com")
    fake_session.queue(FakeResponse(200, {"access_token": "at", "token_type": "DPoP", "expires_in": 60}))
    client.auth.client_credentials("c", "s", dpop=DpopProofSigner())
    _, url, kw = fake_session.last
    assert url == DOMAIN + "/api/v1/oauth/token"
    assert split_jws(kw["headers"]["DPoP"])[1]["htu"] == url


# ── Raw requests ──────────────────────────────────────────────────────


def test_raw_request_paths_on_a_custom_domain(fake_session):
    http = HttpClient(PLATFORM, org_id=ORG, custom_domain="auth.acme.com", session=fake_session)
    for given, sent in [
        ("/api/v1/documents/1", DOMAIN + "/api/v1/documents/1"),
        # The prefix of the client's own organization is dropped.
        (f"/orgs/{ORG}/api/v1/documents/1", DOMAIN + "/api/v1/documents/1"),
        # Another organization's prefix is not guessed away.
        ("/orgs/other-org/api/v1/documents/1", DOMAIN + "/orgs/other-org/api/v1/documents/1"),
        (f"/orgs/{ORG}-eu/api/v1/documents/1", DOMAIN + f"/orgs/{ORG}-eu/api/v1/documents/1"),
        # A full URL is sent as it stands.
        (f"https://api.acme.com/orgs/{ORG}/x", f"https://api.acme.com/orgs/{ORG}/x"),
    ]:
        http.request("GET", given, auth=False)
        assert fake_session.last[1] == sent

    # Without the organization ID the SDK cannot tell whose prefix it is.
    unknown = HttpClient("", custom_domain="auth.acme.com", session=fake_session)
    unknown.request("GET", f"/orgs/{ORG}/api/v1/documents/1", auth=False)
    assert fake_session.last[1] == DOMAIN + f"/orgs/{ORG}/api/v1/documents/1"

    # A client without a custom domain sends the prefixed path, as before.
    platform = HttpClient(PLATFORM, org_id=ORG, session=fake_session)
    platform.request("GET", f"/orgs/{ORG}/api/v1/documents/1", auth=False)
    assert fake_session.last[1] == f"{PLATFORM}/orgs/{ORG}/api/v1/documents/1"


# ── The agent client and its helpers ──────────────────────────────────


@pytest.fixture()
def agent(fake_session: FakeSession) -> LumoAuthAgent:
    """An authenticated agent on a custom domain, with no organization ID."""
    a = LumoAuthAgent(
        base_url="https://eu.app.lumoauth.dev",
        client_id="agt_1",
        client_secret="s",
        custom_domain="auth.acme.com",
    )
    fake_session.queue(FakeResponse(200, {"access_token": "agent-at", "expires_in": 3600}))
    assert a.authenticate() is True
    return a


def test_agent_signs_in_and_calls_on_the_custom_domain(agent, fake_session):
    assert (agent.custom_domain, agent.base_url, agent.org_id) == (DOMAIN, DOMAIN, "")
    assert _urls(fake_session) == [DOMAIN + "/api/v1/oauth/token"]

    fake_session.queue(
        FakeResponse(200, {"allowed": True}),
        FakeResponse(200, {"sub": "agent_agt_1", "capabilities": []}),
        FakeResponse(200, {"ok": True}),
        FakeResponse(200, {"access_token": "mcp-at", "token_type": "Bearer"}),
    )
    agent.ask("document:read")
    agent.get_agent_info()
    agent.api_request("GET", "/api/v1/documents/1")
    agent.get_mcp_token("https://mcp.example.com/mcp")
    assert _urls(fake_session)[1:] == [
        DOMAIN + "/api/v1/agents/ask",
        DOMAIN + "/api/v1/oauth/userinfo",
        DOMAIN + "/api/v1/documents/1",
        DOMAIN + "/api/v1/oauth/token",
    ]
    # The raw request carries the agent's token to the custom domain.
    assert fake_session.calls[-2][2]["headers"]["Authorization"] == "Bearer agent-at"


def test_agent_reads_the_environment(fake_session, monkeypatch):
    monkeypatch.setenv("LUMOAUTH_CUSTOM_DOMAIN", "https://auth.acme.com/")
    monkeypatch.setenv("LUMOAUTH_ORG_ID", ORG)
    a = LumoAuthAgent(client_id="agt_1", client_secret="s")
    assert (a.custom_domain, a.base_url, a.org_id) == (DOMAIN, DOMAIN, ORG)
    fake_session.queue(FakeResponse(200, {"access_token": "at", "expires_in": 3600}), FakeResponse(200, {}))
    a.authenticate()
    # A path written for the platform host keeps working: the agent's own prefix is dropped.
    a.api_request("GET", f"/orgs/{ORG}/api/v1/documents/1")
    assert _urls(fake_session) == [DOMAIN + "/api/v1/oauth/token", DOMAIN + "/api/v1/documents/1"]


def test_agent_without_a_custom_domain_is_unchanged(fake_session):
    a = LumoAuthAgent(base_url=PLATFORM, org_id=ORG, client_id="agt_1", client_secret="s")
    assert a.custom_domain is None and a.base_url == PLATFORM
    fake_session.queue(FakeResponse(200, {"access_token": "at", "expires_in": 3600}))
    a.authenticate()
    assert _urls(fake_session) == [f"{PLATFORM}/orgs/{ORG}/api/v1/oauth/token"]


def test_client_assertion_audience_is_the_bare_domain(fake_session):
    pytest.importorskip("cryptography")
    from lumoauth import ClientAssertionSigner
    from lumoauth._jose import split_jws

    signer = ClientAssertionSigner.generate("ES256", key_id="k1")
    a = LumoAuthAgent(client_id="agt_1", private_key=signer, custom_domain="auth.acme.com")
    assert split_jws(a.client_assertion())[1]["aud"] == DOMAIN

    fake_session.queue(FakeResponse(200, {"access_token": "at", "expires_in": 3600}))
    assert a.authenticate() is True
    _, url, kw = fake_session.last
    assert url == DOMAIN + "/api/v1/oauth/token"
    assert split_jws(kw["data"]["client_assertion"])[1]["aud"] == DOMAIN

    # With the organization ID too, the audience is still the domain.
    b = LumoAuthAgent(org_id=ORG, client_id="agt_1", private_key=signer, custom_domain="auth.acme.com")
    assert split_jws(b.client_assertion())[1]["aud"] == DOMAIN
    # Without a custom domain it is the platform issuer, as before.
    c = LumoAuthAgent(base_url=PLATFORM, org_id=ORG, client_id="agt_1", private_key=signer)
    assert split_jws(c.client_assertion())[1]["aud"] == PLATFORM_ISSUER
    # An explicit issuer still wins.
    d = LumoAuthAgent(client_id="agt_1", private_key=signer, custom_domain="auth.acme.com", issuer="https://issuer.example")
    assert split_jws(d.client_assertion())[1]["aud"] == "https://issuer.example"


def test_require_approval_helper_on_a_custom_domain(agent, fake_session, monkeypatch):
    monkeypatch.setattr("lumoauth.approval.time.sleep", lambda _s: None)
    fake_session.queue(
        FakeResponse(200, {"approval_token": "tok_abc", "status": "pending"}),
        FakeResponse(200, {"status": "approved", "approval_token": "tok_abc"}),
    )
    result = require_approval(agent, task_id="t", reason="r", on_behalf_of="u")
    assert result.status == "approved"
    assert _urls(fake_session)[1:] == [
        DOMAIN + "/api/v1/agents/me/approvals",
        DOMAIN + "/api/v1/agents/me/approvals/tok_abc/status",
    ]


def test_require_approval_helper_still_needs_an_org_id_on_the_platform_host(fake_session):
    class NoOrg:
        org_id = ""

    with pytest.raises(LumoAuthConfigError):
        require_approval(NoOrg(), task_id="t", reason="r", on_behalf_of="u")
    assert fake_session.calls == []


def test_jit_context_and_delegation_chain_follow_the_agent(agent, fake_session):
    fake_session.queue(
        FakeResponse(200, {"task_id": "task_7"}),
        FakeResponse(200, {"status": "completed"}),
    )
    with JITContext(agent) as jit:
        jit.create_task(name="Analyse")
    assert _urls(fake_session)[1:] == [
        DOMAIN + "/api/v1/jit/task",
        DOMAIN + "/api/v1/jit/task/task_7/complete",
    ]

    chain = DelegationChain(agent, redirect_uri="https://agent.example/cb")
    assert chain.get_consent_url("s1").startswith(DOMAIN + "/api/v1/oauth/authorize?")
    fake_session.queue(FakeResponse(200, {"access_token": "user-at", "refresh_token": "rt"}))
    chain.handle_consent_callback("s1", "code")
    assert fake_session.last[1] == DOMAIN + "/api/v1/oauth/token"
    assert all("/orgs/" not in url for url in _urls(fake_session))


# ── AAuth ─────────────────────────────────────────────────────────────


def _aauth_client(**kwargs: Any):
    pytest.importorskip("cryptography")
    from lumoauth import AAuthClient

    pem, _ = AAuthClient.generate_keypair()
    return AAuthClient("https://agent.example.com", pem, **kwargs)


def _ok(payload: Dict[str, Any]) -> mock.Mock:
    resp = mock.Mock(status_code=200)
    resp.json.return_value = payload
    return resp


def test_aauth_token_endpoint_and_metadata_on_a_custom_domain(monkeypatch):
    client = _aauth_client(base_url="https://eu.app.lumoauth.dev", custom_domain="auth.acme.com")
    assert (client.custom_domain, client.base_url) == (DOMAIN, DOMAIN)
    assert client._token_url() == DOMAIN + "/api/v1/aauth/agent/token"

    with mock.patch("lumoauth.aauth.requests.post") as post:
        post.return_value = _ok({"auth_token": "t"})
        client.request_authorization(resource_token="rt", scope="read", agent_token="agent.jwt")
    (url,), kw = post.call_args
    assert url == DOMAIN + "/api/v1/aauth/agent/token"
    # The HTTP message signature covers the URL that is called.
    assert '"@authority"' in kw["headers"]["Signature-Input"] and '"@path"' in kw["headers"]["Signature-Input"]

    with mock.patch("lumoauth.aauth.requests.get") as get:
        get.return_value = _ok({"issuer": DOMAIN})
        client.discover_issuer()
    assert get.call_args[0][0] == DOMAIN + "/api/v1/.well-known/aauth-issuer"

    monkeypatch.setenv("LUMOAUTH_CUSTOM_DOMAIN", "auth.acme.com")
    assert _aauth_client(org_id=ORG)._token_url() == DOMAIN + "/api/v1/aauth/agent/token"
    with pytest.raises(LumoAuthConfigError):
        _aauth_client(custom_domain="https://auth.acme.com/orgs/acme-corp")


def test_aauth_signature_covers_the_custom_domain_url():
    import base64
    import hashlib

    from cryptography.exceptions import InvalidSignature

    client = _aauth_client(custom_domain="auth.acme.com")
    headers = client.sign_request("POST", client._token_url(), body=b"{}")
    params = headers["Signature-Input"].split("=", 1)[1]
    signature = headers["Signature"][len("sig1=:"):-1]
    signature_bytes = base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
    digest = base64.b64encode(hashlib.sha256(b"{}").digest()).decode()

    def signature_base(authority: str, path: str) -> bytes:
        values = {
            "@method": "POST",
            "@authority": authority,
            "@path": path,
            "signature-key": "",
            "content-digest": f"sha-256=:{digest}:",
            "content-type": "application/json",
            "authorization": "",
        }
        lines = [f'"{name}": {values[name]}' for name in client._COVERED]
        lines.append(f'"@signature-params": {params}')
        return "\n".join(lines).encode()

    public_key = client._private_key.public_key()
    # The signature is over the domain and the prefix-less path.
    public_key.verify(signature_bytes, signature_base("auth.acme.com", "/api/v1/aauth/agent/token"))
    with pytest.raises(InvalidSignature):
        public_key.verify(
            signature_bytes, signature_base("app.lumoauth.dev", f"/orgs/{ORG}/api/v1/aauth/agent/token")
        )


def _metadata_response(document: Any) -> mock.Mock:
    resp = mock.Mock(status_code=200)
    resp.json.return_value = document
    return resp


@needs_vector
def test_vector_aauth_issuer_metadata_url_in_both_forms():
    aauth = VECTOR["aauth"]
    platform = _aauth_client(
        base_url=VECTOR["platform"]["base_url"], org_id=VECTOR["platform"]["org_id"]
    )
    custom = _aauth_client(custom_domain=VECTOR["custom_domain"]["custom_domain"])
    for client, form in ((platform, "platform"), (custom, "custom_domain")):
        with mock.patch("lumoauth.aauth.requests.get") as get:
            get.return_value = _metadata_response({})
            client.discover_issuer()
        assert get.call_args[0][0] == aauth["issuer_metadata_url"][form]


@needs_vector
def test_vector_aauth_issuer_is_read_from_the_metadata_on_a_custom_domain():
    aauth = VECTOR["aauth"]
    domain = VECTOR["custom_domain"]["custom_domain"]
    # A base URL of another region is given too: it must play no part.
    client = _aauth_client(base_url="https://eu.app.lumoauth.dev", custom_domain=domain)
    with mock.patch("lumoauth.aauth.requests.get") as get:
        get.return_value = _metadata_response(aauth["issuer_metadata_document_on_the_custom_domain"])
        issuer = client.get_issuer()
        assert client.get_issuer() == issuer  # kept: the document is read once
    assert get.call_count == 1
    assert get.call_args[0][0] == aauth["issuer_metadata_url"]["custom_domain"]

    # The audience that the agent addresses, and the iss that an AAuth token names.
    assert issuer == aauth["expected_issuer"]["custom_domain"]
    assert issuer == aauth["token_with_issuer_accepted_on_a_custom_domain"]
    assert issuer != aauth["token_with_issuer_refused_on_a_custom_domain"]
    assert issuer != normalize_custom_domain(domain)
    assert "eu.app.lumoauth.dev" not in issuer
    # The requests themselves still go to the domain.
    assert client._token_url() == domain + "/api/v1/aauth/agent/token"


@needs_vector
def test_vector_aauth_issuer_on_the_platform_host():
    aauth = VECTOR["aauth"]
    client = _aauth_client(
        base_url=VECTOR["platform"]["base_url"], org_id=VECTOR["platform"]["org_id"]
    )
    with mock.patch("lumoauth.aauth.requests.get") as get:
        assert client.get_issuer() == aauth["expected_issuer"]["platform"]
    get.assert_not_called()


def test_aauth_issuer_is_never_derived_from_the_custom_domain():
    from lumoauth.errors import LumoAuthValidationError

    # An issuer that the caller configured is used as it is, without a request.
    configured = _aauth_client(custom_domain="auth.acme.com", issuer=PLATFORM_ISSUER + "/")
    with mock.patch("lumoauth.aauth.requests.get") as get:
        assert configured.get_issuer() == PLATFORM_ISSUER
    get.assert_not_called()

    # A document that names no issuer is an error: the domain is not a fallback,
    # and neither is the organization ID with the default base URL.
    for document in ({}, {"issuer": None}, {"issuer": 5}, {"issuer": "auth.acme.com"}, []):
        client = _aauth_client(custom_domain="auth.acme.com", org_id=ORG)
        with mock.patch("lumoauth.aauth.requests.get") as get:
            get.return_value = _metadata_response(document)
            with pytest.raises(LumoAuthValidationError):
                client.get_issuer()

    with pytest.raises(LumoAuthConfigError):
        _aauth_client(custom_domain="auth.acme.com", issuer="app.lumoauth.dev/orgs/acme-corp")
    # On the platform host the issuer needs the organization ID.
    with pytest.raises(LumoAuthConfigError):
        _aauth_client(base_url=PLATFORM).get_issuer()


def test_aauth_without_a_custom_domain_is_unchanged():
    client = _aauth_client(base_url=PLATFORM, org_id=ORG)
    assert client.custom_domain is None
    assert client._token_url() == f"{PLATFORM}/orgs/{ORG}/api/v1/aauth/agent/token"
    with mock.patch("lumoauth.aauth.requests.get") as get:
        get.return_value = _ok({})
        client.discover_issuer()
    assert get.call_args[0][0] == f"{PLATFORM}/orgs/{ORG}/api/v1/.well-known/aauth-issuer"


# ── Local token verification ──────────────────────────────────────────

RESOURCE = "https://mcp.example.com/mcp"
NOW = 1_800_000_000


def _signing_material():
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.asymmetric import ec

    from lumoauth._jose import public_jwk

    key = ec.generate_private_key(ec.SECP256R1())
    return key, {"keys": [dict(public_jwk(key.public_key()), kid="k1", use="sig")]}


def _token(key: Any, issuer: str) -> str:
    from lumoauth._jose import b64url_encode, sign

    header = {"typ": "at+jwt", "alg": "ES256", "kid": "k1"}
    claims = {"iss": issuer, "sub": "user-1", "aud": RESOURCE, "exp": NOW + 600, "scope": "tools:read"}
    h = b64url_encode(json.dumps(header).encode())
    p = b64url_encode(json.dumps(claims).encode())
    return f"{h}.{p}.{b64url_encode(sign(key, 'ES256', f'{h}.{p}'.encode()))}"


def test_verification_accepts_exactly_the_custom_domain_issuer():
    from lumoauth import AccessTokenVerifier, verify_access_token
    from lumoauth.errors import LumoAuthTokenError

    key, jwks = _signing_material()
    claims = verify_access_token(
        _token(key, DOMAIN), resource=RESOURCE, custom_domain="auth.acme.com", jwks=jwks, now=NOW
    )
    assert claims.iss == DOMAIN

    # A token that names the platform form of the issuer is refused.
    with pytest.raises(LumoAuthTokenError) as info:
        verify_access_token(
            _token(key, PLATFORM_ISSUER), resource=RESOURCE, custom_domain="auth.acme.com", jwks=jwks, now=NOW
        )
    assert info.value.code == "TOKEN_WRONG_ISSUER"
    with pytest.raises(LumoAuthTokenError):
        verify_access_token(
            _token(key, DOMAIN + "/api/v1"), resource=RESOURCE, custom_domain="auth.acme.com", jwks=jwks, now=NOW
        )

    # The verifier class takes the same option; the issuer of the client fits it.
    verifier = AccessTokenVerifier(resource=RESOURCE, custom_domain="https://auth.acme.com/", jwks=jwks)
    assert (verifier.issuer, verifier.custom_domain) == (DOMAIN, DOMAIN)
    assert verifier.verify(_token(key, DOMAIN), now=NOW).sub == "user-1"
    assert AccessTokenVerifier(LumoAuth(custom_domain="auth.acme.com").issuer, RESOURCE, jwks=jwks).issuer == DOMAIN

    # Without a custom domain the platform issuer is accepted, as before, and the domain is not.
    assert verify_access_token(_token(key, PLATFORM_ISSUER), issuer=PLATFORM_ISSUER, resource=RESOURCE, jwks=jwks, now=NOW)
    with pytest.raises(LumoAuthTokenError):
        verify_access_token(_token(key, DOMAIN), issuer=PLATFORM_ISSUER, resource=RESOURCE, jwks=jwks, now=NOW)


def test_verification_reads_keys_from_the_custom_domain():
    from lumoauth import AccessTokenVerifier

    key, jwks = _signing_material()
    fetched: List[str] = []

    def fetch(url: str) -> Any:
        fetched.append(url)
        if url.endswith("/openid-configuration"):
            return {"issuer": DOMAIN, "jwks_uri": DOMAIN + "/api/v1/.well-known/jwks.json"}
        return jwks

    verifier = AccessTokenVerifier(resource=RESOURCE, custom_domain="auth.acme.com", fetch=fetch)
    assert verifier.verify(_token(key, DOMAIN), now=NOW).iss == DOMAIN
    assert fetched == [
        DOMAIN + "/api/v1/.well-known/openid-configuration",
        DOMAIN + "/api/v1/.well-known/jwks.json",
    ]


def test_verification_refuses_conflicting_or_missing_issuers():
    from lumoauth import AccessTokenVerifier, verify_access_token

    _, jwks = _signing_material()
    with pytest.raises(LumoAuthConfigError):
        AccessTokenVerifier(PLATFORM_ISSUER, RESOURCE, custom_domain="auth.acme.com", jwks=jwks)
    with pytest.raises(LumoAuthConfigError):
        AccessTokenVerifier(resource=RESOURCE, jwks=jwks)
    with pytest.raises(LumoAuthConfigError):
        AccessTokenVerifier(resource=RESOURCE, custom_domain="https://auth.acme.com/api/v1", jwks=jwks)
    with pytest.raises(LumoAuthConfigError):
        verify_access_token("x.y.z", resource=RESOURCE, jwks=jwks)
    # The same issuer given twice is fine.
    assert AccessTokenVerifier(DOMAIN + "/", RESOURCE, custom_domain="auth.acme.com", jwks=jwks).issuer == DOMAIN


# ── The generated client ──────────────────────────────────────────────


@pytest.fixture()
def generated_client(monkeypatch: pytest.MonkeyPatch) -> types.ModuleType:
    """A stand-in for ``lumoauth_api_client`` that builds URLs as the generated code does."""
    module = types.ModuleType("lumoauth_api_client")

    class Configuration:
        def __init__(self, host: str) -> None:
            self.host = host
            self.api_key: Dict[str, str] = {}
            self.verify_ssl = True

    class ApiClient:
        def __init__(self, configuration: Configuration) -> None:
            self.configuration = configuration

        def param_serialize(self, method: str, resource_path: str, path_params: Any = None, **_: Any) -> Tuple[str, str]:
            for name, value in (path_params or {}).items():
                resource_path = resource_path.replace("{%s}" % name, str(value))
            return method, self.configuration.host + resource_path

    module.Configuration = Configuration  # type: ignore[attr-defined]
    module.ApiClient = ApiClient  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "lumoauth_api_client", module)
    return module


def test_generated_client_drops_the_segment_on_a_custom_domain(generated_client):
    api = LumoAuth(custom_domain="auth.acme.com", api_key="lmk_x").api
    assert api.configuration.host == DOMAIN
    assert api.param_serialize(
        method="GET", resource_path="/orgs/{orgId}/api/v1/admin/users/{userId}", path_params={"orgId": "anything", "userId": "u1"}
    ) == ("GET", DOMAIN + "/api/v1/admin/users/u1")
    assert api.param_serialize("POST", "/orgs/{orgId}/api/v1/abac/check", {"orgId": ORG}) == (
        "POST",
        DOMAIN + "/api/v1/abac/check",
    )
    assert api.param_serialize(method="POST", resource_path="/api/v1/authz/check") == ("POST", DOMAIN + "/api/v1/authz/check")


def test_generated_client_is_unchanged_without_a_custom_domain(generated_client):
    api = LumoAuth(base_url=PLATFORM, org_id=ORG, api_key="lmk_x").api
    assert type(api) is generated_client.ApiClient
    assert api.param_serialize(
        method="GET", resource_path="/orgs/{orgId}/api/v1/admin/users", path_params={"orgId": ORG}
    ) == ("GET", f"{PLATFORM}/orgs/{ORG}/api/v1/admin/users")

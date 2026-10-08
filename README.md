# LumoAuth Python SDK

[![lumoauth on PyPI](https://img.shields.io/pypi/v/lumoauth.svg?label=lumoauth)](https://pypi.org/project/lumoauth/)
[![Python >= 3.9](https://img.shields.io/badge/python-%3E%3D3.9-blue.svg)](#installation)
[![Typed](https://img.shields.io/badge/typing-typed-informational.svg)](#api-reference)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-green.svg)](#license)

The official Python SDK for [LumoAuth](https://lumoauth.dev): authorization
checks (RBAC, Zanzibar-style ReBAC, ABAC), sign-in for FastAPI apps, and a
complete identity toolkit for AI agents, including push approvals, Just-in-Time
permissions, delegation and cryptographic AAuth identity.

```python
from lumoauth import LumoAuth

client = LumoAuth(api_key="lk_…", org_id="acme-corp")

if client.permissions.check("document.edit"):
    ...
```

One dependency (`requests`), fully typed, Python 3.9 to 3.13.

## Contents

- [Which entry point do I need?](#which-entry-point-do-i-need)
- [Installation](#installation)
- [Configuration](#configuration)
- [Quick start](#quick-start)
  - [Check permissions from a backend](#1-check-permissions-from-a-backend)
  - [Add sign-in to a FastAPI app](#2-add-sign-in-to-a-fastapi-app)
  - [Authenticate an AI agent](#3-authenticate-an-ai-agent)
- [Guides](#guides)
  - [Authorization checks](#authorization-checks)
  - [Agents](#agents)
  - [Human approvals](#human-approvals)
  - [Just-in-Time permissions](#just-in-time-permissions)
  - [Delegation](#delegation)
  - [AAuth cryptographic identity](#aauth-cryptographic-identity)
  - [FastAPI integration](#fastapi-integration)
  - [Error handling](#error-handling)
  - [Beyond the curated surface](#beyond-the-curated-surface)
- [End-to-end example](#end-to-end-example)
- [API reference](#api-reference)
- [Changelog](#changelog)
- [License](#license)

## Which entry point do I need?

Everything lives in one package. Pick the row that matches what you are
building and jump to its guide.

| You are building… | Start with | Guide |
|---|---|---|
| A **backend service** that checks what users may do | `LumoAuth` | [Authorization checks](#authorization-checks) |
| A **FastAPI web app** with sign-in | `lumoauth.fastapi` | [FastAPI integration](#fastapi-integration) |
| An **AI agent** with its own identity | `LumoAuthAgent` | [Agents](#agents) |
| An agent that must **ask a human** before acting | `require_approval` | [Human approvals](#human-approvals) |
| An agent that needs **short-lived, scoped access** | `JITContext` | [Just-in-Time permissions](#just-in-time-permissions) |
| An agent acting **on behalf of a user** or sub-agents | `DelegationChain` | [Delegation](#delegation) |
| An agent with a **cryptographic key** that signs requests | `AAuthClient` | [AAuth cryptographic identity](#aauth-cryptographic-identity) |

Still unsure? Services and apps use `LumoAuth`. Anything autonomous uses
`LumoAuthAgent`, and the other agent helpers build on top of it.

## Installation

```bash
pip install lumoauth
```

Optional extras add features on demand:

| Extra | Install | Adds |
|---|---|---|
| `aauth` | `pip install "lumoauth[aauth]"` | Ed25519 signing for the AAuth protocol (`cryptography`) |
| `fastapi` | `pip install "lumoauth[fastapi]"` | Login, callback and logout routes for FastAPI |
| `api` | `pip install "lumoauth[api]"` | Generated client for the full REST API behind `client.api` |

Extras combine: `pip install "lumoauth[aauth,fastapi]"`.

From a local checkout:

```bash
pip install -e ./sdk-python                # core
pip install -e "./sdk-python[aauth,dev]"   # core + AAuth + test tooling
```

## Configuration

Every client accepts its settings as constructor arguments and falls back to
environment variables, so production code can stay credential-free:

| Variable | Used by | Description | Default |
|---|---|---|---|
| `LUMOAUTH_URL` | all | LumoAuth instance URL | `https://app.lumoauth.dev` |
| `LUMOAUTH_ORG_ID` | all | Organization ID | *(required)* |
| `LUMOAUTH_API_KEY` | `LumoAuth` | API key, sent as `X-API-Key` | — |
| `AGENT_CLIENT_ID` | `LumoAuthAgent` | Agent OAuth client ID | *(required for agents)* |
| `AGENT_CLIENT_SECRET` | `LumoAuthAgent` | Agent OAuth client secret | *(required for agents)* |

```python
# Explicit…
client = LumoAuth(api_key="lk_…", org_id="acme-corp", base_url="https://auth.acme.com")

# …or from the environment
client = LumoAuth()
```

## Quick start

### 1. Check permissions from a backend

`LumoAuth` is the general-purpose client. It is organised into resource
namespaces, one per LumoAuth feature.

```python
from lumoauth import LumoAuth

client = LumoAuth(api_key="lk_…", org_id="acme-corp")

# RBAC: does the caller hold this permission?
if client.permissions.check("document.edit"):
    ...

# ReBAC (Zanzibar): is bob a viewer of this document?
if client.zanzibar.is_viewer("document:readme", "user:bob"):
    ...

# ABAC: evaluate attribute-based policy for a resource
decision = client.abac.check("document", "read", "doc-123")
if decision["allowed"]:
    ...
```

Namespaces: `auth`, `permissions`, `zanzibar`, `abac`, `agents`,
`delegation`, `jit`, `approvals`, `mcp`, plus `api` for the full generated
client.

### 2. Add sign-in to a FastAPI app

Three routes and one dependency give you a complete OAuth 2.0 + PKCE login.

```python
import os
from fastapi import Depends, FastAPI
from starlette.middleware.sessions import SessionMiddleware
from lumoauth.fastapi import User, lumo_auth_router, require_auth

app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key=os.environ["SESSION_SECRET"])
app.include_router(
    lumo_auth_router(
        base_url="https://app.lumoauth.dev",
        organization="acme-corp",
        client_id=os.environ["LUMOAUTH_CLIENT_ID"],
        client_secret=os.environ["LUMOAUTH_CLIENT_SECRET"],
        callback_path="/auth/callback",
    ),
    prefix="/auth",
)

@app.get("/api/me")
def me(user: User = Depends(require_auth())):
    return user.model_dump()
```

Visit `/auth/login` to sign in and `/auth/logout` to sign out.

### 3. Authenticate an AI agent

`LumoAuthAgent` gives an agent its own identity via the OAuth 2.0
client-credentials flow, then keeps the token fresh for you.

```python
from lumoauth import LumoAuthAgent

agent = LumoAuthAgent()        # reads LUMOAUTH_* and AGENT_* env vars
agent.authenticate()

# Preflight: ask LumoAuth before calling a tool
if agent.is_allowed("document.read", context={"id": "doc_99"}):
    resp = agent.api_request("GET", "https://api.acme.com/documents/doc_99")
    print(resp.json())
```

## Guides

### Authorization checks

All three authorization models are available on `LumoAuth`. Each has a
boolean fast path and a `*_detailed` variant that returns the full decision.

**RBAC** checks permission slugs:

```python
client.permissions.check("document.edit")
client.permissions.check("document.edit", user_id="user_42")    # on behalf of a user
client.permissions.check_any(["document.edit", "document.admin"])
client.permissions.check_all(["document.read", "document.edit"])
client.permissions.check_bulk(["document.edit", "document.delete"])
# → {"document.edit": True, "document.delete": False}

detail = client.permissions.check_detailed("document.edit")
```

**ReBAC (Zanzibar)** checks relationships between objects and subjects:

```python
client.zanzibar.check("document:readme", "viewer", "user:bob")
client.zanzibar.is_viewer("document:readme", "user:bob")
client.zanzibar.is_editor("document:readme", "user:bob")
client.zanzibar.is_owner("folder:finance", "user:alice")
client.zanzibar.is_member("team:platform", "user:alice")
client.zanzibar.is_admin("org:acme", "user:alice")
```

**ABAC** evaluates policies over user and resource attributes:

```python
decision = client.abac.check("document", "read", "doc-123", context={"ip": "10.0.0.8"})
if client.abac.is_allowed("document", "read", "doc-123"):
    ...

# Manage the attributes policies evaluate
client.abac.set_user_attribute("user_42", "department", "finance")
client.abac.set_resource_attribute("document", "doc-123", "classification", "internal")
print(client.abac.get_my_attributes())
```

### Agents

#### Authentication and token refresh

Call `authenticate()` once at startup. Every other method calls
`ensure_authenticated()` for you, so refreshes are transparent.

```python
agent = LumoAuthAgent(client_id="agt_…", client_secret="…", org_id="acme-corp")
agent.authenticate()

print(agent.access_token)   # current bearer token
print(agent.token_scopes)   # granted scopes
```

#### Capabilities, budget and identity

```python
info = agent.get_agent_info()          # sub, name, capabilities, budget_policy, …

if agent.has_capability("tool:search_web"):
    ...

if agent.is_budget_exhausted():
    print("Daily token budget reached, backing off")

me = agent.get_identity()              # GET /agents/me
print(me["identity"]["id"], me["capabilities"], me["workspace"])
```

#### Ask API: preflight checks for tool calls

The Ask API is a fast "may I do this?" check designed for LLM tool dispatch.
Ask before you act, and the decision is audited either way.

```python
result = agent.ask("document.read", context={"id": "doc_99"})
# {"allowed": True, "action": "document.read", "reason": "capability granted",
#  "audit_id": "…", "context": {…}}

def dispatch_tool(tool_name: str, args: dict):
    if not agent.is_allowed(tool_name, context=args):
        return {"error": f"Agent is not authorised to run {tool_name}"}
    # … execute the tool
```

#### Authenticated HTTP requests

`api_request()` adds the `Authorization` header and accepts either a full URL
or a path relative to your LumoAuth instance.

```python
resp = agent.api_request("GET", "https://api.acme.com/documents/123")
resp = agent.api_request(
    "POST",
    "https://api.acme.com/documents",
    data={"query": "quarterly revenue"},
)
```

#### Capability gates with a decorator

`@require_capability` raises `PermissionError` when the agent lacks the named
capability.

```python
from lumoauth import LumoAuthAgent, require_capability

class ResearchAgent(LumoAuthAgent):
    @require_capability("tool:search_web")
    def search(self, query: str) -> dict:
        return self.api_request("POST", "https://api.acme.com/search", data={"query": query}).json()
```

#### MCP token exchange

Exchange the agent token for one scoped to a secured MCP server
([RFC 8693](https://www.rfc-editor.org/rfc/rfc8693)):

```python
mcp_token = agent.get_mcp_token("urn:mcp:financial-data")
```

### Human approvals

Before an irreversible action, ask a human. `require_approval()` sends a push
notification with the action context and blocks until the user approves,
denies, or the request expires.

```python
from lumoauth import LumoAuthAgent, require_approval

agent = LumoAuthAgent()
agent.authenticate()

result = require_approval(
    agent,
    task_id="wire-2026-05-07-001",
    reason="Wire $4,500 to vendor INV-7741",
    impact="high",                      # low | medium | high | critical
    on_behalf_of="ada@acme.com",
    meta={"action": "wire-transfer", "amount": 4500},
    timeout_s=90,
)

if result.status != "approved":
    raise RuntimeError(f"Denied: {result.status} ({result.reason})")

# result.token authorises the side-effecting call
```

Need finer control? `agent.approvals.create()`, `.get_status()` and `.wait()`
expose the individual steps.

### Just-in-Time permissions

JIT permissions let an agent request exactly the access it needs, when it
needs it, for a short window. Each request creates an ephemeral task, asks for
specific permissions using
[RFC 9396 authorization details](https://www.rfc-editor.org/rfc/rfc9396),
and receives a short-lived token that is revoked when the task completes.

```python
from lumoauth import LumoAuthAgent, JITContext

agent = LumoAuthAgent()
agent.authenticate()

with JITContext(agent) as jit:
    jit.create_task(name="Analyse Q4 financial report", task_type="analysis")

    result = jit.request_permission(
        {
            "type": "file_access",
            "actions": ["read"],
            "identifier": "quarterly_report_q4_2024.pdf",
            "locations": ["https://storage.acme-corp.com/finance/"],
        },
        justification="User asked: 'What were our Q4 revenues?'",
    )

    if result["status"] == "approved":
        token = jit.get_token(result["request_id"])
        resp = jit.call(token, "GET", "https://storage.acme-corp.com/finance/quarterly_report_q4_2024.pdf")
        print(f"Read {len(resp.content)} bytes")
    elif result["status"] == "denied":
        print("Denied:", result.get("deny_reason"))
# Leaving the block completes the task and revokes every JIT token
```

**Auto-escalate on 403.** When a resource answers `403` with an
`Insufficient-Authorization-Details` header, `call_with_escalation()` parses
it, requests the missing permission, and retries:

```python
with JITContext(agent) as jit:
    jit.create_task(name="Ad-hoc data access")
    resp = jit.call_with_escalation(
        "GET",
        "https://api.acme-corp.com/v1/documents/doc_9982",
        justification="User asked for a summary of doc_9982",
    )
```

**Human-in-the-loop.** High-risk requests enter a `pending` state until an
approver acts. `request_permission()` polls by default; pass
`wait_for_approval=False` to return immediately and check `status_url`
yourself.

```python
result = jit.request_permission(
    {"type": "database_access", "actions": ["write"], "identifier": "users_table"},
    justification="Update email for user 42",
    ttl=300,
    poll_timeout=300,
)
```

**On behalf of a user.** Call `jit.delegate_on_behalf_of(user_token)` first
and every subsequent request is made "as the user, via the agent".

**Without the context manager.** Call `jit.create_task(...)` and make sure
`jit.complete_task()` runs in a `finally` block.

### Delegation

Delegation (Chain of Agency) lets an agent act on behalf of a user and,
optionally, hand off to sub-agents. It uses RFC 8693 token exchange, and every
resulting JWT carries an `act` claim so LumoAuth can trace who is behind each
action.

```python
from lumoauth import LumoAuthAgent, DelegationChain

agent = LumoAuthAgent()
agent.authenticate()

chain = DelegationChain(agent, redirect_uri="https://agent.example.com/callback")

# 1. Send the user to consent
url = chain.get_consent_url("session_1", scopes=["read:documents", "write:documents"])

# 2. Handle the callback
chain.handle_consent_callback("session_1", authorization_code)

# 3. Exchange for a delegated token and use it
token = chain.exchange("session_1", scopes=["read:documents"])
resp = chain.request("session_1", "GET", "https://api.acme.com/documents/abc")
```

Already hold a user token from another OAuth session? Skip consent:

```python
chain.set_user_token("session_1", user_access_token)
token = chain.exchange("session_1")
```

**Nested delegation** (user → orchestrator → specialist, up to three levels):

```python
sub_agent = LumoAuthAgent(client_id="agt_specialist", client_secret="…")
sub_agent.authenticate()

nested = chain.delegate_to_sub_agent("session_1", sub_agent.access_token, scopes=["read:documents"])

DelegationChain.get_subject(nested)         # "user:alice"
DelegationChain.parse_actor_chain(nested)   # ["agent:orchestrator", "agent:specialist"]
```

**Housekeeping:** `chain.revoke("session_1")`, `chain.revoke_all()`,
`chain.active_sessions`, `chain.has_delegation("session_1")`.

### AAuth cryptographic identity

AAuth extends OAuth 2.1 with cryptographic agent identity. The agent holds an
Ed25519 private key, signs every HTTP request
([RFC 9421](https://www.rfc-editor.org/rfc/rfc9421)), and receives
proof-of-possession tokens that cannot be replayed.

> Requires `pip install "lumoauth[aauth]"`.

**Generate a key pair** once, store the private key securely, and publish the
JWKS at `https://<agent>/.well-known/jwks.json`:

```python
from lumoauth import AAuthClient

private_pem, jwks = AAuthClient.generate_keypair()
```

**Create a client and obtain tokens:**

```python
client = AAuthClient(
    agent_identifier="https://my-agent.example.com",
    private_key_pem=open("agent-key.pem").read(),
    org_id="acme-corp",
)

result = client.request_authorization(
    resource_token=resource_tok,
    scope="read write",
    agent_token=agent_tok,
    redirect_uri="https://my-agent.example.com/callback",
)

if result.get("authorization_required"):
    # Send the user to result["auth_url"]; on return, redeem the code.
    # redirect_uri must match the URI the code was delivered to.
    tokens = client.exchange_code(code, "https://my-agent.example.com/callback", agent_token=agent_tok)
else:
    tokens = result    # pre-approved: tokens returned directly
```

**Call protected resources** with both a Bearer token and an Agent-Auth
signature:

```python
resp = client.signed_request(
    "POST",
    "https://api.example.com/v1/actions",
    auth_token=tokens["access_token"],
    data={"action": "analyse", "target": "report_q4"},
)
```

**Refresh** needs a fresh resource token for the target resource; the refresh
token itself is not rotated:

```python
new_tokens = client.refresh(tokens["refresh_token"], fresh_resource_tok, agent_token=agent_tok)
```

**Discovery:** `client.discover_issuer()` and
`client.discover_resource("https://api.example.com")` fetch the
`.well-known` metadata documents.

### FastAPI integration

> Requires `pip install "lumoauth[fastapi]"`.

`lumo_auth_router()` mounts `/login`, `/callback` and `/logout` under the
prefix you choose and completes the OAuth 2.0 + PKCE dance. The PKCE verifier
and `state` live in the Starlette session, never in URLs or cookies, so the
app **must** add `SessionMiddleware`.

| Helper | Purpose |
|---|---|
| `lumo_auth_router(...)` | Builds the router. `callback_path` must match a redirect URI registered on the OAuth client. |
| `get_current_user` | Dependency returning the signed-in `User`, or `None`. |
| `require_auth(scopes=None)` | Dependency that responds `401` when signed out and `403` when a scope is missing. |
| `User` | Pydantic model of the `/userinfo` claims (`sub`, `email`, `name`, …). Extra claims are preserved. |

```python
@app.get("/api/admin")
def admin(user: User = Depends(require_auth(scopes=["admin"]))):
    return {"hello": user.name}

@app.get("/")
def home(user: User | None = Depends(get_current_user)):
    return {"signed_in": user is not None}
```

Pass `?return_to=/dashboard` to `/login` to land somewhere specific after
sign-in. Only same-site paths are honoured.

### Error handling

Every HTTP failure raises a subclass of `LumoAuthError`, so you can catch
exactly what you care about.

```
LumoAuthError
├── LumoAuthApiError                 .status_code, .code, .body
│   ├── LumoAuthAuthenticationError  401
│   ├── LumoAuthPermissionDeniedError 403
│   ├── LumoAuthNotFoundError        404
│   └── LumoAuthRateLimitError       429, .retry_after
├── LumoAuthValidationError          .issues
├── LumoAuthConfigError
├── LumoAuthNetworkError
├── LumoAuthApprovalDeniedError
├── LumoAuthApprovalTimeoutError
└── LumoAuthBudgetExceededError
```

```python
import time
from lumoauth import LumoAuthPermissionDeniedError, LumoAuthRateLimitError

try:
    client.permissions.check_detailed("document.edit")
except LumoAuthRateLimitError as err:
    time.sleep(err.retry_after or 1)
except LumoAuthPermissionDeniedError as err:
    print(err.status_code, err.code, err.body)
```

For backwards compatibility `LumoAuthApiError` also subclasses
`RuntimeError`, and `LumoAuthConfigError` / `LumoAuthValidationError` also
subclass `ValueError`.

### Beyond the curated surface

The namespaces above cover the common surface. For anything else, `client.api`
exposes the generated OpenAPI client, configured lazily with the same base
URL and credentials. Agent tokens are resolved per request, so refreshes keep
working.

```bash
pip install "lumoauth[api]"
```

```python
client = LumoAuth(api_key="lk_…", org_id="acme-corp")
client.api   # lumoauth_api_client.ApiClient, ready to use
```

Prefer a bearer token over an API key? Pass `token_provider=lambda: my_token`
to `LumoAuth`. When both are set, the provider wins.

## End-to-end example

A research agent that preflights its tools with the Ask API, gates a method
with a capability, and reads a protected document through JIT with automatic
escalation.

```python
from lumoauth import LumoAuthAgent, JITContext, require_capability


class ResearchAgent(LumoAuthAgent):
    @require_capability("tool:search_web")
    def search_web(self, query: str) -> dict:
        return self.api_request(
            "POST",
            f"/orgs/{self.org_id}/api/v1/tools/search",
            data={"query": query},
        ).json()

    def read_document(self, doc_url: str, justification: str) -> bytes:
        with JITContext(self) as jit:
            jit.create_task(name=f"Read {doc_url}")
            resp = jit.call_with_escalation("GET", doc_url, justification=justification)
            resp.raise_for_status()
            return resp.content


agent = ResearchAgent()
agent.authenticate()

if agent.is_allowed("tool:search_web"):
    print(agent.search_web("LumoAuth JIT permissions"))

content = agent.read_document(
    "https://storage.acme-corp.com/reports/q4.pdf",
    justification="User asked for a Q4 summary",
)
```

## API reference

### `LumoAuth`

```python
LumoAuth(*, api_key=None, base_url=None, org_id=None, token_provider=None,
         timeout=30, skip_cert_validation=False)
```

| Namespace | Methods |
|---|---|
| `client.auth` | `authorization_url(…)`, `exchange_code(code, redirect_uri, …)`, `refresh_token(…)`, `client_credentials(client_id, client_secret, scopes=None)`, `token_exchange(subject_token, …)`, `revoke(token, …)`, `userinfo(access_token=None)` |
| `client.permissions` | `check(permission, context=None, *, user_id=None)`, `check_detailed`, `check_bulk`, `check_any`, `check_all`, `check_any_detailed`, `check_all_detailed`, `list()`, `list_slugs()` |
| `client.zanzibar` | `check(object, relation, subject)`, `check_detailed`, `is_viewer`, `is_editor`, `is_owner`, `is_member`, `is_admin` |
| `client.abac` | `check(resource_type, action, resource_id=None, context=None)`, `is_allowed`, `check_bulk(requests)`, `get_my_attributes()`, `set_user_attribute(user_id, slug, value)`, `get_resource_attributes(type, id)`, `set_resource_attribute(type, id, slug, value)`, `get_attribute_definitions(type=None)` |
| `client.agents` | `ask(action, context=None)`, `is_allowed`, `me()`, `register(name, *, client_id, …)`, `info()`, `capabilities()`, `budget()` |
| `client.delegation` | `consent_url(…)`, `exchange_code(…)`, `exchange(subject_token, actor_token, scopes=None)`, `refresh_user_token(…)`, `revoke(token, …)`, `parse_actor_chain(token)`, `get_subject(token)` |
| `client.jit` | `create_task(…)`, `complete_task(task_id)`, `evaluate_task(task_id, …)`, `request(task_id, authorization_details, …)`, `get_status(request_id)`, `get_token(request_id)`, `pending()` |
| `client.approvals` | `create(…)`, `get_status(token)`, `wait(token, …)`, `require(*, task_id, reason, on_behalf_of, …)` |
| `client.mcp` | `get_token(server_id, *, subject_token=None)` |
| `client.api` | Generated OpenAPI client (lazy; requires `lumoauth[api]`) |

### `LumoAuthAgent`

```python
LumoAuthAgent(base_url=None, org_id=None, client_id=None, client_secret=None,
              skip_cert_validation=False)
```

| Method | Description |
|---|---|
| `authenticate(scopes=None)` | OAuth 2.0 client-credentials authentication |
| `ensure_authenticated()` | Transparent token refresh |
| `get_agent_info()` | Identity and capabilities from UserInfo |
| `has_capability(cap)` | Check a single capability |
| `get_budget_status()` / `is_budget_exhausted()` | Budget policy and exhaustion check |
| `ask(action, context=None)` / `is_allowed(…)` | Ask API preflight check |
| `get_identity()` | Agent self-inspection (`GET /agents/me`) |
| `api_request(method, endpoint, …)` | Authenticated HTTP request |
| `get_mcp_token(mcp_server_id)` | RFC 8693 token exchange for MCP servers |
| `register(name, …)` | Register or update the agent record |
| `.jit` / `.delegation` / `.mcp` / `.approvals` | Raw resource namespaces (same objects as on `LumoAuth`) |

### `JITContext`

```python
JITContext(agent, *, delegated_token=None)
```

| Method | Description |
|---|---|
| `delegate_on_behalf_of(user_token)` | RFC 8693 token exchange for delegation |
| `create_task(name=…, task_type=…, on_behalf_of=…)` | Create an ephemeral task |
| `complete_task()` | Complete the task and revoke all JIT tokens |
| `request_permission(authorization_details, …)` | RFC 9396 permission request with optional HITL polling |
| `get_token(request_id)` | Exchange an approval for a short-lived JIT token |
| `call(jit_token, method, url, …)` | API call with a JIT token |
| `call_with_escalation(method, url, …)` | Auto-escalate on 403 and retry |

### `DelegationChain`

```python
DelegationChain(agent, *, redirect_uri=None)
```

| Method | Description |
|---|---|
| `get_consent_url(session_id, scopes=…)` | Build the user consent URL |
| `handle_consent_callback(session_id, code)` | Redeem the authorization code |
| `set_user_token(session_id, token)` | Use an existing user token |
| `exchange(session_id, scopes=None)` | Obtain a delegated token |
| `request(session_id, method, url, …)` | HTTP request with the delegated token |
| `delegate_to_sub_agent(session_id, sub_agent_token, scopes=…)` | Nested delegation |
| `revoke(session_id)` / `revoke_all()` | Revoke delegations |
| `parse_actor_chain(token)` / `get_subject(token)` *(static)* | Inspect any delegated JWT |

### `AAuthClient`

```python
AAuthClient(agent_identifier, private_key_pem, *, base_url=None, org_id=None,
            kid="key-1", skip_cert_validation=False)
```

| Method | Description |
|---|---|
| `generate_keypair()` *(static)* | Ed25519 key pair plus JWKS |
| `sign_request(method, url, …)` | RFC 9421 HTTP message signature headers |
| `request_authorization(resource_token, scope, …)` | Obtain tokens (direct or via user consent) |
| `exchange_code(code, redirect_uri, *, agent_token)` | Redeem a consent code |
| `refresh(refresh_token, resource_token, *, scope=None, agent_token)` | Refresh with a fresh resource token |
| `signed_request(method, url, auth_token=…, …)` | Authenticated and signed HTTP request |
| `discover_issuer()` / `discover_resource(url)` | Fetch `.well-known` metadata |

### Helpers

| Name | Description |
|---|---|
| `require_capability(cap)` | Decorator for `LumoAuthAgent` methods; raises `PermissionError` when the capability is missing |
| `require_approval(agent, *, task_id, reason, on_behalf_of, impact="medium", meta=None, poll_interval_s=1.5, timeout_s=90)` | Push approval that blocks until resolved; returns `ApprovalResult` |
| `ApprovalResult` | Frozen dataclass: `status`, `token`, `task_id`, `impact`, `reason`, `responded_at`, `approved_by` |

### `lumoauth.fastapi`

| Name | Description |
|---|---|
| `lumo_auth_router(*, base_url, organization, client_id, client_secret=None, callback_path="/auth/callback", scope="openid profile email", post_login_redirect="/", post_logout_redirect="/")` | Router with `/login`, `/callback`, `/logout` |
| `get_current_user(request)` | Dependency returning `User` or `None` |
| `require_auth(scopes=None)` | Dependency factory raising `401` / `403` |
| `User` | Pydantic model of the signed-in principal |
| `LumoAuthFastAPI` | Configuration container, for sharing settings with custom dependencies |

## Changelog

### 1.0.0

- New `LumoAuth` client with resource namespaces (`auth`, `permissions`,
  `zanzibar`, `abac`, `agents`, `delegation`, `jit`, `approvals`, `mcp`) and a
  lazy `client.api` escape hatch to the generated OpenAPI client
  (`pip install "lumoauth[api]"`).
- Typed error taxonomy (`LumoAuthError` / `LumoAuthApiError` /
  `LumoAuthAuthenticationError` / …) replacing bare `ValueError` /
  `RuntimeError`. The new classes subclass the builtins they replaced, so
  existing `except` clauses keep working.
- All endpoint paths centralised in `lumoauth._routes.ROUTES` with an
  OpenAPI drift test.
- `LumoAuthAgent` moved to `lumoauth.agent` (importing it from
  `lumoauth.client` or `lumoauth` still works) and is now a thin layer over
  `LumoAuth`. Every existing method keeps its name, signature and behaviour.
- `DelegationChain` and `JITContext` keep their ergonomic surfaces but
  delegate to the shared resources internally.

### 0.2.0

**Breaking fixes.** The AAuth client now matches the AAuth 1.0 server
contract for the agent token endpoint:

- `AAuthClient.exchange_code(code, redirect_uri, *, agent_token)`: the second
  parameter is now `redirect_uri` (previously `request_token`). The code is
  bound to the exact redirect URI it was delivered to.
- `AAuthClient.refresh(refresh_token, resource_token, *, scope=None,
  agent_token)`: a fresh `resource_token` for the target resource is now a
  required second positional parameter, and `scope` became keyword-only.

## License

Apache-2.0

# LumoAuth Python SDK

[![lumoauth on PyPI](https://img.shields.io/pypi/v/lumoauth.svg?label=lumoauth)](https://pypi.org/project/lumoauth/)
[![Python >= 3.9](https://img.shields.io/badge/python-%3E%3D3.9-blue.svg)](#requirements)
[![Typed](https://img.shields.io/badge/typing-typed-informational.svg)](#api-reference)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-green.svg)](#license)

The official Python SDK for [LumoAuth](https://lumoauth.dev). Use it to ask
LumoAuth whether a user or an AI agent may do something, to sign users in to a
FastAPI app, and to give an AI agent its own identity. Agent features include
push approvals, Just-in-Time (JIT) permissions, delegation and AAuth request
signing.

```python
from lumoauth import LumoAuth

client = LumoAuth(api_key="lmk_…", org_id="acme-corp")

if client.permissions.check("document.edit"):
    ...
```

## Contents

- [Requirements](#requirements)
- [Install](#install)
- [Quick start](#quick-start)
- [Core concepts](#core-concepts)
  - [Organization and base URL](#organization-and-base-url)
  - [Credentials](#credentials)
  - [Scopes](#scopes)
- [Configuration](#configuration)
- [Guides](#guides)
  - [Check permissions](#check-permissions)
  - [Check relationships (Zanzibar)](#check-relationships-zanzibar)
  - [Attribute-based checks (ABAC)](#attribute-based-checks-abac)
  - [Sign users in with OAuth](#sign-users-in-with-oauth)
  - [FastAPI integration](#fastapi-integration)
  - [Agents](#agents)
  - [Human approvals](#human-approvals)
  - [Just-in-Time permissions](#just-in-time-permissions)
  - [Delegation and token exchange](#delegation-and-token-exchange)
  - [MCP tokens](#mcp-tokens)
  - [AAuth cryptographic identity](#aauth-cryptographic-identity)
  - [The generated API client](#the-generated-api-client)
- [Errors](#errors)
- [API reference](#api-reference)
- [Troubleshooting](#troubleshooting)
- [Versioning and compatibility](#versioning-and-compatibility)
- [Development](#development)
- [Changelog](#changelog)
- [License](#license)

## Requirements

- Python 3.9 to 3.13.
- One required dependency: `requests` 2.25 or later.
- Optional extras, which you install only for the features that need them:

| Extra | Install | Adds |
|---|---|---|
| `aauth` | `pip install "lumoauth[aauth]"` | Ed25519 signing for AAuth (`cryptography` 41 or later) |
| `fastapi` | `pip install "lumoauth[fastapi]"` | Login, callback and logout routes for FastAPI 0.110 or later |
| `api` | `pip install "lumoauth[api]"` | The generated client for the full REST API, as `client.api` |

## Install

```bash
pip install lumoauth
```

Extras combine:

```bash
pip install "lumoauth[aauth,fastapi]"
```

To work from a local checkout:

```bash
pip install -e ./sdk-python                # core only
pip install -e "./sdk-python[aauth,dev]"   # core, AAuth and the test tools
```

## Quick start

**Check a permission from a backend service.** This program asks LumoAuth
whether the owner of the API key holds the `document.edit` permission.

```python
from lumoauth import LumoAuth

client = LumoAuth(api_key="lmk_…", org_id="acme-corp")

if client.permissions.check("document.edit"):
    print("Allowed")
else:
    print("Denied")
```

**Give an AI agent its own identity.** The agent signs in with its client ID
and secret, then asks LumoAuth before it runs a tool.

```python
from lumoauth import LumoAuthAgent

agent = LumoAuthAgent()        # reads LUMOAUTH_* and AGENT_* environment variables
agent.authenticate()

if agent.is_allowed("document.read", context={"id": "doc_99"}):
    resp = agent.api_request("GET", "https://api.acme.com/documents/doc_99")
    print(resp.json())
```

Not sure which class to start with? Use this table.

| You are building… | Start with | Guide |
|---|---|---|
| A **backend service** that checks what users may do | `LumoAuth` | [Check permissions](#check-permissions) |
| A **FastAPI web app** with sign-in | `lumoauth.fastapi` | [FastAPI integration](#fastapi-integration) |
| An **AI agent** with its own identity | `LumoAuthAgent` | [Agents](#agents) |
| An agent that must **ask a person** before it acts | `require_approval` | [Human approvals](#human-approvals) |
| An agent that needs **short-lived access** to one resource | `JITContext` | [Just-in-Time permissions](#just-in-time-permissions) |
| An agent that acts **for a user**, or hands work to sub-agents | `DelegationChain` | [Delegation and token exchange](#delegation-and-token-exchange) |
| An agent with a **key pair** that signs each request | `AAuthClient` | [AAuth cryptographic identity](#aauth-cryptographic-identity) |

Services and web apps use `LumoAuth`. Autonomous agents use `LumoAuthAgent`.
The other agent helpers build on `LumoAuthAgent`.

## Core concepts

### Organization and base URL

Every LumoAuth customer has an **organization**, identified by a short slug
such as `acme-corp`. Most API routes include that slug, so pass it as
`org_id` or set `LUMOAUTH_ORG_ID`. A call that needs the slug raises
`LumoAuthConfigError` when it is missing.

The **base URL** is the LumoAuth region that hosts your organization:

- `https://app.lumoauth.dev` (the default)
- `https://eu.app.lumoauth.dev` for the EU region

### Credentials

The SDK sends one credential with each request. LumoAuth accepts three kinds,
and each kind may call a different set of routes.

| Credential | How the SDK sends it | What it may call |
|---|---|---|
| **Organization API key** (`lmk_…`), passed as `api_key` | `X-API-Key` header | Permission checks, Zanzibar check and expand, and the admin API. Not ABAC, agents, JIT, approvals or userinfo. |
| **User access token**, returned by a user's sign-in | `Authorization: Bearer` | Calls about the signed-in user. Some routes also need a [scope](#scopes). |
| **Agent credential**: a client-credentials token, or an agent key (`agk_…`) | `Authorization: Bearer` | Agent routes: ask, me, approvals, JIT, token exchange. LumoAuth checks the agent's capabilities to determine what it may do. |

On `LumoAuth`, pass a user or agent token through `token_provider`. This is a
function with no arguments that returns the token. It runs before each
request, so it can return a refreshed token. When it returns a token, that
token wins over `api_key`.

```python
client = LumoAuth(org_id="acme-corp", token_provider=lambda: session["access_token"])
```

`LumoAuthAgent` manages its own token, so you do not pass one.

Token endpoint calls (`client.auth.exchange_code`, `refresh_token`,
`client_credentials`, `token_exchange` and `revoke`) authenticate with the
values in the form body. They never send the client's default credential.

### Scopes

A user access token carries **scopes**, which the user granted at sign-in. LumoAuth
rejects a user token on some routes when the token lacks the right scope.

| Call | Scope that a user access token needs |
|---|---|
| `permissions.list()`, `permissions.list_slugs()` | `authz:read` |
| ABAC checks and attribute reads | `abac:read` |
| ABAC attribute writes | `abac:write` |
| `jit.pending()`, `JITContext.list_pending_requests()` (human review) | `jit:approve` |
| `agents.register()` | `admin:agents:write` |
| Permission checks, Zanzibar check and expand, `agents.ask()`, `agents.me()`, `auth.userinfo()` | none |

- The blanket `admin` scope satisfies all of the scopes in this table.
- A check about another user or agent (`user_id=…` or `agent_id=…`) needs
  the `authz:check` scope or the `authz.check` permission. API keys can hold
  `authz:check`.
- `agents.me()` returns an empty `capabilities` list to a user token that
  lacks `authz:read`.
- Organization API keys can never hold these user scopes. With an API key,
  `permissions.list()` fails with a 403 error.
- Agent credentials do not use scopes. LumoAuth checks the agent's
  capabilities instead.

When a scope is missing, LumoAuth answers with HTTP 403. The SDK raises
`LumoAuthPermissionDeniedError`, and its `required_scopes` attribute names the
missing scopes. See [Errors](#errors).

Request scopes when the user signs in. For example, an app that lists the
user's permissions requests `openid profile email authz:read`.

## Configuration

Every constructor argument falls back to an environment variable. Production
code can therefore keep credentials out of the source.

| Variable | Used by | Meaning | Default |
|---|---|---|---|
| `LUMOAUTH_URL` | all clients | Base URL of your LumoAuth region | `https://app.lumoauth.dev` |
| `LUMOAUTH_ORG_ID` | all clients | Organization slug | none; needed by org-scoped calls |
| `LUMOAUTH_API_KEY` | `LumoAuth` | Organization API key, sent as `X-API-Key` | none |
| `AGENT_CLIENT_ID` | `LumoAuthAgent` | The agent's OAuth client ID | none; required |
| `AGENT_CLIENT_SECRET` | `LumoAuthAgent` | The agent's OAuth client secret | none; required |

```python
# Explicit arguments…
client = LumoAuth(api_key="lmk_…", org_id="acme-corp", base_url="https://eu.app.lumoauth.dev")

# …or the environment
client = LumoAuth()
```

`LumoAuth` takes these keyword-only arguments:

| Argument | Type | Default | Meaning |
|---|---|---|---|
| `api_key` | `str` | `LUMOAUTH_API_KEY` | Organization API key |
| `base_url` | `str` | `LUMOAUTH_URL`, then `https://app.lumoauth.dev` | Base URL |
| `org_id` | `str` | `LUMOAUTH_ORG_ID` | Organization slug |
| `token_provider` | `Callable[[], str \| None]` | none | Returns a bearer token for each request; wins over `api_key` |
| `timeout` | `float` | `30` | Request timeout in seconds |
| `skip_cert_validation` | `bool` | `False` | Turns off the checks of TLS certificates. Use it for local development only. |

`LumoAuthAgent` takes `base_url`, `org_id`, `client_id`, `client_secret` and
`skip_cert_validation`. It raises `LumoAuthConfigError` when it cannot find a
client ID and secret.

## Guides

### Check permissions

Use permission checks for role-based access control (RBAC). A permission is a
slug such as `document.edit`. Users receive permissions through their roles,
including roles that come from their groups.

```python
client.permissions.check("document.edit")                        # True or False
client.permissions.check("document.edit", user_id="01a176cb-4095-7bb1-b3fe-7a9b8943e0cf")  # about another user
client.permissions.check_any(["document.edit", "document.admin"])  # at least one
client.permissions.check_all(["document.read", "document.edit"])   # every one
client.permissions.check_bulk(["document.edit", "document.delete"])
```

- `check`, `check_any` and `check_all` return a `bool`.
- `check_detailed`, `check_any_detailed` and `check_all_detailed` return the
  full response as a `dict`, which includes `allowed`.
- `check_bulk` returns a `dict` whose `results` key maps each slug to a
  `bool`.
- Every check method accepts an optional `context` dict, which LumoAuth uses
  for attribute conditions.

A check answers for the principal behind the credential. With an API key,
that principal is the user who created the key. To ask about another user,
pass `user_id` with the user's LumoAuth ID, which is a UUID (the `sub` claim
of that user's tokens). To ask about an agent, pass `agent_id` with its
`agt_…` ID. The SDK sends either one as `subject` in the request body.

Asking about someone else needs the `authz:check` scope or the
`authz.check` permission. Without it, LumoAuth answers 403 with the code
`INSUFFICIENT_PERMISSIONS`. An ID that is not in your organization gets 404
with the code `SUBJECT_NOT_FOUND`.

To list every permission that the caller holds:

```python
result = client.permissions.list()        # {"permissions": [{"slug": …}, …], …}
slugs = client.permissions.list_slugs()   # {"document.edit", "document.read", …}
```

A user access token needs the `authz:read` scope for these two calls.
Organization API keys cannot hold that scope, so the calls fail with an API
key.

### Check relationships (Zanzibar)

Use relationship checks for relationship-based access control (ReBAC). A
check asks whether a subject has a relation to an object. Objects and
subjects are written as `namespace:id`, for example `document:readme` and
`user:bob`.

```python
client.zanzibar.check("document:readme", "viewer", "user:bob")   # True or False
client.zanzibar.check_detailed("document:readme", "viewer", "user:bob")  # full dict

# Shortcuts for common relations
client.zanzibar.is_viewer("document:readme", "user:bob")
client.zanzibar.is_editor("document:readme", "user:bob")
client.zanzibar.is_owner("folder:finance", "user:alice")
client.zanzibar.is_member("team:platform", "user:alice")
client.zanzibar.is_admin("org:acme", "user:alice")
```

The check is true when the relation exists directly or through an inherited
relation.

`expand` answers the opposite question: who has this relation?

```python
tree = client.zanzibar.expand("document:readme", "viewer")
# {"type": "union", "object": …, "relation": …, "children": […], "subjects": […]}
```

Expansion shows other subjects, so it needs the `authz:check` scope or the
`authz.check` permission. A caller that may only check itself gets a 403
error.

### Attribute-based checks (ABAC)

Use ABAC when a decision depends on attributes of the user, of the resource
or of the request. An example is "finance staff may read internal documents".

```python
decision = client.abac.check("document", "read", "doc-123")
# {"allowed": True, "reason": …, "matchedPolicies": […], …}

if client.abac.is_allowed("document", "read", "doc-123"):
    ...

# Several checks in one request (at most 100)
result = client.abac.check_bulk(
    [
        {"resource_type": "document", "action": "read", "resource_id": "doc-1"},
        {"resource_type": "document", "action": "edit", "resource_id": "doc-2"},
    ],
    environment={"pep": {"ip": "10.0.0.8"}},
)
# {"results": [{"index": 0, "allowed": True, "reason": …, …}, …]}
```

`context` holds the environment attributes that your policies evaluate. The
SDK sends it as the request's `environment`. A bulk call takes one shared
`environment`, because LumoAuth applies the same environment to every check
in the call. An item may carry its own `context`, but every item that has one
must use the same value. Different contexts raise `LumoAuthValidationError`.
In that case, call `check()` once for each context.

**Request environment.** The environment keys `ip`, `userAgent`,
`requestMethod` and `requestPath` always describe the request that LumoAuth
received from your server. LumoAuth ignores values that you send under those
names and keeps them under `pep` instead. To pass the end user's IP address,
send it under `pep` and write your policies against `pep.ip`:

```python
client.abac.check("document", "read", "doc-123", context={"pep": {"ip": "10.0.0.8"}})
```

**Attributes.** Policies evaluate attributes, which you can read and set:

```python
client.abac.get_my_attributes()                                  # the caller's attributes
client.abac.set_user_attribute("user_42", "department", "finance")
client.abac.get_resource_attributes("document", "doc-123")
client.abac.set_resource_attribute("document", "doc-123", "classification", "internal")
client.abac.get_attribute_definitions(type="resource")           # "user", "resource" or "environment"
```

The ABAC routes need a user access token or an agent credential. A user
access token needs `abac:read` for checks and reads, and `abac:write` for
writes. Setting an attribute also needs the `abac.manage` permission.
Organization API keys are not accepted on the ABAC routes.

### Sign users in with OAuth

`client.auth` covers the OAuth 2.1 and OpenID Connect endpoints. For a
FastAPI app, the [FastAPI integration](#fastapi-integration) runs the whole
flow for you. For other frameworks, use these calls.

**1. Send the user to LumoAuth.** Build the authorization URL with a PKCE
challenge and a random `state`, and store both values in the user's session.

```python
import base64, hashlib, secrets

verifier = secrets.token_urlsafe(48)
challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
state = secrets.token_urlsafe(24)

url = client.auth.authorization_url(
    client_id="client_…",
    redirect_uri="https://app.example.com/callback",
    scope="openid profile email",
    state=state,
    code_challenge=challenge,           # code_challenge_method defaults to S256
)
```

**2. Handle the callback.** Check that `state` matches, then exchange the code
for tokens.

```python
tokens = client.auth.exchange_code(
    code,
    "https://app.example.com/callback",
    client_id="client_…",
    client_secret="…",                  # omit for a public client
    code_verifier=verifier,
)
# {"access_token": …, "refresh_token": …, "id_token": …, "scope": …, "expires_in": …}
```

**3. Use and refresh the tokens.**

```python
profile = client.auth.userinfo(access_token=tokens["access_token"])
fresh = client.auth.refresh_token(tokens["refresh_token"], client_id="client_…", client_secret="…")
client.auth.revoke(tokens["refresh_token"], token_type_hint="refresh_token", client_id="client_…")
```

`userinfo()` needs a bearer token. Pass `access_token`, or create the client
with a `token_provider`. An organization API key is not accepted there.

For machine-to-machine calls, use the client-credentials grant:

```python
tokens = client.auth.client_credentials("client_…", "secret", scopes=["read:documents"])
```

### FastAPI integration

> Requires `pip install "lumoauth[fastapi]"`.

`lumo_auth_router()` adds three routes under the prefix that you choose:
`/login`, `/callback` and `/logout`. Together they run the OAuth 2.0
authorization-code flow with PKCE.

```python
import os
from fastapi import Depends, FastAPI
from starlette.middleware.sessions import SessionMiddleware
from lumoauth.fastapi import User, get_current_user, lumo_auth_router, require_auth

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

@app.get("/")
def home(user: User | None = Depends(get_current_user)):
    return {"signed_in": user is not None}
```

How it works:

1. `/auth/login` creates a PKCE verifier and a `state` value and stores them
   in the session. Then it redirects the browser to LumoAuth.
2. LumoAuth redirects back to `callback_path`. The route checks `state`,
   exchanges the code, fetches the user's profile from `/userinfo`, and stores
   the tokens and the profile in the session.
3. `/auth/logout` deletes the LumoAuth data from the session and redirects to
   `post_logout_redirect`. It accepts GET and POST. It does not end the user's
   LumoAuth session.

The app **must** add `SessionMiddleware`. The router keeps its state in the
session under the key `__lumoauth`, never in URLs. Without the middleware,
`/auth/login` answers with HTTP 500 and the error `session_middleware_missing`.

`callback_path` must match a redirect URI that is registered on the OAuth
client. Add `?return_to=/dashboard` to the login URL to choose the page that
opens after sign-in. The router accepts only paths on the same site. For
anything else it uses `post_login_redirect`.

| Name | Purpose |
|---|---|
| `lumo_auth_router(...)` | Builds the router. See the [API reference](#lumoauthfastapi) for every argument. |
| `get_current_user` | Dependency that returns the signed-in `User`, or `None`. |
| `require_auth(scopes=None)` | Dependency that answers 401 when nobody is signed in, and 403 when the granted scopes lack one of `scopes`. |
| `User` | Pydantic model of the `/userinfo` claims: `sub`, `email`, `email_verified`, `name`, `given_name`, `family_name`, `picture`. Extra claims are kept. |
| `LumoAuthFastAPI` | Configuration container. Use it to share settings with your own dependencies. |

The router requests `openid profile email` by default. Pass the `scope`
argument to request more, for example
`scope="openid profile email authz:read"` when the app lists the user's
permissions or reads roles from `agents.me()`.

### Agents

An agent is a program, such as a program that runs tools for an LLM, that has its own identity
in LumoAuth. `LumoAuthAgent` signs the agent in with the OAuth 2.0
client-credentials grant and refreshes its token before the token expires.

#### Sign in

```python
from lumoauth import LumoAuthAgent

agent = LumoAuthAgent(client_id="agt_…", client_secret="…", org_id="acme-corp")
if not agent.authenticate():
    raise SystemExit("Agent sign-in failed")   # the reason is in the log

print(agent.access_token)   # the current bearer token
print(agent.token_scopes)   # the scopes that LumoAuth granted
```

- `authenticate(scopes=None)` returns `True` on success and `False` on
  failure. Without `scopes`, LumoAuth grants the agent's registered defaults.
- Every other method calls `ensure_authenticated()` first. That method signs
  in again when the token is missing or within 60 seconds of expiry.

#### Capabilities, budget and identity

A **capability** is something that an administrator allowed the agent to do,
such as `tool:search_web`. A **budget** limits how many tokens the agent may
use each day.

```python
info = agent.get_agent_info()      # sub, name, agent_id, capabilities, budget_policy, …

if agent.has_capability("tool:search_web"):
    ...

if agent.is_budget_exhausted():
    print("Daily token budget reached")

me = agent.get_identity()          # GET /agents/me
print(me["identity"]["id"], me["capabilities"], me["workspace"])
```

`get_agent_info()` reads the userinfo endpoint and caches the result.
`has_capability()` and `get_budget_status()` use that cache.

#### Ask before you act

The Ask API answers the question "may I do this?" for one action. Call it
before an LLM runs a tool. LumoAuth records the decision in the audit log
either way.

```python
result = agent.ask("document.read", context={"id": "doc_99"})
# {"allowed": True, "action": "document.read", "reason": …, "decided_by": …, "audit_id": …, "context": {…}}

def dispatch_tool(tool_name: str, args: dict):
    if not agent.is_allowed(tool_name, context=args):
        return {"error": f"The agent may not run {tool_name}"}
    ...  # run the tool
```

As with ABAC, the keys `ip`, `userAgent`, `requestMethod` and `requestPath`
in the context describe the real request. Values that you send under those
names are moved under `pep`.

#### Authenticated HTTP requests

`api_request()` adds the agent's bearer token to a request. It accepts a full
URL, or a path that it appends to the base URL. It returns a
`requests.Response`.

```python
resp = agent.api_request("GET", "https://api.acme.com/documents/123")
resp = agent.api_request("POST", "https://api.acme.com/search", data={"query": "Q4 revenue"})
```

#### Require a capability with a decorator

`@require_capability` raises `PermissionError` when the agent lacks the named
capability.

```python
from lumoauth import LumoAuthAgent, require_capability

class ResearchAgent(LumoAuthAgent):
    @require_capability("tool:search_web")
    def search(self, query: str) -> dict:
        return self.api_request("POST", "https://api.acme.com/search", data={"query": query}).json()
```

#### Register the agent

`register()` creates or updates the agent's record in the organization. It
identifies the agent by the client ID of this instance.

```python
agent.register(
    "Research assistant",
    description="Answers questions about finance reports",
    capabilities=["tool:search_web", "read:documents"],
    jwks_uri="https://agent.example.com/.well-known/jwks.json",   # needed for AAuth
)
```

The lower-level `client.agents.register(name, client_id=…, …)` does the same
with any credential. A user access token needs the `admin:agents:write` scope
for it.

### Human approvals

Before an action that cannot be undone, ask a person. `require_approval()`
sends a push notification to the user's phone and waits. It returns when the
user approves or denies, or when the time limit passes.

```python
from lumoauth import LumoAuthAgent, require_approval

agent = LumoAuthAgent()
agent.authenticate()

result = require_approval(
    agent,
    task_id="wire-2026-05-07-001",
    reason="Wire $4,500 to vendor INV-7741",
    on_behalf_of="ada@acme.com",
    impact="high",                       # "low", "medium" (default), "high" or "critical"
    meta={"action": "wire-transfer", "amount": 4500},
    timeout_s=90,
)

if result.status != "approved":
    raise RuntimeError(f"Not approved: {result.status} ({result.reason})")

# result.token authorizes the action that needed approval
```

The result is an `ApprovalResult` with these fields: `status`, `token`,
`task_id`, `impact`, `reason`, `responded_at` and `approved_by`. `status` is
`approved`, `denied` or `expired`. It stays `pending` when your `timeout_s`
passes before anybody answers. After an approval, `approved_by` is
`{"user_id": 42}`, with the user's numeric ID. Otherwise it is `None`.
LumoAuth does not return the user's email.

**When no push prompt is sent.** Some users have no enrolled push device.
LumoAuth then cannot ask them on their phone, so the approval cannot happen
in this call:

- When LumoAuth can email the user, it sends a plain notice and answers
  HTTP 202 with the status `email_fallback_sent`. The email has no approval
  link and no sign-in link. LumoAuth gives the same answer for a user who
  does not exist, so the answer reveals nothing about the account.
- When the email fails too, LumoAuth answers HTTP 428 with the error
  `no_enrolled_device`.

`require_approval()` and `approvals.require()` raise
`LumoAuthApprovalNotDeliveredError` in both cases. They never poll, and they
never treat the request as approved. Its `reason` field is
`"email_fallback_sent"` or `"no_enrolled_device"`. Its `task_id` field holds
the task ID when the response has one. Tell the user to check their email or
to enroll the LumoAuth app, and try again later:

```python
from lumoauth import LumoAuthApprovalNotDeliveredError

try:
    result = require_approval(agent, task_id="t-1", reason="Delete project X",
                              on_behalf_of="ada@acme.com")
except LumoAuthApprovalNotDeliveredError as err:
    if err.reason == "email_fallback_sent":
        print("No push device. We emailed the user; ask them to enroll the app.")
    else:  # "no_enrolled_device"
        print("No push device, and the email failed.")
```

Other things to know:

- LumoAuth refuses a test token from the portal with a 403 error and the code
  `test_token_not_accepted`. Use the agent's real credentials.
- `require_approval()` makes its HTTP calls through `agent.api_request()`.
  Apart from the two cases above, an HTTP failure there raises
  `requests.HTTPError`, not an SDK error.

For finer control, use the steps one at a time. These methods raise SDK
errors. On a 202 answer, `create()` does not raise. It returns the status
`email_fallback_sent` with `approval_token` set to `None`, so check the
status before you poll. On a 428 answer, `create()` raises
`LumoAuthApprovalNotDeliveredError`.

```python
created = agent.approvals.create(task_id="t-1", reason="Delete project X", on_behalf_of="ada@acme.com")
if created["status"] == "email_fallback_sent":
    ...  # no token: tell the user to check their email
status = agent.approvals.get_status(created["approval_token"])
final = agent.approvals.wait(created["approval_token"], timeout_s=120)
result = agent.approvals.require(task_id="t-2", reason="…", on_behalf_of="ada@acme.com")  # ApprovalResult
```

### Just-in-Time permissions

JIT permissions let an agent ask for exactly the access that it needs, at the
moment that it needs it. The access is short-lived. The flow has four steps:

1. Create a **task**, which groups the work.
2. Request a permission. The request uses
   [RFC 9396 authorization details](https://www.rfc-editor.org/rfc/rfc9396).
3. Exchange the approved request for a **JIT token**.
4. Complete the task. LumoAuth then revokes every JIT token of the task.

`JITContext` runs these steps. As a context manager, it completes the task
when the block ends, even after an exception.

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
```

**Request results.** `request_permission()` returns a `dict` with
`request_id`, `status` and `risk_level`. `status` is `approved`, `pending` or
`denied`. LumoAuth approves low-risk requests at once. A high-risk request
stays pending until a person approves or denies it.

**Waiting for a person.** By default `request_permission()` polls until a
person decides, or until `poll_timeout` seconds pass. On timeout it returns
the `pending` result. Pass `wait_for_approval=False` to return at once, then
poll the `status_url` in the result yourself.

```python
result = jit.request_permission(
    {"type": "database_access", "actions": ["write"], "identifier": "users_table"},
    justification="Update the email address of user 42",
    ttl=300,             # token lifetime in seconds; LumoAuth allows at most 900
    poll_interval=5,
    poll_timeout=300,
)
```

**Automatic escalation on 403.** A protected API can answer 403 with an
`Insufficient-Authorization-Details` header. That header names the permission
that is missing. `call_with_escalation()` reads the header, requests the
permission, gets a JIT token and retries the call once.

```python
with JITContext(agent) as jit:
    jit.create_task(name="Ad-hoc data access")
    resp = jit.call_with_escalation(
        "GET",
        "https://api.acme-corp.com/v1/documents/doc_9982",
        justification="User asked for a summary of doc_9982",
    )
```

When the request is not approved, `call_with_escalation()` returns the
original 403 response.

**On behalf of a user.** Call `jit.delegate_on_behalf_of(user_token)` before
`create_task()`. The later requests then act as the user, through the agent.

**Without the context manager.** Call `jit.create_task(...)`, and call
`jit.complete_task()` in a `finally` block. To close a task with a specific
outcome, call `jit.evaluate_task(result="failed", notes="…")`. The outcome is
`completed`, `failed` or `cancelled`.

**Reviewing requests.** `jit.list_pending_requests()` and
`client.jit.pending()` list the requests that are pending review by a person. They are
reviewer calls. They need a browser session or a user access token with the
`jit:approve` scope. An agent's own token cannot call them. Each item in the
list is one request, read from the `data` field of the response.

### Delegation and token exchange

Delegation lets an agent act for a user, and lets it hand work to sub-agents.
It uses [RFC 8693 token exchange](https://www.rfc-editor.org/rfc/rfc8693). The
delegated token is a JWT with an `act` claim, which records who acts for
whom.

`DelegationChain` runs the whole flow for one or more sessions:

```python
from lumoauth import LumoAuthAgent, DelegationChain

agent = LumoAuthAgent()
agent.authenticate()

chain = DelegationChain(agent, redirect_uri="https://agent.example.com/callback")

# 1. Send the user to the consent page
url = chain.get_consent_url("session_1", scopes=["read:documents", "write:documents"])

# 2. Handle the callback with the authorization code
chain.handle_consent_callback("session_1", authorization_code)

# 3. Exchange for a delegated token, and use it
token = chain.exchange("session_1", scopes=["read:documents"])
resp = chain.request("session_1", "GET", "https://api.acme.com/documents/abc")
```

Already hold a user token from another sign-in? Skip the consent step:

```python
chain.set_user_token("session_1", user_access_token)
token = chain.exchange("session_1")
```

**Audience.** Pass `resource`, the absolute https URL of the target API, to
bind the token to that API. LumoAuth puts it in the token's `aud` claim.
Without `resource`, the token is bound to the acting agent's own ID. LumoAuth
does not set `aud` from the `audience` parameter.

```python
token = chain.exchange("session_1", resource="https://api.acme.com")
```

**Nested delegation.** A chain can go from the user to an orchestrator agent
to a specialist agent. LumoAuth allows at most three levels.

```python
sub_agent = LumoAuthAgent(client_id="agt_specialist", client_secret="…")
sub_agent.authenticate()

nested = chain.delegate_to_sub_agent("session_1", sub_agent.access_token, scopes=["read:documents"])

DelegationChain.get_subject(nested)         # "user:alice"
DelegationChain.parse_actor_chain(nested)   # ["agent:orchestrator", "agent:specialist"]
```

`get_subject` and `parse_actor_chain` read the JWT without checking its
signature. Use them to inspect a token, not to trust one.

**Housekeeping.** `chain.revoke("session_1")`, `chain.revoke_all()`,
`chain.active_sessions` and `chain.has_delegation("session_1")`.

**Low-level token exchange.** `client.auth.token_exchange()` sends an RFC 8693
request directly. Declare the type of each token that you send. LumoAuth
checks the token against the declared type and answers `invalid_grant` when
they differ.

| Constant (in `lumoauth.resources.auth`) | Use it for |
|---|---|
| `ACCESS_TOKEN_TYPE` (the default) | A LumoAuth access token |
| `JWT_TOKEN_TYPE` | An `at+jwt` access token, or a JWT from an external workload |
| `ID_TOKEN_TYPE` | An OpenID Connect ID token |
| `REFRESH_TOKEN_TYPE` | A refresh token. LumoAuth refuses it as the subject when an agent acts for a user. |

```python
from lumoauth.resources.auth import ID_TOKEN_TYPE

tokens = client.auth.token_exchange(
    id_token,
    subject_token_type=ID_TOKEN_TYPE,
    actor_token=agent.access_token,
    resource="https://api.acme.com",
)
```

The subject of an exchange must still be active. LumoAuth answers
`invalid_grant` for a deactivated or blocked user, for a suspended agent, and
for a JIT token used as the subject.

### MCP tokens

An agent that calls a secured MCP server exchanges its token first:

```python
mcp_token = agent.get_mcp_token("https://mcp.example.com/mcp")   # None on failure
mcp_token = client.mcp.get_token("https://mcp.example.com/mcp", subject_token=token)  # raises on failure
```

The server ID is the MCP server's https URL. It is the server's
[RFC 8707](https://www.rfc-editor.org/rfc/rfc8707) resource identifier. Both
calls send it as the `resource` parameter, and LumoAuth sets the token's `aud`
to it. The MCP server can then check that the token was issued for it. The
calls also send the ID as `audience`, which LumoAuth ignores.

The ID must be an absolute `https` URL with no fragment. LumoAuth accepts
`http` only for localhost and private hosts. Any other value, such as
`urn:mcp:financial-data`, raises `LumoAuthValidationError` before the SDK
sends a request. `get_mcp_token()` raises this error too, and does not
return `None` for it.

The token names exactly one MCP server. Pass the Resource URI that is
registered for that server. The token works only at that MCP server, and
LumoAuth's own API rejects it. If the MCP server requires DPoP, you need a
DPoP-bound exchange. These two helpers do not make one.

#### Check a tool from an MCP server

An MCP server can ask LumoAuth whether a caller may run one tool. The
server must not forward the caller's token, because the MCP specification
(revision 2026-07-28) forbids token passthrough. The server signs in with
its own client credentials and the scope `mcp:authorize` instead. An
administrator must list the server's client as a tool authorizer of the
MCP server.

```python
from lumoauth import LumoAuth

lumo = LumoAuth(org_id="acme-corp")
cc = lumo.auth.client_credentials("mcp-server-client", "…", scopes=["mcp:authorize"])
server = LumoAuth(org_id="acme-corp", token_provider=lambda: cc["access_token"])

# claims: the verified MCP token of the caller
subject_type = "agent" if claims["sub"].startswith("agent_") else "user"
decision = server.mcp.authorize_tool(
    "mcp_0123456789abcdef01234567",   # the registered MCP server id
    subject_type,
    claims["sub"],
    "send_payment_reminder",
)
if not decision.allowed:
    ...  # refuse the tool call
```

- The first argument is the id of the MCP server in LumoAuth (`mcp_…`).
  It is not the Resource URI.
- For a user, pass the `sub` of the MCP token. For an agent, pass the
  `sub` (`agent_agt_…`) or the agent id (`agt_…`).
- The method returns `McpToolDecision(allowed, subject_type, subject_id,
  resource_type, resource_id)`. The `resource_id` has the form
  `<server id>/<tool>`.
- A deny returns `allowed=False` and does not raise. A 403 without a
  decision, such as `insufficient_scope`, raises
  `LumoAuthPermissionDeniedError`. An unknown server raises
  `LumoAuthNotFoundError`.
- A tool name or server id that is empty, or that contains `/`, `:`, `#`
  or `*`, raises `LumoAuthValidationError`. So does a tool name longer
  than 80 characters. The SDK sends no request in that case.

The token from `client_credentials()` expires. Request a new one before
it does, or wrap the call in your own token cache.

#### Check a tool as an agent

An agent can ask the same question about itself, with its own credential:

```python
decision = agent.authorize_mcp_tool("mcp_0123456789abcdef01234567", "send_payment_reminder")
if decision.allowed:
    ...  # call the tool
```

The method returns `AgentMcpToolDecision(allowed, agent_id, resource_type,
resource_id)`. A deny returns `allowed=False` and does not raise. The
server id must name an active MCP server. Otherwise the call raises
`LumoAuthNotFoundError` (`unknown_server`). `client.agents.authorize_mcp_tool()`
does the same on a `LumoAuth` client that holds an agent token or an
`agk_` key.

### AAuth cryptographic identity

AAuth extends OAuth 2.1 with a cryptographic identity for the agent. The agent
holds an Ed25519 private key and signs each HTTP request with
[RFC 9421 HTTP message signatures](https://www.rfc-editor.org/rfc/rfc9421).
The tokens that it receives are bound to that key, so a stolen token is
useless without the key.

> Requires `pip install "lumoauth[aauth]"`.

**1. Create a key pair once.** Store the private key securely. Publish the
JWKS at `https://<agent>/.well-known/jwks.json` and register it with the
agent (see [Register the agent](#register-the-agent)).

```python
from lumoauth import AAuthClient

private_pem, jwks = AAuthClient.generate_keypair()   # the JWKS key ID is "key-1"
```

**2. Create a client and request tokens.** You need a resource token from the
target resource, and an agent token.

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
    # Send the user to result["auth_url"]. When they return, redeem the code.
    # redirect_uri must match the URI that received the code.
    tokens = client.exchange_code(code, "https://my-agent.example.com/callback", agent_token=agent_tok)
else:
    tokens = result    # pre-approved: the tokens came back directly
```

**3. Call the protected resource.** `signed_request()` sends the token as a
Bearer token and adds the signature headers.

```python
resp = client.signed_request(
    "POST",
    "https://api.example.com/v1/actions",
    auth_token=tokens["auth_token"],
    data={"action": "analyse", "target": "report_q4"},
)
```

**4. Refresh.** A refresh needs a fresh resource token for the target
resource. LumoAuth does not rotate the refresh token.

```python
new_tokens = client.refresh(tokens["refresh_token"], fresh_resource_tok, agent_token=agent_tok)
```

**Discovery.** `client.discover_issuer()` and
`client.discover_resource("https://api.example.com")` fetch the `.well-known`
metadata documents.

The Python SDK signs AAuth requests and obtains tokens. It does not verify
AAuth tokens on the resource side. It also does not wrap the consent route,
the agent metadata document, the issuer JWKS or token revocation.

### The generated API client

The namespaces above cover the common calls. For any other route, `client.api`
returns the generated OpenAPI client. It uses the same base URL and
credentials. With a `token_provider`, it asks for the token on each request,
so refreshed agent tokens keep working.

```bash
pip install "lumoauth[api]"
```

```python
client = LumoAuth(api_key="lmk_…", org_id="acme-corp")
client.api   # a configured lumoauth_api_client.ApiClient
```

Without the extra, `client.api` raises `LumoAuthConfigError`.

## Errors

Every failure raises a subclass of `LumoAuthError`. Catch the class that you
care about.

```
LumoAuthError                        .message, .code
├── LumoAuthApiError                 any non-2xx response: .status_code, .body
│   ├── LumoAuthAuthenticationError  401: the credential is missing, invalid or expired
│   ├── LumoAuthPermissionDeniedError 403: not allowed; .required_scopes
│   ├── LumoAuthNotFoundError        404: the resource does not exist
│   └── LumoAuthRateLimitError       429: too many requests; .retry_after (seconds)
├── LumoAuthValidationError          bad input, or a response of the wrong shape; .issues
├── LumoAuthConfigError              missing or invalid configuration
├── LumoAuthNetworkError             no HTTP response (DNS, TLS, timeout)
├── LumoAuthApprovalDeniedError      a person denied an approval
├── LumoAuthApprovalTimeoutError     nobody answered an approval in time
├── LumoAuthApprovalNotDeliveredError no push prompt was sent; .reason, .task_id
└── LumoAuthBudgetExceededError      the agent's budget is used up
```

- `code` is the `code` or `error` field of the response body when it has one.
  Otherwise it is the class default, such as `PERMISSION_DENIED`.
- `message` comes from `error_description`, `message`, `detail` or `error`.
- `body` is the decoded response body.

```python
import time
from lumoauth import LumoAuthPermissionDeniedError, LumoAuthRateLimitError

try:
    client.permissions.list()
except LumoAuthRateLimitError as err:
    time.sleep(err.retry_after or 1)
except LumoAuthPermissionDeniedError as err:
    if err.required_scopes:
        print("Sign the user in again with these scopes:", err.required_scopes)
    else:
        print("Not allowed:", err.message)
```

**Missing scopes.** When a route needs a scope that the token lacks, LumoAuth
answers with HTTP 403 and this body:

```json
{"error": "forbidden", "message": "Insufficient scope: …", "status": 403,
 "details": {"required_scopes": ["authz:read"], "granted_scopes": ["…"]}}
```

The SDK raises `LumoAuthPermissionDeniedError`. Its `required_scopes` is
`["authz:read"]` and its `code` is `forbidden`. For any other 403,
`required_scopes` is an empty list.

**Compatibility with older code.** Earlier releases raised built-in
exceptions. To keep old `except` clauses working:

- `LumoAuthApiError` is also a `RuntimeError`.
- `LumoAuthConfigError` and `LumoAuthValidationError` are also a `ValueError`.
- `LumoAuthNetworkError` is also a `ConnectionError`.

## API reference

### `LumoAuth`

```python
LumoAuth(*, api_key=None, base_url=None, org_id=None, token_provider=None,
         timeout=30, skip_cert_validation=False)
```

#### `client.auth`

| Method | What it does | Credential |
|---|---|---|
| `authorization_url(*, client_id, redirect_uri, scope="openid profile email", state=None, response_type="code", code_challenge=None, code_challenge_method=None, prompt=None, access_type=None, extra=None)` | Builds the URL for the authorization-code flow | none (no request) |
| `exchange_code(code, redirect_uri, *, client_id, client_secret=None, code_verifier=None)` | Exchanges an authorization code for tokens | form body |
| `refresh_token(refresh_token, *, client_id, client_secret=None, scopes=None)` | Refreshes an access token | form body |
| `client_credentials(client_id, client_secret, scopes=None)` | Client-credentials grant | form body |
| `token_exchange(subject_token, *, actor_token=None, audience=None, scopes=None, subject_token_type=ACCESS_TOKEN_TYPE, actor_token_type=ACCESS_TOKEN_TYPE, resource=None)` | RFC 8693 token exchange; `resource` becomes `aud` | form body |
| `revoke(token, *, token_type_hint=None, client_id=None, client_secret=None)` | Revokes an access or refresh token | form body |
| `userinfo(access_token=None)` | OpenID Connect UserInfo | bearer token |

#### `client.permissions`

| Method | What it does | User token scope |
|---|---|---|
| `check(permission, context=None, *, user_id=None, agent_id=None)` | `True` when the principal holds the permission | none |
| `check_detailed(permission, context=None, *, user_id=None, agent_id=None)` | The full decision `dict` | none |
| `check_bulk(permissions, context=None, *, user_id=None, agent_id=None)` | `results` maps each slug to a `bool` | none |
| `check_any(...)`, `check_any_detailed(...)` | At least one permission is held | none |
| `check_all(...)`, `check_all_detailed(...)` | Every permission is held | none |
| `list()` | Every permission that the caller holds | `authz:read` |
| `list_slugs()` | The same, as a `set` of slugs | `authz:read` |

`user_id` (a LumoAuth user UUID) or `agent_id` asks about another subject and
needs `authz:check`. Passing both raises `LumoAuthValidationError`.

#### `client.zanzibar`

| Method | What it does |
|---|---|
| `check(object, relation, subject)` | `True` when the relation exists |
| `check_detailed(object, relation, subject)` | The full decision `dict` |
| `expand(object, relation)` | The tree of subjects that have the relation; needs `authz:check` |
| `is_viewer`, `is_editor`, `is_owner`, `is_member`, `is_admin` `(object, subject)` | `check` with a fixed relation |

#### `client.abac`

| Method | What it does | User token scope |
|---|---|---|
| `check(resource_type, action, resource_id=None, context=None)` | The decision `dict` | `abac:read` |
| `is_allowed(...)` | The decision as a `bool` | `abac:read` |
| `check_bulk(requests, environment=None)` | Up to 100 checks in one request, with one shared environment | `abac:read` |
| `get_my_attributes()` | The caller's attributes | `abac:read` |
| `get_resource_attributes(resource_type, resource_id)` | A resource's attributes | `abac:read` |
| `get_attribute_definitions(type=None)` | Attribute definitions, filtered by `user`, `resource` or `environment` | `abac:read` |
| `set_user_attribute(user_id, attribute_slug, value)` | Sets a user attribute | `abac:write` |
| `set_resource_attribute(resource_type, resource_id, attribute_slug, value)` | Sets a resource attribute | `abac:write` |

#### `client.agents`

| Method | What it does |
|---|---|
| `ask(action, context=None)` | Ask API decision `dict` |
| `is_allowed(action, context=None)` | The decision as a `bool` |
| `me()` (alias `get_current()`) | `identity`, `capabilities` and `workspace` |
| `authorize_mcp_tool(server_id, tool)` | Asks whether the calling agent may run a tool on a registered MCP server; returns `AgentMcpToolDecision`, with `allowed=False` for a deny |
| `register(name, *, client_id, description=None, capabilities=None, jwks_uri=None)` | Creates or updates an agent record; a user token needs `admin:agents:write` |
| `info()` | The userinfo claims of the agent |
| `capabilities()` | The agent's capability slugs |
| `budget()` | The agent's budget policy (`{}` when none) |

#### `client.approvals`

| Method | What it does |
|---|---|
| `create(*, task_id, reason, on_behalf_of, impact="medium", meta=None)` | Creates a request; the result contains `approval_token`, or the status `email_fallback_sent` and no token |
| `get_status(token)` | The current status `dict` |
| `wait(token, *, poll_interval_s=1.5, timeout_s=90.0)` | Polls until the status is no longer `pending` |
| `require(*, task_id, reason, on_behalf_of, impact="medium", meta=None, poll_interval_s=1.5, timeout_s=90.0)` | `create` and `wait` together; returns `ApprovalResult`, or raises `LumoAuthApprovalNotDeliveredError` |

#### `client.jit`

| Method | What it does |
|---|---|
| `create_task(*, name=None, task_type=None, on_behalf_of=None)` | Creates a task |
| `complete_task(task_id)` | Completes a task and revokes its JIT tokens |
| `evaluate_task(task_id, *, result="completed", notes=None)` | Closes a task with an outcome |
| `request(task_id, authorization_details, *, justification=None, ttl=300)` | Requests a permission; `ttl` is capped at 900 |
| `get_status(request_id)` | The status of a request |
| `get_token(request_id)` | The token response for an approved request |
| `pending()` | Requests that are pending review; a user token with `jit:approve` |

#### `client.delegation`

| Method | What it does |
|---|---|
| `consent_url(*, client_id, redirect_uri, scopes=None, state=None)` | Consent URL with `prompt=consent` and `access_type=offline` |
| `exchange_code(code, redirect_uri, *, client_id, client_secret=None)` | Redeems the consent code |
| `refresh_user_token(refresh_token, *, client_id, client_secret=None)` | Refreshes the user's token |
| `exchange(subject_token, actor_token, scopes=None, *, resource=None)` | Creates a delegated token |
| `revoke(token, *, token_type_hint="refresh_token", client_id=None, client_secret=None)` | Revokes a delegation |
| `parse_actor_chain(token)`, `get_subject(token)` *(static)* | Read the `act` chain and `sub` of a JWT |

#### `client.mcp` and `client.api`

| Member | What it does |
|---|---|
| `mcp.get_token(server_id, *, subject_token=None)` | Token exchange for an MCP server, with `server_id` (its https URL) as `resource`; returns the token string |
| `mcp.authorize_tool(server_id, subject_type, subject_id, tool)` | Per-tool check for an MCP server, made with the server's own `mcp:authorize` token; returns `McpToolDecision`, with `allowed=False` for a deny |
| `api` | The generated OpenAPI client; needs `lumoauth[api]` |

### `LumoAuthAgent`

```python
LumoAuthAgent(base_url=None, org_id=None, client_id=None, client_secret=None,
              skip_cert_validation=False)
```

| Member | What it does |
|---|---|
| `authenticate(scopes=None)` | Client-credentials sign-in; returns `True` or `False` |
| `ensure_authenticated()` | Signs in again when the token is missing or about to expire |
| `access_token`, `token_scopes`, `agent_info` | Current token, granted scopes and cached userinfo |
| `get_agent_info()` | Identity, capabilities and budget from userinfo |
| `has_capability(capability)` | `True` when the agent has the capability |
| `get_budget_status()`, `is_budget_exhausted()` | Budget policy, and whether today's budget is used up |
| `ask(action, context=None)`, `is_allowed(...)` | Ask API |
| `get_identity()` | `GET /agents/me` |
| `authorize_mcp_tool(server_id, tool)` | Asks whether this agent may run a tool on a registered MCP server; returns `AgentMcpToolDecision` |
| `api_request(method, endpoint, *, data=None, json=None, params=None, timeout=30)` | Authenticated request; returns `requests.Response` |
| `register(name, description=None, capabilities=None, jwks_uri=None)` | Creates or updates the agent record |
| `get_mcp_token(mcp_server_id)` | MCP token bound to the server's https URL, or `None` when the exchange fails |
| `jit`, `delegation`, `mcp`, `approvals` | The same namespaces as on `LumoAuth`, with the agent's token |

### `JITContext`

```python
JITContext(agent, *, delegated_token=None)
```

| Method | What it does |
|---|---|
| `delegate_on_behalf_of(user_token)` | Exchanges the user's token so that later calls act for the user |
| `create_task(*, name=None, task_type=None, on_behalf_of=None)` | Creates the task; returns its ID |
| `request_permission(authorization_details, *, justification=None, ttl=300, wait_for_approval=True, poll_interval=5, poll_timeout=300)` | Requests a permission and, by default, waits for review |
| `get_token(request_id)` | Returns the JIT token string |
| `call(jit_token, method, url, *, data=None, timeout=30)` | Calls an API with a JIT token |
| `call_with_escalation(method, url, *, justification=…, data=None, timeout=30)` | Requests a missing permission on 403 and retries once |
| `evaluate_task(task_id=None, *, result="completed", notes=None)` | Closes a task with an outcome |
| `complete_task()` | Completes the task and revokes its JIT tokens |
| `list_pending_requests()` | Reviewer call; needs `jit:approve` |

### `DelegationChain`

```python
DelegationChain(agent, *, redirect_uri=None)
```

| Member | What it does |
|---|---|
| `get_consent_url(session_id, scopes=None, state=None)` | Builds the consent URL |
| `handle_consent_callback(session_id, authorization_code)` | Redeems the authorization code |
| `set_user_token(session_id, access_token)` | Uses a user token that you already hold |
| `exchange(session_id, scopes=None, *, resource=None)` | Returns a delegated token |
| `request(session_id, method, endpoint, *, data=None, params=None, timeout=30)` | Request with the delegated token |
| `delegate_to_sub_agent(session_id, sub_agent_token, scopes=None, *, resource=None)` | Nested delegation |
| `revoke(session_id)`, `revoke_all()` | Revokes delegations |
| `active_sessions`, `has_delegation(session_id)` | Session state |
| `parse_actor_chain(token)`, `get_subject(token)` *(static)* | Inspect a delegated JWT |

### `AAuthClient`

```python
AAuthClient(agent_identifier, private_key_pem, *, base_url=None, org_id=None,
            kid="key-1", skip_cert_validation=False)
```

| Method | What it does |
|---|---|
| `generate_keypair()` *(static)* | Returns `(private_pem, jwks)` for a new Ed25519 key |
| `sign_request(method, url, *, body=None, content_type="application/json", agent_token=None, authorization="", signature_key="")` | Returns RFC 9421 signature headers |
| `request_authorization(resource_token, scope, *, agent_token=None, redirect_uri=None, timeout=30)` | Tokens, or `{"authorization_required": True, "auth_url": …, "request_token": …}` |
| `exchange_code(code, redirect_uri, *, agent_token, timeout=30)` | Redeems a consent code |
| `refresh(refresh_token, resource_token, *, scope=None, agent_token, timeout=30)` | Refreshes with a fresh resource token |
| `signed_request(method, url, *, auth_token, data=None, timeout=30)` | Signed request with a Bearer token |
| `discover_issuer()`, `discover_resource(resource_url)` | Fetch `.well-known` metadata |

`request_authorization()` raises `LumoAuthValidationError` without an
`agent_token`.

### Helpers

| Name | What it does |
|---|---|
| `require_capability(capability)` | Decorator for `LumoAuthAgent` methods; raises `PermissionError` when the capability is missing |
| `require_approval(agent, *, task_id, reason, on_behalf_of, impact="medium", meta=None, poll_interval_s=1.5, timeout_s=90)` | Sends a push approval and polls until it is answered; returns `ApprovalResult` |
| `ApprovalResult` | Frozen dataclass: `status`, `token`, `task_id`, `impact`, `reason`, `responded_at`, `approved_by` (`{"user_id": …}` or `None`) |

### `lumoauth.fastapi`

| Name | What it does |
|---|---|
| `lumo_auth_router(*, base_url, organization, client_id, client_secret=None, callback_path="/auth/callback", scope="openid profile email", post_login_redirect="/", post_logout_redirect="/")` | Router with `/login`, `/callback` and `/logout` |
| `get_current_user(request)` | Dependency that returns `User` or `None` |
| `require_auth(scopes=None)` | Dependency factory that answers 401 or 403 |
| `User` | Pydantic model of the signed-in user |
| `LumoAuthFastAPI` | Configuration container |

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| 401 from an ABAC, agent, JIT or approvals call made with an API key | Organization API keys work only for permission checks, Zanzibar and the admin API | Use a user access token or an agent credential |
| 401 or 400 from `auth.userinfo()` or `agents.info()` | The client sends an API key, and userinfo needs a bearer token | Pass `access_token=…`, or use `LumoAuthAgent` |
| `LumoAuthPermissionDeniedError` from `permissions.list()`, with `required_scopes == ["authz:read"]` | The token lacks `authz:read`, or the client uses an API key | Request `authz:read` at sign-in; API keys cannot hold it |
| 403 from ABAC with `required_scopes` set | The user token lacks `abac:read` or `abac:write` | Add the scope to the client and request it |
| `agents.me()` returns an empty `capabilities` list | A user token without `authz:read` | Request `authz:read`, or call with an agent credential |
| 403 `INSUFFICIENT_PERMISSIONS` from `zanzibar.expand()` or from a check with `user_id` / `agent_id` | The caller lacks `authz:check` | Grant the `authz:check` scope or the `authz.check` permission |
| 404 `SUBJECT_NOT_FOUND` from a check with `user_id` | The ID is not a LumoAuth user UUID in your organization, for example an email or your app's own user ID | Pass the user's LumoAuth ID (the `sub` claim) |
| `invalid_grant` from a token exchange | The declared token type does not match the token. Or the subject is no longer active. Or the subject is a JIT token. | Declare the right type; use an active user's or agent's token |
| 400 `invalid_request` when an agent exchanges a refresh token for a user | A refresh token cannot be the subject of an on-behalf-of exchange | Exchange the user's access token or ID token |
| 403 `test_token_not_accepted` from approvals | The agent uses a portal test token | Use the agent's real credentials |
| `require_approval()` returns status `pending` | `timeout_s` passed before anybody answered | Raise `timeout_s`, or poll later with `approvals.get_status()` |
| `LumoAuthRateLimitError` (429) | Too many requests | Wait `err.retry_after` seconds, then retry |
| `LumoAuthConfigError: org_id is required` | The call is org-scoped and no slug is set | Pass `org_id` or set `LUMOAUTH_ORG_ID` |
| `authenticate()` returns `False` | Wrong client ID or secret, or the agent is suspended | Check the credentials; the log contains the HTTP status |
| FastAPI `/auth/login` answers 500 `session_middleware_missing` | `SessionMiddleware` is not added | Add `SessionMiddleware` before the router |

## Versioning and compatibility

| Item | Value |
|---|---|
| SDK version | 1.0.0 |
| Minimum LumoAuth server API | 1.0.0 |
| Python | 3.9 to 3.13 |

The SDK follows semantic versioning. Its routes come from the shared SDK
contract, and a test fails when they drift from the server's API.

## Development

Run the tests from the repository root:

```bash
pip install -e ".[aauth,dev]"
pytest
```

Without a local Python environment, run them in Docker:

```bash
docker run --rm -v "$PWD":/src -w /src python:3.12 \
  sh -c 'pip install -q requests pytest cryptography && PYTHONPATH=src python -m pytest -q'
```

The contract tests read `../sdk-contract`, or the path in `LUMO_SDK_CONTRACT`.
They are skipped when neither exists.

## Changelog

### Unreleased

- New `mcp.authorize_tool()` lets an MCP server ask whether a verified
  user or agent may run one tool. The server calls it with its own
  client-credentials token (scope `mcp:authorize`), not with the caller's
  token. New `agents.authorize_mcp_tool()` and
  `LumoAuthAgent.authorize_mcp_tool()` let an agent ask about itself. On
  both, a deny returns `allowed=False` and does not raise.
- `LumoAuthPermissionDeniedError.required_scopes` lists the scopes that
  LumoAuth names when it refuses a request for a missing scope.
- Fix: permission checks with `user_id` now send the user as
  `subject: {"type": "user", "id": …}`. Earlier releases sent a top-level
  `user_id`, which LumoAuth ignores, so those checks answered for the caller
  instead of the named user.
- New `agent_id` argument on the permission checks asks about an agent.
- Fix: `abac.check()` now sends `context` as `environment`, which is the
  field that LumoAuth evaluates. Earlier releases sent `context`, which the
  server ignores.
- Fix: approvals without a push prompt. LumoAuth answers HTTP 202 with the
  status `email_fallback_sent` when the user has no enrolled device, and 428
  `no_enrolled_device` when the email notice fails too. `approvals.create()`
  now returns the 202 status with `approval_token` set to `None`. It raises
  the new `LumoAuthApprovalNotDeliveredError` on 428. `approvals.require()`
  and `require_approval()` raise this error in both cases, with `reason` and
  `task_id`. Earlier releases failed on the missing token, or raised a
  generic error.
- Fix: MCP tokens are now bound to the MCP server. `mcp.get_token()` and
  `get_mcp_token()` send the server ID as the RFC 8707 `resource`, which
  LumoAuth uses for the token's `aud`. Earlier releases sent only `audience`,
  which LumoAuth ignores. The server ID must now be the server's https URL;
  any other value, such as a `urn:mcp:` ID, raises `LumoAuthValidationError`.
- Fix: `jit.pending()` and `JITContext.list_pending_requests()` now read the
  `data` list of the response. Earlier releases read a `requests` field that
  LumoAuth does not send, so they always returned an empty list.
- Fix: `abac.check_bulk()` now sends `checks`, plus one shared `environment`.
  Earlier releases sent `requests`, which LumoAuth rejects with 400. The new
  `environment` argument sets the shared environment. Items with different
  contexts raise `LumoAuthValidationError`.

### 1.0.0

- New `LumoAuth` client with resource namespaces (`auth`, `permissions`,
  `zanzibar`, `abac`, `agents`, `delegation`, `jit`, `approvals`, `mcp`) and
  a lazy `client.api` property for the generated OpenAPI client
  (`pip install "lumoauth[api]"`).
- Typed error classes (`LumoAuthError`, `LumoAuthApiError`,
  `LumoAuthAuthenticationError` and others) replace bare `ValueError` and
  `RuntimeError`. The new classes subclass the built-ins that they replace,
  so existing `except` clauses keep working.
- All endpoint paths are in `lumoauth._routes.ROUTES`, with a test that
  compares them with the OpenAPI spec.
- `LumoAuthAgent` moved to `lumoauth.agent`. Imports from `lumoauth.client`
  or `lumoauth` still work. It is now a thin layer over `LumoAuth`, and every
  method keeps its name, signature and behavior.
- `DelegationChain` and `JITContext` keep their methods but use the shared
  resources internally.

### 0.2.0

**Breaking fixes.** The AAuth client now matches the AAuth 1.0 server
contract for the agent token endpoint:

- `AAuthClient.exchange_code(code, redirect_uri, *, agent_token)`: the second
  parameter is now `redirect_uri` (previously `request_token`). The code is
  bound to the exact redirect URI that received it.
- `AAuthClient.refresh(refresh_token, resource_token, *, scope=None,
  agent_token)`: a fresh `resource_token` for the target resource is now a
  required second positional parameter, and `scope` became keyword-only.

## License

Apache-2.0

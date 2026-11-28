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
  - [Use a custom domain](#use-a-custom-domain)
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
  - [Private key JWT: sign in without a secret](#private-key-jwt-sign-in-without-a-secret)
  - [Workload attestation: sign in with the platform's token](#workload-attestation-sign-in-with-the-platforms-token)
  - [DPoP-bound tokens](#dpop-bound-tokens)
  - [Verify a LumoAuth token in your MCP server](#verify-a-lumoauth-token-in-your-mcp-server)
  - [Verify a JIT token in your API](#verify-a-jit-token-in-your-api)
  - [Verify requests from personal agents](#verify-requests-from-personal-agents)
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
| `dpop` | `pip install "lumoauth[dpop]"` | DPoP proofs (RFC 9449) for sender-constrained tokens (`cryptography` 41 or later) |
| `verify` | `pip install "lumoauth[verify]"` | Local verification of LumoAuth access tokens in your MCP or API server (`cryptography` 41 or later) |
| `fastapi` | `pip install "lumoauth[fastapi]"` | Login, callback and logout routes for FastAPI 0.110 or later, and the dependencies for resource servers and for requests from personal agents |
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

if agent.is_allowed("document:read", context={"id": "doc_99"}):
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
| An **API that personal agents call** | `client.poppy`, `LumoAuthPoppy` | [Verify requests from personal agents](#verify-requests-from-personal-agents) |

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

An organization that serves LumoAuth on its own domain needs neither value.
See the next section.

### Use a custom domain

An organization can serve LumoAuth on its own domain, for example
`https://auth.acme.com`. Pass the domain as `custom_domain`, or set
`LUMOAUTH_CUSTOM_DOMAIN`.

```python
from lumoauth import LumoAuth

client = LumoAuth(custom_domain="auth.acme.com", api_key="lmk_…")

if client.permissions.check("document.edit"):   # POST https://auth.acme.com/api/v1/authz/check
    print("Allowed")

print(client.issuer)                            # https://auth.acme.com
```

- **The organization ID is not needed.** When you pass `org_id` too, the SDK
  never puts it in a path.
- **Paths have no `/orgs/...` segment.** The token endpoint is
  `/orgs/acme-corp/api/v1/oauth/token` on the platform host and
  `/api/v1/oauth/token` on the domain. A route without that segment, such as
  `/api/v1/authz/check`, keeps its path.
- **The issuer is the bare domain**, `https://auth.acme.com`.
  `client.issuer` returns it. OAuth and OpenID Connect tokens that LumoAuth
  issues through the domain name it in `iss`, and a client assertion names
  it in `aud`. AAuth is the one exception: see below.
- **The custom domain wins over `base_url`.** The SDK sends no request to
  the base URL.
- The value is a host name or an `https://` origin. `http://` is accepted
  only for `localhost`, `127.0.0.1` and `[::1]`. A value with a path, a
  query, a fragment or credentials raises `LumoAuthConfigError` when you
  create the client.

Every entry point takes the option:

| Entry point | With `custom_domain` |
|---|---|
| `LumoAuth`, and each namespace below it (`client.poppy` too) | Every call goes to the domain |
| `LumoAuthAgent` | Sign-in, the Ask API, MCP token exchange and `api_request()` use the domain. `JITContext`, `DelegationChain` and `require_approval()` follow their agent. |
| `AAuthClient` | The token endpoint and the issuer metadata are on the domain, and the request signature covers that URL. The AAuth issuer stays the platform address. |
| `verify_access_token()`, `AccessTokenVerifier` | The token must name the domain as its issuer. Leave `issuer` out. |
| `lumoauth.fastapi`: `lumo_auth_router()`, `require_access_token()` | Sign-in, token and userinfo addresses are on the domain. `LumoAuthPoppy` follows its client. |

`LumoAuth`, `LumoAuthAgent` and `AAuthClient` read `LUMOAUTH_CUSTOM_DOMAIN`.
The verification functions and the FastAPI helpers take the argument only.

```python
from lumoauth import LumoAuthAgent, verify_access_token

agent = LumoAuthAgent(custom_domain="auth.acme.com")   # reads AGENT_CLIENT_ID and AGENT_CLIENT_SECRET
agent.authenticate()                                   # POST https://auth.acme.com/api/v1/oauth/token


def verify(token: str):
    """In your MCP or API server: verify a token that the domain issued."""
    return verify_access_token(token, custom_domain="auth.acme.com",
                               resource="https://mcp.acme.com/mcp")
```

Local verification with a custom domain accepts exactly one issuer, the
domain. A token that names the platform issuer
(`https://app.lumoauth.dev/orgs/acme-corp/api/v1`) is refused with
`TOKEN_WRONG_ISSUER`.

**AAuth keeps the platform issuer.** LumoAuth names the AAuth issuer with
the platform address on every host:
`https://app.lumoauth.dev/orgs/acme-corp/api/v1`. On a custom domain
`AAuthClient` sends its requests to the domain, but AAuth tokens still name
the platform address in `iss`, and the agent still addresses it as the
audience. `AAuthClient.get_issuer()` returns that issuer:

```python
from lumoauth import AAuthClient

aauth = AAuthClient(
    agent_identifier="https://my-agent.example.com",
    private_key_pem=open("agent-key.pem").read(),
    custom_domain="auth.acme.com",
)
print(aauth.get_issuer())   # https://app.lumoauth.dev/orgs/acme-corp/api/v1
```

With a custom domain, `get_issuer()` reads the `issuer` member of the issuer
metadata document at `https://auth.acme.com/api/v1/.well-known/aauth-issuer`
and keeps the value. The SDK never builds the AAuth issuer from the domain.
Pass `issuer=` to `AAuthClient` to set it yourself.

A raw request takes a path: `agent.api_request()` and
`DelegationChain.request()`. On a custom domain, give the path without the
`/orgs/...` segment. A path that carries the segment of the client's own
organization still works when `org_id` is set, because the SDK removes that
segment. The SDK leaves every other path unchanged.

The generated client (`client.api`) also sends its requests to the domain,
without the segment. Its methods still take an `org_id` argument. Pass any
value: the SDK does not send it.

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

The Personal Agent Protocol calls (`client.poppy`) authenticate with HTTP
Basic: the `client_id` and `client_secret` of a confidential application.
They never send the client's API key or token either. See
[Verify requests from personal agents](#verify-requests-from-personal-agents).

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
| `LUMOAUTH_ORG_ID` | all clients | Organization slug | none; needed by org-scoped calls, unless a custom domain is set |
| `LUMOAUTH_CUSTOM_DOMAIN` | all clients | The organization's own domain, such as `auth.acme.com`. It wins over `LUMOAUTH_URL`. See [Use a custom domain](#use-a-custom-domain). | none |
| `LUMOAUTH_API_KEY` | `LumoAuth` | Organization API key, sent as `X-API-Key` | none |
| `AGENT_CLIENT_ID` | `LumoAuthAgent` | The agent's OAuth client ID | none; required |
| `AGENT_CLIENT_SECRET` | `LumoAuthAgent` | The agent's OAuth client secret | none; required |
| `LUMOAUTH_CLIENT_ID` | `LumoAuth` | Client ID of a confidential application, for the `client.poppy` calls | none; needed by `client.poppy` |
| `LUMOAUTH_CLIENT_SECRET` | `LumoAuth` | The secret of that application | none; needed by `client.poppy` |

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
| `org_id` | `str` | `LUMOAUTH_ORG_ID` | Organization slug. Not needed with `custom_domain`. |
| `custom_domain` | `str` | `LUMOAUTH_CUSTOM_DOMAIN` | The organization's own domain, as a host name or an `https://` origin. It wins over `base_url`. |
| `token_provider` | `Callable[[], str \| None]` | none | Returns a bearer token for each request; wins over `api_key` |
| `timeout` | `float` | `30` | Request timeout in seconds |
| `skip_cert_validation` | `bool` | `False` | Turns off the checks of TLS certificates. Use it for local development only. |
| `client_id` | `str` | `LUMOAUTH_CLIENT_ID` | Client ID of a confidential application. Only the `client.poppy` calls use it. |
| `client_secret` | `str` | `LUMOAUTH_CLIENT_SECRET` | The secret of that application. Its allowed scopes must include `poppy:verify`. |

`LumoAuthAgent` takes `base_url`, `org_id`, `custom_domain`, `client_id`,
`client_secret` and `skip_cert_validation`. It raises `LumoAuthConfigError` when it cannot find a
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
tokens = client.auth.client_credentials("client_…", "secret", scopes=["documents:read"])
```

Add `resource` to get a token for one API. Its `aud` is then that address,
not the client ID:

```python
tokens = client.auth.client_credentials(
    "client_…", "secret", scopes=["documents:read"], resource="https://api.example.com"
)
```

When the application lists audience URIs, the address must be one of them or
start with one. LumoAuth refuses any other address with `invalid_target`.

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
3. `/auth/logout` deletes the LumoAuth data from the session and revokes the
   refresh token. Then it sends the browser to LumoAuth's end-session
   endpoint with the ID token as `id_token_hint`. LumoAuth ends the user's
   session there and redirects to `post_logout_redirect`. The route accepts
   GET and POST.

The app **must** add `SessionMiddleware`. The router keeps its state in the
session under the key `__lumoauth`, never in URLs. Without the middleware,
`/auth/login` answers with HTTP 500 and the error `session_middleware_missing`.

**Sign-out.** LumoAuth redirects back only to a registered address. Add the
absolute form of `post_logout_redirect` to the application's
**Post-logout redirect URIs** (in the portal: **Applications**, your
application, **Configuration**, **Logout**). A relative value such as the
default `/` is made absolute with the address of the request, so with the app
on `http://localhost:8000` you register `http://localhost:8000/`. When the
address is not registered, the user stays on LumoAuth's signed-out page. Keep
`openid` in `scope`: without an ID token LumoAuth asks the user to confirm the
sign-out. To clear only the local session and leave the LumoAuth session open,
pass `end_session_on_logout=False`. The next sign-in then completes without
the sign-in page.

For your own sign-out route, `client.auth.end_session_url(id_token_hint=…,
post_logout_redirect_uri=…, state=…)` builds the same address.

**Call an API with the user's access token.** Create the configuration
yourself, so that the router and the `access_token` dependency share it:

```python
from lumoauth.fastapi import LumoAuthFastAPI

lumo = LumoAuthFastAPI(
    base_url="https://app.lumoauth.dev",
    organization="acme-corp",
    client_id=os.environ["LUMOAUTH_CLIENT_ID"],
    client_secret=os.environ["LUMOAUTH_CLIENT_SECRET"],
)
app.include_router(lumo.router(), prefix="/auth")

@app.get("/api/documents")
def documents(token: str = Depends(lumo.access_token)):
    ...  # send "Authorization: Bearer {token}" to your API
```

`lumo.access_token` returns the access token of the session. When the token
expires in less than 60 seconds, the dependency first gets a new one with the
refresh token and stores it in the session. It answers 401 when nobody is
signed in, and when the token has expired and cannot be refreshed. The
LumoAuth data of the session is then deleted, so the user signs in again. It
answers 503 when LumoAuth cannot be reached, and keeps the session. The
router never refreshes a token by itself: `get_current_user` and
`require_auth` read only the session.

**What the session holds.** After sign-in the session holds the profile from
`/userinfo` and these token values: the access token and its expiry time, the
refresh token, the granted scopes, and the ID token for the sign-out (not kept
with `end_session_on_logout=False`). Know these limits of Starlette's
`SessionMiddleware`:

- It keeps the session in a cookie that is signed but not encrypted. Anybody
  who gets the cookie can read the tokens. Pass `https_only=True` outside
  local development, so that the browser sends the cookie over HTTPS only.
- A browser keeps no cookie larger than 4096 bytes and gives no error. With
  the default scopes the cookie is about 3.2 KB. More scopes and more claims
  make the tokens larger. When the cookie passes the limit, the router logs a
  warning on the `lumoauth.fastapi` logger, and the sign-in does not stick.
  Then request fewer scopes, or use a session middleware that keeps the data
  on the server.
- LumoAuth replaces the refresh token at each refresh, and a used refresh
  token is refused. A second use also revokes every token of that sign-in. The
  dependency makes one refresh per refresh token in each process, and requests
  that arrive with the old cookie shortly after get the same new token. When
  the app runs in several processes, two requests at the moment of a refresh
  can reach two processes. Use a session middleware that keeps the data on the
  server for such an app.

For an organization on its own domain, pass `custom_domain="auth.acme.com"`
in place of `base_url` and `organization`.

`callback_path` must match a redirect URI that is registered on the OAuth
client. Add `?return_to=/dashboard` to the login URL to choose the page that
opens after sign-in. The router accepts only paths on the same site. For
anything else it uses `post_login_redirect`.

**Sign-in parameters for one sign-in.** The login route passes these query
parameters on to LumoAuth, and no others:

| Parameter | Use |
|---|---|
| `acr_values` | Ask for a stronger sign-in, such as `urn:lumoauth:acr:mfa` (step-up) |
| `max_age` | Ask for a sign-in that is at most this many seconds old; `0` asks for a new one |
| `resource` | The absolute https URL of the API that the access token is for (RFC 8707) |
| `login_hint` | The address to fill in on the sign-in page |
| `prompt` | `login`, `consent`, `select_account` or `none` |

For example, when your API answers 401 with `insufficient_user_authentication`
and asks for multi-factor sign-in, redirect to the login route with those
values:

```python
from urllib.parse import urlencode
from fastapi.responses import RedirectResponse

@app.get("/payouts/step-up")
def step_up():
    query = urlencode({"acr_values": "urn:lumoauth:acr:mfa", "max_age": 300,
                       "resource": "https://api.example.com", "return_to": "/payouts"})
    return RedirectResponse(f"/auth/login?{query}")
```

The new tokens replace the old ones in the session. A malformed value is
answered with 400 `invalid_request`. These parameters can only ask for a
stricter sign-in or give a hint; LumoAuth checks `resource` against the
application.

| Name | Purpose |
|---|---|
| `lumo_auth_router(...)` | Builds the router. See the [API reference](#lumoauthfastapi) for every argument. |
| `get_current_user` | Dependency that returns the signed-in `User`, or `None`. |
| `require_auth(scopes=None)` | Dependency that answers 401 when nobody is signed in, and 403 when the granted scopes lack one of `scopes`. |
| `User` | Pydantic model of the `/userinfo` claims: `sub`, `email`, `email_verified`, `name`, `given_name`, `family_name`, `picture`. Extra claims are kept. |
| `LumoAuthFastAPI` | The configuration. `lumo.router()` builds the router from it, and `Depends(lumo.access_token)` gives a route the user's access token, refreshed when it expires. |

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
- `LumoAuthAgent(dpop=True)`, or `dpop=DpopKey.from_pem(...)`, binds the
  token to a key that the agent holds. See
  [DPoP-bound tokens](#dpop-bound-tokens).
- Every other method calls `ensure_authenticated()` first. That method signs
  in again when the token is missing or within 60 seconds of expiry.

#### Capabilities, budget and identity

A **capability** is something that an administrator allowed the agent to do,
such as `web:search`. A **budget** limits the agent's calls, model tokens
and cost per hour, day and month. LumoAuth does not see your model calls, so
token and cost limits count only the usage that you report with
`report_usage()`.

```python
info = agent.get_agent_info()      # sub, name, agent_id, capabilities, budget_policy, …

if agent.has_capability("web:search"):
    ...

resp = llm.chat(messages)
agent.report_usage(tokens=resp.usage.total_tokens, cost_usd=0.0042)

if agent.is_budget_exhausted():    # any limit reached: the next Ask, token or JIT request gets 429
    print("Budget spent")

me = agent.get_identity()          # GET /agents/me
print(me["identity"]["id"], me["capabilities"], me["workspace"])
```

`get_agent_info()` reads the userinfo endpoint and caches the result.
`has_capability()` and `get_budget_status()` use that cache.

`has_capability()` matches names the way the server does. Write a capability
as `<resource>:<action>`, such as `invoices:read`. LumoAuth refuses the dot
form (`invoices.read`) when you register a capability or request a scope.
The match compares ASCII letters in lower case and reads a `.` as `:` only
when it compares, so a dotted permission slug such as `invoices.read` matches
the held `invoices:read`. A `-` is part of a name, so `invoices-read` is a
different capability. A held wildcard such as `invoices:*` covers
`invoices:read`, but not `invoices` itself. The same
rules are available as `normalize_capability()`, `capability_covers()` and
`any_capability_covers()`, and `AccessTokenClaims.has_capability()` uses them
for a verified token. The check reads only the agent's registered list.
`ask()` also applies your policies and the token's scope.

#### Ask before you act

The Ask API answers the question "may I do this?" for one action. Call it
before an LLM runs a tool. LumoAuth records the decision in the audit log
either way.

```python
result = agent.ask("document:read", context={"id": "doc_99"})
# {"allowed": True, "action": "document:read", "reason": …, "decided_by": …, "audit_id": …, "context": {…}}

def dispatch_tool(tool_name: str, args: dict):
    if not agent.is_allowed(tool_name, context=args):
        return {"error": f"The agent may not run {tool_name}"}
    ...  # run the tool
```

As with ABAC, the keys `ip`, `userAgent`, `requestMethod` and `requestPath`
in the context describe the real request. Values that you send under those
names are moved under `pep`.

To find the decision in your distributed trace, pass the W3C `traceparent` of
the current span. The audit entries of the decision then carry its trace ID:

```python
result = agent.ask("document:read", traceparent="00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
```

`is_allowed()` and `client.agents.ask()` take the same argument. An
OpenTelemetry instrumentation of `requests` adds the header to every call
instead.

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
    @require_capability("web:search")
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
    capabilities=["web:search", "documents:read"],
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

`DelegationChain` runs the whole flow for one or more sessions. The person
consents to an **application** of your organization, never to the agent: an
agent does not start a sign-in. Pass the application's client ID, its secret
when it is confidential, and one of its registered redirect URIs:

```python
from lumoauth import LumoAuthAgent, DelegationChain

agent = LumoAuthAgent()
agent.authenticate()

chain = DelegationChain(
    agent,
    redirect_uri="https://app.example.com/callback",   # registered on the application
    app_client_id="client_…",                          # the application, not the agent
    app_client_secret="…",                             # only for a confidential application
)

# 1. Send the person to the consent page (PKCE S256 and a random state)
url = chain.get_consent_url("session_1", scopes=["documents:read"], offline_access=True)

# 2. The application redeems the code of the callback
chain.handle_consent_callback("session_1", code, state=returned_state)

# 3. Exchange for a delegated token, and use it
token = chain.exchange("session_1", scopes=["documents:read"])
resp = chain.request("session_1", "GET", "https://api.acme.com/documents/abc")
```

- The URL asks for `openid` plus your scopes, and `offline_access` when you
  pass `offline_access=True`. The application must be allowed these scopes,
  and the agent must hold the scopes as capabilities; otherwise the exchange
  issues no scope (`400 invalid_scope`).
- `handle_consent_callback()` redeems the code with the application's client
  ID, its secret and the PKCE verifier. The agent's credentials play no part.
  The person's tokens are the application's tokens, and the application also
  refreshes them.
- Without `app_client_id`, `get_consent_url()` and
  `handle_consent_callback()` still use the agent's ID, as earlier releases
  did, and issue a `FutureWarning`: LumoAuth refuses that request.

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
to a specialist agent. A chain holds at most five actors
(`MAX_DELEGATION_DEPTH`); LumoAuth refuses a deeper exchange with 400
`invalid_request`.

```python
sub_agent = LumoAuthAgent(client_id="agt_specialist", client_secret="…")
sub_agent.authenticate()

nested = chain.delegate_to_sub_agent("session_1", sub_agent.access_token, scopes=["documents:read"])

DelegationChain.get_subject(nested)         # "user:alice"
DelegationChain.parse_actor_chain(nested)   # ["agent:orchestrator", "agent:specialist"]
```

`get_subject` and `parse_actor_chain` read the JWT without checking its
signature. Use them to inspect a token, not to trust one.

**Revocation.** `chain.revoke("session_1")` revokes the person's refresh
token as the application (`/oauth/revoke` with `app_client_id` and its
secret). That ends the whole grant, including every delegated token that the
agent got from it, and returns `True`. It needs a consent with
`offline_access=True`. Without a refresh token or without `app_client_id`,
nothing can be revoked at LumoAuth: the agent's own credentials cannot revoke
the application's token. `revoke()` then only forgets the session here, logs
a warning and returns `False`. The delegated token stays valid until it
expires (at most the lifetime of the person's token). The person can also end
it on their account page, under "AI agents acting for you".

**Housekeeping.** `chain.revoke_all()`, `chain.active_sessions` and
`chain.has_delegation("session_1")`.

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

**Exchange as an application.** An agent that sends its own token as
`actor_token` needs no client authentication. A confidential application
(with token exchange turned on in its settings) authenticates as at the token
endpoint: `client_id` with `client_secret`, sent as HTTP Basic, or with
`client_auth_method="client_secret_post"` in the form body. A
`private_key_jwt` application passes `client_assertion` (from
`ClientAssertionSigner.create()`) instead of the secret.

```python
tokens = client.auth.token_exchange(
    user_access_token,
    resource="https://api.acme.com",
    client_id="client_…",
    client_secret="…",
)
```

### MCP tokens

An agent that calls a secured MCP server exchanges its token first:

```python
credential = agent.get_mcp_credential("https://mcp.example.com/mcp")   # raises on failure
mcp_token = credential.access_token
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

`agent.get_mcp_token()` returns only the token string, and `None` when
LumoAuth refuses the exchange. It then logs the error and issues a
`FutureWarning` with the reason. Returning `None` is deprecated: a later
major release will raise. Use `get_mcp_credential()`, which raises the typed
error now.

The token names exactly one MCP server. Pass the Resource URI that is
registered for that server. The token works only at that MCP server, and
LumoAuth's own API rejects it. If the MCP server requires DPoP, make the
exchange DPoP-bound: create the agent with `dpop=True`, or pass a
`DpopProofSigner` as `dpop=` to `client.mcp.get_token()`. See
[DPoP-bound tokens](#dpop-bound-tokens).

`agent.get_mcp_credential()` returns the whole answer as an `McpToken`
(`access_token`, `token_type`, `expires_in`, `scope`), and its
`headers(method, url)` builds the request headers for the MCP server, with
the DPoP proof when the token needs one. `client.mcp.exchange()` does the
same on a plain client.

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

### Private key JWT: sign in without a secret

An agent registered with the **Private key JWT** identity type has no client
secret. Whenever it needs a token, it signs a short-lived JWT (a client
assertion, [RFC 7523](https://www.rfc-editor.org/rfc/rfc7523)) with its
private key. Only the public key is registered.

```python
from lumoauth import ClientAssertionSigner, LumoAuthAgent

signer = ClientAssertionSigner.generate("ES256", key_id="agent-2026-11")
open("agent-private-key.pem", "w").write(signer.to_pem())   # keep it in your secret store
print(signer.jwks())                                        # paste this into the agent's public keys

agent = LumoAuthAgent(
    client_id="agt_0123456789abcdef",
    private_key=open("agent-private-key.pem").read(),        # or set AGENT_PRIVATE_KEY
    key_id="agent-2026-11",                                  # or set AGENT_KEY_ID
)
agent.authenticate()
```

Every token request carries a new assertion: `iss` and `sub` are the agent ID,
`aud` is the organization's issuer identifier (`{base_url}/orgs/{org_id}/api/v1`,
or the bare domain with `custom_domain=`), `exp` is 60 seconds ahead and `jti` is random.
`ClientAssertionSigner` signs with ES256, ES384, ES512, EdDSA, RS256 to RS512 or
PS256 to PS512. Pass either `client_secret` or `private_key`, not both. Combine
it with `dpop=` to also bind the tokens to a key.

### Workload attestation: sign in with the platform's token

An agent registered with the **Workload** identity type has no secret
either. Its runtime (GitHub Actions, AWS, Azure, Google Cloud, Kubernetes or
SPIFFE) gives the workload an OIDC token. LumoAuth checks that token against
the identity registered on the agent and issues a short-lived access token
for the agent.

```python
import os

import requests
from lumoauth import LumoAuth

AGENT_ID = "agt_0123456789abcdef"
AUDIENCE = f"https://app.lumoauth.dev/orgs/acme-corp/api/v1/agents/{AGENT_ID}"


def github_oidc_token() -> str:
    """A new OIDC token of the GitHub Actions job, for the agent's audience."""
    answer = requests.get(
        os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"],
        params={"audience": AUDIENCE},
        headers={"Authorization": f"Bearer {os.environ['ACTIONS_ID_TOKEN_REQUEST_TOKEN']}"},
        timeout=10,
    )
    answer.raise_for_status()
    return answer.json()["value"]


lumo = LumoAuth(org_id="acme-corp")   # no credential needed
result = lumo.agents.attest(AGENT_ID, github_oidc_token(), scopes=["orders:read"])

api = LumoAuth(org_id="acme-corp", token_provider=lambda: result.access_token)
```

- `result` is a `WorkloadAttestation`: `access_token`, `token_type`,
  `expires_in` (900 seconds), `scope` and `scopes`, and `identity` (the
  verified workload: `provider`, `subject`, `issuer`).
- `scopes` asks for fewer values than the agent's capabilities. Each value
  must be covered by a capability, or LumoAuth answers 400 `invalid_scope`.
  Without it the token carries every capability.
- `dpop=` (a `DpopProofSigner`) binds the token to a key. An agent
  registered with DPoP-bound tokens needs it.
- The request carries no credential of the client: the OIDC token is the
  proof. A refused token raises `LumoAuthAuthenticationError` with the code
  `attestation_rejected`. LumoAuth gives this one answer for an unknown
  agent, an inactive agent and a token that failed verification.
- Each token counts against the agent's budget. A spent budget raises
  `LumoAuthBudgetExceededError`.
- LumoAuth accepts each OIDC token once. Fetch a new one for every
  attestation: a token file that the platform has not renewed yet, such as
  a Kubernetes projected token, is refused the second time. Attest again
  before the access token expires.

### DPoP-bound tokens

[DPoP](https://www.rfc-editor.org/rfc/rfc9449) (RFC 9449) binds a token to a
key that the agent holds. A stolen token is then useless without the key. An
MCP server registered with "Require DPoP" accepts only such tokens.

```python
from lumoauth import LumoAuthAgent
from lumoauth.dpop import DpopKey

key = DpopKey.generate()                      # ES256 (P-256); DpopKey.generate("EdDSA") for Ed25519
open("dpop.pem", "w").write(key.to_pem())     # keep it between runs, or use dpop=True for an ephemeral key

agent = LumoAuthAgent(dpop=DpopKey.from_pem(open("dpop.pem").read()))
agent.authenticate()
print(agent.token_type)                       # "DPoP"

cred = agent.get_mcp_credential("https://mcp.example.com/mcp")
headers = cred.headers("POST", "https://mcp.example.com/mcp")
# {"Authorization": "DPoP <token>", "DPoP": "<proof with ath>"}
requests.post("https://mcp.example.com/mcp", headers=headers, json=body)
```

- The client-credentials sign-in, every MCP token exchange and every request
  that the agent makes to LumoAuth's own API carry a DPoP proof. The proof
  names the method (`htm`), the URL without its query (`htu`), the time
  (`iat`), a fresh `jti`, and the hash of the token (`ath`) when a token is
  sent with it.
- When LumoAuth answers `use_dpop_nonce` with a `DPoP-Nonce` header, the SDK
  retries once with that nonce and remembers the latest nonce for each
  origin.
- `agent.token_type` and `McpToken.token_type` are `"DPoP"` for a bound
  token and `"Bearer"` otherwise. A bound token travels as `Authorization:
  DPoP …`, never as `Bearer`.
- Call `headers()` once per request. A proof is good for one request only.
- For an endpoint that the SDK does not wrap,
  `agent.dpop_headers("POST", url)` gives the `Authorization` and `DPoP`
  headers for the agent's own token, and `agent.dpop_proof("POST", url)`
  gives a bare proof. Workload attestation takes a signer:
  `client.agents.attest(..., dpop=signer)`.
- On a plain `LumoAuth` client, pass a signer to the token-endpoint flows:
  `client.auth.client_credentials(..., dpop=signer)`,
  `client.auth.token_exchange(..., dpop=signer)` and
  `client.mcp.get_token(..., dpop=signer)`.

DPoP needs the `cryptography` package: `pip install "lumoauth[dpop]"`.

### Verify a LumoAuth token in your MCP server

An MCP server, or any API, that receives a LumoAuth access token verifies it
locally. No call to LumoAuth is needed for each request: the SDK fetches the
organization's signing keys once and caches them.

```python
from lumoauth import verify_access_token

claims = verify_access_token(token, issuer="https://app.lumoauth.dev/orgs/acme-corp/api/v1",
                             resource="https://mcp.example.com/mcp")
if not claims.has_scope("tools:read"): ...
```

- `issuer` is the organization issuer, `{base_url}/orgs/{org}/api/v1`. The
  SDK reads `{issuer}/.well-known/openid-configuration` for the `jwks_uri`,
  caches the keys, and fetches them again once when a token names an unknown
  `kid`.
- For an organization on its own domain, pass `custom_domain="auth.acme.com"`
  and leave `issuer` out. The issuer is then the bare domain, and the SDK
  reads the discovery document below `https://auth.acme.com/api/v1`. See
  [Use a custom domain](#use-a-custom-domain).
- `resource` is your server's resource URI. The token's `aud` must contain it.
- The checks: the signature (RS256, PS256 or ES256 against the JWKS), the
  `typ` header (`at+jwt`), `iss`, `aud`, `exp` and `nbf` (60 seconds of
  leeway by default), and `sub`. A test token (`token_use: "test"`) is
  refused. `alg: none` and HMAC algorithms are refused.
- `AccessTokenClaims` has `sub`, `scopes`, `has_scope()`, `has_scopes()`,
  `missing_scopes()`, `is_agent`, `agent_id`, `capabilities`,
  `has_capability()`, the delegation chain (`act`, `act_chain`, `actor`,
  `is_delegated`), `cnf`, `is_dpop_bound`, `exp`, `nbf`, `jti`, and the raw
  `claims` and `header` dicts.
- Every failure raises `LumoAuthTokenError`. Its `code` is stable:
  `TOKEN_EXPIRED`, `TOKEN_WRONG_AUDIENCE`, `TOKEN_WRONG_ISSUER`,
  `TOKEN_WRONG_TYPE`, `TOKEN_BAD_SIGNATURE`, `TOKEN_UNKNOWN_KEY`,
  `TOKEN_TEST_TOKEN`, `DPOP_REQUIRED`, `DPOP_KEY_MISMATCH`, `DPOP_REPLAYED`
  and more. `www_authenticate` is a ready-made challenge for a 401 answer.

**DPoP-bound tokens.** A token with `cnf.jkt` must arrive as
`Authorization: DPoP …` with a `DPoP` proof. Pass what the request carried,
and the verifier checks the proof: its key matches `cnf.jkt`, its `htm` and
`htu` match the request, its `ath` matches the token, its `iat` is recent,
and its `jti` was not seen before (a process-local replay cache with a
300-second window; pass `replay_cache=` with a `check_and_add(key, ttl)`
method to share one between workers).

```python
from lumoauth import DpopRequest, verify_access_token

claims = verify_access_token(
    token,
    issuer=issuer,
    resource="https://mcp.example.com/mcp",
    dpop=DpopRequest(method=request.method, url=str(request.url),
                     proof=request.headers.get("DPoP"), scheme=scheme),   # scheme: "Bearer" or "DPoP"
    require_dpop=True,      # refuse tokens that are not DPoP-bound
)
```

Hold an `AccessTokenVerifier(issuer, resource, ...)` yourself to control the
JWKS cache (`jwks=` for pinned keys, `fetch=` for your own HTTP) and the replay
cache. The module-level function keeps one verifier per issuer and resource.

**FastAPI.** `require_access_token()` does all of this as a dependency. It
reads the `Authorization` and `DPoP` headers, answers 401 with a
`WWW-Authenticate` challenge or 403 `insufficient_scope`, and returns the
claims:

```python
from fastapi import Depends, FastAPI
from lumoauth.fastapi import require_access_token, AccessTokenClaims

app = FastAPI()
auth = require_access_token(issuer="https://app.lumoauth.dev/orgs/acme-corp/api/v1",
                            resource="https://mcp.example.com/mcp")

@app.post("/mcp")
def mcp(claims: AccessTokenClaims = Depends(auth)):
    return {"sub": claims.sub}
```

For an organization on its own domain, pass `custom_domain=` in place of
`issuer=`.

Behind a reverse proxy, pass `request_url=` to rebuild the public URL that
the client signed into the proof. Verification needs the `cryptography`
package: `pip install "lumoauth[verify]"`.

### Verify a JIT token in your API

A JIT token is the approval of one [Just-in-Time request](#just-in-time-permissions).
It is not an access token: its header `typ` is `JWT`, its `aud` is the
organization slug, and the approval is in `permissions.authorization_details`.
`verify_access_token()` refuses it. Use `verify_jit_token()`:

```python
from lumoauth import LumoAuthTokenError, verify_jit_token

try:
    approval = verify_jit_token(
        jit_token,
        issuer="https://app.lumoauth.dev/orgs/acme-corp/api/v1",
        caller=claims,   # the verified access token of the same request, optional
    )
except LumoAuthTokenError as err:
    ...  # err.code: JIT_TOKEN_INVALID or JIT_TOKEN_NOT_FOR_CALLER

if not approval.covers("file_access", actions=["read"], identifier="report_2024.pdf"):
    ...  # the approval does not allow this action
```

The checks:

- The signature verifies with a key of the organization's JWKS (RS256 to
  RS512, PS256 to PS512, ES256 to ES512; `kid` required).
- `iss` is the organization's issuer, `aud` is the organization slug (taken
  from the issuer, or from `org_id=`; with `custom_domain=` pass `org_id`),
  `jit` is `true`, and `exp`, `nbf` and `iat` hold with 60 seconds of leeway.
- `permissions` names the agent (`agent_id`) and holds at least one approved
  entry.
- With `caller`: the token's `sub` is the caller's `sub`, and its agent is the
  caller's agent (`act.sub` of a delegated token, else `sub`). An approval
  that an agent got for itself is refused in a call that it makes for a user,
  and the reverse.

`approval.covers()` applies the matching of RFC 9396: the same `type` (or
`*`), every requested action and location (or `*`), and the same
`identifier` (or `*`). The result also has `subject`, `agent_id`, `exp`,
`jti`, `task_id`, `request_id` and `claims`. The token is not checked for
revocation: for an action with consequences, also introspect it, as
[the JIT guide](https://docs.lumoauth.dev/agents/jit#validate-a-jit-token-in-your-api)
describes. `JitTokenVerifier(issuer, *, org_id=None, custom_domain=None,
jwks=None, fetch=None, clock_skew=60)` keeps its own key cache.

### Verify requests from personal agents

A personal agent that uses the
[Personal Agent Protocol](https://personalagentprotocol.org) sends a
`Poppy-Session` header to your API, not to LumoAuth. The SDK forwards the
method, the public URL and the protocol headers of each request to LumoAuth.
LumoAuth then answers who the request is from: the personal agent, its user,
the Session and, for a signed-in request, the account.

The calls authenticate as one of your organization's confidential
applications, with its client ID and secret over HTTP Basic:

- The application's allowed scopes must include `poppy:verify`. Add the
  scope under **Applications**, on the application that your API uses.
- Pass the credentials as `client_id` and `client_secret`, or set
  `LUMOAUTH_CLIENT_ID` and `LUMOAUTH_CLIENT_SECRET`.
- These calls never send the client's API key or bearer token.

The [guide to Session verification](https://docs.lumoauth.dev/agents/personal-agent-protocol-verify)
describes the endpoints in full.

#### Protect FastAPI routes

> Requires `pip install "lumoauth[fastapi]"`.

`LumoAuthPoppy` gives you a dependency for the routes that personal agents
call. Save this program as `shop.py` and run it with `uvicorn shop:app`.

```python
import os

from fastapi import Depends, FastAPI
from lumoauth import LumoAuth, PoppyVerification
from lumoauth.fastapi import LumoAuthPoppy

app = FastAPI()

lumo = LumoAuth(
    org_id="acme-corp",
    client_id=os.environ["LUMOAUTH_CLIENT_ID"],
    client_secret=os.environ["LUMOAUTH_CLIENT_SECRET"],
)
# The address that personal agents call, for example https://shop.example.com
poppy = LumoAuthPoppy(lumo, public_origin=os.environ["PUBLIC_ORIGIN"])
poppy.install(app)

CATALOG = [{"sku": "trail-socks-3", "name": "Trail socks, pack of 3", "price": 18}]
ORDERS = {}  # account id -> list of orders


@app.get("/api/catalog")
def catalog(who: PoppyVerification = Depends(poppy.session())):
    # Signed out or signed in. Store Session state, such as a cart, under who.session.id.
    return {"items": CATALOG, "signed_in": who.signed_in}


@app.get("/api/orders")
def orders(who: PoppyVerification = Depends(poppy.session("orders:read"))):
    # Signed in, and the access token has the scope. who.account.sub is the user's id.
    return {"orders": ORDERS.get(who.account.sub, [])}
```

- **`public_origin` comes from your configuration.** It is the address
  that personal agents call. The helper builds the URL from `public_origin`
  and from the raw path of the request, as the client sent it. It never
  reads the `Host` or `X-Forwarded-*` headers. Behind a proxy that removes a
  path prefix, put the prefix in `public_origin`, for example
  `https://example.com/shop`. A missing `public_origin` raises
  `LumoAuthConfigError` when you create the helper.
- **`poppy.session(required_scope=None, *, resource=None, allow_replay=False)`**
  builds the dependency. `required_scope` is a space-separated string or a
  list. The dependency returns the `PoppyVerification` and also stores it as
  `request.state.poppy`. It does not read the request body.
- **A refusal is relayed unchanged.** When LumoAuth refuses a request, the
  route does not run. The personal agent gets the response that LumoAuth
  wrote for it: its status, each of its headers and its body. `poppy.install(app)`
  registers the handler that sends this response. Call it on every FastAPI
  application that has such routes, including a mounted application.
- **An SDK error is never relayed.** LumoAuth may be unreachable, the
  protocol may be switched off for the organization (LumoAuth then answers
  404), or LumoAuth may answer 401, 403 or 429 about your own application. The
  route does not run, and the personal agent gets `503` with
  `{"error": "temporarily_unavailable", "error_description": "Requests from
  personal agents cannot be verified right now."}` and `Cache-Control:
  no-store`. The cause is logged as a warning on the `lumoauth.fastapi`
  logger and is not sent to the personal agent.
- **Use one dependency per route.** LumoAuth accepts a Session JWT for one
  verification. A service that checks one request in several places passes
  `allow_replay=True`.

A verified `PoppyVerification` has these attributes:

| Attribute | Meaning |
|---|---|
| `active` | `True` for a verified request, `False` for a refusal |
| `client_id`, `client_name` | The personal agent. The `client_id` is what LumoAuth checked. |
| `user_id` | The agent's stable name for its user at your company. It is not an account. |
| `agent_id` | Set when the personal agent runs several agents for one user; otherwise `None` |
| `session` | `PoppySessionInfo(id, sid, is_new, started_at)` |
| `signed_in`, `account` | Whether the request carried a valid access token, and `PoppyAccount(sub, scope, scopes, aud, exp, token_type)` or `None` |
| `version`, `extensions` | The `Poppy-Version` of the request, and its extensions as name and version |
| `raw` | The decoded answer of LumoAuth |

Use `account.sub` to find account data. Never use `user_id` for that,
because the personal agent chose that value.

#### Verify a request without the helper

`client.poppy.verify_request()` works with any framework. Pass the method,
the public URL and the headers of the request. You may pass every header:
the SDK sends only `Poppy-Session`, `Poppy-Version`, `Poppy-Extensions`,
`Authorization` and `DPoP`, so no cookie and no API key leaves your service.

```python
import os

from lumoauth import LumoAuth

lumo = LumoAuth(org_id="acme-corp")  # reads LUMOAUTH_CLIENT_ID and LUMOAUTH_CLIENT_SECRET
PUBLIC_ORIGIN = os.environ["PUBLIC_ORIGIN"].rstrip("/")  # for example https://shop.example.com


def handle(method, raw_path, headers):
    """Takes the method, raw path and headers of a request. Returns status, headers and JSON body."""
    who = lumo.poppy.verify_request(
        method,
        PUBLIC_ORIGIN + raw_path,
        headers,
        required_scope="orders:read",
    )
    if not who.active:
        # The response that the personal agent must get, unchanged.
        refusal = who.response
        if refusal.body is None:
            return refusal.status, refusal.headers, None
        return refusal.status, {**refusal.headers, "Content-Type": "application/json"}, refusal.body
    return 200, {"Content-Type": "application/json"}, {"account": who.account.sub}
```

- A refusal is a result with `active=False`. It does not raise. It has
  `error`, `error_description`, `scope` and `response`, a
  `PoppyResponse(status, headers, body)`. Send that response unchanged. When
  `body` is `None`, send no body and no `Content-Type`.
- Any other failure raises: `LumoAuthAuthenticationError` (401),
  `LumoAuthPermissionDeniedError` (403, the application lacks
  `poppy:verify`), `LumoAuthNotFoundError` (404, the protocol is switched
  off), `LumoAuthRateLimitError` (429) or `LumoAuthNetworkError`. These
  errors are about your own application. Answer the personal agent with a
  5xx status and never relay them.
- A 200 answer that is neither a verified result nor a well-formed refusal
  raises `LumoAuthValidationError`. The SDK never returns it as verified.
- Without a client ID and secret, the call raises `LumoAuthConfigError`
  before it sends a request.
- `build_poppy_verify_body(public_origin, method, target, headers, ...)`
  builds the request body without any I/O. It applies the URL rules: it
  removes trailing slashes from the origin, appends the raw path, and drops
  the query. Use it to see what the SDK sends for a request.

In a FastAPI route that calls `poppy.verify(request)` itself,
`poppy_refusal_response(who)` builds the response for a refusal:

```python
from fastapi import Request
from lumoauth.fastapi import poppy_refusal_response

@app.get("/api/cart")
def cart(request: Request):
    who = poppy.verify(request)
    if not who.active:
        return poppy_refusal_response(who)
    return {"session": who.session.id}
```

#### Look up and end a Session

Sometimes you must know the state of a Session when the personal agent sent
no request. The main case is a website that joined a browser to a Session:
ask LumoAuth on each page request.

```python
status = lumo.poppy.get_session_status(who.client_id, who.session.sid)

if status.status != "active":        # "active", "ended" or "unknown"
    ...  # drop the cookie: the browser is a visitor again
elif not status.signed_in:
    ...  # keep the Session, and treat the browser as signed out
```

`get_session_status()` returns `PoppySessionStatus(status, user_id, agent_id,
account, signed_in, last_seen_at)`. An unknown Session is a result with
`status="unknown"`, not an error.

End a Session when your own rules require it, for example after a fraud
signal. The user stays signed in, and the personal agent starts a new Session.

```python
ended = lumo.poppy.end_session(who.client_id, who.session.sid)
# True; False when the Session had ended before
```

An unknown Session raises `LumoAuthNotFoundError`. Both calls raise
`LumoAuthValidationError` for an empty argument, before they send a request.

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
target resource, and an agent token. The scope of the auth token comes from
the resource token: LumoAuth ignores the `scope` argument of
`request_authorization()`.

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

**4. Refresh.** A refresh needs a resource token from the same resource as
the original grant. LumoAuth does not rotate the refresh token. The optional
`scope` argument only narrows: a scope outside the grant is refused with
`invalid_scope`.

```python
new_tokens = client.refresh(tokens["refresh_token"], fresh_resource_tok, agent_token=agent_tok)
```

**Discovery.** `client.discover_issuer()` and
`client.discover_resource("https://api.example.com")` fetch the `.well-known`
metadata documents. `client.get_issuer()` returns the AAuth issuer. It is the
`iss` of AAuth tokens and the audience that the agent addresses, for example
in the `aud` of its agent token. The AAuth issuer is always the platform
address, `{base_url}/orgs/{org_id}/api/v1`, also for an organization on its
own domain. See [Use a custom domain](#use-a-custom-domain).

The Python SDK signs AAuth requests and obtains tokens. It does not verify
AAuth tokens on the resource side. It also does not wrap the `exchange`
request type, the consent route, the agent metadata document, the issuer JWKS
or token revocation.

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
│       └── LumoAuthBudgetExceededError 429 with the body code budget_exceeded: the agent's budget is used up
├── LumoAuthValidationError          bad input, or a response of the wrong shape; .issues
│   └── LumoAuthTokenError           an access token or DPoP proof failed local verification; .code says why
├── LumoAuthConfigError              missing or invalid configuration
├── LumoAuthNetworkError             no HTTP response (DNS, TLS, timeout)
├── LumoAuthApprovalDeniedError      a person denied an approval
├── LumoAuthApprovalTimeoutError     nobody answered an approval in time
└── LumoAuthApprovalNotDeliveredError no push prompt was sent; .reason, .task_id
```

- `code` is the `code` or `error` field of the response body when it has one.
  Otherwise it is the class default, such as `PERMISSION_DENIED`.
- The SDK never retries a request by itself: a 429 raises at once.
  `retry_after` comes from the `Retry-After` header, as a number of seconds or
  as an HTTP date (then the seconds until that date). It is `None` when the
  answer has no such header.
- A 429 whose body code is `budget_exceeded` raises
  `LumoAuthBudgetExceededError`: a limit of the agent's budget is reached.
  `retry_after` is the number of seconds until the spent window starts again.
  The class is a `LumoAuthRateLimitError`, so an `except
  LumoAuthRateLimitError` clause catches it too.
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
         timeout=30, skip_cert_validation=False, client_id=None, client_secret=None,
         custom_domain=None)
```

#### `client.auth`

| Method | What it does | Credential |
|---|---|---|
| `authorization_url(*, client_id, redirect_uri, scope="openid profile email", state=None, response_type="code", code_challenge=None, code_challenge_method=None, prompt=None, access_type=None, extra=None)` | Builds the URL for the authorization-code flow | none (no request) |
| `exchange_code(code, redirect_uri, *, client_id, client_secret=None, code_verifier=None)` | Exchanges an authorization code for tokens | form body |
| `refresh_token(refresh_token, *, client_id, client_secret=None, scopes=None)` | Refreshes an access token | form body |
| `client_credentials(client_id, client_secret=None, scopes=None, dpop=None, *, client_assertion=None, resource=None)` | Client-credentials grant; `dpop` (a `DpopProofSigner`) makes the token DPoP-bound; `resource` (RFC 8707) becomes the token's `aud` | form body |
| `token_exchange(subject_token, *, actor_token=None, audience=None, scopes=None, subject_token_type=ACCESS_TOKEN_TYPE, actor_token_type=ACCESS_TOKEN_TYPE, resource=None, dpop=None, client_id=None, client_secret=None, client_assertion=None, client_auth_method="client_secret_basic")` | RFC 8693 token exchange; `resource` becomes `aud`; `dpop` binds the new token; `client_id` with `client_secret` or `client_assertion` authenticates an application | form body, or HTTP Basic |
| `revoke(token, *, token_type_hint=None, client_id=None, client_secret=None)` | Revokes an access or refresh token | form body |
| `end_session_url(*, id_token_hint=None, post_logout_redirect_uri=None, state=None)` | Builds the OpenID Connect end-session URL (RP-initiated logout). Send the browser there to end the LumoAuth session | none (no request) |
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
| `ask(action, context=None, *, traceparent=None)` | Ask API decision `dict`; `traceparent` is sent as the W3C header |
| `is_allowed(action, context=None)` | The decision as a `bool` |
| `me()` (alias `get_current()`) | `identity`, `capabilities` and `workspace` |
| `authorize_mcp_tool(server_id, tool)` | Asks whether the calling agent may run a tool on a registered MCP server; returns `AgentMcpToolDecision`, with `allowed=False` for a deny |
| `register(name, *, client_id, description=None, capabilities=None, jwks_uri=None)` | Creates or updates an agent record; a user token needs `admin:agents:write` |
| `attest(agent_id, attestation_token, *, scopes=None, dpop=None)` | Workload attestation: exchanges the workload's OIDC token for an access token of the agent and returns `WorkloadAttestation` (`access_token`, `token_type`, `expires_in`, `scope`, `scopes`, `identity`, `raw`). Sends no credential of the client |
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
| `consent_url(*, client_id, redirect_uri, scopes=None, state=None, code_challenge=None)` | Consent URL for an application's `client_id`; with `code_challenge` it carries PKCE S256 (and no `prompt` / `access_type`), without it `prompt=consent` and `access_type=offline` |
| `exchange_code(code, redirect_uri, *, client_id, client_secret=None, code_verifier=None)` | Redeems the consent code as the application |
| `refresh_user_token(refresh_token, *, client_id, client_secret=None)` | Refreshes the user's token |
| `exchange(subject_token, actor_token, scopes=None, *, resource=None)` | Creates a delegated token |
| `revoke(token, *, token_type_hint="refresh_token", client_id=None, client_secret=None)` | Revokes a delegation |
| `parse_actor_chain(token)`, `get_subject(token)` *(static)* | Read the `act` chain and `sub` of a JWT |

#### `client.poppy`

These calls authenticate with HTTP Basic (`client_id` and `client_secret`),
never with the API key or the token. The application needs the
`poppy:verify` scope.

| Method | What it does |
|---|---|
| `verify_request(method, url, headers, *, required_scope=None, resource=None, allow_replay=False)` | Asks LumoAuth who a request of a personal agent is from. `url` is the public URL; `headers` is a mapping or a list of pairs, of which only the five protocol headers are sent. Returns `PoppyVerification`, with `active=False` and the `response` to relay for a refusal |
| `get_session_status(personal_agent, sid)` | Looks a Session up; returns `PoppySessionStatus(status, user_id, agent_id, account, signed_in, last_seen_at)` with `status` `"active"`, `"ended"` or `"unknown"` |
| `end_session(personal_agent, sid)` | Ends a Session; returns `True`, or `False` when the Session had ended before; an unknown Session raises `LumoAuthNotFoundError` |

| Name | What it is |
|---|---|
| `PoppyVerification` | Frozen dataclass: `active`; for a verified request `client_id`, `client_name`, `user_id`, `agent_id`, `session`, `signed_in`, `account`, `version`, `extensions`; for a refusal `error`, `error_description`, `scope`, `response`; and `raw` |
| `PoppySessionInfo` | `id` (integer), `sid`, `is_new`, `started_at` |
| `PoppyAccount` | `sub`, `scope` (string), `scopes` (tuple), `aud` (tuple), `exp` (integer), `token_type`, and `has_scope(scope)` |
| `PoppyResponse` | The response to relay for a refusal: `status`, `headers` (dict of string to string), `body` (dict or `None`) |
| `build_poppy_verify_body(public_origin, method, target, headers, *, required_scope=None, resource=None, allow_replay=False)` | Pure function that builds the JSON body of `verify_request` from a public origin, a method, a raw request target and the headers |
| `POPPY_FORWARDED_HEADERS` | The five header names that the SDK sends to LumoAuth |

#### `client.mcp` and `client.api`

| Member | What it does |
|---|---|
| `mcp.get_token(server_id, *, subject_token=None, dpop=None)` | Token exchange for an MCP server, with `server_id` (its https URL) as `resource`; returns the token string; `dpop` makes it DPoP-bound |
| `mcp.exchange(server_id, *, subject_token=None, dpop=None)` | The same exchange; returns `McpToken(access_token, token_type, expires_in, scope, resource)` whose `headers(method, url)` builds the request headers |
| `mcp.authorize_tool(server_id, subject_type, subject_id, tool)` | Per-tool check for an MCP server, made with the server's own `mcp:authorize` token; returns `McpToolDecision`, with `allowed=False` for a deny |
| `api` | The generated OpenAPI client; needs `lumoauth[api]` |

### `LumoAuthAgent`

```python
LumoAuthAgent(base_url=None, org_id=None, client_id=None, client_secret=None,
              skip_cert_validation=False, dpop=None, private_key=None, key_id=None,
              issuer=None, custom_domain=None)
```

`dpop` is `True` (ephemeral ES256 key), a `DpopKey` or a `DpopProofSigner`.

| Member | What it does |
|---|---|
| `authenticate(scopes=None)` | Client-credentials sign-in; returns `True` or `False` |
| `ensure_authenticated()` | Signs in again when the token is missing or about to expire |
| `access_token`, `token_type`, `token_scopes`, `agent_info` | Current token, its type (`Bearer` or `DPoP`), granted scopes and cached userinfo |
| `get_agent_info()` | Identity, capabilities and budget from userinfo |
| `has_capability(capability)` | `True` when the agent has the capability |
| `get_budget_status()`, `is_budget_exhausted()` | Budget policy, and whether today's budget is used up |
| `ask(action, context=None, *, traceparent=None)`, `is_allowed(...)` | Ask API |
| `get_identity()` | `GET /agents/me` |
| `authorize_mcp_tool(server_id, tool)` | Asks whether this agent may run a tool on a registered MCP server; returns `AgentMcpToolDecision` |
| `api_request(method, endpoint, *, data=None, json=None, params=None, timeout=30)` | Authenticated request; returns `requests.Response` |
| `register(name, description=None, capabilities=None, jwks_uri=None)` | Creates or updates the agent record |
| `get_mcp_token(mcp_server_id)` | MCP token bound to the server's https URL, or `None` (deprecated, with a `FutureWarning`) when the exchange fails; DPoP-bound when the agent has `dpop`. Prefer `get_mcp_credential()` |
| `get_mcp_credential(mcp_server_id)` | The same exchange as an `McpToken` (`token_type`, `expires_in`, `headers(method, url)`); raises on failure |
| `dpop`, `dpop_headers(method, url, *, access_token=None)`, `dpop_proof(method, url, *, access_token=None)` | The agent's `DpopProofSigner`; `Authorization: DPoP` plus a `DPoP` proof for one request; a bare proof |
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
DelegationChain(agent, *, redirect_uri=None, app_client_id=None, app_client_secret=None)
```

| Member | What it does |
|---|---|
| `get_consent_url(session_id, scopes=None, state=None, *, offline_access=False)` | Builds the consent URL for the application, with PKCE |
| `handle_consent_callback(session_id, authorization_code, *, state=None)` | Redeems the authorization code as the application |
| `set_user_token(session_id, access_token)` | Uses a user token that you already hold |
| `exchange(session_id, scopes=None, *, resource=None)` | Returns a delegated token |
| `request(session_id, method, endpoint, *, data=None, params=None, timeout=30)` | Request with the delegated token |
| `delegate_to_sub_agent(session_id, sub_agent_token, scopes=None, *, resource=None)` | Nested delegation |
| `revoke(session_id)`, `revoke_all()` | Revokes the person's refresh token as the application (`True`), or only forgets the session (`False`) |
| `active_sessions`, `has_delegation(session_id)` | Session state |
| `parse_actor_chain(token)`, `get_subject(token)` *(static)* | Inspect a delegated JWT |

### `AAuthClient`

```python
AAuthClient(agent_identifier, private_key_pem, *, base_url=None, org_id=None,
            kid="key-1", skip_cert_validation=False, custom_domain=None, issuer=None)
```

| Method | What it does |
|---|---|
| `generate_keypair()` *(static)* | Returns `(private_pem, jwks)` for a new Ed25519 key |
| `sign_request(method, url, *, body=None, content_type="application/json", agent_token=None, authorization="", signature_key="")` | Returns RFC 9421 signature headers |
| `request_authorization(resource_token, scope, *, agent_token=None, redirect_uri=None, timeout=30)` | Tokens, or `{"authorization_required": True, "auth_url": …, "request_token": …}` |
| `exchange_code(code, redirect_uri, *, agent_token, timeout=30)` | Redeems a consent code |
| `refresh(refresh_token, resource_token, *, scope=None, agent_token, timeout=30)` | Refreshes with a resource token from the same resource. `scope` only narrows |
| `signed_request(method, url, *, auth_token, data=None, timeout=30)` | Signed request with a Bearer token |
| `discover_issuer()`, `discover_resource(resource_url)` | Fetch `.well-known` metadata |
| `get_issuer()` | The AAuth issuer: the constructor's `issuer`, else the platform address built from `base_url` and `org_id`, else (with `custom_domain`) the `issuer` member of the issuer metadata document, read once. Never the custom domain |

`request_authorization()` raises `LumoAuthValidationError` without an
`agent_token`. LumoAuth ignores its `scope` argument: the resource token names
the scope. `sign_request()` does not cover `@query`, so sign only URLs without
a query string.

### `lumoauth.dpop`

| Name | What it does |
|---|---|
| `DpopKey.generate(alg="ES256")` | New P-256 (`ES256`), P-384, P-521 or Ed25519 (`EdDSA`) key |
| `DpopKey.from_pem(pem, password=None)`, `to_pem()` | Load and store the private key |
| `DpopKey.alg`, `public_jwk`, `thumbprint` | The JWS algorithm, the public JWK and its RFC 7638 thumbprint |
| `DpopProofSigner(key=None)` | Signs proofs; without a key it generates one |
| `create_proof(method, url, *, access_token=None, nonce=None)` | One `dpop+jwt` proof: `jti`, `htm`, `htu`, `iat`, `ath` with a token, `nonce` |
| `headers(method, url, access_token=None)` | `{"DPoP": proof}` plus `Authorization: DPoP …` with a token |
| `remember_nonce(url, nonce)`, `nonce_for(url)`, `observe_response(url, headers)` | Nonce memory per origin |

### `lumoauth.verify`

| Name | What it does |
|---|---|
| `verify_access_token(token, *, issuer=None, resource, jwks=None, fetch=None, clock_skew=60, require_dpop=False, dpop=None, replay_cache=None, now=None, custom_domain=None)` | Verifies a LumoAuth access token; returns `AccessTokenClaims` or raises `LumoAuthTokenError`. Pass `issuer`, or `custom_domain` for an organization on its own domain |
| `AccessTokenVerifier(issuer=None, resource=None, *, jwks=None, fetch=None, jwks_uri=None, clock_skew=60, require_dpop=False, replay_cache=None, proof_max_age=300, custom_domain=None)` | A verifier with its own JWKS and replay caches; `verify(token, *, dpop=None)` |
| `AccessTokenClaims` | `sub`, `iss`, `aud`, `exp`, `nbf`, `jti`, `scopes`, `scope`, `has_scope()`, `has_scopes()`, `missing_scopes()`, `is_agent`, `agent_id`, `capabilities`, `has_capability()`, `act`, `act_chain`, `actor`, `is_delegated`, `cnf`, `dpop_thumbprint`, `is_dpop_bound`, `token_use`, `claims`, `header` |
| `DpopRequest(method, url, proof, scheme="DPoP", nonce=None)` | What the incoming request carried, for the DPoP check |
| `InMemoryReplayCache`, `ReplayCache` | The default `jti` cache, and the protocol (`check_and_add(key, ttl) -> bool`) for your own |
| `JwksCache(issuer, *, jwks=None, fetch=None, jwks_uri=None, ttl=3600)` | Discovery plus JWKS cache with one refetch on an unknown `kid` |
| `verify_jit_token(token, *, issuer=None, org_id=None, custom_domain=None, caller=None, jwks=None, fetch=None, clock_skew=60, now=None)` | Verifies a LumoAuth JIT token; returns `JitTokenClaims` or raises `LumoAuthTokenError` (`JIT_TOKEN_INVALID`, `JIT_TOKEN_NOT_FOR_CALLER`) |
| `JitTokenVerifier(issuer=None, *, org_id=None, custom_domain=None, jwks=None, fetch=None, clock_skew=60)` | A JIT token verifier with its own JWKS cache; `verify(token, *, caller=None)` |
| `JitTokenClaims` | `authorization_details`, `covers(type, *, actions=None, locations=None, identifier=None)`, `subject`, `agent_id`, `exp`, `jti`, `task_id`, `request_id`, `claims` |

### Helpers

| Name | What it does |
|---|---|
| `require_capability(capability)` | Decorator for `LumoAuthAgent` methods; raises `PermissionError` when the capability is missing |
| `require_approval(agent, *, task_id, reason, on_behalf_of, impact="medium", meta=None, poll_interval_s=1.5, timeout_s=90)` | Sends a push approval and polls until it is answered; returns `ApprovalResult` |
| `ApprovalResult` | Frozen dataclass: `status`, `token`, `task_id`, `impact`, `reason`, `responded_at`, `approved_by` (`{"user_id": …}` or `None`) |

### `lumoauth.fastapi`

| Name | What it does |
|---|---|
| `lumo_auth_router(*, base_url=None, organization=None, client_id, client_secret=None, callback_path="/auth/callback", scope="openid profile email", post_login_redirect="/", post_logout_redirect="/", custom_domain=None, end_session_on_logout=True)` | Router with `/login`, `/callback` and `/logout`. Pass `base_url` and `organization`, or `custom_domain`. `/logout` ends the LumoAuth session too, unless `end_session_on_logout=False` |
| `LumoAuthFastAPI(base_url=None, organization=None, client_id, client_secret=None, …, end_session_on_logout=True)` | The same options as `lumo_auth_router()`, as an object |
| `lumo.router()` | Builds the router from the configuration |
| `lumo.access_token(request)` | Dependency that returns the user's access token, refreshed when it expires in less than 60 seconds; answers 401 or 503 |
| `lumo.end_session_url(*, id_token_hint=None, post_logout_redirect_uri=None, state=None)` | The end-session URL of the organization |
| `get_current_user(request)` | Dependency that returns `User` or `None` |
| `require_auth(scopes=None)` | Dependency factory that answers 401 or 403 |
| `require_access_token(*, issuer=None, resource, scopes=None, require_dpop=False, verifier=None, jwks=None, fetch=None, clock_skew=60, replay_cache=None, request_url=None, custom_domain=None)` | Dependency factory for resource servers: verifies the incoming LumoAuth token (and its DPoP proof) and returns `AccessTokenClaims`; answers 401 with `WWW-Authenticate` or 403 `insufficient_scope` |
| `parse_authorization(value)` | Splits an `Authorization` header into `("Bearer" or "DPoP", token)` |
| `User` | Pydantic model of the signed-in user |
| `LumoAuthPoppy(client, *, public_origin)` | Helper for routes that personal agents call. `client` is a `LumoAuth` client with `client_id` and `client_secret`; a missing `public_origin` raises `LumoAuthConfigError` |
| `poppy.install(app)` | Registers the handler that relays a refusal; call it once on each application |
| `poppy.session(required_scope=None, *, resource=None, allow_replay=False)` | Dependency factory: returns the `PoppyVerification` of a verified request (also `request.state.poppy`); a refusal is relayed unchanged and the route does not run |
| `poppy.verify(request, *, required_scope=None, resource=None, allow_replay=False)` | Verifies a request and returns the `PoppyVerification`, verified or refused |
| `poppy_refusal_response(verification)` | Builds the response for a refusal: its status, headers and body, unchanged |
| `PoppyRefusal`, `poppy_refusal_handler` | The exception that the dependency raises for a refusal, and its handler |
| `PoppyUnavailable`, `poppy_unavailable_response()` | The exception (a `PoppyRefusal`, with `cause`) for a request that could not be verified at all, and its `503` answer |

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
| `LumoAuthBudgetExceededError` (429, code `budget_exceeded`) | The agent used up a limit of its budget | Wait `err.retry_after` seconds (the start of the next window), or raise the limit on the agent |
| `LumoAuthConfigError: org_id is required` | The call is org-scoped and no slug is set | Pass `org_id` or set `LUMOAUTH_ORG_ID`. For an organization on its own domain, pass `custom_domain` |
| Every call to an organization on its own domain answers 404 | The domain is set as `base_url`, so the paths carry `/orgs/...` | Pass the domain as `custom_domain`, not as `base_url` |
| `authenticate()` returns `False` | Wrong client ID or secret, or the agent is suspended | Check the credentials; the log contains the HTTP status |
| FastAPI `/auth/login` answers 500 `session_middleware_missing` | `SessionMiddleware` is not added | Add `SessionMiddleware` before the router |
| After `/auth/logout` the user stays on LumoAuth's signed-out page | The absolute form of `post_logout_redirect` is not a registered post-logout redirect URI of the application | Add it under **Logout** in the application's configuration |
| The sign-in completes, but the next page is signed out again; the log shows a warning from `lumoauth.fastapi` about the cookie size | The session cookie is larger than the 4096 bytes that browsers keep | Request fewer scopes, or use a session middleware that keeps the data on the server |
| `LumoAuthPermissionDeniedError` (`insufficient_scope`) from a `client.poppy` call | The application lacks the `poppy:verify` scope | Add `poppy:verify` to the allowed scopes of the application |
| Every request of a personal agent is refused with `invalid_session`, and the description names another URL (`htu`) | `public_origin` is not the address that the personal agent called | Set `public_origin` to the public address, with the path prefix that your proxy removes |
| A route with `poppy.session()` answers 503 `temporarily_unavailable`, and the log shows a warning from `lumoauth.fastapi` | LumoAuth could not verify the request: the protocol is off for the organization (404), the application lacks `poppy:verify`, or LumoAuth is out of reach | Read the cause in the warning: switch the protocol on, or fix the application |
| A route with `poppy.session()` answers 500, and the log shows `LumoAuthConfigError` about the refusal handler | `poppy.install(app)` was not called on the application that serves the route | Call `poppy.install(app)`, also on a mounted application |

## Versioning and compatibility

| Item | Value |
|---|---|
| SDK version | The latest version is on the [PyPI page of `lumoauth`](https://pypi.org/project/lumoauth/). `pip install lumoauth` installs it. |
| Minimum LumoAuth server API | 1.0.0 |
| Python | 3.9 to 3.13 |

The notes for each release are in the
[`release-notes`](release-notes) folder. The SDK follows semantic versioning. Its routes come from the shared SDK
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
  sh -c 'pip install -q requests pytest cryptography fastapi httpx && PYTHONPATH=src python -m pytest -q'
```

The contract tests read `../sdk-contract`, or the path in `LUMO_SDK_CONTRACT`.
They are skipped when neither exists.

## Changelog

### Unreleased

- `DelegationChain` takes `app_client_id` and `app_client_secret`: the
  application that the person consents to. `get_consent_url()` then builds
  the URL with the application's client ID, PKCE (S256), a random `state`
  and `openid` (`offline_access=True` asks for a refresh token);
  `handle_consent_callback(..., state=)` redeems the code as the application;
  the application refreshes the person's token. Earlier releases used the
  agent's ID, which LumoAuth refuses; without `app_client_id` that path is
  kept with a `FutureWarning`. `revoke()` revokes the person's refresh token
  as the application and returns `True`; without the application's
  credentials or a refresh token it only forgets the session, logs a
  warning and returns `False` (earlier releases always returned `True`).
  `client.delegation.consent_url()` takes `code_challenge`, and
  `exchange_code()` takes `code_verifier`.
- New `verify_jit_token()`, `JitTokenVerifier` and `JitTokenClaims` in
  `lumoauth.verify` (also exported from `lumoauth`): local verification of a
  JIT token (`typ` `JWT`, `aud` = the organization), with `covers()` for the
  approved `authorization_details` and an optional check that the approval
  belongs to the caller. The rules are the same as in `lumoauth-fastmcp`.
- FastAPI `LumoAuthPoppy`: when the request cannot be verified at all
  (LumoAuth out of reach, protocol switched off, the application's own call
  refused), the route answers `503` `temporarily_unavailable` with
  `Cache-Control: no-store` and logs the cause. Earlier releases answered 500.
- `client.auth.token_exchange()` can authenticate the application:
  `client_id` with `client_secret` (HTTP Basic, or `client_auth_method=
  "client_secret_post"`) or with `client_assertion` (`private_key_jwt`).
  Earlier releases sent no client authentication, so only agents could use
  the call.
- `MAX_DELEGATION_DEPTH` is now 5, as LumoAuth enforces (a chain holds at
  most five actors). A deeper exchange in `DelegationChain` raises
  `LumoAuthApiError` (400 `invalid_request`) whose message starts with
  "Delegation chain too deep (max depth: 5)".
- `retry_after` of a 429 error also reads a `Retry-After` header in the HTTP
  date form (RFC 9110), as the seconds until that date. Earlier releases
  gave `None` for it.
- `agent.get_mcp_token()` still returns `None` when the exchange fails, but
  now also issues a `FutureWarning` with the reason. Returning `None` is
  deprecated; use `get_mcp_credential()`, which raises.
- `LumoAuthAgent.ask()`, `is_allowed()` and `client.agents.ask()` take
  `traceparent=`: the W3C header is sent with the request, so that the audit
  entries of the decision carry your trace ID.
- New `client.agents.attest(agent_id, attestation_token, *, scopes=None,
  dpop=None)` for workload attestation. It returns the new
  `WorkloadAttestation`. New `resource` argument on
  `client.auth.client_credentials()` (RFC 8707): the token's `aud` is then
  that address.
- A 429 with the body code `budget_exceeded` now raises
  `LumoAuthBudgetExceededError`, which is now a subclass of
  `LumoAuthRateLimitError` (status 429, `retry_after`). Earlier releases
  raised `LumoAuthRateLimitError` and never raised the budget error. `except
  LumoAuthRateLimitError` still catches it, and `code` stays
  `budget_exceeded`.
- FastAPI: the login route of `lumo_auth_router()` passes the query
  parameters `acr_values`, `max_age`, `resource`, `login_hint` and `prompt`
  on to LumoAuth (an allow-list, each value checked), for step-up and for a
  token for one API.
- FastAPI: `/auth/logout` of `lumo_auth_router()` now also ends the user's
  LumoAuth session. It revokes the refresh token and redirects through the
  end-session endpoint with `id_token_hint`; a relative
  `post_logout_redirect` is made absolute with the request's address, and it
  must be a registered post-logout redirect URI of the application. Earlier
  releases cleared only the local session, so the next sign-in completed
  without the sign-in page. `end_session_on_logout=False` keeps the old
  behaviour. New `client.auth.end_session_url()` builds the end-session URL.
  New `LumoAuthFastAPI.router()` and the dependency
  `LumoAuthFastAPI.access_token`, which refreshes the access token when it
  expires. The session no longer keeps `token_type`, keeps the ID token only
  when the sign-out needs it, and now keeps `expires_at`. A warning is logged
  when Starlette's session cookie passes 4096 bytes. Upgrade note: an own
  sign-out route that reads `session["__lumoauth"]["tokens"]["id_token"]`
  (as the FastAPI quickstart for 1.7.0 shows) keeps working, because the ID
  token stays at that key unless you pass `end_session_on_logout=False`. You
  can remove such a route and link to `/auth/logout` instead; then register
  the absolute form of `post_logout_redirect` as a post-logout redirect URI.
- New: custom domains. An organization can serve LumoAuth on its own domain,
  such as `https://auth.acme.com`. Pass `custom_domain=` to `LumoAuth`,
  `LumoAuthAgent`, `AAuthClient`, `verify_access_token()`,
  `AccessTokenVerifier`, `lumo_auth_router()` or `require_access_token()`,
  or set `LUMOAUTH_CUSTOM_DOMAIN`. The SDK then sends every request to the
  domain, with paths that have no `/orgs/{org_id}` segment, and `org_id` is
  not needed. The issuer is the bare domain: local token verification
  accepts exactly that issuer, and a client assertion names it in `aud`.
  The custom domain wins over `base_url`. New `client.issuer` and
  `client.custom_domain`. AAuth is the exception: its issuer stays the
  platform address on a custom domain, and the new `AAuthClient.get_issuer()`
  reads it from the issuer metadata document. Earlier releases put `/orgs/{org_id}` in every
  organization path, so each call to a custom domain answered 404.
- Capability matching follows the server's `<resource>:<action>` form
  (`invoices:read`, `invoices:*`). `normalize_capability()` now returns that
  form, and `capability_covers()`, `any_capability_covers()`,
  `has_capability()` and `@require_capability` honour the `prefix:*`
  wildcard. LumoAuth refuses the dot form (`invoices.read`) when you register
  a capability, request a scope for its API or call `agent.ask()`; the matcher
  reads a `.` as `:` only when it compares, for example with a dotted
  permission slug. A `-` is now part of a name: `invoices-read` no longer
  matches `invoices:read`.
- The default scope of `DelegationChain.get_consent_url()` and
  `client.delegation.consent_url()` is now `documents:read` (was
  `read:documents`), resource first like every other scope.
- New: DPoP (RFC 9449). `LumoAuthAgent(dpop=True)` or `dpop=DpopKey.from_pem(...)`
  binds the agent's token, its MCP token exchanges and its API requests to
  a key the agent holds. `lumoauth.dpop` has `DpopKey` and
  `DpopProofSigner`. `client.auth.client_credentials()`,
  `token_exchange()`, `refresh_token()`, `exchange_code()` and
  `client.mcp.get_token()` take `dpop=`. A `use_dpop_nonce` answer is
  retried once, and the latest nonce is kept per origin. New
  `agent.get_mcp_credential()` and `client.mcp.exchange()` return an
  `McpToken` with `token_type` and `headers(method, url)`; new
  `agent.token_type`, `agent.dpop_headers()` and `agent.dpop_proof()`.
- New: local verification of LumoAuth access tokens for MCP and API
  servers. `verify_access_token()` and `AccessTokenVerifier` in
  `lumoauth.verify` check the signature against the organization JWKS
  (found through the issuer's discovery document), `typ`, `iss`, `aud`,
  `exp`, `nbf`, refuse test tokens, and check the DPoP proof of a bound
  token (`cnf.jkt`, `htm`/`htu`/`ath`/`iat`, replayed `jti`). They raise
  the new `LumoAuthTokenError` with a stable `code`. New FastAPI dependency
  `require_access_token()`. New extras `lumoauth[dpop]` and
  `lumoauth[verify]` (both install `cryptography`).
- New `mcp.authorize_tool()` lets an MCP server ask whether a verified
  user or agent may run one tool. The server calls it with its own
  client-credentials token (scope `mcp:authorize`), not with the caller's
  token. New `agents.authorize_mcp_tool()` and
  `LumoAuthAgent.authorize_mcp_tool()` let an agent ask about itself. On
  both, a deny returns `allowed=False` and does not raise.
- New: Session verification for the Personal Agent Protocol.
  `client.poppy.verify_request()` asks LumoAuth who a request of a personal
  agent is from. It returns a `PoppyVerification`: a verified result, or a
  refusal with the exact response to relay. `client.poppy.get_session_status()`
  looks a Session up and `client.poppy.end_session()` ends one. The calls
  authenticate with HTTP Basic, with the new `client_id` and `client_secret`
  arguments of `LumoAuth` (`LUMOAUTH_CLIENT_ID`, `LUMOAUTH_CLIENT_SECRET`).
  The application needs the `poppy:verify` scope. New FastAPI helper
  `LumoAuthPoppy`: its dependency `poppy.session()` gives a route the
  verified result and relays a refusal unchanged, and
  `poppy_refusal_response()` relays one by hand. New pure function
  `build_poppy_verify_body()`.
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

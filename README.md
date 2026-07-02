# lumoauth

Python SDK for [LumoAuth](https://lumoauth.dev) agent authentication, capability
management, AAuth cryptographic identity, and Just-in-Time (JIT) permissions.

## Installation

```bash
pip install lumoauth
```

For AAuth protocol support (Ed25519 signing) install the optional `aauth` extra:

```bash
pip install lumoauth[aauth]
```

Or install from a local checkout:

```bash
pip install -e ./path/to/lumoauth        # core
pip install -e "./path/to/lumoauth[aauth]" # core + AAuth
```

## Environment variables

| Variable | Description | Default |
| --- | --- | --- |
| `LUMOAUTH_URL` | LumoAuth instance URL | `https://app.lumoauth.dev` |
| `LUMOAUTH_ORG_ID` | Organization ID | *(required)* |
| `AGENT_CLIENT_ID` | Agent OAuth client ID | *(required)* |
| `AGENT_CLIENT_SECRET` | Agent OAuth client secret | *(required)* |

All four can also be passed directly to the `LumoAuthAgent` constructor.

---

## Quick start

```python
from lumoauth import LumoAuthAgent

# Reads LUMOAUTH_URL, LUMOAUTH_ORG_ID, AGENT_CLIENT_ID, AGENT_CLIENT_SECRET
# from environment variables automatically.
agent = LumoAuthAgent()
agent.authenticate()

# Inspect capabilities and budget
info = agent.get_agent_info()
print(info["capabilities"])

# Automatically append 'Authorization' header with access token
# Assumes the endpoint is secured with LumoAuth as the identity provider
if agent.has_capability("read:documents"):
    resp = agent.api_request("GET", "https://my.api.endpoint.com/documents/123")
    print(resp.json())
```

---

## Core features

### Authentication

`LumoAuthAgent` uses the OAuth 2.0 **client-credentials** flow. Call
`authenticate()` once at startup — the SDK handles transparent token refresh
via `ensure_authenticated()`, which every other method calls automatically.

```python
agent = LumoAuthAgent()
agent.authenticate()

# The access token and granted scopes are available as properties
print(agent.access_token)
print(agent.token_scopes)
```

### Capability & budget introspection

```python
# Full agent info (sub, name, capabilities, budget_policy, …)
info = agent.get_agent_info()

# Check a single capability
if agent.has_capability("tool:search_web"):
    print("Search allowed")

# Budget awareness
budget = agent.get_budget_status()
if agent.is_budget_exhausted():
    print("Daily token budget reached — backing off")
```

### Authenticated API requests

```python
# Assumes the endpoint is secured with LumoAuth as the identity provider
# Automatically appends 'Authorization' header with the access token

# GET
resp = agent.api_request("GET", "https://my.api.endpoint.com/documents/123")

# POST with JSON body
resp = agent.api_request(
    "POST",
    "https://my.api.endpoint.com/documents",
    data={"query": "quarterly revenue"},
)
print(resp.json())
```

### MCP token exchange

Exchange the agent's token for one scoped to a secured MCP server (RFC 8693):

```python
mcp_token = agent.get_mcp_token("urn:mcp:financial-data")
```

### Subclassing with capability gates

The `@require_capability` decorator raises `PermissionError` if the agent
lacks the required capability when the method is called:

```python
from lumoauth import LumoAuthAgent, require_capability

class ResearchAgent(LumoAuthAgent):
    @require_capability("tool:search_web")
    def search(self, query: str) -> dict:
        return self.api_request(
            "POST",
            "https://my.api.endpoint.com/documents",
            data={"query": query},
        ).json()
```

---

## Delegation (Chain of Agency)

**Delegation** lets an agent act on behalf of a user — and optionally
delegate further to sub-agents — using
[RFC 8693 Token Exchange](https://www.rfc-editor.org/rfc/rfc8693). Every
resulting JWT carries an `act` (actor) claim so LumoAuth can trace exactly
who is behind each action.

### Basic flow

```python
from lumoauth import LumoAuthAgent
from lumoauth.delegation import DelegationChain

agent = LumoAuthAgent()
agent.authenticate()

chain = DelegationChain(agent, redirect_uri="https://agent.example.com/callback")

# 1. Generate the consent URL and redirect the user
url = chain.get_consent_url(
    "session_1",
    scopes=["read:documents", "write:documents"],
)
print(f"Redirect user to: {url}")

# 2. After the user grants consent and is redirected back:
chain.handle_consent_callback("session_1", authorization_code)

# 3. Get a delegated token via RFC 8693 token exchange
token = chain.exchange("session_1", scopes=["read:documents"])

# 4. Make API calls on behalf of the user
resp = chain.request(
    "session_1",
    "GET",
    "https://my.api.endpoint.com/documents/abc",
)
print(resp.json())
```

### Using a pre-existing user token

If you already have a user's access token (e.g. from an existing OAuth
session), skip the consent flow:

```python
chain = DelegationChain(agent)
chain.set_user_token("session_1", user_access_token)
token = chain.exchange("session_1")
```

### Nested delegation (agent → sub-agent)

Agents can delegate to other agents, creating an auditable chain of any
depth (up to 3 levels):

```python
# The sub-agent authenticates itself
sub_agent = LumoAuthAgent(
    client_id="agt_specialist_xyz",
    client_secret="secret_yyy",
)
sub_agent.authenticate()

# Create a nested delegation: user → orchestrator → specialist
nested_token = chain.delegate_to_sub_agent(
    "session_1",
    sub_agent.access_token,
    scopes=["read:documents"],
)
```

The resulting JWT contains nested `act` claims:

```json
{
  "sub": "user:alice",
  "act": {
    "sub": "agent:orchestrator",
    "act": {
      "sub": "agent:specialist"
    }
  }
}
```

### Inspecting the delegation chain

```python
# Parse the actor chain from any delegated token
actors = DelegationChain.parse_actor_chain(token)
# ["agent:orchestrator", "agent:specialist"]

subject = DelegationChain.get_subject(token)
# "user:alice"
```

### Revoking delegations

```python
# Revoke a single session
chain.revoke("session_1")

# Revoke all active sessions
chain.revoke_all()

# Check active sessions
print(chain.active_sessions)
print(chain.has_delegation("session_1"))
```

---

## Ask API

The **Ask API** is a lightweight preflight check — ask the server "can I do
this?" *before* invoking a tool. It's optimised for LLM tool-calling
patterns where you want a fast yes/no decision.

### Preflight check

```python
result = agent.ask("document.read", context={"id": "doc_99"})
# result → {"allowed": True, "action": "document.read",
#           "reason": "capability granted", "audit_id": "…", "context": {…}}

# Boolean shorthand
if agent.is_allowed("document.read"):
    # … proceed with tool call
    pass
```

### Self-inspection

`get_identity()` returns the agent's own identity, capabilities, and
workspace information — equivalent to `GET /agents/me`:

```python
me = agent.get_identity()
print(me["identity"]["id"])      # agent ID
print(me["capabilities"])         # list of granted capabilities
print(me["workspace"])            # workspace metadata
```

### Use with tool dispatch

```python
def dispatch_tool(agent, tool_name, args):
    """Only execute the tool if the Ask API confirms it's allowed."""
    if not agent.is_allowed(tool_name, context=args):
        return {"error": f"Agent is not authorised to run {tool_name}"}
    # … execute the tool
```

---

## AAuth protocol

AAuth extends OAuth 2.1 with **cryptographic agent identity**. Each agent
holds an Ed25519 private key, signs every HTTP request (RFC 9421), and
obtains proof-of-possession tokens that cannot be replayed.

> **Install extra:** `pip install lumoauth[aauth]`

### Generate a key pair

```python
from lumoauth.aauth import AAuthClient

private_pem, jwks = AAuthClient.generate_keypair()

# Save private_pem securely. Publish jwks at
# https://my-agent.example.com/.well-known/jwks.json
import json, pathlib
pathlib.Path("agent-key.pem").write_text(private_pem)
print(json.dumps(jwks, indent=2))
```

### Create an AAuth client

```python
client = AAuthClient(
    agent_identifier="https://my-agent.example.com",
    private_key_pem=open("agent-key.pem").read(),
    org_id="acme-corp",
)
```

### Direct authorisation (no user interaction)

When the agent has pre-approved access to a resource, the server returns
tokens directly:

```python
tokens = client.request_authorization(
    resource_token=resource_tok,
    scope="read write",
)
print(tokens["access_token"])
```

### User consent flow

If the resource requires user consent, `request_authorization()` returns the
URL to redirect the user to. After the user grants consent, exchange the
code:

```python
redirect_uri = "https://my-agent.example.com/callback"

result = client.request_authorization(
    resource_token=resource_tok,
    scope="read write",
    agent_token=agent_tok,
    redirect_uri=redirect_uri,
)

if result.get("authorization_required"):
    # Redirect user to result["auth_url"]
    print(f"Please visit: {result['auth_url']}")

    # After callback, exchange the code. redirect_uri must be the exact
    # URI the code was delivered to.
    code = "..."  # from the redirect query string
    tokens = client.exchange_code(code, redirect_uri, agent_token=agent_tok)
```

### Token refresh

A refresh requires a **fresh resource token** for the target resource;
the refresh token itself is not rotated:

```python
new_tokens = client.refresh(
    tokens["refresh_token"],
    fresh_resource_tok,
    agent_token=agent_tok,
)
```

### Signed requests to protected resources

Every request carries both a Bearer token **and** an Agent-Auth HTTP
message signature, binding the request to the agent's cryptographic
identity:

```python
resp = client.signed_request(
    "GET",
    "https://api.example.com/v1/data",
    auth_token=tokens["access_token"],
)
print(resp.json())

# POST with body
resp = client.signed_request(
    "POST",
    "https://api.example.com/v1/actions",
    auth_token=tokens["access_token"],
    data={"action": "analyse", "target": "report_q4"},
)
```

### Discovery

```python
# Authorisation server metadata
issuer = client.discover_issuer()
print(issuer["issuer"], issuer["token_endpoint"])

# Resource server metadata
resource = client.discover_resource("https://api.example.com")
print(resource["resource"], resource["auth_server"])
```

---

## JIT permissions

**Just-in-Time permissions** let an agent request exactly the access it
needs, precisely when it needs it, for a short window. Each request creates
an ephemeral task (sub-identity), requests specific permissions using
[RFC 9396 authorization_details](https://www.rfc-editor.org/rfc/rfc9396),
and obtains short-lived tokens that are revoked when the task completes.

### Basic flow

```python
from lumoauth import LumoAuthAgent
from lumoauth.jit import JITContext

agent = LumoAuthAgent()
agent.authenticate()

# JITContext cleans up automatically when used as a context manager
with JITContext(agent) as jit:
    # 1. Create an ephemeral task
    jit.create_task(name="Analyse Q4 Financial Report", task_type="analysis")

    # 2. Request specific permission (RFC 9396)
    result = jit.request_permission(
        {
            "type": "file_access",
            "actions": ["read"],
            "identifier": "quarterly_report_q4_2024.pdf",
            "locations": ["https://storage.acme-corp.com/finance/"],
        },
        justification="User asked: 'What were our Q4 revenues?'",
    )

    # 3. Exchange approval for a short-lived token
    if result["status"] == "approved":
        jit_token = jit.get_token(result["request_id"])

        # 4. Use the token to access the resource
        resp = jit.call(
            jit_token,
            "GET",
            "https://storage.acme-corp.com/finance/quarterly_report_q4_2024.pdf",
        )
        print(f"Read {len(resp.content)} bytes")

    elif result["status"] == "denied":
        print(f"Permission denied: {result.get('deny_reason')}")
# ← task is completed and all JIT tokens are revoked here
```

### Acting on behalf of a user

Use `delegate_on_behalf_of()` to exchange the agent + user tokens for a
delegated token (RFC 8693). All subsequent JIT requests are made "as the
user, via the agent":

```python
with JITContext(agent) as jit:
    # user_token comes from the user's OAuth login flow
    jit.delegate_on_behalf_of(user_token)

    jit.create_task(
        name="Look up Alice's calendar",
        on_behalf_of="alice@acme-corp.com",
    )

    result = jit.request_permission(
        {"type": "calendar_access", "actions": ["read"]},
        justification="User asked: 'What's on my calendar today?'",
    )
    # …
```

### Human-in-the-loop (HITL) approval

High-risk requests (e.g. write access, PII) are not auto-approved — they
enter a **pending** state and wait for a human approver. By default,
`request_permission()` polls automatically:

```python
# Blocks up to 5 minutes waiting for an admin to approve
result = jit.request_permission(
    {"type": "database_access", "actions": ["write"], "identifier": "users_table"},
    justification="Need to update email for user 42",
    ttl=300,
    poll_timeout=300,
)

# Or skip waiting and handle it yourself
result = jit.request_permission(
    {"type": "database_access", "actions": ["write"], "identifier": "users_table"},
    wait_for_approval=False,
)
if result["status"] == "pending":
    print(f"Waiting for approval — check status at {result['status_url']}")
```

### Auto-escalation on 403

`call_with_escalation()` handles the full 403 → JIT request → retry flow
automatically. When a resource returns `403` with an
`Insufficient-Authorization-Details` header, the SDK parses it, requests the
missing permission, obtains a JIT token, and retries:

```python
with JITContext(agent) as jit:
    jit.create_task(name="Ad-hoc data access")

    # This will automatically escalate if the first request returns 403
    resp = jit.call_with_escalation(
        "GET",
        "https://api.acme-corp.com/v1/documents/doc_9982",
        justification="User asked for summary of doc_9982",
    )
    print(resp.json())
```

### Manual task lifecycle

If you prefer not to use the context manager:

```python
jit = JITContext(agent)
jit.create_task(name="My task")
try:
    # … request permissions, get tokens, call APIs
    pass
finally:
    jit.complete_task()  # always clean up
```

---

## End-to-end examples

### Research agent with Ask API + JIT

```python
from lumoauth import LumoAuthAgent, require_capability
from lumoauth.jit import JITContext


class ResearchAgent(LumoAuthAgent):
    @require_capability("tool:search_web")
    def search_web(self, query: str) -> dict:
        return self.api_request(
            "POST",
            f"/orgs/{self.org_id}/api/v1/tools/search",
            data={"query": query},
        ).json()

    def read_document(self, doc_url: str, justification: str) -> bytes:
        """Read a protected document via JIT."""
        with JITContext(self) as jit:
            jit.create_task(name=f"Read {doc_url}")
            resp = jit.call_with_escalation(
                "GET", doc_url, justification=justification,
            )
            resp.raise_for_status()
            return resp.content


agent = ResearchAgent()
agent.authenticate()

# Preflight: check if we're allowed to search
if agent.is_allowed("tool:search_web"):
    results = agent.search_web("LumoAuth JIT permissions")
    print(results)

# JIT-protected document access
content = agent.read_document(
    "https://storage.acme-corp.com/reports/q4.pdf",
    justification="User asked for Q4 summary",
)
```

### AAuth + JIT combined

```python
from lumoauth.aauth import AAuthClient
from lumoauth.jit import JITContext
from lumoauth import LumoAuthAgent

# 1. AAuth: obtain a proof-of-possession token
aauth = AAuthClient(
    agent_identifier="https://my-agent.example.com",
    private_key_pem=open("agent-key.pem").read(),
    org_id="acme-corp",
)
tokens = aauth.request_authorization(
    resource_token=resource_tok,
    scope="read write",
)

# 2. JIT: request fine-grained access with the agent's identity
agent = LumoAuthAgent()
agent.authenticate()

with JITContext(agent) as jit:
    jit.create_task(name="Signed data access")
    result = jit.request_permission(
        {"type": "api_access", "actions": ["read"], "identifier": "/v1/data"},
        justification="Cryptographically-signed agent needs read access",
    )
    if result["status"] == "approved":
        jit_token = jit.get_token(result["request_id"])
        # Use the JIT token with AAuth signing for defence in depth
        resp = aauth.signed_request(
            "GET",
            "https://api.example.com/v1/data",
            auth_token=jit_token,
        )
        print(resp.json())
```

---

## API reference

### `LumoAuthAgent`

| Method | Description |
| --- | --- |
| `authenticate(scopes=None)` | OAuth 2.0 client-credentials authentication |
| `ensure_authenticated()` | Transparent token refresh |
| `get_agent_info()` | Fetch identity & capabilities from UserInfo |
| `has_capability(cap)` | Check a specific capability |
| `get_budget_status()` | Return budget policy dict |
| `is_budget_exhausted()` | `True` if daily token budget is reached |
| `ask(action, context=None)` | Ask API preflight check |
| `is_allowed(action, context=None)` | Boolean shorthand for `ask()` |
| `get_identity()` | Agent self-inspection (`GET /agents/me`) |
| `api_request(method, endpoint, …)` | Authenticated HTTP request |
| `get_mcp_token(mcp_server_id)` | RFC 8693 token exchange for MCP servers |

### `AAuthClient`

| Method | Description |
| --- | --- |
| `generate_keypair()` *(static)* | Generate Ed25519 key pair + JWKS |
| `sign_request(method, url, …)` | RFC 9421 HTTP message signature headers |
| `request_authorization(resource_token, scope, …)` | Obtain auth token (direct or user-consent) |
| `exchange_code(code, redirect_uri)` | Exchange consent code for tokens |
| `refresh(refresh_token, resource_token, scope=None)` | Refresh an auth token (fresh resource token required) |
| `signed_request(method, url, auth_token=…, …)` | Authenticated + signed HTTP request |
| `discover_issuer()` | Fetch `/.well-known/aauth-issuer` |
| `discover_resource(resource_url)` | Fetch `/.well-known/aauth-resource` |

### `JITContext`

| Method | Description |
| --- | --- |
| `delegate_on_behalf_of(user_token)` | RFC 8693 token exchange for delegation |
| `create_task(name=…, task_type=…, on_behalf_of=…)` | Create ephemeral task |
| `complete_task()` | Complete task & revoke all JIT tokens |
| `request_permission(authorization_details, …)` | RFC 9396 JIT permission request with optional HITL polling |
| `get_token(request_id)` | Exchange approval for short-lived JIT token |
| `call(jit_token, method, url, …)` | Make an API call with a JIT token |
| `call_with_escalation(method, url, …)` | Auto-escalate on 403 (parse header → request → retry) |

### `require_capability`

Decorator for `LumoAuthAgent` methods. Raises `PermissionError` if the
agent lacks the named capability.

---

## Changelog

### 0.2.0

**Breaking fixes** — the AAuth client now matches the AAuth 1.0 server
contract for the agent token endpoint:

- `AAuthClient.exchange_code(code, redirect_uri, *, agent_token)`: the
  second parameter is now `redirect_uri` (previously `request_token`).
  The server's `request_type=code` redemption requires `code` +
  `redirect_uri` and never accepted `request_token`; the code is bound to
  the exact redirect URI it was delivered to.
- `AAuthClient.refresh(refresh_token, resource_token, *, scope=None,
  agent_token)`: a fresh `resource_token` for the target resource is now a
  required second positional parameter (the server rejects
  `request_type=refresh` without it), and `scope` became keyword-only.

## License

Apache-2.0

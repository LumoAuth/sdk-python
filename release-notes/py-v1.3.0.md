# LumoAuth Python SDK v1.3.0 (`py-v1.3.0`)

**Release Date:** November 5, 2026  
**Tag:** `py-v1.3.0`

## Packages Updated

| Package | Version |
| :--- | :--- |
| `lumoauth` | `1.3.0` |

---

## Highlights & New Features

### 1. Private Key JWT (`private_key_jwt`) Agent Authentication (`lumoauth`)

Agents registered with the **Private key JWT** identity type can now authenticate without a client secret by signing short-lived RFC 7523 JWT client assertions (`urn:ietf:params:oauth:client-assertion-type:jwt-bearer`, `typ: client-authentication+jwt`).

- Added `ClientAssertionSigner`, `CLIENT_ASSERTION_TYPE`, and `issuer_for` (`src/lumoauth/client_assertion.py`) with support for `ES256`, `ES384`, `ES512`, `EdDSA` (Ed25519), `RS256`–`RS512`, and `PS256`–`PS512` (RSA ≥ 2048 bits):
  - `ClientAssertionSigner.generate(alg="ES256", key_id=...)` to generate key pairs and export `public_jwk()`, `jwks()`, and `to_pem()`.
  - `ClientAssertionSigner.from_pem(pem, key_id=..., password=..., alg=..., lifetime=60)` to load PEM private keys (PKCS#8, SEC 1, or PKCS#1).
  - Single-use assertion generation via `signer.create(client_id, audience)` with random `jti` and configurable lifetime (default `60s`, max `600s`).
- Extended `LumoAuthAgent` (`src/lumoauth/agent.py`) with:
  - `private_key` parameter (accepts a `ClientAssertionSigner`, PEM `str`, or `bytes`; defaults to `AGENT_PRIVATE_KEY`).
  - `key_id` parameter (defaults to `AGENT_KEY_ID`).
  - `issuer` parameter for custom domains (defaults to `{base_url}/orgs/{org_id}/api/v1` via `issuer_for`).
  - `agent.client_assertion()` and `agent.client_assertion_signer`.
  - Strict validation ensuring `client_secret` and `private_key` are mutually exclusive.
- Extended `AuthResource.client_credentials()` (`src/lumoauth/resources/auth.py`) to accept an optional `client_assertion` keyword argument as an alternative to `client_secret`.

```python
from lumoauth import ClientAssertionSigner, LumoAuthAgent

agent = LumoAuthAgent(
    client_id="agt_0123456789abcdef",
    private_key=ClientAssertionSigner.from_pem(
        open("agent-private-key.pem").read(),
        key_id="agent-2026-11",
    ),
)
agent.authenticate()
```

### 2. W3C `traceparent` Support & JIT / RAR Token Claim Helpers (`lumoauth.resources.mcp`, `lumoauth.verify`)

- **MCP Tool Authorization Tracing**: Added optional `traceparent` keyword argument to `McpResource.authorize_tool()` (`src/lumoauth/resources/mcp.py`) to forward the W3C `traceparent` header and correlate MCP authorization decisions in LumoAuth's audit log with the caller's distributed trace.
- **Access Token Claim Helpers**: Extended `AccessTokenClaims` (`src/lumoauth/verify.py`) with new properties for inspecting Rich Authorization Requests (RFC 9396), JIT tokens, and distributed trace context:
  - `authorization_details`: Returns top-level and `permissions`-nested RFC 9396 `authorization_details` entries.
  - `is_jit`: Returns `True` when the token is a task-bound JIT token (`jit: true` or `permissions.jit_request_id`) or carries `authorization_details`.
  - `traceparent`: Extracts the W3C `traceparent` associated with the request or token (`_traceparent` or `traceparent`).
  - `trace_id`: Extracts the 32-hex W3C trace ID from token claims (`_trace_id`, `trace_id`, or `act.trace_id`).

---

## Commit Log (`py-v1.2.0..py-v1.3.0`)

- `e95e121` — `release: lumoauth@1.3.0`
- `a65f665` — `feat: implement private key JWT support for agent authentication and client assertions`
- `4e9b5a3` — `feat(mcp, verify): add traceparent support for authorization and token claims`

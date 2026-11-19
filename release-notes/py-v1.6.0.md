# LumoAuth Python SDK v1.6.0 (`py-v1.6.0`)

**Release Date:** November 18, 2026  
**Tag:** `py-v1.6.0`

## Packages Updated

| Package | Version |
| :--- | :--- |
| `lumoauth` | `1.6.0` |

---

## Highlights & New Features

### 1. Capabilities in `<resource>:<action>` Form (`lumoauth.capabilities`)

An agent capability is one of the agent's OAuth scope values. LumoAuth now writes every capability as `<resource>:<action>`, such as `invoices:read`, with the wildcard `invoices:*`. The SDK's capability matching follows the server again.

- `normalize_capability()` now returns the server's canonical form, with `:` between the parts. It trims the name, lower-cases ASCII letters, turns every `.` into `:`, collapses runs of `:` and trims `:` from both ends.
- A `-` is now part of a name, not a separator. `pull-requests:comment` is one resource and one action, and `invoices-read` is a different capability from `invoices:read`.
- A name that ends in `:*` covers every action under that prefix, at any depth, but not the prefix itself. `invoices:*` covers `invoices:read` and `invoices:read:draft`, but not `invoices`.
- A `.` is still read as `:` when the SDK compares. A dotted permission slug such as `invoices.read` matches the held `invoices:read`, and a capability stored as `invoices.*` still covers `invoices:read`.
- The same rules apply in all of these places:
  - `normalize_capability()`, `capability_covers()` and `any_capability_covers()`
  - `LumoAuthAgent.has_capability()` and the `@require_capability` decorator
  - `AccessTokenClaims.has_capability()` for verified tokens
- `AccessTokenClaims.has_scope()` still compares scopes exactly.

| Input to `normalize_capability()` | 1.5.0 | 1.6.0 |
| :--- | :--- | :--- |
| `"Invoices:Read"` | `"invoices.read"` | `"invoices:read"` |
| `"Invoices.Read"` | `"invoices.read"` | `"invoices:read"` |
| `"invoices-read"` | `"invoices.read"` | `"invoices-read"` |

```python
from lumoauth import capability_covers, normalize_capability

normalize_capability("Pull-Requests:Comment")   # "pull-requests:comment"
capability_covers("users:*", "USERS.DELETE")    # True
capability_covers("users:*", "users-delete")    # False: "-" is part of a name
capability_covers("invoices:*", "invoices")     # False
```

### 2. AAuth Consent Responses and Issuer Discovery (`lumoauth.aauth`)

`AAuthClient` now reads LumoAuth's AAuth responses correctly.

- **Consent is detected on `200`.** When the user has to consent, LumoAuth answers `request_authorization()` with `200`, a `request_token` and an `authorization_uri`, and no `auth_token`. The method now returns that response with `"authorization_required": True` and `auth_url` added. `auth_url` has the same value as `authorization_uri`. In 1.5.0 this response came back unchanged, so code that checked `authorization_required` read it as a token response.
- **A `401` is now an error.** LumoAuth answers `401` (`authentication_required`) when it rejects the agent token or the signature. `request_authorization()` now raises `LumoAuthApiError` with `status_code` 401. In 1.5.0 every `401` came back as a consent request with an empty `auth_url`. A `401` that does carry a consent address is still returned as a consent request.
- **`discover_issuer()` reads the right address.** It now fetches `{base_url}/orgs/{org_id}/api/v1/.well-known/aauth-issuer`, the issuer URL of the organization. In 1.5.0 it fetched `/.well-known/aauth-issuer` at the host root, which answers 404.

```python
result = client.request_authorization(
    resource_tok, "documents:read",
    agent_token=agent_tok,
    redirect_uri="https://agent.example.com/callback",
)

if result.get("authorization_required"):
    # Keep result["request_token"], then send the user to the consent page.
    redirect(result["auth_url"])
else:
    auth_token = result["auth_token"]
```

### 3. Resource-First Scopes in Defaults and Examples (`lumoauth`)

- `DelegationChain.get_consent_url()` and `client.delegation.consent_url()` now ask for `documents:read` when you pass no scopes. Earlier releases asked for `read:documents`.
- When a token exchange is refused with 403, the `DelegationChain` error message now reads `Token exchange forbidden — the agent may not be allowed to act on behalf of users`. Earlier releases named a `delegate:on_behalf` capability.
- Every scope and capability example in the docstrings now puts the resource first: `documents:read`, `web:search`, `admin:read`.
- The `LumoAuth` docstring examples now show an organization API key as `lmk_…`.

---

## Upgrade Notes

- **`normalize_capability()` returns a different string.** It now returns `invoices:read` where 1.5.0 returned `invoices.read`. Update any code that stores or compares its output.
- **A `-` no longer matches a `:` or a `.`.** `has_capability("invoices-read")` is now `False` for an agent that holds `invoices:read`, and a held `users:*` no longer covers `users-delete`. This also applies to `@require_capability` and to `AccessTokenClaims.has_capability()` in MCP servers. Write these names as `<resource>:<action>`.
- **Register capabilities and request scopes in `<resource>:<action>` form.** LumoAuth refuses the dot form (`invoices.read`) when you register a capability, request a scope for its API or call `agent.ask()`. The SDK does not check this before it sends the request.
- **The default scope for delegation changed.** If your code calls `get_consent_url()` or `consent_url()` without scopes and expects `read:documents`, pass `scopes=["read:documents"]`.
- **Catch `LumoAuthApiError` around `request_authorization()`.** A refused agent token or signature now raises instead of returning `authorization_required`.
- **Check for messages that changed.** If your code matches the text of the token exchange 403 error, update it to the new message.
- No dependency changes in this release.

---

## Documentation & Tests

- Updated `README.md`:
  - "Capabilities, budget and identity" explains the `<resource>:<action>` form, the `prefix:*` wildcard, and why `invoices-read` is a different capability.
  - Every example for capabilities, scopes, the Ask API, delegation and client credentials now puts the resource first.
  - The AAuth section says that the scope of an auth token comes from the resource token, and that LumoAuth ignores the `scope` argument of `request_authorization()`.
  - The AAuth refresh step says that a refresh needs a resource token from the same resource as the original grant, and that `scope` only narrows. A scope outside the grant is refused with `invalid_scope`.
  - The AAuth reference says that `sign_request()` does not cover `@query`, so sign only URLs without a query string. The SDK also does not wrap the `exchange` request type.
- Clarified the `AAuthClient` docstrings:
  - `sign_request()` does not return the `Authorization` or `Signature-Key` headers that it covers. Send the same values yourself. A `Signature-Key` must use the label `sig1`.
  - `refresh()` never widens the scope, and the response carries no new refresh token.
- Added the release notes for 1.5.0 to the repository (`release-notes/py-v1.5.0.md`).
- Updated `tests/test_capabilities.py` for the new form. It still runs the shared contract cases in `sdk-contract/vectors/agent-capabilities.json`, which are now in the `<resource>:<action>` form. Point `LUMO_SDK_CONTRACT` at a contract checkout with those cases. Without a checkout, the contract cases are skipped.
- Added `TestRequestAuthorization` and `TestDiscoverIssuer` to `tests/test_aauth.py`. They cover the `200` consent response, an unchanged token response, the `401` error and the issuer address.
- Added a test for the default delegation scope to `tests/test_agent_compat.py`, and moved the other test fixtures to resource-first scopes.

---

## Commit Log (`py-v1.5.0..py-v1.6.0`)

- `2161ccd` — `release: lumoauth@1.6.0`
- `a0cf9b0` — `feat: update capability format to use <resource>:<action> syntax across documentation and code`
- `8a3ea44` — `feat: update README and AAuth client to clarify token handling and consent flow`
- `270a443` — `feat: add release notes for LumoAuth Python SDK v1.5.0 with LangGraph approval gate example`

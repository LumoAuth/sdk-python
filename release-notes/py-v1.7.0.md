# LumoAuth Python SDK v1.7.0 (`py-v1.7.0`)

**Release Date:** November 26, 2026  
**Tag:** `py-v1.7.0`

## Packages Updated

| Package | Version |
| :--- | :--- |
| `lumoauth` | `1.7.0` |

The `client.poppy` calls need a LumoAuth server that has these three endpoints:

- `POST /orgs/{orgId}/api/v1/poppy/sessions/verify`
- `POST /orgs/{orgId}/api/v1/poppy/sessions/status`
- `POST /orgs/{orgId}/api/v1/poppy/sessions/end`

---

## Highlights & New Features

### 1. Verify Requests from Personal Agents (`client.poppy`, `lumoauth.fastapi`)

A personal agent that follows the [Personal Agent Protocol](https://personalagentprotocol.org) sends the `Poppy-Session` header to your own API, not to LumoAuth. The new `client.poppy` namespace asks LumoAuth who such a request is from: the personal agent, its user, the Session, and the account when the request carries an access token.

- **Three calls.** `client.poppy.verify_request()`, `client.poppy.get_session_status()` and `client.poppy.end_session()`.
- **The calls authenticate as a confidential application.** They send its client ID and secret with HTTP Basic. They never send the API key or the token of the client. The allowed scopes of the application must include `poppy:verify`.
- **`LumoAuth` has two new arguments for these credentials:** `client_id` and `client_secret`. Without them, the client reads `LUMOAUTH_CLIENT_ID` and `LUMOAUTH_CLIENT_SECRET`. Only the `client.poppy` calls use the values.
- **A refusal is a result, not an error.** `verify_request()` returns a `PoppyVerification` with `active=False`. Its `response` is a `PoppyResponse(status, headers, body)`: the exact response for the personal agent. Send it unchanged. When `body` is `None`, send no body and no `Content-Type`.
- **An SDK error is about your service.** The call raises when LumoAuth could not be reached or rejected your own application: `LumoAuthAuthenticationError` (401), `LumoAuthPermissionDeniedError` (403), `LumoAuthNotFoundError` (404), `LumoAuthRateLimitError` (429) or `LumoAuthNetworkError`. Never relay such an error to the personal agent. Answer with a `5xx` status.
- **A malformed answer is never read as verified.** A `200` answer that is neither a verified result nor a well-formed refusal raises `LumoAuthValidationError`.
- **Only the protocol's headers leave your service.** You may pass every header of the request. The SDK sends five: `Poppy-Session`, `Poppy-Version`, `Poppy-Extensions`, `Authorization` and `DPoP`. `POPPY_FORWARDED_HEADERS` lists them.

**FastAPI.** `LumoAuthPoppy` from `lumoauth.fastapi` gives you a dependency for the routes that personal agents call.

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


@app.get("/api/orders")
def orders(who: PoppyVerification = Depends(poppy.session("orders:read"))):
    return {"account": who.account.sub, "orders": []}
```

- `poppy.session(required_scope=None, *, resource=None, allow_replay=False)` builds the dependency. It returns the `PoppyVerification` of a verified request and also stores it as `request.state.poppy`. It does not read the request body.
- For a refusal, the route does not run. `poppy.install(app)` registers the handler that relays the response of LumoAuth unchanged. Call it on every FastAPI application that has such routes, including a mounted application.
- For an SDK error, the route does not run and FastAPI answers with its normal `500` response. The error message does not reach the personal agent.
- `poppy.verify(request)` is the same check as a method, for a route that needs more control. `poppy_refusal_response(who)` then builds the response for a refusal.

**`public_origin` comes from your configuration.** A Session JWT names the address that the personal agent called. The helper builds the URL from `public_origin` and the raw path of the request, without the query. It never reads the `Host` header or the `X-Forwarded-*` headers. A missing `public_origin` raises `LumoAuthConfigError` when you create the helper.

**Other frameworks.** Call `client.poppy.verify_request(method, url, headers, required_scope=...)` yourself. `build_poppy_verify_body()` builds the same request body from a public origin and a raw request target, without I/O.

**Sessions.** `get_session_status(personal_agent, sid)` returns a `PoppySessionStatus` with `status` `"active"`, `"ended"` or `"unknown"`. An unknown Session is a result, not an error. `end_session(personal_agent, sid)` returns `True`, or `False` when the Session had ended before. It raises `LumoAuthNotFoundError` for an unknown Session.

New public names in `lumoauth`: `PoppyVerification`, `PoppySessionInfo`, `PoppyAccount`, `PoppyResponse`, `PoppySessionStatus`, `build_poppy_verify_body` and `POPPY_FORWARDED_HEADERS`. New in `lumoauth.fastapi`: `LumoAuthPoppy`, `PoppyRefusal`, `poppy_refusal_handler` and `poppy_refusal_response`.

### 2. Custom Domains (`lumoauth`, `lumoauth.fastapi`)

An organization can serve LumoAuth on its own domain, for example `https://auth.acme.com`. Before this release, the SDK put `/orgs/{org_id}` in every organization path. A custom domain does not serve such a path, so every call to it got 404. The new argument `custom_domain` fixes that.

```python
from lumoauth import LumoAuth

client = LumoAuth(custom_domain="auth.acme.com", api_key="lmk_…")

if client.permissions.check("document.edit"):   # POST https://auth.acme.com/api/v1/authz/check
    print("Allowed")

print(client.issuer)                            # https://auth.acme.com
```

With a custom domain:

- **No path has the `/orgs/...` segment.** A path that never had the segment, such as `/api/v1/authz/check`, stays the same.
- **The organization ID is not needed.** When you pass `org_id` too, the SDK never puts it in a path.
- **The custom domain wins over `base_url`.** The SDK sends no request to the base URL.
- **The issuer is the bare domain**, `https://auth.acme.com`. A client assertion names it in `aud`. Local token verification accepts exactly that issuer, and a token that names the platform issuer is refused with `TOKEN_WRONG_ISSUER`.

| Entry point | With `custom_domain` |
| :--- | :--- |
| `LumoAuth`, and each namespace below it (`client.poppy` too) | Every call goes to the domain |
| `LumoAuthAgent` | Sign-in, the Ask API, MCP token exchange and `api_request()` use the domain. `JITContext`, `DelegationChain` and `require_approval()` follow their agent. |
| `AAuthClient` | The token endpoint and the issuer metadata are on the domain, and the request signature covers that URL. The AAuth issuer stays the platform address. |
| `verify_access_token()`, `AccessTokenVerifier` | The token must name the domain as its issuer. Leave `issuer` out. |
| `lumo_auth_router()`, `require_access_token()` | Sign-in, token and userinfo addresses are on the domain. `LumoAuthPoppy` follows its client. |

- **The environment variable is `LUMOAUTH_CUSTOM_DOMAIN`.** `LumoAuth`, `LumoAuthAgent` and `AAuthClient` read it. The verification functions and the FastAPI helpers take the argument only.
- **The value** is a host name or an `https://` origin. The SDK changes it to `https://<host>[:port]` in lower case. `http://` is accepted only for `localhost`, `127.0.0.1` and `[::1]`. A value with a path, a query, a fragment or credentials raises `LumoAuthConfigError` when you create the client. An empty value means that no custom domain is set.
- **New attributes:** `client.issuer` and `client.custom_domain`.

**AAuth keeps the platform issuer.** LumoAuth names the AAuth issuer with the platform address on every host, for example `https://app.lumoauth.dev/orgs/acme-corp/api/v1`. An AAuth token carries that address as `iss`, and an agent addresses it as the audience. So `AAuthClient` sends its requests to the custom domain, but it never builds the AAuth issuer from the domain.

- The new method `AAuthClient.get_issuer()` returns the AAuth issuer. With a custom domain it reads the `issuer` member of `https://auth.acme.com/api/v1/.well-known/aauth-issuer` once and keeps the value.
- The new argument `issuer=` of `AAuthClient` sets the issuer yourself. No request is then made.
- `discover_issuer()` reads the document on the custom domain, without the segment.

**Paths that you write yourself.** `agent.api_request()` and `DelegationChain.request()` take a path. On a custom domain, give the path without the `/orgs/...` segment. When `org_id` is set, the SDK removes the segment of that organization from a path. It leaves every other path unchanged.

**The generated client.** `client.api` also sends its requests to the domain, without the segment. Its methods still take an `org_id` argument. Pass any value, because the SDK does not send it.

---

## Upgrade Notes

- **Nothing changes for a client without a custom domain.** Every address on the LumoAuth host is the same as in 1.6.0.
- **If your organization has a custom domain, pass it as `custom_domain`, not as `base_url`.** A client that gets the domain as `base_url` still sends `/orgs/...` paths, and the domain answers 404.
- **Leave `issuer` out when you pass `custom_domain` to the verifiers.** `verify_access_token()`, `AccessTokenVerifier` and `require_access_token()` raise `LumoAuthConfigError` when the two name different issuers. If you set `issuer=` on `LumoAuthAgent` for a custom domain before, use `custom_domain=` now.
- **Tokens must come from the custom domain.** A verifier with `custom_domain` accepts only tokens whose issuer is the bare domain. A token that was issued through the platform address names the platform issuer and is refused.
- **Check your environment for `LUMOAUTH_CUSTOM_DOMAIN`.** When the variable is set, `LumoAuth`, `LumoAuthAgent` and `AAuthClient` use the domain, also when you pass `base_url` in code.
- **`issuer` is now optional in three signatures.** It is a keyword argument with the default `None` in `verify_access_token()` and `require_access_token()`, and the first argument of `AccessTokenVerifier` has the default `None`. Existing calls need no change. A call with neither `issuer` nor `custom_domain` raises `LumoAuthConfigError`.
- **`base_url` and `organization` are now optional in `lumo_auth_router()`.** Pass both, or pass `custom_domain`.
- **To use `client.poppy`, set up a confidential application.** Add `poppy:verify` to its allowed scopes under **Applications**, and pass its `client_id` and `client_secret`. Without both values, each call raises `LumoAuthConfigError` before it sends a request.
- **Set `public_origin` to the address that personal agents call.** Behind a proxy that removes a path prefix, put the prefix in `public_origin`, for example `https://example.com/shop`. With a wrong value, every personal agent gets `invalid_session`, and the description names another URL (`htu`).
- **Call `poppy.install(app)`.** Without it, a refused request answers `500`, and the log shows a `LumoAuthConfigError` about the refusal handler.
- **Verify each request once.** LumoAuth accepts each Session JWT one time. Use one dependency per route, and do not cache a result. A service that checks one request in several places passes `allow_replay=True`.
- **The FastAPI helper needs the `fastapi` extra:** `pip install "lumoauth[fastapi]"`.
- No dependency changes in this release.

---

## Documentation & Tests

- Updated `README.md`:
  - Two new guides: "Use a custom domain" and "Verify requests from personal agents".
  - The reference has a section for `client.poppy`, the `Poppy…` types and the FastAPI helper.
  - The configuration tables list `custom_domain`, `client_id` and `client_secret`, and the environment table lists `LUMOAUTH_CUSTOM_DOMAIN`, `LUMOAUTH_CLIENT_ID` and `LUMOAUTH_CLIENT_SECRET`.
  - The AAuth section says that the AAuth issuer is always the platform address.
  - The troubleshooting table has four new rows, for custom domains and for requests from personal agents.
  - The README no longer names an SDK version. It said 1.0.0. It now points to the PyPI page and to this folder.
  - The test command in the README now also installs `fastapi` and `httpx`.
- `examples/langgraph-approval/.env.example` shows `LUMOAUTH_CUSTOM_DOMAIN` as a comment.
- The route registry now has `aauth.issuerMetadata`, and `discover_issuer()` uses it.
- Added `tests/test_poppy.py`. It runs every case of `vectors/poppy-verification.json` from the SDK contract: the request body, the verified and refused answers, the malformed answers, and the two Session calls.
- Added `tests/test_fastapi_poppy.py`. It covers the dependency, the relay of a refusal, the public URL with router prefixes and mounted applications, and the error that never reaches the personal agent.
- Added `tests/test_custom_domain.py`. It runs every case of `vectors/custom-domain.json` from the SDK contract: every route of the SDK in both forms, the addresses that the SDK builds, the AAuth issuer and the accepted and refused values. It also covers each entry point of the table above.
- Added `tests/test_fastapi_custom_domain.py` for `lumo_auth_router()`, `require_access_token()` and `LumoAuthPoppy` on a custom domain.
- The vector tests skip no case. A contract route that this SDK does not have is no test case, and a separate test checks that each such route is declared in the contract.
- Point `LUMO_SDK_CONTRACT` at a contract checkout that has both vector files. Without a checkout, the vector tests are skipped.
- The suite runs 606 tests with the `aauth`, `fastapi` and `dev` extras and `httpx`. All of them pass, and none is skipped.
- Added the release notes for 1.6.0 to the repository (`release-notes/py-v1.6.0.md`).

---

## Commit Log (`py-v1.6.0..py-v1.7.0`)

- `1afa5ca` — `release: lumoauth@1.7.0`
- `9563341` — `feat: enhance vector route tests for SDK coverage and declaration validation`
- `7f89eff` — `Add comprehensive tests for Poppy verification protocol`
- `51d758e` — `Merge branch 'main' of github-lumo:LumoAuth/sdk-python`
- `84dd775` — `feat: add release notes for LumoAuth Python SDK v1.6.0 with new capabilities and AAuth updates`
- `c219ff4` — `Merge pull request #6 from LumoAuth/release/python-1.6.0`

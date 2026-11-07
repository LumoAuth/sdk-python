# LumoAuth Python SDK v1.4.0 (`py-v1.4.0`)

**Release Date:** November 6, 2026  
**Tag:** `py-v1.4.0`

## Packages Updated

| Package | Version |
| :--- | :--- |
| `lumoauth` | `1.4.0` |

---

## Highlights & New Features

### 1. Token and Cost Usage Reporting (`lumoauth`)

LumoAuth does not see an agent's model calls. Agents can now report the tokens and cost of their model calls, so that the token and cost limits of the agent's budget (`max_tokens_per_hour`, `max_tokens_per_day`, `max_cost_per_day_usd`, `max_cost_per_month_usd`) count real usage.

- Added `AgentsResource.report_usage(tokens=0, cost_usd=0.0)` (`src/lumoauth/resources/agents.py`). It sends `{ "tokens", "cost_usd" }` to `POST /orgs/{org_id}/api/v1/agents/me/usage`, registered as the new `agents.reportUsage` route in `src/lumoauth/_routes.py`.
- Added `LumoAuthAgent.report_usage(tokens=0, cost_usd=0.0)` (`src/lumoauth/agent.py`):
  - It authenticates first when the agent has no token yet.
  - It stores the returned `budget` in the cached agent info, so `is_budget_exhausted()` and `get_budget_status()` reflect the report at once.
  - It raises `LumoAuthApiError` with the prefix `Usage report failed` when the request fails.
- The SDK checks the report before it sends a request. It raises `ValueError` in these cases:
  - `tokens` is negative, is not an `int`, or is a `bool`.
  - `cost_usd` is negative, is not an `int` or `float`, or is a `bool`.
  - Both values are zero.
- The result is a `dict` with two keys:
  - `recorded`: the tokens and cost that the server added (`{"tokens", "cost_usd"}`).
  - `budget`: the agent's budget after the report, in the same shape as `budget_policy` in UserInfo. `budget["exhausted"]` is `True` when the next metered call (Ask API call, token request or JIT request) gets HTTP 429.
- A report is not a metered call. The server accepts it even when the budget is spent.
- Only agent credentials can report usage. The `agents` resource on `LumoAuth` also has the method, but the server answers other tokens and portal test tokens with 403.
- The server limits how often each agent can report (429 `rate_limited`). If your agent calls models often, send fewer, larger reports.

```python
from lumoauth import LumoAuthAgent

agent = LumoAuthAgent()  # AGENT_CLIENT_ID, AGENT_CLIENT_SECRET, ...
agent.authenticate()

resp = llm.chat(messages)
agent.report_usage(tokens=resp.usage.total_tokens, cost_usd=0.0042)

if agent.is_budget_exhausted():
    # The next Ask API call, token request or JIT request gets 429.
    raise RuntimeError("budget spent")
```

### 2. Capability Matching Like the Server (`lumoauth.capabilities`)

Capability checks in the SDK compared strings exactly, so they could disagree with the server. The server stores `tool:search_web` as `tool.search_web`, and a held `invoices.*` covers `invoices.read`. The SDK now uses the server's rules.

- Added `src/lumoauth/capabilities.py`, exported from `lumoauth`:
  - `normalize_capability(capability)` returns the stored form. It trims the name, lower-cases ASCII letters, turns `:` and `-` into `.`, collapses runs of `.` and trims `.` from both ends. `"Invoices:Read"` and `"invoices-read"` both become `"invoices.read"`.
  - `capability_covers(capability, action)` says whether one capability covers an action, in any spelling of either. `*` covers every action. A name that ends in `.*` covers every action under that prefix at any depth, but not the prefix itself: `invoices.*` covers `invoices.read.draft`, not `invoices`.
  - `any_capability_covers(capabilities, action)` checks a list and ignores entries that are not strings.
- These checks now use the new rules:
  - `LumoAuthAgent.has_capability()` (`src/lumoauth/agent.py`)
  - the `@require_capability` decorator, through `has_capability()` (`src/lumoauth/decorators.py`)
  - `AccessTokenClaims.has_capability()` for verified tokens (`src/lumoauth/verify.py`)
- `AccessTokenClaims.has_scope()` still compares scopes exactly.
- `has_capability()` reads only the agent's registered capabilities. The Ask API (`agent.ask()`) also applies your policies and the token's scope.

```python
from lumoauth import capability_covers, normalize_capability

normalize_capability("Tool:Search-Web")             # "tool.search.web"
capability_covers("users:*", "USERS-DELETE")        # True
capability_covers("invoices.*", "invoices")         # False
```

### 3. `is_budget_exhausted()` Covers Every Limit (`lumoauth`)

`LumoAuthAgent.is_budget_exhausted()` now returns the server's `exhausted` field from `budget_policy`. That field is `True` when any limit is reached: calls, tokens or cost, per hour, day or month. If the server omits the field, the method compares the daily token cap with today's usage, as in 1.3.0.

---

## Upgrade Notes

- **Capability checks can now return `True` where 1.3.0 returned `False`.** An agent that holds `tool.search_web` now passes `has_capability("tool:search_web")`, and an agent that holds `tool.*` now passes `has_capability("tool.search_web")`. This change also applies to `@require_capability` and to `AccessTokenClaims.has_capability()` in MCP servers. The new answers match the server's. Review any code that relied on an exact string comparison.
- **`is_budget_exhausted()` can now return `True` before the daily token cap is reached.** Call limits, hourly limits and cost limits also count now.
- No dependency changes in this release.

---

## Documentation & Tests

- Updated the "Capabilities, budget and identity" section of `README.md`: budget limits per hour, day and month, a `report_usage()` example, and the capability matching rules.
- Added `tests/test_usage_report.py` for the usage report request, validation and budget cache.
- Added `tests/test_capabilities.py`. It runs inline cases and the shared contract cases in `sdk-contract/vectors/agent-capabilities.json`, which the contract repo also checks against the server's own matcher. Set `LUMO_SDK_CONTRACT` to point the tests at a contract checkout. Without one, the contract cases are skipped.

---

## Commit Log (`py-v1.3.0..py-v1.4.0`)

- `4e7df90` — `release: lumoauth@1.4.0`
- `9255cfc` — `feat: add report_usage method for tracking model token usage and costs`
- `a9d401f` — `feat: implement capability matching functions and enhance agent capability checks`
- `1278c23` — `feat: add release notes for LumoAuth Python SDK v1.3.0 with private key JWT support and traceparent enhancements`

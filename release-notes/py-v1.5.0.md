# LumoAuth Python SDK v1.5.0 (`py-v1.5.0`)

**Release Date:** November 13, 2026  
**Tag:** `py-v1.5.0`

## Packages Updated

| Package | Version |
| :--- | :--- |
| `lumoauth` | `1.5.0` |

---

## Highlights & New Features

### 1. LangGraph Approval Gate Example (`examples/langgraph-approval`)

This release adds the first runnable example to the repository. It shows how to put a person between a model's decision and a tool that moves money.

An OpenAI model is asked to pay a $4,500 invoice and decides to call `wire_transfer`. Before the tool runs, `require_approval()` sends a push to the approver's phone. The wire goes out only after the approver taps Approve.

```
START → plan ─tool call─→ ask_human ─approved──→ send_wire ─→ plan → END
          │                         └─otherwise─→ cancel ────→ plan → END
          └─no tool call─→ END
```

- Added `examples/langgraph-approval/wire_agent.py`, a LangGraph `StateGraph` with four nodes:
  - `plan` calls the model with the `wire_transfer` tool bound. The model can make one tool call at a time (`parallel_tool_calls=False`).
  - `ask_human` calls `require_approval()` with `impact="high"` and `timeout_s=90`. The `reason` and the `meta` carry the arguments that the model chose, so the approver sees the vendor, the amount and the invoice on their phone.
  - `send_wire` is a LangGraph `ToolNode`. It runs only after the status `approved`, and it runs the same tool call that the approver saw.
  - `cancel` answers the tool call with `Not sent: <status>` for any other status. The model then tells the user why the wire was not sent.
- The agent signs in as itself with `LumoAuthAgent()` and client credentials from the environment. The approver is the user in `APPROVER_EMAIL`, passed as `on_behalf_of`.
- Added `examples/langgraph-approval/.env.example` with the variables that the script reads: `LUMOAUTH_URL`, `LUMOAUTH_ORG_ID`, `AGENT_CLIENT_ID`, `AGENT_CLIENT_SECRET`, `APPROVER_EMAIL`, `OPENAI_API_KEY` and `OPENAI_MODEL` (default `gpt-5-mini`).
- Added `examples/langgraph-approval/requirements.txt`: `langgraph>=1.0`, `langchain-openai>=1.0` and `lumoauth>=1.4.0`.
- Added `examples/langgraph-approval/README.md` with the graph, the setup steps and the run commands.

The gate itself is one call inside a graph node:

```python
def ask_human(state: State):
    args = state["messages"][-1].tool_calls[0]["args"]
    result = require_approval(
        agent,
        task_id=f"wire-{args['invoice']}-{time.strftime('%H%M%S')}",
        reason=f"Wire ${args['amount']:,} to {args['vendor']} for invoice {args['invoice']}",
        on_behalf_of=APPROVER,
        impact="high",
        meta={"action": "wire-transfer", **args},
        timeout_s=90,
    )
    return {"decision": result.status}
```

**Before you run it**

- Your organization has an agent with **May act on behalf of users** turned on.
- The approver is a user in the same organization, and the LumoAuth app is enrolled on their phone.
- You have an OpenAI API key.

```bash
cd examples/langgraph-approval
cp .env.example .env        # then fill in the values
pip install -r requirements.txt
set -a && . ./.env && set +a
python wire_agent.py
```

**Things to know**

- The example is in the repository only. `pip install lumoauth` does not install it.
- Always set `APPROVER_EMAIL`. When the variable is missing, the script falls back to a fixed address in the code.
- When 90 seconds pass with no answer, `require_approval()` returns the status `pending`. The graph treats it like a denial and runs `cancel`.
- When the approver has no enrolled phone, `require_approval()` raises `LumoAuthApprovalNotDeliveredError`. The example does not catch this error, so the script stops. See "Human approvals" in `README.md` for how to handle it.
- `wire_transfer` only returns a string. Call your bank's API there in a real agent.

---

## Upgrade Notes

- **The library code is the same as in 1.4.0.** Nothing changed under `src/lumoauth`, so no class, function or default behaves differently. You can upgrade from 1.4.0 without code changes.
- No dependency changes in this release.

---

## Documentation & Tests

- Added the release notes for 1.4.0 to the repository (`release-notes/py-v1.4.0.md`).
- The SDK's `README.md` and the test suite are unchanged. The example has no automated tests in this repository.

---

## Commit Log (`py-v1.4.0..py-v1.5.0`)

- `d215681` — `release: lumoauth@1.5.0`
- `3374f05` — `feat: add LangGraph approval gate example with environment configuration and wire transfer functionality`
- `fe30d0a` — `feat: add release notes for LumoAuth Python SDK v1.4.0 with token usage reporting and capability matching enhancements`

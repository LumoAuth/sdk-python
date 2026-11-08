# LangGraph approval gate

An OpenAI model is asked to pay a $4,500 invoice and decides to call
`wire_transfer`. Before the tool runs, LumoAuth sends a push to the approver's
phone. The wire goes out only after they tap Approve.

```
START → plan ─tool call─→ ask_human ─approved──→ send_wire ─→ plan → END
          │                         └─otherwise─→ cancel ────→ plan → END
          └─no tool call─→ END
```

The push shows the arguments the model chose, and `send_wire` runs that same
tool call, so the approver sees exactly what will be executed.

## Before you run it

- An agent in your LumoAuth organization with **May act on behalf of users** turned on.
- The approver is a user in the same organization with the LumoAuth app enrolled on their phone.
- An OpenAI API key.

## Run

Copy `.env.example` to `.env` and fill in its values, then:

```bash
pip install -r requirements.txt
set -a && . ./.env && set +a
python wire_agent.py
```

Approve on the phone and the graph runs `send_wire`. Deny it, or let 90 seconds
pass, and it runs `cancel`. Either way the model reports back to the user.

"""A LangGraph payments agent on OpenAI that asks a person before it moves money.

The model decides to call wire_transfer. LumoAuth sends a push to the
approver's phone, and the tool runs only after they tap Approve.
"""

import os
import time

import requests
from langchain_core.messages import ToolMessage
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from langgraph.graph import END, START, MessagesState, StateGraph
from langgraph.prebuilt import ToolNode
from lumoauth import LumoAuthAgent, require_approval

APPROVER = os.environ.get("APPROVER_EMAIL", "stdch@proton.me")

# 1. The agent signs in as itself (client credentials from the environment).
agent = LumoAuthAgent()
agent.authenticate()


@tool
def wire_transfer(vendor: str, amount: int, invoice: str) -> str:
    """Wire money in US dollars to a vendor to pay an invoice."""
    return f"Wired ${amount:,} to {vendor} for invoice {invoice}"  # call the bank API here


SYSTEM = "You pay invoices with wire_transfer. If a wire is not sent, don't retry. Say why."
llm = ChatOpenAI(model=os.environ.get("OPENAI_MODEL", "gpt-5-mini"))
llm = llm.bind_tools([wire_transfer], parallel_tool_calls=False)


class State(MessagesState):
    decision: str  # approved | denied | expired


def plan(state: State):
    return {"messages": [llm.invoke([("system", SYSTEM), *state["messages"]])]}


def needs_approval(state: State) -> str:
    return "ask_human" if state["messages"][-1].tool_calls else END


def ask_human(state: State):
    # 2. The model wants to move money. A person decides on their phone.
    args = state["messages"][-1].tool_calls[0]["args"]
    print(f"   asking {APPROVER} to approve on their phone (90 s) ...")
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


def route(state: State) -> str:
    return "send_wire" if state["decision"] == "approved" else "cancel"


def cancel(state: State):
    call_id = state["messages"][-1].tool_calls[0]["id"]
    return {"messages": [ToolMessage(f"Not sent: {state['decision']}", tool_call_id=call_id)]}


builder = StateGraph(State)
builder.add_node(plan)
builder.add_node(ask_human)
builder.add_node("send_wire", ToolNode([wire_transfer]))  # 3. only after an approval
builder.add_node(cancel)
builder.add_edge(START, "plan")
builder.add_conditional_edges("plan", needs_approval, ["ask_human", END])
builder.add_conditional_edges("ask_human", route, ["send_wire", "cancel"])
builder.add_edge("send_wire", "plan")
builder.add_edge("cancel", "plan")
graph = builder.compile()


if __name__ == "__main__":
    request = "Pay Bluepeak Supplies invoice INV-7741 for $4,500."
    try:
        for step in graph.stream({"messages": [("user", request)]}, stream_mode="updates"):
            for node, update in step.items():
                print(f"\n[{node}]")
                for msg in update.get("messages", []):
                    msg.pretty_print()
                if "decision" in update:
                    print(f"approver answered: {update['decision']}")
    except requests.HTTPError as e:
        print(e.response.status_code, e.response.text)
        raise

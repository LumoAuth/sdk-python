"""LumoAuth Agent SDK — authenticate AI agents via LumoAuth.

Quick start::

    from lumoauth import LumoAuthAgent

    agent = LumoAuthAgent()   # reads LUMOAUTH_* / AGENT_* env vars
    agent.authenticate()

    if agent.has_capability("read:documents"):
        resp = agent.api_request("GET", f"/orgs/{agent.org_id}/api/v1/documents/123")

Delegation (Chain of Agency — RFC 8693 token exchange)::

    from lumoauth import DelegationChain

AAuth (cryptographic identity + HTTP signing)::

    from lumoauth import AAuthClient

JIT permissions (ephemeral tasks + RFC 9396)::

    from lumoauth import JITContext

    with JITContext(agent) as jit:
        jit.create_task(name="Analyse Q4 report")
        result = jit.request_permission({"type": "file_access", "actions": ["read"],
                                         "identifier": "report_q4.pdf"})
        if result["status"] == "approved":
            token = jit.get_token(result["request_id"])
"""

from lumoauth.client import LumoAuthAgent
from lumoauth.decorators import require_capability
from lumoauth.delegation import DelegationChain
from lumoauth.jit import JITContext
from lumoauth.aauth import AAuthClient
from lumoauth.approval import require_approval, ApprovalResult

__all__ = [
    "LumoAuthAgent",
    "DelegationChain",
    "JITContext",
    "AAuthClient",
    "require_capability",
    "require_approval",
    "ApprovalResult",
]

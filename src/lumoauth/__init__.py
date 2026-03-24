"""LumoAuth Agent SDK — authenticate AI agents via LumoAuth.

Quick start::

    from lumoauth import LumoAuthAgent

    agent = LumoAuthAgent()   # reads LUMOAUTH_* / AGENT_* env vars
    agent.authenticate()

    if agent.has_capability("read:documents"):
        resp = agent.api_request("GET", f"/t/{agent.tenant}/api/v1/documents/123")

Delegation (Chain of Agency — RFC 8693 token exchange)::

    from lumoauth.delegation import DelegationChain

AAuth (cryptographic identity + HTTP signing)::

    from lumoauth.aauth import AAuthClient

JIT permissions (ephemeral tasks + RFC 9396)::

    from lumoauth.jit import JITContext
"""

from lumoauth.client import LumoAuthAgent
from lumoauth.decorators import require_capability
from lumoauth.delegation import DelegationChain

__all__ = ["LumoAuthAgent", "DelegationChain", "require_capability"]

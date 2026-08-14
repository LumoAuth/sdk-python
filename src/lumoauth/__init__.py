"""LumoAuth Python SDK — authenticate apps and AI agents via LumoAuth.

General-purpose client (RBAC / ReBAC / ABAC / agents / JIT / delegation)::

    from lumoauth import LumoAuth

    client = LumoAuth(api_key="lk_…", org_id="acme-corp")
    if client.permissions.check("document.edit"):
        ...
    allowed = client.zanzibar.is_viewer("document:readme", "user:bob")
    decision = client.abac.check("document", "read", "doc-123")

Agent quick start::

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

from lumoauth.aauth import AAuthClient
from lumoauth.agent import LumoAuthAgent
from lumoauth.approval import ApprovalResult, require_approval
from lumoauth.client import LumoAuth
from lumoauth.decorators import require_capability
from lumoauth.delegation import DelegationChain
from lumoauth.errors import (
    LumoAuthApiError,
    LumoAuthApprovalDeniedError,
    LumoAuthApprovalTimeoutError,
    LumoAuthAuthenticationError,
    LumoAuthBudgetExceededError,
    LumoAuthConfigError,
    LumoAuthError,
    LumoAuthNetworkError,
    LumoAuthNotFoundError,
    LumoAuthPermissionDeniedError,
    LumoAuthRateLimitError,
    LumoAuthValidationError,
)
from lumoauth.jit import JITContext

__all__ = [
    # Clients
    "LumoAuth",
    "LumoAuthAgent",
    "DelegationChain",
    "JITContext",
    "AAuthClient",
    # Helpers
    "require_capability",
    "require_approval",
    "ApprovalResult",
    # Errors
    "LumoAuthError",
    "LumoAuthApiError",
    "LumoAuthAuthenticationError",
    "LumoAuthPermissionDeniedError",
    "LumoAuthNotFoundError",
    "LumoAuthRateLimitError",
    "LumoAuthValidationError",
    "LumoAuthConfigError",
    "LumoAuthNetworkError",
    "LumoAuthApprovalDeniedError",
    "LumoAuthApprovalTimeoutError",
    "LumoAuthBudgetExceededError",
]

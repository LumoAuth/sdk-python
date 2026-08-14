"""Resource namespaces exposed by :class:`lumoauth.LumoAuth`."""

from lumoauth.resources.abac import AbacResource
from lumoauth.resources.agents import AgentsResource
from lumoauth.resources.approvals import ApprovalsResource
from lumoauth.resources.auth import AuthResource
from lumoauth.resources.delegation import DelegationResource
from lumoauth.resources.jit import JitResource
from lumoauth.resources.mcp import McpResource
from lumoauth.resources.permissions import PermissionsResource
from lumoauth.resources.zanzibar import ZanzibarResource

__all__ = [
    "AbacResource",
    "AgentsResource",
    "ApprovalsResource",
    "AuthResource",
    "DelegationResource",
    "JitResource",
    "McpResource",
    "PermissionsResource",
    "ZanzibarResource",
]

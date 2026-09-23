"""Central registry of every LumoAuth endpoint the SDK talks to.

Each entry maps a stable route name to ``(HTTP method, path template)``.
Path templates use ``{placeholders}`` in snake_case; org-scoped routes
embed the ``/orgs/{org_id}/api/v1`` base explicitly so the registry can be
membership-checked against ``server/openapi.json`` (see
``tests/test_route_drift.py``).

Do NOT hardcode endpoint paths anywhere else in the SDK — add them here.
"""

from __future__ import annotations

from typing import Dict, Tuple
from urllib.parse import quote

__all__ = ["ROUTES", "format_path"]

# Org-scoped API base shared by most routes.
_ORG = "/orgs/{org_id}/api/v1"

ROUTES: Dict[str, Tuple[str, str]] = {
    # ── OAuth 2.1 core ────────────────────────────────────────────────
    "oauth.authorize": ("GET", _ORG + "/oauth/authorize"),
    "oauth.token": ("POST", _ORG + "/oauth/token"),
    "oauth.userinfo": ("GET", _ORG + "/oauth/userinfo"),
    "oauth.revoke": ("POST", _ORG + "/oauth/revoke"),
    # ── Agent identity ────────────────────────────────────────────────
    "agents.ask": ("POST", _ORG + "/agents/ask"),
    "agents.me": ("GET", _ORG + "/agents/me"),
    "agents.register": ("POST", _ORG + "/agents/register"),
    # ── Push approvals ────────────────────────────────────────────────
    "approvals.create": ("POST", _ORG + "/agents/me/approvals"),
    "approvals.status": ("GET", _ORG + "/agents/me/approvals/{token}/status"),
    # ── JIT permissions ───────────────────────────────────────────────
    "jit.task.create": ("POST", _ORG + "/jit/task"),
    "jit.task.complete": ("POST", _ORG + "/jit/task/{task_id}/complete"),
    "jit.task.evaluate": ("POST", _ORG + "/jit/task/{task_id}/evaluate"),
    "jit.request.create": ("POST", _ORG + "/jit/request"),
    "jit.request.status": ("GET", _ORG + "/jit/request/{request_id}/status"),
    "jit.request.token": ("POST", _ORG + "/jit/request/{request_id}/token"),
    "jit.pending": ("GET", _ORG + "/jit/pending"),
    # ── AAuth (Agent Auth protocol) ───────────────────────────────────
    "aauth.agent.token": ("POST", _ORG + "/aauth/agent/token"),
    # ── RBAC permission checks (org-inferred from the credential) ─────
    "authz.check": ("POST", "/api/v1/authz/check"),
    "authz.check_bulk": ("POST", "/api/v1/authz/check-bulk"),
    "authz.check_any": ("POST", "/api/v1/authz/check-any"),
    "authz.check_all": ("POST", "/api/v1/authz/check-all"),
    "authz.permissions": ("GET", "/api/v1/authz/permissions"),
    # ── Zanzibar (ReBAC) ──────────────────────────────────────────────
    "authz.zanzibar.check": ("POST", "/api/v1/authz/zanzibar/check"),
    "authz.zanzibar.expand": ("POST", "/api/v1/authz/zanzibar/expand"),
    # ── ABAC ──────────────────────────────────────────────────────────
    "abac.check": ("POST", _ORG + "/abac/check"),
    "abac.check_bulk": ("POST", _ORG + "/abac/check-bulk"),
    "abac.my_attributes": ("GET", _ORG + "/abac/my-attributes"),
    "abac.user_attribute.set": (
        "PUT",
        _ORG + "/abac/users/{user_id}/attributes/{attribute_slug}",
    ),
    "abac.resource_attributes": (
        "GET",
        _ORG + "/abac/resources/{resource_type}/{resource_id}/attributes",
    ),
    "abac.resource_attribute.set": (
        "PUT",
        _ORG + "/abac/resources/{resource_type}/{resource_id}/attributes/{attribute_slug}",
    ),
    "abac.attribute_definitions": ("GET", _ORG + "/abac/attribute-definitions"),
    # ── Discovery ─────────────────────────────────────────────────────
    # NOTE: served at the instance root; the OpenAPI spec only documents the
    # org-scoped variant (/orgs/{org_id}/api/v1/.well-known/aauth-issuer).
    # Tracked as KNOWN_DRIFT in tests/test_route_drift.py.
    "wellknown.aauth_issuer": ("GET", "/.well-known/aauth-issuer"),
}


def format_path(name: str, **params: object) -> Tuple[str, str]:
    """Return ``(method, concrete_path)`` for a registered route.

    Path parameters are URL-quoted.  Raises ``KeyError`` for unknown route
    names or missing placeholders.
    """
    method, template = ROUTES[name]
    quoted = {k: quote(str(v), safe="") for k, v in params.items()}
    return method, template.format(**quoted)

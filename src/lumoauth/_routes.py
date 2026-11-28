"""Central registry of every LumoAuth endpoint the SDK talks to.

Each entry maps a stable route name to ``(HTTP method, path template)``.
Path templates use ``{placeholders}`` in snake_case; org-scoped routes
embed the ``/orgs/{org_id}/api/v1`` base explicitly so the registry can be
membership-checked against ``server/openapi.json`` (see
``tests/test_route_drift.py``).

Do NOT hardcode endpoint paths anywhere else in the SDK — add them here.

Custom domains
--------------
An organization can serve LumoAuth on its own domain, such as
``https://auth.acme.com``. There every route is served at its path without
the ``/orgs/{org_id}`` segment, a route that has no such segment keeps its
path, and the issuer is the bare domain. The registry keeps the prefixed
form, and this module is the one place that holds the rule:

- :func:`normalize_custom_domain` checks the option.
- :func:`format_path` drops the segment for a client on a custom domain.
- :func:`strip_org_segment` does the same for a path or a path template
  that comes from somewhere else.
- :func:`org_api_base` and :func:`issuer_url` give the two addresses that
  the SDK derives from its configuration.

Every other part of the SDK that builds an address calls these functions.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Optional, Tuple
from urllib.parse import quote, urlsplit

from lumoauth.errors import LumoAuthConfigError

__all__ = [
    "ROUTES",
    "format_path",
    "issuer_url",
    "normalize_custom_domain",
    "org_api_base",
    "strip_org_segment",
]

# Org-scoped API base shared by most routes.
_ORG = "/orgs/{org_id}/api/v1"

ROUTES: Dict[str, Tuple[str, str]] = {
    # ── OAuth 2.1 core ────────────────────────────────────────────────
    "oauth.authorize": ("GET", _ORG + "/oauth/authorize"),
    "oauth.token": ("POST", _ORG + "/oauth/token"),
    "oauth.userinfo": ("GET", _ORG + "/oauth/userinfo"),
    "oauth.revoke": ("POST", _ORG + "/oauth/revoke"),
    # OpenID Connect end-session endpoint (RP-initiated logout). A browser
    # address: the SDK builds the URL and never sends a request to it.
    "oauth.logout": ("GET", _ORG + "/oauth/logout"),
    # ── Agent identity ────────────────────────────────────────────────
    "agents.ask": ("POST", _ORG + "/agents/ask"),
    "agents.me": ("GET", _ORG + "/agents/me"),
    "agents.reportUsage": ("POST", _ORG + "/agents/me/usage"),
    "agents.register": ("POST", _ORG + "/agents/register"),
    # Workload attestation: no credential, the workload's OIDC token is the proof.
    "agents.attest": ("POST", _ORG + "/agents/{agent_id}/attest"),
    "agents.authorize_mcp_tool": ("POST", _ORG + "/agents/me/mcp/authorize"),
    # ── MCP per-tool checks (the MCP server's own token) ──────────────
    "mcp.authorize_tool": (
        "POST",
        _ORG + "/mcp/servers/{server_id}/tools/authorize",
    ),
    # ── Personal Agent Protocol: Session verification ─────────────────
    # HTTP Basic with the client id and secret of a confidential application
    # whose allowed scopes include poppy:verify. No bearer token, no API key.
    "poppy.verifyRequest": ("POST", _ORG + "/poppy/sessions/verify"),
    "poppy.getSessionStatus": ("POST", _ORG + "/poppy/sessions/status"),
    "poppy.endSession": ("POST", _ORG + "/poppy/sessions/end"),
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
    "aauth.issuerMetadata": ("GET", _ORG + "/.well-known/aauth-issuer"),
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


# The path segment that names the organization on the platform host. A
# custom domain serves the same routes without it.
_ORG_SEGMENT = "/orgs/{org_id}"
# The API base below the organization segment.
_API_PREFIX = "/api/v1"

_HOST_NAME = re.compile(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$")
_IPV6_LITERAL = re.compile(r"^[0-9a-f:.]+$")
# http:// is accepted for these hosts only (local development).
_LOOPBACK_HOSTS = ("localhost", "127.0.0.1", "::1")


def normalize_custom_domain(value: Any) -> Optional[str]:
    """Check a custom domain and return it as ``https://<host>[:port]``.

    The value is a host name (``auth.acme.com``) or an ``https://`` origin.
    The result has a lower-case host and no trailing slash. ``http://`` is
    accepted only for ``localhost``, ``127.0.0.1`` and ``[::1]``. ``None``
    and an empty or blank value mean "not set" and give ``None``.

    Raises:
        LumoAuthConfigError: The value has a path, a query, a fragment or
            credentials, or it is not a host name or an origin.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        raise LumoAuthConfigError("custom_domain must be a host name or an https:// origin")
    text = value.strip()
    if not text:
        return None
    invalid = LumoAuthConfigError(
        "invalid custom_domain: use the host name or the https:// origin of the domain, "
        "such as 'auth.acme.com' or 'https://auth.acme.com', without path, query, "
        "fragment or credentials (http:// only for localhost, 127.0.0.1 and [::1])"
    )
    if re.search(r"\s", text) or "\\" in text:
        raise invalid
    if "://" not in text:
        text = "https://" + text
    try:
        parts = urlsplit(text)
        host = (parts.hostname or "").lower()
        port = parts.port
    except ValueError:
        raise invalid from None
    scheme = parts.scheme.lower()
    is_ipv6 = ":" in host
    if (
        scheme not in ("https", "http")
        or not host
        or "@" in parts.netloc
        or parts.path not in ("", "/")
        or "?" in text
        or "#" in text
        or (scheme == "http" and host not in _LOOPBACK_HOSTS)
        or not (_IPV6_LITERAL if is_ipv6 else _HOST_NAME).match(host)
        or (is_ipv6 and "[" not in parts.netloc)
    ):
        raise invalid
    origin = f"{scheme}://[{host}]" if is_ipv6 else f"{scheme}://{host}"
    return origin if port is None else f"{origin}:{port}"


def strip_org_segment(path: str, org: str = "{org_id}") -> str:
    """Drop a leading ``/orgs/<org>`` segment from a path or a path template.

    This is the form of an organization route on a custom domain. A path
    without that segment is returned unchanged. *org* is the placeholder of
    a template (the default), or the slug of the client's own organization
    for a concrete path. The function never guesses another organization.
    """
    prefix = "/orgs/" + org
    if org and (path == prefix or path.startswith(prefix + "/")):
        return path[len(prefix):] or "/"
    return path


def format_path(name: str, *, custom_domain: bool = False, **params: object) -> Tuple[str, str]:
    """Return ``(method, concrete_path)`` for a registered route.

    Path parameters are URL-quoted.  Raises ``KeyError`` for unknown route
    names or missing placeholders.

    With ``custom_domain=True`` the path has no ``/orgs/{org_id}`` segment,
    and ``org_id`` is not needed (it is ignored when given). A route without
    that segment has the same path in both forms.
    """
    method, template = ROUTES[name]
    if custom_domain:
        template = strip_org_segment(template)
    quoted = {k: quote(str(v), safe="") for k, v in params.items()}
    return method, template.format(**quoted)


def org_api_base(base_url: str, org_id: Optional[str], custom_domain: Optional[str] = None) -> str:
    """The address below which an organization's API routes are served.

    ``{base_url}/orgs/{org_id}/api/v1`` on the platform host, and
    ``{custom_domain}/api/v1`` on a custom domain. The discovery document
    and the key set are served below it (``/.well-known/…``).

    Raises:
        LumoAuthConfigError: No custom domain is set and *org_id* is missing.
    """
    domain = normalize_custom_domain(custom_domain)
    if domain is not None:
        return domain + _API_PREFIX
    if not org_id:
        raise LumoAuthConfigError(
            "org_id is required to address the organization: pass org_id "
            "(LUMOAUTH_ORG_ID), or custom_domain (LUMOAUTH_CUSTOM_DOMAIN)."
        )
    path = (_ORG_SEGMENT + _API_PREFIX).format(org_id=org_id)
    return f"{(base_url or '').rstrip('/')}{path}"


def issuer_url(base_url: str, org_id: Optional[str], custom_domain: Optional[str] = None) -> str:
    """The issuer identifier of an organization.

    ``{base_url}/orgs/{org_id}/api/v1`` on the platform host, and the bare
    domain on a custom domain. It is the ``iss`` of the organization's
    tokens and the ``aud`` of a client assertion.

    Raises:
        LumoAuthConfigError: No custom domain is set and *org_id* is missing.
    """
    domain = normalize_custom_domain(custom_domain)
    if domain is not None:
        return domain
    return org_api_base(base_url, org_id)

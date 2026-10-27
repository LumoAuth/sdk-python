"""RBAC permission checks — mirrors the JS SDK's ``client.permissions`` module."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional, Set

from lumoauth._http import HttpClient
from lumoauth.errors import LumoAuthValidationError

__all__ = ["PermissionsResource"]


class PermissionsResource:
    """Permission checks for the authenticated principal.

    Single checks, bulk checks, logical combinations (any / all), and
    listing all granted permissions.  All methods return plain dicts /
    booleans matching the server's response shapes.
    """

    def __init__(self, http: HttpClient) -> None:
        self._http = http

    # ── Single check ──────────────────────────────────────────────────

    def check(
        self,
        permission: str,
        context: Optional[Mapping[str, Any]] = None,
        *,
        user_id: Optional[str] = None,
        agent_id: Optional[str] = None,
    ) -> bool:
        """Return ``True`` if the principal has *permission*.

        Args:
            permission: Permission slug, e.g. ``"document.edit"``.
            context: Optional context attributes for ABAC evaluation.
            user_id: Optional LumoAuth user id (a UUID) to ask about instead of
                the caller. It is sent as ``subject: {"type": "user", "id": …}``.
            agent_id: Optional agent id (``agt_…``) to ask about instead of the
                caller. It is sent as ``subject: {"type": "agent", "id": …}``.

        Asking about another subject needs the ``authz:check`` scope (API keys
        can hold it) or the ``authz.check`` permission; without it LumoAuth
        answers 403 ``INSUFFICIENT_PERMISSIONS``. An id that is not in the
        organization gets 404 ``SUBJECT_NOT_FOUND``. Without either argument
        the check answers for the principal behind the credential (for an API
        key, the user who created the key).
        """
        return bool(self.check_detailed(permission, context, user_id=user_id, agent_id=agent_id).get("allowed", False))

    def check_detailed(
        self,
        permission: str,
        context: Optional[Mapping[str, Any]] = None,
        *,
        user_id: Optional[str] = None,
        agent_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Single permission check returning the full response dict."""
        body = self._body(permission=permission, context=context, user_id=user_id, agent_id=agent_id)
        return self._http.call("authz.check", json=body)

    # ── Bulk / combinations ───────────────────────────────────────────

    def check_bulk(
        self,
        permissions: List[str],
        context: Optional[Mapping[str, Any]] = None,
        *,
        user_id: Optional[str] = None,
        agent_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Check many permissions at once; ``results`` maps slug → bool."""
        self._require_permissions(permissions)
        body = self._body(permissions=permissions, context=context, user_id=user_id, agent_id=agent_id)
        return self._http.call("authz.check_bulk", json=body)

    def check_any(
        self,
        permissions: List[str],
        context: Optional[Mapping[str, Any]] = None,
        *,
        user_id: Optional[str] = None,
        agent_id: Optional[str] = None,
    ) -> bool:
        """``True`` if the principal has at least one of *permissions* (OR)."""
        return bool(self.check_any_detailed(permissions, context, user_id=user_id, agent_id=agent_id).get("allowed", False))

    def check_all(
        self,
        permissions: List[str],
        context: Optional[Mapping[str, Any]] = None,
        *,
        user_id: Optional[str] = None,
        agent_id: Optional[str] = None,
    ) -> bool:
        """``True`` if the principal has all of *permissions* (AND)."""
        return bool(self.check_all_detailed(permissions, context, user_id=user_id, agent_id=agent_id).get("allowed", False))

    def check_any_detailed(
        self,
        permissions: List[str],
        context: Optional[Mapping[str, Any]] = None,
        *,
        user_id: Optional[str] = None,
        agent_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        self._require_permissions(permissions)
        body = self._body(permissions=permissions, context=context, user_id=user_id, agent_id=agent_id)
        return self._http.call("authz.check_any", json=body)

    def check_all_detailed(
        self,
        permissions: List[str],
        context: Optional[Mapping[str, Any]] = None,
        *,
        user_id: Optional[str] = None,
        agent_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        self._require_permissions(permissions)
        body = self._body(permissions=permissions, context=context, user_id=user_id, agent_id=agent_id)
        return self._http.call("authz.check_all", json=body)

    # ── Listing ───────────────────────────────────────────────────────

    def list(self) -> Dict[str, Any]:
        """List all permissions granted to the authenticated principal.

        A user access token needs the ``authz:read`` scope (or ``admin``).
        Organization API keys cannot hold that scope, so with an API key this
        raises :class:`LumoAuthPermissionDeniedError` with
        ``required_scopes == ["authz:read"]``.
        """
        return self._http.call("authz.permissions")

    def list_slugs(self) -> Set[str]:
        """Flat set of permission slugs — convenience wrapper around :meth:`list`.

        Needs the same ``authz:read`` scope as :meth:`list`.
        """
        result = self.list() or {}
        return {p.get("slug") for p in result.get("permissions", []) if p.get("slug")}

    # ── Internal ──────────────────────────────────────────────────────

    @staticmethod
    def _require_permissions(permissions: List[str]) -> None:
        if not permissions:
            raise LumoAuthValidationError("At least one permission is required.")

    @staticmethod
    def _body(
        *,
        permission: Optional[str] = None,
        permissions: Optional[List[str]] = None,
        context: Optional[Mapping[str, Any]] = None,
        user_id: Optional[str] = None,
        agent_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        if permission is not None and not permission:
            raise LumoAuthValidationError("Permission slug is required.")
        body: Dict[str, Any] = {}
        if permission is not None:
            body["permission"] = permission
        if permissions is not None:
            body["permissions"] = list(permissions)
        if context:
            body["context"] = dict(context)
        if user_id is not None and agent_id is not None:
            raise LumoAuthValidationError("Pass user_id or agent_id, not both.")
        # The server reads the checked principal from `subject` only; a
        # top-level `user_id` is ignored and would silently answer for the
        # caller instead.
        if user_id is not None:
            body["subject"] = {"type": "user", "id": str(user_id)}
        elif agent_id is not None:
            body["subject"] = {"type": "agent", "id": str(agent_id)}
        return body

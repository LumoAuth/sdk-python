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
    ) -> bool:
        """Return ``True`` if the principal has *permission*.

        Args:
            permission: Permission slug, e.g. ``"document.edit"``.
            context: Optional context attributes for ABAC evaluation.
            user_id: Optional user to check on behalf of (backend/API-key
                callers only; the endpoint defaults to the authenticated user).
        """
        return bool(self.check_detailed(permission, context, user_id=user_id).get("allowed", False))

    def check_detailed(
        self,
        permission: str,
        context: Optional[Mapping[str, Any]] = None,
        *,
        user_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Single permission check returning the full response dict."""
        body = self._body(permission=permission, context=context, user_id=user_id)
        return self._http.call("authz.check", json=body)

    # ── Bulk / combinations ───────────────────────────────────────────

    def check_bulk(
        self,
        permissions: List[str],
        context: Optional[Mapping[str, Any]] = None,
        *,
        user_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Check many permissions at once; ``results`` maps slug → bool."""
        self._require_permissions(permissions)
        body = self._body(permissions=permissions, context=context, user_id=user_id)
        return self._http.call("authz.check_bulk", json=body)

    def check_any(
        self,
        permissions: List[str],
        context: Optional[Mapping[str, Any]] = None,
        *,
        user_id: Optional[str] = None,
    ) -> bool:
        """``True`` if the principal has at least one of *permissions* (OR)."""
        return bool(self.check_any_detailed(permissions, context, user_id=user_id).get("allowed", False))

    def check_all(
        self,
        permissions: List[str],
        context: Optional[Mapping[str, Any]] = None,
        *,
        user_id: Optional[str] = None,
    ) -> bool:
        """``True`` if the principal has all of *permissions* (AND)."""
        return bool(self.check_all_detailed(permissions, context, user_id=user_id).get("allowed", False))

    def check_any_detailed(
        self,
        permissions: List[str],
        context: Optional[Mapping[str, Any]] = None,
        *,
        user_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        self._require_permissions(permissions)
        body = self._body(permissions=permissions, context=context, user_id=user_id)
        return self._http.call("authz.check_any", json=body)

    def check_all_detailed(
        self,
        permissions: List[str],
        context: Optional[Mapping[str, Any]] = None,
        *,
        user_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        self._require_permissions(permissions)
        body = self._body(permissions=permissions, context=context, user_id=user_id)
        return self._http.call("authz.check_all", json=body)

    # ── Listing ───────────────────────────────────────────────────────

    def list(self) -> Dict[str, Any]:
        """List all permissions granted to the authenticated principal."""
        return self._http.call("authz.permissions")

    def list_slugs(self) -> Set[str]:
        """Flat set of permission slugs — convenience wrapper around :meth:`list`."""
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
        if user_id is not None:
            body["user_id"] = user_id
        return body

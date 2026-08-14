"""ABAC (attribute-based access control) — mirrors the JS SDK's ``client.abac``."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional

from lumoauth._http import HttpClient
from lumoauth.errors import LumoAuthValidationError

__all__ = ["AbacResource"]


class AbacResource:
    """Context-aware authorization from user/resource/environment attributes.

    ABAC is mounted org-scoped on the server (``/orgs/{org_id}/api/v1/abac/…``)
    so the client must be constructed with an ``org_id``.

    Note: the server's ABAC request bodies use camelCase keys
    (``resourceType``, ``resourceId``); this resource accepts snake_case
    Python arguments and translates.
    """

    def __init__(self, http: HttpClient) -> None:
        self._http = http

    # ── Authorization checks ──────────────────────────────────────────

    def check(
        self,
        resource_type: str,
        action: str,
        resource_id: Optional[str] = None,
        context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Evaluate ABAC policies for a single resource/action.

        Returns the full decision dict (``allowed``, ``reason``,
        ``matchedPolicies``, …).
        """
        if not resource_type:
            raise LumoAuthValidationError("resource_type is required.")
        if not action:
            raise LumoAuthValidationError("action is required.")
        body: Dict[str, Any] = {"resourceType": resource_type, "action": action}
        if resource_id is not None:
            body["resourceId"] = resource_id
        if context:
            body["context"] = dict(context)
        return self._http.call("abac.check", json=body)

    def is_allowed(
        self,
        resource_type: str,
        action: str,
        resource_id: Optional[str] = None,
        context: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """Shorthand for :meth:`check` returning just ``True``/``False``."""
        return bool(self.check(resource_type, action, resource_id, context).get("allowed", False))

    def check_bulk(self, requests: List[Mapping[str, Any]]) -> Dict[str, Any]:
        """Check multiple resource/action pairs in one request (max 100).

        Each item may use snake_case (``resource_type``/``resource_id``) or
        camelCase keys; snake_case is translated for the wire.
        """
        if not requests:
            raise LumoAuthValidationError("At least one check request is required.")
        wire = []
        for item in requests:
            entry: Dict[str, Any] = {}
            for key, value in item.items():
                if key == "resource_type":
                    entry["resourceType"] = value
                elif key == "resource_id":
                    entry["resourceId"] = value
                else:
                    entry[key] = value
            wire.append(entry)
        return self._http.call("abac.check_bulk", json={"requests": wire})

    # ── User attributes ───────────────────────────────────────────────

    def get_my_attributes(self) -> Dict[str, Any]:
        """All ABAC attributes for the authenticated user (built-in + custom)."""
        return self._http.call("abac.my_attributes")

    def set_user_attribute(self, user_id: str, attribute_slug: str, value: Any) -> Any:
        """Set an attribute value for a user."""
        return self._http.call(
            "abac.user_attribute.set",
            path_params={"user_id": user_id, "attribute_slug": attribute_slug},
            json={"value": value},
        )

    # ── Resource attributes ───────────────────────────────────────────

    def get_resource_attributes(self, resource_type: str, resource_id: str) -> Dict[str, Any]:
        """ABAC attributes for a specific resource."""
        return self._http.call(
            "abac.resource_attributes",
            path_params={"resource_type": resource_type, "resource_id": resource_id},
        )

    def set_resource_attribute(
        self, resource_type: str, resource_id: str, attribute_slug: str, value: Any
    ) -> Any:
        """Set an attribute value for a resource."""
        return self._http.call(
            "abac.resource_attribute.set",
            path_params={
                "resource_type": resource_type,
                "resource_id": resource_id,
                "attribute_slug": attribute_slug,
            },
            json={"value": value},
        )

    # ── Attribute definitions ─────────────────────────────────────────

    def get_attribute_definitions(self, type: Optional[str] = None) -> List[Dict[str, Any]]:
        """List attribute definitions, optionally filtered by type.

        Args:
            type: ``"user"``, ``"resource"``, or ``"environment"``.
        """
        params = {"type": type} if type else None
        raw = self._http.call("abac.attribute_definitions", params=params)
        if isinstance(raw, dict) and "data" in raw:
            return raw["data"]
        return raw if isinstance(raw, list) else []

"""Zanzibar (ReBAC) relationship checks — mirrors the JS SDK's ``client.zanzibar``."""

from __future__ import annotations

from typing import Any, Dict

from lumoauth._http import HttpClient
from lumoauth.errors import LumoAuthValidationError

__all__ = ["ZanzibarResource"]


class ZanzibarResource:
    """Google-Zanzibar-style relationship-based access control.

    Checks whether a **subject** has a **relation** to an **object**
    (``namespace:id`` tuples, e.g. ``document:123`` / ``user:alice``).
    """

    def __init__(self, http: HttpClient) -> None:
        self._http = http

    def check(self, object: str, relation: str, subject: str) -> bool:
        """Return ``True`` if the relationship exists (directly or inherited)."""
        return bool(self.check_detailed(object, relation, subject).get("allowed", False))

    def check_detailed(self, object: str, relation: str, subject: str) -> Dict[str, Any]:
        """Check a relationship tuple and return the full response dict."""
        self._validate(object, relation, subject)
        body = {"object": object, "relation": relation, "subject": subject}
        return self._http.call("authz.zanzibar.check", json=body)

    def expand(self, object: str, relation: str) -> Dict[str, Any]:
        """Expand ``object#relation`` into its full userset tree.

        The inverse of :meth:`check`: ``check`` answers "does this subject
        have the relation", ``expand`` answers "who has it at all" —
        including subjects reached through namespace rewrites.

        Returns the root node: ``{"type": "union"|"intersection"|"leaf",
        "object": ..., "relation": ..., "children": [...], "subjects": [...]}``.

        Expansion always reveals other subjects, so the server requires the
        oracle privilege (the ``authz.check`` permission or the
        ``authz:check`` scope); there is no self-service variant. A token
        that can only check itself gets a 403.
        """
        self._validate_object_relation(object, relation)
        body = {"object": object, "relation": relation}
        response = self._http.call("authz.zanzibar.expand", json=body)
        tree = response.get("tree")
        if not isinstance(tree, dict):
            raise LumoAuthValidationError(
                "Unexpected response from LumoAuth API: expected a 'tree' object."
            )
        return tree

    # ── Convenience helpers ───────────────────────────────────────────

    def is_viewer(self, object: str, subject: str) -> bool:
        return self.check(object, "viewer", subject)

    def is_editor(self, object: str, subject: str) -> bool:
        return self.check(object, "editor", subject)

    def is_owner(self, object: str, subject: str) -> bool:
        return self.check(object, "owner", subject)

    def is_member(self, object: str, subject: str) -> bool:
        return self.check(object, "member", subject)

    def is_admin(self, object: str, subject: str) -> bool:
        return self.check(object, "admin", subject)

    # ── Internal ──────────────────────────────────────────────────────

    @classmethod
    def _validate(cls, object: str, relation: str, subject: str) -> None:
        cls._validate_object_relation(object, relation)
        if not subject or ":" not in subject:
            raise LumoAuthValidationError(
                'Subject must be in "namespace:id" or "namespace:id#relation" format.'
            )

    @staticmethod
    def _validate_object_relation(object: str, relation: str) -> None:
        """Shared by check and expand; expand takes no subject."""
        if not object or ":" not in object:
            raise LumoAuthValidationError(
                'Object must be in "namespace:id" format (e.g. "document:123").'
            )
        if not relation:
            raise LumoAuthValidationError(
                'Relation is required (e.g. "viewer", "editor", "owner").'
            )

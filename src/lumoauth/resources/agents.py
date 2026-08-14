"""Agent identity operations — ask, me, register, capabilities, budget."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Mapping, Optional

from lumoauth._http import HttpClient

logger = logging.getLogger("lumoauth.agents")

__all__ = ["AgentsResource"]


class AgentsResource:
    """Identity, capability, and budget operations for the calling agent."""

    def __init__(self, http: HttpClient) -> None:
        self._http = http

    # ── Ask API (preflight authorization) ─────────────────────────────

    def ask(
        self, action: str, context: Optional[Mapping[str, Any]] = None
    ) -> Dict[str, Any]:
        """Ask whether the agent may perform *action* (LLM tool preflight).

        Returns a dict with ``allowed``, ``action``, ``reason``, ``audit_id``
        and the original ``context``.
        """
        body: Dict[str, Any] = {"action": action}
        if context:
            body["context"] = dict(context)
        return self._http.call("agents.ask", json=body)

    def is_allowed(
        self, action: str, context: Optional[Mapping[str, Any]] = None
    ) -> bool:
        """Boolean shorthand for :meth:`ask`."""
        return bool(self.ask(action, context).get("allowed", False))

    # ── Identity ──────────────────────────────────────────────────────

    def me(self) -> Dict[str, Any]:
        """Return the agent's own identity, capabilities, and workspace info."""
        return self._http.call("agents.me")

    # Alias used by callers preferring an explicit name.
    get_current = me

    def register(
        self,
        name: str,
        *,
        client_id: str,
        description: Optional[str] = None,
        capabilities: Optional[List[str]] = None,
        jwks_uri: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create or update the agent record in the organization directory."""
        body: Dict[str, Any] = {"client_id": client_id, "name": name}
        if description:
            body["description"] = description
        if capabilities:
            body["capabilities"] = capabilities
        if jwks_uri:
            body["jwks_uri"] = jwks_uri
        return self._http.call("agents.register", json=body)

    # ── Capabilities & budget (via UserInfo) ──────────────────────────

    def info(self) -> Dict[str, Any]:
        """Agent info from the UserInfo endpoint (capabilities, budget, …)."""
        return self._http.call("oauth.userinfo")

    def capabilities(self) -> List[str]:
        """Capability slugs granted to the agent."""
        return list(self.info().get("capabilities", []))

    def budget(self) -> Dict[str, Any]:
        """The agent's budget policy dict (empty when no policy is set)."""
        return self.info().get("budget_policy", {}) or {}

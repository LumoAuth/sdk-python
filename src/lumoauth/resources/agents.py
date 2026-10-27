"""Agent identity operations — ask, me, register, capabilities, budget."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional

from lumoauth._http import HttpClient
from lumoauth.errors import LumoAuthPermissionDeniedError, LumoAuthValidationError
from lumoauth.resources.mcp import (
    deny_body,
    validate_registered_server_id,
    validate_tool_name,
)

logger = logging.getLogger("lumoauth.agents")

__all__ = ["AgentsResource", "AgentMcpToolDecision"]


@dataclass(frozen=True)
class AgentMcpToolDecision:
    """Answer of :meth:`AgentsResource.authorize_mcp_tool`.

    ``allowed`` is ``False`` for a deny decision. A deny is a normal result,
    not an error. ``resource_id`` has the form ``"<server_id>/<tool>"``.
    """

    allowed: bool
    agent_id: Optional[str]
    resource_type: str
    resource_id: str


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
        and the original ``context``. ``ip``, ``userAgent``, ``requestMethod``
        and ``requestPath`` in the context always describe the request that
        LumoAuth received; values you pass under those names are kept under
        ``pep`` (the same rule as ABAC).
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
        """Return the agent's own identity, capabilities, and workspace info.

        For an agent credential, ``capabilities`` are the agent's capability
        roles. A user access token without the ``authz:read`` scope gets an
        empty list.
        """
        return self._http.call("agents.me")

    # Alias used by callers preferring an explicit name.
    get_current = me

    def authorize_mcp_tool(self, server_id: str, tool: str) -> AgentMcpToolDecision:
        """Ask whether the calling agent may run *tool* on an MCP server.

        Call this with the agent's own credential (an agent access token or
        an ``agk_`` key). An MCP server must not call it, because it would
        have to forward the agent's token. A server uses
        :meth:`lumoauth.resources.mcp.McpResource.authorize_tool` instead.

        Args:
            server_id: The registered MCP server id, such as
                ``"mcp_0123456789abcdef01234567"``. It must name an active
                MCP server.
            tool: The tool name, at most 80 characters.

        Returns:
            :class:`AgentMcpToolDecision`. A deny returns ``allowed=False``
            and does not raise.

        Raises:
            LumoAuthValidationError: An argument is empty or malformed. No
                request is sent.
            LumoAuthPermissionDeniedError: 403 without a decision, such as
                ``agent_required``.
            LumoAuthNotFoundError: 404 ``unknown_server``.
        """
        validate_registered_server_id(server_id)
        validate_tool_name(tool)
        try:
            body = self._http.call(
                "agents.authorize_mcp_tool",
                json={"server_id": server_id, "tool": tool},
            )
        except LumoAuthPermissionDeniedError as exc:
            body = deny_body(exc)
            if body is None:
                raise

        if not isinstance(body, dict):
            raise LumoAuthValidationError("unexpected MCP authorize response")
        resource = body.get("resource") if isinstance(body.get("resource"), dict) else {}
        agent_id = body.get("agent_id")
        return AgentMcpToolDecision(
            allowed=body.get("allowed") is True,
            agent_id=agent_id if isinstance(agent_id, str) else None,
            resource_type=str(resource.get("type", "mcp_tool")),
            resource_id=str(resource.get("id", f"{server_id}/{tool}")),
        )

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

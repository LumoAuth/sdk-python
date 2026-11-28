"""Agent identity operations — ask, me, register, attest, capabilities, budget."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Dict, List, Mapping, Optional, Sequence, Union

from lumoauth._http import HttpClient
from lumoauth.errors import LumoAuthPermissionDeniedError, LumoAuthValidationError
from lumoauth.resources.mcp import (
    deny_body,
    validate_registered_server_id,
    validate_tool_name,
)

if TYPE_CHECKING:  # pragma: no cover
    from lumoauth.dpop import DpopProofSigner

logger = logging.getLogger("lumoauth.agents")

__all__ = ["AgentsResource", "AgentMcpToolDecision", "WorkloadAttestation"]


@dataclass(frozen=True)
class WorkloadAttestation:
    """Answer of :meth:`AgentsResource.attest`: a short-lived token for the agent.

    ``token_type`` is ``"DPoP"`` when the token is bound to the key of the
    ``dpop`` signer, otherwise ``"Bearer"``. ``scope`` is the issued scope
    values separated by one space, or ``None`` when none was issued.
    ``identity`` is the verified workload identity (``provider``,
    ``subject``, ``issuer``, ...). ``raw`` is the whole answer.
    """

    access_token: str
    token_type: str
    expires_in: Optional[int]
    scope: Optional[str]
    identity: Dict[str, Any] = field(default_factory=dict)
    raw: Dict[str, Any] = field(default_factory=dict, repr=False)

    @property
    def scopes(self) -> List[str]:
        """The issued scope values as a list."""
        return self.scope.split() if self.scope else []


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
        self,
        action: str,
        context: Optional[Mapping[str, Any]] = None,
        *,
        traceparent: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Ask whether the agent may perform *action* (LLM tool preflight).

        Returns a dict with ``allowed``, ``action``, ``reason``, ``audit_id``
        and the original ``context``. ``ip``, ``userAgent``, ``requestMethod``
        and ``requestPath`` in the context always describe the request that
        LumoAuth received; values you pass under those names are kept under
        ``pep`` (the same rule as ABAC).

        ``traceparent`` (a W3C Trace Context header value) is sent as the
        ``traceparent`` header, so that the audit entries of the decision
        carry the trace ID of your trace.
        """
        body: Dict[str, Any] = {"action": action}
        if context:
            body["context"] = dict(context)
        headers = {"traceparent": traceparent} if traceparent else None
        return self._http.call("agents.ask", json=body, headers=headers)

    def is_allowed(
        self,
        action: str,
        context: Optional[Mapping[str, Any]] = None,
        *,
        traceparent: Optional[str] = None,
    ) -> bool:
        """Boolean shorthand for :meth:`ask`."""
        return bool(self.ask(action, context, traceparent=traceparent).get("allowed", False))

    # ── Usage ─────────────────────────────────────────────────────────

    def report_usage(self, tokens: int = 0, cost_usd: float = 0.0) -> Dict[str, Any]:
        """Report the model tokens and cost that the agent used.

        LumoAuth does not see the agent's model calls, so token and cost
        limits count only the usage reported here. Report after each model
        call (or batch a few). Returns ``recorded`` and ``budget`` (the same
        shape as ``budget_policy`` in UserInfo); ``budget["exhausted"]`` means
        that the next Ask, token or JIT request gets 429. Agent credentials
        only.
        """
        if isinstance(tokens, bool) or not isinstance(tokens, int) or tokens < 0:
            raise ValueError("tokens must be a non-negative integer")
        if isinstance(cost_usd, bool) or not isinstance(cost_usd, (int, float)) or cost_usd < 0:
            raise ValueError("cost_usd must be a non-negative number")
        if tokens == 0 and cost_usd == 0:
            raise ValueError("report tokens or cost_usd greater than zero")
        return self._http.call("agents.reportUsage", json={"tokens": tokens, "cost_usd": cost_usd})

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

    def attest(
        self,
        agent_id: str,
        attestation_token: str,
        *,
        scopes: Optional[Union[str, Sequence[str]]] = None,
        dpop: Optional["DpopProofSigner"] = None,
    ) -> WorkloadAttestation:
        """Exchange a workload's OIDC token for an access token of the agent.

        Workload attestation: the agent's runtime (GitHub Actions, AWS,
        Azure, Google Cloud, Kubernetes, SPIFFE, ...) gives the workload an
        OIDC token, and LumoAuth checks it against the identity registered on
        the agent. No client secret is needed, and the request sends no
        credential of this client: the attestation token is the proof.

        Args:
            agent_id: The agent's ID (``agt_...``).
            attestation_token: The workload's OIDC token (a JWT).
            scopes: Fewer scope values than the agent's capabilities, as a
                list or a space-separated string. Each value must be covered
                by a capability of the agent, or LumoAuth answers 400
                ``invalid_scope``. Without it the token carries every
                capability.
            dpop: A :class:`~lumoauth.dpop.DpopProofSigner`. The request then
                carries a DPoP proof and the token is bound to its key
                (``token_type`` ``"DPoP"``). An agent registered with
                DPoP-bound tokens needs one. A ``use_dpop_nonce`` answer is
                retried once.

        Returns:
            :class:`WorkloadAttestation`.

        Raises:
            LumoAuthValidationError: ``agent_id`` or ``attestation_token`` is
                empty (no request is sent), or the answer has no token.
            LumoAuthAuthenticationError: 401 ``attestation_rejected``. The
                token failed verification, or the agent or organization is
                not active (LumoAuth gives one answer for all of these).
            LumoAuthPermissionDeniedError: 403 ``access_policy_denied``.
            LumoAuthBudgetExceededError: 429 ``budget_exceeded``: the
                agent's budget is used up (a ``LumoAuthRateLimitError``).
            LumoAuthRateLimitError: 429 for too many attestation requests.
            LumoAuthApiError: any other error, such as 400 ``invalid_scope``.
        """
        if not isinstance(agent_id, str) or not agent_id.strip():
            raise LumoAuthValidationError("attest() needs the agent_id")
        if not isinstance(attestation_token, str) or not attestation_token.strip():
            raise LumoAuthValidationError("attest() needs the attestation_token")
        body: Dict[str, Any] = {"attestation_token": attestation_token}
        values = scopes.split() if isinstance(scopes, str) else [s for s in (scopes or []) if s]
        if values:
            body["scope"] = " ".join(values)
        answer = self._http.call(
            "agents.attest",
            path_params={"agent_id": agent_id},
            json=body,
            auth=False,
            dpop=dpop,
        )
        if not isinstance(answer, dict) or not isinstance(answer.get("access_token"), str):
            raise LumoAuthValidationError("unexpected attestation response: no access_token")
        expires_in = answer.get("expires_in")
        scope = answer.get("scope")
        identity = answer.get("identity")
        return WorkloadAttestation(
            access_token=answer["access_token"],
            token_type=str(answer.get("token_type") or "Bearer"),
            expires_in=expires_in if isinstance(expires_in, int) and not isinstance(expires_in, bool) else None,
            scope=scope if isinstance(scope, str) and scope else None,
            identity=identity if isinstance(identity, dict) else {},
            raw=answer,
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

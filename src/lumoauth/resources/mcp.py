"""MCP token exchange and per-tool authorization checks."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, Literal, Optional
from urllib.parse import urlsplit

from lumoauth._http import HttpClient
from lumoauth.errors import (
    LumoAuthConfigError,
    LumoAuthPermissionDeniedError,
    LumoAuthValidationError,
)
from lumoauth.resources.auth import AuthResource

logger = logging.getLogger("lumoauth.mcp")

__all__ = [
    "McpResource",
    "McpToolDecision",
    "McpSubjectType",
    "validate_mcp_server_id",
]

McpSubjectType = Literal["user", "agent"]

# Characters that the server rejects in a tool name or registered server id.
_FORBIDDEN_CHARS = ("/", ":", "#", "*")
_MAX_TOOL_LENGTH = 80


@dataclass(frozen=True)
class McpToolDecision:
    """Answer of :meth:`McpResource.authorize_tool`.

    ``allowed`` is ``False`` for a deny decision. A deny is a normal result,
    not an error. ``resource_id`` has the form ``"<server_id>/<tool>"``.
    """

    allowed: bool
    subject_type: str
    subject_id: str
    resource_type: str
    resource_id: str


def _require_text(value: Any, what: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise LumoAuthValidationError(f"{what} is required")


def _check_name(value: str, what: str) -> None:
    bad = [c for c in _FORBIDDEN_CHARS if c in value]
    if bad:
        raise LumoAuthValidationError(
            f"invalid {what} {value!r}: it must not contain '/', ':', '#' or '*'"
        )


def validate_registered_server_id(server_id: Any) -> None:
    """Check a registered MCP server id, such as ``"mcp_0123456789abcdef01234567"``.

    This is the id of the server record in LumoAuth. It is not the
    server's https URL.
    """
    _require_text(server_id, "server_id")
    _check_name(server_id, "MCP server id")


def validate_tool_name(tool: Any) -> None:
    """Check an MCP tool name before it is sent to LumoAuth."""
    _require_text(tool, "tool")
    _check_name(tool, "tool name")
    if len(tool) > _MAX_TOOL_LENGTH:
        raise LumoAuthValidationError(
            f"invalid tool name: it has {len(tool)} characters, "
            f"and the limit is {_MAX_TOOL_LENGTH}"
        )


def deny_body(exc: LumoAuthPermissionDeniedError) -> Optional[Dict[str, Any]]:
    """Return the body of a 403 deny decision, or ``None`` for a real error.

    A deny decision is a 403 whose JSON body has ``"allowed": false``.
    Other 403 answers, such as ``insufficient_scope``, have no
    ``allowed`` key and stay errors.
    """
    body = exc.body
    if exc.status_code == 403 and isinstance(body, dict) and body.get("allowed") is False:
        return body
    return None


def validate_mcp_server_id(server_id: str) -> None:
    """Check that *server_id* can be sent as the RFC 8707 ``resource``.

    LumoAuth binds the token's ``aud`` from ``resource`` only. The value
    must be an absolute ``https`` URL (``http`` only for localhost and
    private hosts, which the server checks) with no fragment.
    """
    parts = urlsplit(server_id) if isinstance(server_id, str) else None
    if (
        parts is None
        or parts.scheme.lower() not in ("https", "http")
        or not parts.netloc
        or parts.fragment
        or "#" in server_id
    ):
        raise LumoAuthValidationError(
            f"invalid MCP server id {server_id!r}: the MCP server id must be the "
            "server's https URL (its RFC 8707 resource identifier), e.g. "
            "'https://mcp.example.com/mcp'"
        )


class McpResource:
    """MCP operations.

    - :meth:`get_token`: RFC 8693 token exchange for a token bound to one
      MCP server (RFC 8707 ``resource``).
    - :meth:`authorize_tool`: per-tool check for an MCP server, made with
      the server's own client-credentials token.
    """

    def __init__(self, http: HttpClient) -> None:
        self._http = http
        self._auth = AuthResource(http)

    def get_token(
        self, server_id: str, *, subject_token: Optional[str] = None
    ) -> str:
        """Exchange a token for one bound to a secured MCP server.

        The new token names exactly one MCP server. The server id goes out
        as the RFC 8707 ``resource`` parameter, and LumoAuth sets the
        token's ``aud`` to it. It is also sent as ``audience``, which
        LumoAuth ignores. Pass the server's registered Resource URI.

        The token works only at that MCP server. LumoAuth's own API rejects
        it. If the MCP server requires DPoP, you need a DPoP-bound exchange
        instead, and this helper does not make one.

        Args:
            server_id: The MCP server's https URL, its RFC 8707 resource
                identifier (e.g. ``"https://mcp.example.com/mcp"``).
            subject_token: Token to exchange.  Defaults to the client's
                bearer token (from its ``token_provider``).

        Returns:
            The access token string, with ``aud`` set to *server_id*.

        Raises:
            LumoAuthValidationError: *server_id* is not an absolute http(s)
                URL, or it has a fragment.
        """
        validate_mcp_server_id(server_id)
        token = subject_token
        if not token and self._http.token_provider:
            token = self._http.token_provider()
        if not token:
            raise LumoAuthConfigError(
                "MCP token exchange needs a subject token — authenticate first "
                "or pass subject_token explicitly."
            )
        response = self._auth.token_exchange(
            token, audience=server_id, resource=server_id
        )
        return response["access_token"]

    def authorize_tool(
        self,
        server_id: str,
        subject_type: McpSubjectType,
        subject_id: str,
        tool: str,
    ) -> McpToolDecision:
        """Ask whether a verified caller may run one tool on an MCP server.

        The MCP server calls this method. The client must hold the MCP
        server's own client-credentials token with the scope
        ``mcp:authorize``, and its client must be listed as a tool
        authorizer of that server. Never pass the caller's token: the MCP
        specification forbids token passthrough.

        Args:
            server_id: The registered MCP server id, such as
                ``"mcp_0123456789abcdef01234567"``. This is not the
                resource URI.
            subject_type: ``"user"`` or ``"agent"``.
            subject_id: The ``sub`` claim of the verified MCP token. For
                an agent you may also pass the agent id (``agt_…``).
            tool: The tool name, at most 80 characters.

        Returns:
            :class:`McpToolDecision`. A deny returns ``allowed=False`` and
            does not raise.

        Raises:
            LumoAuthValidationError: An argument is empty or malformed. No
                request is sent.
            LumoAuthAuthenticationError: 401, the token is not a
                client-credentials token of this organization.
            LumoAuthPermissionDeniedError: 403 without a decision, such as
                ``insufficient_scope`` or ``forbidden``.
            LumoAuthNotFoundError: 404, the MCP server does not exist.
            LumoAuthRateLimitError: 429.
        """
        validate_registered_server_id(server_id)
        if subject_type not in ("user", "agent"):
            raise LumoAuthValidationError(
                f"invalid subject_type {subject_type!r}: use 'user' or 'agent'"
            )
        _require_text(subject_id, "subject_id")
        validate_tool_name(tool)

        payload = {"subject": {"type": subject_type, "id": subject_id}, "tool": tool}
        try:
            body = self._http.call(
                "mcp.authorize_tool",
                path_params={"server_id": server_id},
                json=payload,
            )
        except LumoAuthPermissionDeniedError as exc:
            body = deny_body(exc)
            if body is None:
                raise

        if not isinstance(body, dict):
            raise LumoAuthValidationError("unexpected MCP authorize response")
        subject = body.get("subject") if isinstance(body.get("subject"), dict) else {}
        resource = body.get("resource") if isinstance(body.get("resource"), dict) else {}
        return McpToolDecision(
            allowed=body.get("allowed") is True,
            subject_type=str(subject.get("type", subject_type)),
            subject_id=str(subject.get("id", subject_id)),
            resource_type=str(resource.get("type", "mcp_tool")),
            resource_id=str(resource.get("id", f"{server_id}/{tool}")),
        )

"""MCP token exchange — tokens bound to one secured MCP server."""

from __future__ import annotations

import logging
from typing import Optional
from urllib.parse import urlsplit

from lumoauth._http import HttpClient
from lumoauth.errors import LumoAuthConfigError, LumoAuthValidationError
from lumoauth.resources.auth import AuthResource

logger = logging.getLogger("lumoauth.mcp")

__all__ = ["McpResource", "validate_mcp_server_id"]


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
    """RFC 8693 token exchange bound to one MCP server (RFC 8707 ``resource``)."""

    def __init__(self, http: HttpClient) -> None:
        self._http = http
        self._auth = AuthResource(http)

    def get_token(
        self, server_id: str, *, subject_token: Optional[str] = None
    ) -> str:
        """Exchange a token for one bound to a secured MCP server.

        The server id goes out as the RFC 8707 ``resource`` parameter, which
        becomes the token's ``aud`` (it is also sent as ``audience``, which
        LumoAuth ignores).

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

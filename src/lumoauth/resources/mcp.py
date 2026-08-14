"""MCP token exchange — audience-scoped tokens for secured MCP servers."""

from __future__ import annotations

import logging
from typing import Optional

from lumoauth._http import HttpClient
from lumoauth.errors import LumoAuthConfigError
from lumoauth.resources.auth import AuthResource

logger = logging.getLogger("lumoauth.mcp")

__all__ = ["McpResource"]


class McpResource:
    """RFC 8693 token exchange scoped to an MCP server audience."""

    def __init__(self, http: HttpClient) -> None:
        self._http = http
        self._auth = AuthResource(http)

    def get_token(
        self, server_id: str, *, subject_token: Optional[str] = None
    ) -> str:
        """Exchange a token for one scoped to a secured MCP server.

        Args:
            server_id: Audience identifier of the target MCP server
                (e.g. ``"urn:mcp:financial-data"``).
            subject_token: Token to exchange.  Defaults to the client's
                bearer token (from its ``token_provider``).

        Returns:
            The audience-scoped access token string.
        """
        token = subject_token
        if not token and self._http.token_provider:
            token = self._http.token_provider()
        if not token:
            raise LumoAuthConfigError(
                "MCP token exchange needs a subject token — authenticate first "
                "or pass subject_token explicitly."
            )
        response = self._auth.token_exchange(token, audience=server_id)
        return response["access_token"]

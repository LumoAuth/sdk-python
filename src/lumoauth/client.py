"""``LumoAuth`` — the general-purpose LumoAuth API client with resource namespaces."""

from __future__ import annotations

import os
from typing import Any, Callable, Optional

from lumoauth._http import HttpClient
from lumoauth.errors import LumoAuthConfigError
from lumoauth.resources import (
    AbacResource,
    AgentsResource,
    ApprovalsResource,
    AuthResource,
    DelegationResource,
    JitResource,
    McpResource,
    PermissionsResource,
    ZanzibarResource,
)

__all__ = ["LumoAuth"]

_DEFAULT_BASE_URL = "https://app.lumoauth.dev"


class LumoAuth:
    """LumoAuth API client.

    Curated resource namespaces cover the common surface; the ``api``
    property exposes the generated OpenAPI client for everything else.

    Example::

        from lumoauth import LumoAuth

        client = LumoAuth(api_key="lk_…", org_id="acme-corp")

        if client.permissions.check("document.edit"):
            ...
        decision = client.abac.check("document", "read", "doc-123")

    All constructor arguments are keyword-only and fall back to environment
    variables:

    ==================  =========================
    Parameter           Environment variable
    ==================  =========================
    ``base_url``        ``LUMOAUTH_URL``
    ``org_id``          ``LUMOAUTH_ORG_ID``
    ``api_key``         ``LUMOAUTH_API_KEY``
    ==================  =========================

    Args:
        api_key: API key sent as ``X-API-Key``.
        base_url: LumoAuth instance URL.
        org_id: Organization ID (required for org-scoped endpoints).
        token_provider: Zero-argument callable returning a bearer token;
            when it yields a token it wins over ``api_key``.
        timeout: Default request timeout in seconds.
        skip_cert_validation: Disable TLS verification (local dev only).
    """

    def __init__(
        self,
        *,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        org_id: Optional[str] = None,
        token_provider: Optional[Callable[[], Optional[str]]] = None,
        timeout: float = 30,
        skip_cert_validation: bool = False,
    ) -> None:
        self.base_url: str = (
            base_url or os.environ.get("LUMOAUTH_URL") or _DEFAULT_BASE_URL
        ).rstrip("/")
        self.org_id: Optional[str] = org_id or os.environ.get("LUMOAUTH_ORG_ID") or None
        self.api_key: Optional[str] = api_key or os.environ.get("LUMOAUTH_API_KEY") or None
        self.timeout: float = timeout

        self._http = HttpClient(
            self.base_url,
            org_id=self.org_id,
            api_key=self.api_key,
            token_provider=token_provider,
            timeout=timeout,
            verify_tls=not skip_cert_validation,
        )

        # Resource namespaces
        self.auth = AuthResource(self._http)
        self.permissions = PermissionsResource(self._http)
        self.zanzibar = ZanzibarResource(self._http)
        self.abac = AbacResource(self._http)
        self.agents = AgentsResource(self._http)
        self.delegation = DelegationResource(self._http)
        self.jit = JitResource(self._http)
        self.approvals = ApprovalsResource(self._http)
        self.mcp = McpResource(self._http)

        self._api: Any = None

    # ── Escape hatch: generated OpenAPI client ────────────────────────

    @property
    def api(self) -> Any:
        """The generated ``lumoauth_api_client`` for the full API surface.

        Configured lazily with this client's ``base_url`` and credentials.
        Requires the optional generated client package::

            pip install lumoauth-api-client     # or: pip install "lumoauth[api]"
        """
        if self._api is None:
            try:
                import lumoauth_api_client  # type: ignore[import-not-found]
            except ImportError as exc:
                raise LumoAuthConfigError(
                    "The generated API client is not installed. Install it with "
                    "`pip install lumoauth-api-client` "
                    '(or `pip install "lumoauth[api]"`) to use `client.api`.'
                ) from exc

            token_provider = self._http.token_provider
            if token_provider:
                # Resolve the token per request (agents refresh tokens); a
                # one-time snapshot would go stale after expiry.
                class _RefreshingConfiguration(lumoauth_api_client.Configuration):
                    @property
                    def access_token(self) -> Any:
                        return token_provider()

                    @access_token.setter
                    def access_token(self, value: Any) -> None:
                        # The generated __init__ assigns a static token here;
                        # the provider is authoritative, so ignore it.
                        pass

                configuration = _RefreshingConfiguration(host=self.base_url)
            else:
                configuration = lumoauth_api_client.Configuration(host=self.base_url)
                if self.api_key:
                    try:
                        configuration.api_key["ApiKeyAuth"] = self.api_key
                    except (AttributeError, TypeError):  # pragma: no cover
                        pass
            if not self._http.verify_tls:
                configuration.verify_ssl = False
            self._api = lumoauth_api_client.ApiClient(configuration=configuration)
        return self._api


def __getattr__(name: str) -> Any:
    # Backwards compatibility: `from lumoauth.client import LumoAuthAgent`
    # worked before the 1.0 restructure moved the agent to lumoauth.agent.
    if name == "LumoAuthAgent":
        from lumoauth.agent import LumoAuthAgent

        return LumoAuthAgent
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

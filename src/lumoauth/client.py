"""``LumoAuth`` — the general-purpose LumoAuth API client with resource namespaces."""

from __future__ import annotations

import os
from typing import Any, Callable, Optional

from lumoauth._http import HttpClient
from lumoauth._routes import normalize_custom_domain, strip_org_segment
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
    PoppyResource,
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

        client = LumoAuth(api_key="lmk_…", org_id="acme-corp")

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
    ``custom_domain``   ``LUMOAUTH_CUSTOM_DOMAIN``
    ``api_key``         ``LUMOAUTH_API_KEY``
    ``client_id``       ``LUMOAUTH_CLIENT_ID``
    ``client_secret``   ``LUMOAUTH_CLIENT_SECRET``
    ==================  =========================

    Args:
        api_key: API key sent as ``X-API-Key``.
        base_url: LumoAuth instance URL.
        org_id: Organization ID (required for org-scoped endpoints, unless
            ``custom_domain`` is set).
        custom_domain: The organization's own domain, as a host name or an
            ``https://`` origin (``"auth.acme.com"``). The client then
            sends every request to that domain, with paths that have no
            ``/orgs/{org_id}`` segment, and ``base_url`` is not used.
            ``org_id`` is not needed. A malformed value raises
            :class:`~lumoauth.LumoAuthConfigError`.
        token_provider: Zero-argument callable returning a bearer token;
            when it yields a token it wins over ``api_key``.
        timeout: Default request timeout in seconds.
        skip_cert_validation: Disable TLS verification (local dev only).
        client_id: Client ID of a confidential application. Only the
            Personal Agent Protocol calls (``client.poppy``) use it: they
            authenticate with HTTP Basic instead of the token or API key.
        client_secret: The secret of that application. Its allowed scopes
            must include ``poppy:verify``.
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
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        custom_domain: Optional[str] = None,
    ) -> None:
        #: The organization's custom domain as ``https://<host>[:port]``, or ``None``.
        self.custom_domain: Optional[str] = normalize_custom_domain(
            custom_domain
        ) or normalize_custom_domain(os.environ.get("LUMOAUTH_CUSTOM_DOMAIN"))
        # A custom domain that is set wins over the base URL.
        self.base_url: str = self.custom_domain or (
            base_url or os.environ.get("LUMOAUTH_URL") or _DEFAULT_BASE_URL
        ).rstrip("/")
        self.org_id: Optional[str] = org_id or os.environ.get("LUMOAUTH_ORG_ID") or None
        self.api_key: Optional[str] = api_key or os.environ.get("LUMOAUTH_API_KEY") or None
        self.timeout: float = timeout
        self.client_id: Optional[str] = client_id or os.environ.get("LUMOAUTH_CLIENT_ID") or None

        self._http = HttpClient(
            self.base_url,
            org_id=self.org_id,
            api_key=self.api_key,
            token_provider=token_provider,
            timeout=timeout,
            verify_tls=not skip_cert_validation,
            custom_domain=self.custom_domain,
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
        # The client secret is kept by the resource only, not on the client.
        self.poppy = PoppyResource(
            self._http,
            client_id=self.client_id,
            client_secret=client_secret or os.environ.get("LUMOAUTH_CLIENT_SECRET") or None,
        )

        self._api: Any = None

    @property
    def issuer(self) -> str:
        """The organization's issuer identifier: the ``iss`` of its tokens.

        ``{base_url}/orgs/{org_id}/api/v1`` on the platform host, and the
        bare domain on a custom domain. Pass it to
        :func:`lumoauth.verify_access_token`.

        Raises:
            LumoAuthConfigError: No custom domain is set and ``org_id`` is
                missing.
        """
        return self._http.issuer

    # ── Escape hatch: generated OpenAPI client ────────────────────────

    @property
    def api(self) -> Any:
        """The generated ``lumoauth_api_client`` for the full API surface.

        Configured lazily with this client's ``base_url`` and credentials.
        Requires the optional generated client package::

            pip install lumoauth-api-client     # or: pip install "lumoauth[api]"

        On a custom domain the generated client sends each request to the
        domain, without the ``/orgs/{orgId}`` segment of the path. Its
        methods still take ``org_id``: pass any value, it is not sent.
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
            api_client_class = lumoauth_api_client.ApiClient
            if self.custom_domain is not None:
                # The generated routes carry "/orgs/{orgId}", which a custom
                # domain does not serve. Drop the segment where the
                # generated client turns a route into a URL.
                class _CustomDomainApiClient(lumoauth_api_client.ApiClient):  # type: ignore[misc]
                    def param_serialize(self, *args: Any, **kwargs: Any) -> Any:
                        if isinstance(kwargs.get("resource_path"), str):
                            kwargs["resource_path"] = strip_org_segment(
                                kwargs["resource_path"], "{orgId}"
                            )
                        elif len(args) > 1 and isinstance(args[1], str):
                            args = (args[0], strip_org_segment(args[1], "{orgId}"), *args[2:])
                        return super().param_serialize(*args, **kwargs)

                api_client_class = _CustomDomainApiClient
            self._api = api_client_class(configuration=configuration)
        return self._api


def __getattr__(name: str) -> Any:
    # Backwards compatibility: `from lumoauth.client import LumoAuthAgent`
    # worked before the 1.0 restructure moved the agent to lumoauth.agent.
    if name == "LumoAuthAgent":
        from lumoauth.agent import LumoAuthAgent

        return LumoAuthAgent
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

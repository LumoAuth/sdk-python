"""Internal HTTP client — auth injection, JSON handling, typed error mapping."""

from __future__ import annotations

import datetime
import email.utils
import logging
import math
import time
from typing import TYPE_CHECKING, Any, Callable, Dict, Mapping, Optional

import requests

from lumoauth._routes import (
    ROUTES,
    format_path,
    issuer_url,
    normalize_custom_domain,
    org_api_base,
    strip_org_segment,
)
from lumoauth.errors import (
    LumoAuthApiError,
    LumoAuthAuthenticationError,
    LumoAuthBudgetExceededError,
    LumoAuthConfigError,
    LumoAuthNetworkError,
    LumoAuthNotFoundError,
    LumoAuthPermissionDeniedError,
    LumoAuthRateLimitError,
)

if TYPE_CHECKING:  # pragma: no cover
    from lumoauth.dpop import DpopProofSigner

logger = logging.getLogger("lumoauth.http")

__all__ = ["HttpClient"]

_STATUS_ERRORS = {
    401: LumoAuthAuthenticationError,
    403: LumoAuthPermissionDeniedError,
    404: LumoAuthNotFoundError,
    429: LumoAuthRateLimitError,
}

# A body code that names a more specific class than the status does
# (sdk-contract/errors.json, body_code_map). Only for these statuses.
_BODY_CODE_ERRORS = {
    (429, "budget_exceeded"): LumoAuthBudgetExceededError,
}


class HttpClient:
    """Thin wrapper around :class:`requests.Session` used by every resource.

    - Injects credentials on each request: a ``token_provider`` callable
      yields a bearer token (``Authorization: Bearer …``); an ``api_key``
      is sent as ``X-API-Key``.  Explicit ``Authorization`` / ``X-API-Key``
      headers passed per-request always win.
    - Maps error statuses to the typed errors in :mod:`lumoauth.errors`,
      parsing ``error`` / ``code`` / ``error_description`` / ``message``
      from JSON bodies when present. A 429 with the body code
      ``budget_exceeded`` raises ``LumoAuthBudgetExceededError`` (a
      ``LumoAuthRateLimitError``).
    - Wraps ``requests`` transport exceptions in ``LumoAuthNetworkError``.
    - Returns parsed JSON (or ``None`` for 204 / empty bodies).
    - DPoP (RFC 9449): when ``dpop`` holds a
      :class:`~lumoauth.dpop.DpopProofSigner`, bearer tokens go out as
      ``Authorization: DPoP …`` with a ``DPoP`` proof; a per-request
      ``dpop=`` signer adds a proof to an unauthenticated call (the token
      endpoint). A ``use_dpop_nonce`` answer is retried once with the
      nonce the server sent.
    - Custom domain: with ``custom_domain`` the domain is the base URL, no
      path carries the ``/orgs/{org_id}`` segment, and ``org_id`` is not
      needed. ``base_url`` is then not used for any request. The rule
      itself is in :mod:`lumoauth._routes`.
    """

    def __init__(
        self,
        base_url: str,
        *,
        org_id: Optional[str] = None,
        api_key: Optional[str] = None,
        token_provider: Optional[Callable[[], Optional[str]]] = None,
        timeout: float = 30,
        verify_tls: bool = True,
        session: Optional[requests.Session] = None,
        custom_domain: Optional[str] = None,
    ) -> None:
        # Raises LumoAuthConfigError for a malformed value, when the client
        # is created. A custom domain that is set wins over the base URL.
        self.custom_domain: Optional[str] = normalize_custom_domain(custom_domain)
        self.base_url = self.custom_domain or (base_url or "").rstrip("/")
        self.org_id = org_id
        self.api_key = api_key
        self.token_provider = token_provider
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.session = session if session is not None else requests.Session()
        # Set when the bearer token from ``token_provider`` is DPoP-bound.
        self.dpop: Optional["DpopProofSigner"] = None

    # ── URL helpers ───────────────────────────────────────────────────

    def org_path(self, path: str) -> str:
        """Prefix *path* with the org-scoped API base.

        ``/orgs/{org}/api/v1`` on the platform host, ``/api/v1`` on a
        custom domain.
        """
        if self.custom_domain is not None:
            return f"/api/v1{path}"
        if not self.org_id:
            raise LumoAuthConfigError(
                "org_id is required for this call — pass org_id to the client "
                "constructor or set LUMOAUTH_ORG_ID."
            )
        return f"/orgs/{self.org_id}/api/v1{path}"

    def _fill_route(self, route: str, path_params: Optional[Mapping[str, Any]]):
        params = dict(path_params or {})
        if self.custom_domain is not None:
            # No path carries the organization on a custom domain, so the
            # organization ID is not needed.
            return format_path(route, custom_domain=True, **params)
        _, template = ROUTES[route]
        if "{org_id}" in template and "org_id" not in params:
            if not self.org_id:
                raise LumoAuthConfigError(
                    f"org_id is required for '{route}' — pass org_id to the "
                    "client constructor or set LUMOAUTH_ORG_ID."
                )
            params["org_id"] = self.org_id
        return format_path(route, **params)

    def route_url(self, route: str, path_params: Optional[Mapping[str, Any]] = None) -> str:
        """The full URL of a registered route for this client."""
        _, path = self._fill_route(route, path_params)
        return f"{self.base_url}{path}"

    @property
    def issuer(self) -> str:
        """The organization's issuer: the ``iss`` of its tokens.

        ``{base_url}/orgs/{org_id}/api/v1`` on the platform host, and the
        bare domain on a custom domain.
        """
        return issuer_url(self.base_url, self.org_id, self.custom_domain)

    @property
    def api_base(self) -> str:
        """The address below which the organization's API routes are served."""
        return org_api_base(self.base_url, self.org_id, self.custom_domain)

    def _own_path(self, path: str) -> str:
        """A path that the caller wrote, in the form that this client's host serves.

        On a custom domain the ``/orgs/{org}`` segment of the client's own
        organization is dropped, so that a path written for the platform
        host keeps working. It is dropped only when the organization ID is
        known. Any other path is sent as it stands.
        """
        if self.custom_domain is not None and self.org_id:
            return strip_org_segment(path, self.org_id)
        return path

    # ── Request entry points ──────────────────────────────────────────

    def call(
        self,
        route: str,
        *,
        path_params: Optional[Mapping[str, Any]] = None,
        json: Optional[Any] = None,
        data: Optional[Any] = None,
        params: Optional[Mapping[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
        timeout: Optional[float] = None,
        auth: bool = True,
        raw: bool = False,
        dpop: Optional["DpopProofSigner"] = None,
        allow_redirects: Optional[bool] = None,
    ) -> Any:
        """Invoke a route from the :mod:`lumoauth._routes` registry."""
        method, path = self._fill_route(route, path_params)
        return self.request(
            method,
            path,
            json=json,
            data=data,
            params=params,
            headers=headers,
            timeout=timeout,
            auth=auth,
            raw=raw,
            dpop=dpop,
            allow_redirects=allow_redirects,
        )

    def request(
        self,
        method: str,
        path_or_url: str,
        *,
        json: Optional[Any] = None,
        data: Optional[Any] = None,
        params: Optional[Mapping[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
        timeout: Optional[float] = None,
        auth: bool = True,
        raw: bool = False,
        dpop: Optional["DpopProofSigner"] = None,
        allow_redirects: Optional[bool] = None,
    ) -> Any:
        """Send a request to a path (joined to ``base_url``) or a full URL.

        With ``raw=True`` the :class:`requests.Response` is returned without
        status mapping (transport errors are still wrapped). ``dpop`` adds a
        DPoP proof without a token (token endpoint); bearer tokens are
        DPoP-bound when :attr:`dpop` is set on the client.
        ``allow_redirects=False`` makes a redirect answer an error instead of
        a second request: use it for a call whose body must not be sent to
        another address.
        """
        url = (
            path_or_url
            if path_or_url.startswith(("http://", "https://"))
            else f"{self.base_url}{self._own_path(path_or_url)}"
        )

        hdrs: Dict[str, str] = dict(headers or {})
        signer = dpop
        proof_token: Optional[str] = None
        if auth and "Authorization" not in hdrs and "X-API-Key" not in hdrs:
            token = self.token_provider() if self.token_provider else None
            if token:
                if self.dpop is not None:
                    signer, proof_token = self.dpop, token
                    hdrs["Authorization"] = f"DPoP {token}"
                else:
                    hdrs["Authorization"] = f"Bearer {token}"
            elif self.api_key:
                # The server accepts API keys via X-API-Key (leaving the
                # Authorization header free for bearer tokens).
                hdrs["X-API-Key"] = self.api_key
        add_proof = signer is not None and "DPoP" not in hdrs
        extra: Dict[str, Any] = {}
        if allow_redirects is not None:
            extra["allow_redirects"] = allow_redirects

        for attempt in (0, 1):
            send_headers = dict(hdrs)
            if add_proof:
                send_headers["DPoP"] = signer.create_proof(method, url, access_token=proof_token)
            try:
                resp = self.session.request(
                    method.upper(),
                    url,
                    json=json,
                    data=data,
                    params=dict(params) if params else None,
                    headers=send_headers,
                    timeout=timeout if timeout is not None else self.timeout,
                    verify=self.verify_tls,
                    **extra,
                )
            except requests.RequestException as exc:
                raise LumoAuthNetworkError(
                    f"Request to {url} failed: {exc}", cause=exc
                ) from exc
            if not add_proof:
                break
            signer.observe_response(url, resp.headers)
            if attempt == 1 or not _wants_new_nonce(resp):
                break
            logger.debug("Server asked for a DPoP nonce; retrying %s %s once", method, url)

        if raw:
            return resp
        return self._handle(resp)

    # ── Response handling ─────────────────────────────────────────────

    def _handle(self, resp: requests.Response) -> Any:
        if resp.status_code == 204:
            return None

        body = self._parse_body(resp)

        if 200 <= resp.status_code < 300:
            return body

        message, code = self._extract_error(resp, body)
        err_cls = _BODY_CODE_ERRORS.get((resp.status_code, code or "")) or _STATUS_ERRORS.get(
            resp.status_code
        )
        if err_cls is not None and issubclass(err_cls, LumoAuthRateLimitError):
            # LumoAuthBudgetExceededError is a LumoAuthRateLimitError too.
            retry_after = _parse_retry_after(resp.headers.get("Retry-After"))
            raise err_cls(
                message, code=code or err_cls().code,
                status_code=resp.status_code, body=body, retry_after=retry_after,
            )
        if err_cls is not None:
            raise err_cls(
                message,
                code=code or err_cls().code,
                status_code=resp.status_code,
                body=body,
            )
        raise LumoAuthApiError(
            message, code=code or "API_ERROR", status_code=resp.status_code, body=body
        )

    @staticmethod
    def _parse_body(resp: requests.Response) -> Any:
        content_type = resp.headers.get("content-type", "")
        text = resp.text
        if not text:
            return None
        if "json" in content_type:
            try:
                return resp.json()
            except ValueError:
                return text
        # Some endpoints omit the content type — try JSON anyway.
        try:
            return resp.json()
        except ValueError:
            return text

    @staticmethod
    def _extract_error(resp: requests.Response, body: Any):
        message = f"HTTP {resp.status_code}"
        code = None
        if isinstance(body, dict):
            message = (
                body.get("error_description")
                or body.get("message")
                or body.get("detail")
                or body.get("error")
                or message
            )
            code = body.get("code") or body.get("error")
            if not isinstance(code, str):
                code = None
            if not isinstance(message, str):
                message = f"HTTP {resp.status_code}"
        elif isinstance(body, str) and body.strip():
            message = f"HTTP {resp.status_code} — {body.strip()[:500]}"
        return message, code


def _wants_new_nonce(resp: requests.Response) -> bool:
    from lumoauth.dpop import wants_new_nonce

    if resp.status_code not in (400, 401):
        return False
    return wants_new_nonce(resp.status_code, resp.headers, HttpClient._parse_body(resp))


def _parse_retry_after(value: Optional[str], now: Optional[float] = None) -> Optional[float]:
    """Seconds from a ``Retry-After`` header (RFC 9110 section 10.2.3).

    The value is a number of seconds (``"120"``) or an HTTP date
    (``"Fri, 27 Nov 2026 18:00:00 GMT"``). A date gives the seconds from now
    until that date, and 0 for a date in the past. Anything else gives None.
    """
    if not value or not isinstance(value, str):
        return None
    text = value.strip()
    try:
        seconds = float(text)
    except ValueError:
        seconds = None
    if seconds is not None:
        return seconds if math.isfinite(seconds) and seconds >= 0 else None
    try:
        when = email.utils.parsedate_to_datetime(text)
    except (TypeError, ValueError, IndexError):
        return None
    if when is None:
        return None
    if when.tzinfo is None:
        # The asctime form has no zone; HTTP dates are always in UTC.
        when = when.replace(tzinfo=datetime.timezone.utc)
    current = time.time() if now is None else now
    return max(0.0, when.timestamp() - current)

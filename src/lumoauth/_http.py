"""Internal HTTP client — auth injection, JSON handling, typed error mapping."""

from __future__ import annotations

import logging
from typing import Any, Callable, Dict, Mapping, Optional

import requests

from lumoauth._routes import ROUTES, format_path
from lumoauth.errors import (
    LumoAuthApiError,
    LumoAuthAuthenticationError,
    LumoAuthConfigError,
    LumoAuthNetworkError,
    LumoAuthNotFoundError,
    LumoAuthPermissionDeniedError,
    LumoAuthRateLimitError,
)

logger = logging.getLogger("lumoauth.http")

__all__ = ["HttpClient"]

_STATUS_ERRORS = {
    401: LumoAuthAuthenticationError,
    403: LumoAuthPermissionDeniedError,
    404: LumoAuthNotFoundError,
    429: LumoAuthRateLimitError,
}


class HttpClient:
    """Thin wrapper around :class:`requests.Session` used by every resource.

    - Injects credentials on each request: a ``token_provider`` callable
      yields a bearer token (``Authorization: Bearer …``); an ``api_key``
      is sent as ``X-API-Key``.  Explicit ``Authorization`` / ``X-API-Key``
      headers passed per-request always win.
    - Maps error statuses to the typed errors in :mod:`lumoauth.errors`,
      parsing ``error`` / ``code`` / ``error_description`` / ``message``
      from JSON bodies when present.
    - Wraps ``requests`` transport exceptions in ``LumoAuthNetworkError``.
    - Returns parsed JSON (or ``None`` for 204 / empty bodies).
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
    ) -> None:
        self.base_url = (base_url or "").rstrip("/")
        self.org_id = org_id
        self.api_key = api_key
        self.token_provider = token_provider
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.session = session if session is not None else requests.Session()

    # ── URL helpers ───────────────────────────────────────────────────

    def org_path(self, path: str) -> str:
        """Prefix *path* with the org-scoped API base (``/orgs/{org}/api/v1``)."""
        if not self.org_id:
            raise LumoAuthConfigError(
                "org_id is required for this call — pass org_id to the client "
                "constructor or set LUMOAUTH_ORG_ID."
            )
        return f"/orgs/{self.org_id}/api/v1{path}"

    def _fill_route(self, route: str, path_params: Optional[Mapping[str, Any]]):
        params = dict(path_params or {})
        _, template = ROUTES[route]
        if "{org_id}" in template and "org_id" not in params:
            if not self.org_id:
                raise LumoAuthConfigError(
                    f"org_id is required for '{route}' — pass org_id to the "
                    "client constructor or set LUMOAUTH_ORG_ID."
                )
            params["org_id"] = self.org_id
        return format_path(route, **params)

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
    ) -> Any:
        """Send a request to a path (joined to ``base_url``) or a full URL.

        With ``raw=True`` the :class:`requests.Response` is returned without
        status mapping (transport errors are still wrapped).
        """
        url = (
            path_or_url
            if path_or_url.startswith(("http://", "https://"))
            else f"{self.base_url}{path_or_url}"
        )

        hdrs: Dict[str, str] = dict(headers or {})
        if auth and "Authorization" not in hdrs and "X-API-Key" not in hdrs:
            token = self.token_provider() if self.token_provider else None
            if token:
                hdrs["Authorization"] = f"Bearer {token}"
            elif self.api_key:
                # The server accepts API keys via X-API-Key (leaving the
                # Authorization header free for bearer tokens).
                hdrs["X-API-Key"] = self.api_key

        try:
            resp = self.session.request(
                method.upper(),
                url,
                json=json,
                data=data,
                params=dict(params) if params else None,
                headers=hdrs,
                timeout=timeout if timeout is not None else self.timeout,
                verify=self.verify_tls,
            )
        except requests.RequestException as exc:
            raise LumoAuthNetworkError(
                f"Request to {url} failed: {exc}", cause=exc
            ) from exc

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
        err_cls = _STATUS_ERRORS.get(resp.status_code)
        if err_cls is LumoAuthRateLimitError:
            retry_after = _parse_retry_after(resp.headers.get("Retry-After"))
            raise LumoAuthRateLimitError(
                message, code=code or "RATE_LIMITED",
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


def _parse_retry_after(value: Optional[str]) -> Optional[float]:
    if not value:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None

"""Implementation of the FastAPI integration. See ``__init__.py`` for usage."""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import re
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, Optional, Tuple
from urllib.parse import urlencode, urlsplit

from lumoauth._http import HttpClient
from lumoauth._routes import format_path, normalize_custom_domain
from lumoauth.errors import LumoAuthApiError, LumoAuthConfigError, LumoAuthError
from lumoauth.resources.auth import AuthResource

try:
    from fastapi import APIRouter, Depends, HTTPException, Request, status
    from fastapi.responses import RedirectResponse, JSONResponse
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "lumoauth.fastapi requires `fastapi` to be installed. "
        "Add `fastapi` to your dependencies (e.g. `pip install fastapi`)."
    ) from exc

try:
    from pydantic import BaseModel, ConfigDict, Field
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "lumoauth.fastapi requires `pydantic` (a FastAPI dependency)."
    ) from exc

logger = logging.getLogger("lumoauth.fastapi")

# Session key under which all LumoAuth state lives. Single nested dict so
# the host app can wipe LumoAuth-only state with `del request.session["__lumoauth"]`
# without touching unrelated keys.
SESSION_KEY = "__lumoauth"

# The access token is refreshed when it expires in less than this many seconds.
REFRESH_LEEWAY_SECONDS = 60
# For this many seconds the answer of a refresh is reused for a request that
# still carries the old refresh token (one sent before the browser got the new
# session cookie). LumoAuth rotates refresh tokens, and presenting a used one
# again revokes every token of the sign-in.
_REFRESH_REUSE_SECONDS = 30
# Browsers drop a cookie whose name and value are larger than this.
_COOKIE_LIMIT_BYTES = 4096


class User(BaseModel):
    """The signed-in principal returned by ``/userinfo``."""

    model_config = ConfigDict(extra="allow")

    sub: str
    email: Optional[str] = None
    email_verified: Optional[bool] = None
    name: Optional[str] = None
    given_name: Optional[str] = None
    family_name: Optional[str] = None
    picture: Optional[str] = None


@dataclass
class LumoAuthFastAPI:
    """Configuration of the FastAPI integration.

    :func:`lumo_auth_router` builds one for you. Create it yourself to use the
    same configuration for the router and for the :meth:`access_token`
    dependency::

        lumo = LumoAuthFastAPI(base_url=..., organization=..., client_id=..., client_secret=...)
        app.include_router(lumo.router(), prefix="/auth")

        @app.get("/api/documents")
        def documents(token: str = Depends(lumo.access_token)):
            ...

    Pass ``base_url`` and ``organization``, or ``custom_domain`` for an
    organization on its own domain. With ``custom_domain`` the sign-in,
    token and userinfo addresses are on that domain and have no
    ``/orgs/{organization}`` segment; ``base_url`` is not used and
    ``organization`` is not needed.

    ``end_session_on_logout`` (default ``True``): the logout route also ends
    the user's LumoAuth session. ``False`` clears only the local session.
    """

    base_url: Optional[str] = None
    organization: Optional[str] = None
    client_id: str = ""
    client_secret: Optional[str] = None
    callback_path: str = "/auth/callback"
    scope: str = "openid profile email"
    post_login_redirect: str = "/"
    post_logout_redirect: str = "/"
    request_timeout_seconds: float = 10.0
    custom_domain: Optional[str] = None
    end_session_on_logout: bool = True
    _auth: Optional[AuthResource] = field(default=None, repr=False, compare=False)
    _refresh_lock: Any = field(default_factory=threading.Lock, init=False, repr=False, compare=False)
    _refresh_locks: Dict[str, Any] = field(default_factory=dict, init=False, repr=False, compare=False)
    _refreshed: Dict[str, Tuple[float, Dict[str, Any]]] = field(
        default_factory=dict, init=False, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        # A malformed custom domain is an error now, not at the first sign-in.
        self.custom_domain = normalize_custom_domain(self.custom_domain)
        if not self.client_id:
            raise LumoAuthConfigError("client_id is required")
        if self.custom_domain is not None:
            # A custom domain that is set wins over the base URL.
            self.base_url = self.custom_domain
        elif not self.base_url or not self.organization:
            raise LumoAuthConfigError(
                "base_url and organization are required, unless custom_domain is set"
            )

    # ---- Resource wiring ------------------------------------------------

    def auth_resource(self) -> AuthResource:
        """The OAuth resource all HTTP goes through (lazily constructed)."""
        if self._auth is None:
            self._auth = AuthResource(
                HttpClient(
                    (self.base_url or "").rstrip("/"),
                    org_id=self.organization,
                    timeout=self.request_timeout_seconds,
                    custom_domain=self.custom_domain,
                )
            )
        return self._auth

    # ---- URL helpers ----------------------------------------------------

    def _route_url(self, route: str) -> str:
        # lumoauth._routes holds the rule for both hosts.
        _, path = format_path(
            route, custom_domain=self.custom_domain is not None, org_id=self.organization
        )
        return f"{(self.base_url or '').rstrip('/')}{path}"

    def authorize_url(self) -> str:
        return self._route_url("oauth.authorize")

    def token_url(self) -> str:
        return self._route_url("oauth.token")

    def userinfo_url(self) -> str:
        return self._route_url("oauth.userinfo")

    def end_session_url(
        self,
        *,
        id_token_hint: Optional[str] = None,
        post_logout_redirect_uri: Optional[str] = None,
        state: Optional[str] = None,
    ) -> str:
        """The OpenID Connect end-session URL. See :meth:`AuthResource.end_session_url`."""
        return self.auth_resource().end_session_url(
            id_token_hint=id_token_hint,
            post_logout_redirect_uri=post_logout_redirect_uri,
            state=state,
        )

    # ---- PKCE -----------------------------------------------------------

    @staticmethod
    def _pkce_pair() -> tuple[str, str]:
        verifier = base64.urlsafe_b64encode(os.urandom(48)).rstrip(b"=").decode()
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            .rstrip(b"=")
            .decode()
        )
        return verifier, challenge

    # ---- Token exchange -------------------------------------------------

    def exchange_code(
        self, code: str, code_verifier: str, redirect_uri: str
    ) -> dict[str, Any]:
        try:
            return self.auth_resource().exchange_code(
                code,
                redirect_uri,
                client_id=self.client_id,
                client_secret=self.client_secret,
                code_verifier=code_verifier,
            )
        except LumoAuthApiError as exc:
            err = exc.body if isinstance(exc.body, dict) else {}
            raise HTTPException(
                status_code=502,
                detail={
                    "error": err.get("error", "token_exchange_failed"),
                    "error_description": err.get(
                        "error_description",
                        f"HTTP {exc.status_code} from token endpoint",
                    ),
                },
            ) from exc

    def fetch_userinfo(self, access_token: str) -> dict[str, Any]:
        return self.auth_resource().userinfo(access_token)

    # ---- Session tokens -------------------------------------------------

    def _session_tokens(self, tokens: Dict[str, Any], previous: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """What the session keeps of a token response: only what the routes use.

        The access token (for :meth:`access_token`), its expiry and the
        refresh token (to refresh it and to revoke it at sign-out), the
        granted scopes (for :func:`require_auth`) and the ID token (the hint
        that the end-session endpoint needs). No ``token_type``: the router
        asks for bearer tokens only. Values that the server did not send are
        left out; on a refresh the previous refresh and ID token are kept
        when no new one comes.
        """
        previous = previous or {}
        kept: Dict[str, Any] = {"access_token": tokens["access_token"]}
        expires_in = tokens.get("expires_in")
        if isinstance(expires_in, (int, float)) or (isinstance(expires_in, str) and expires_in.isdigit()):
            kept["expires_at"] = int(time.time()) + int(expires_in)
        refresh_token = tokens.get("refresh_token") or previous.get("refresh_token")
        if refresh_token:
            kept["refresh_token"] = refresh_token
        scope = tokens.get("scope", previous.get("scope", ""))
        kept["scope"] = scope or ""
        id_token = tokens.get("id_token") or previous.get("id_token")
        if id_token and self.end_session_on_logout:
            kept["id_token"] = id_token
        return kept

    def access_token(self, request: Request) -> str:
        """FastAPI dependency: the signed-in user's access token.

        When the token expires in less than 60 seconds and the session holds
        a refresh token, it is refreshed first and the session is updated.
        Answers 401 when nobody is signed in, and when the token has expired
        and cannot be refreshed; the LumoAuth state of the session is then
        cleared, so the user signs in again. Answers 503 when LumoAuth cannot
        be reached for the refresh, and keeps the session.

        Use it as ``token: str = Depends(lumo.access_token)``.
        """
        state = _read_state(request)
        tokens = state.get("tokens") or {}
        token = tokens.get("access_token")
        if not state.get("user") or not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail={"error": "unauthenticated"}
            )
        expires_at = tokens.get("expires_at")
        now = time.time()
        if not isinstance(expires_at, (int, float)) or expires_at - now >= REFRESH_LEEWAY_SECONDS:
            return token
        refresh_token = tokens.get("refresh_token")
        if not refresh_token:
            if expires_at > now:
                return token
            _clear_state(request)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"error": "token_expired", "error_description": "The access token has expired"},
            )
        try:
            fresh = self._refresh(refresh_token)
        except LumoAuthApiError as exc:
            # The sign-in is no longer valid (refresh token expired or revoked).
            logger.info("lumoauth.fastapi: refresh refused (HTTP %s); signing the user out", exc.status_code)
            _clear_state(request)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"error": "token_expired", "error_description": "The sign-in has expired"},
            ) from exc
        except LumoAuthError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"error": "token_refresh_failed", "error_description": "LumoAuth could not be reached"},
            ) from exc
        state["tokens"] = self._session_tokens(fresh, tokens)
        _write_state(request, state)
        return str(fresh["access_token"])

    def _refresh(self, refresh_token: str) -> Dict[str, Any]:
        """Refresh once per refresh token in this process.

        Requests that run at the same time, or that still carry the old
        refresh token shortly after a refresh, get the same answer, so a
        rotated refresh token is never presented twice from this process.
        """
        key = hashlib.sha256(refresh_token.encode()).hexdigest()
        with self._refresh_lock:
            now = time.monotonic()
            for k in [k for k, (at, _) in self._refreshed.items() if now - at > _REFRESH_REUSE_SECONDS]:
                del self._refreshed[k]
            lock = self._refresh_locks.setdefault(key, threading.Lock())
        # One lock per refresh token: refreshes of other sessions do not wait.
        with lock:
            hit = self._refreshed.get(key)
            if hit is not None:
                return hit[1]
            try:
                fresh = self.auth_resource().refresh_token(
                    refresh_token, client_id=self.client_id, client_secret=self.client_secret
                )
                self._refreshed[key] = (time.monotonic(), fresh)
                return fresh
            finally:
                with self._refresh_lock:
                    self._refresh_locks.pop(key, None)

    def _revoke(self, tokens: Dict[str, Any]) -> None:
        """Revoke the refresh token (or the access token). Best effort."""
        token = tokens.get("refresh_token") or tokens.get("access_token")
        if not token:
            return
        try:
            self.auth_resource().revoke(
                token,
                token_type_hint="refresh_token" if tokens.get("refresh_token") else "access_token",
                client_id=self.client_id,
                client_secret=self.client_secret,
            )
        except Exception as exc:  # noqa: BLE001 - a failure must not block sign-out
            logger.info("lumoauth.fastapi: token revocation at sign-out failed: %s", exc)

    # ---- Router ---------------------------------------------------------

    def router(self) -> APIRouter:
        """An APIRouter with ``/login``, ``/callback`` and ``/logout``.

        Include it under a prefix. ``callback_path`` is the absolute path
        that LumoAuth redirects back to: it must match a redirect URI that
        is registered on the application.
        """
        cfg = self
        router = APIRouter()

        @router.get("/login")
        def login(
            request: Request,
            return_to: Optional[str] = None,
            acr_values: Optional[str] = None,
            max_age: Optional[str] = None,
            resource: Optional[str] = None,
            login_hint: Optional[str] = None,
            prompt: Optional[str] = None,
        ):
            # Sign-in parameters for this one sign-in (step-up: acr_values,
            # max_age; an API: resource). Only this allow-list is passed on.
            extra, problem = _sign_in_parameters(
                acr_values=acr_values, max_age=max_age, resource=resource,
                login_hint=login_hint, prompt=prompt,
            )
            if problem is not None:
                return JSONResponse(
                    {"error": "invalid_request", "error_description": problem}, status_code=400
                )
            # SessionMiddleware may not be mounted — fail fast with a clear
            # message rather than a confusing AttributeError downstream.
            try:
                request.session
            except AssertionError as exc:
                raise HTTPException(
                    status_code=500,
                    detail={
                        "error": "session_middleware_missing",
                        "error_description": (
                            "lumoauth.fastapi requires SessionMiddleware to be mounted."
                        ),
                    },
                ) from exc

            verifier, challenge = LumoAuthFastAPI._pkce_pair()
            oauth_state = secrets.token_urlsafe(24)
            redirect_uri = _absolute_url(request, cfg.callback_path)
            safe_return_to = _sanitize_return_to(return_to, cfg.post_login_redirect)

            # Stash flow state in session.
            state = _read_state(request)
            state["flow"] = {
                "code_verifier": verifier,
                "state": oauth_state,
                "redirect_uri": redirect_uri,
                "return_to": safe_return_to,
            }
            _write_state(request, state)

            params = urlencode({
                "response_type": "code",
                "client_id": cfg.client_id,
                "redirect_uri": redirect_uri,
                "scope": cfg.scope,
                "state": oauth_state,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                **extra,
            })
            return RedirectResponse(f"{cfg.authorize_url()}?{params}", status_code=302)

        @router.get("/callback")
        def callback(
            request: Request,
            code: Optional[str] = None,
            state: Optional[str] = None,
            error: Optional[str] = None,
            error_description: Optional[str] = None,
        ):
            if error:
                return JSONResponse(
                    {"error": error, "error_description": error_description or ""},
                    status_code=400,
                )
            if not code or not state:
                return JSONResponse(
                    {"error": "invalid_request", "error_description": "Missing code or state"},
                    status_code=400,
                )
            sess_state = _read_state(request)
            flow = sess_state.get("flow")
            if not flow:
                return JSONResponse(
                    {"error": "invalid_request", "error_description": "No login in progress"},
                    status_code=400,
                )
            if state != flow.get("state"):
                return JSONResponse(
                    {"error": "invalid_state", "error_description": "CSRF state mismatch"},
                    status_code=400,
                )

            try:
                tokens = cfg.exchange_code(
                    code=code,
                    code_verifier=flow["code_verifier"],
                    redirect_uri=flow["redirect_uri"],
                )
            except HTTPException:
                raise
            except Exception as exc:
                return JSONResponse(
                    {"error": "token_exchange_failed", "error_description": str(exc)},
                    status_code=502,
                )

            userinfo = cfg.fetch_userinfo(tokens["access_token"])
            sess_state["tokens"] = cfg._session_tokens(tokens)
            sess_state["user"] = userinfo
            sess_state.pop("flow", None)
            _write_state(request, sess_state)
            _warn_if_cookie_too_large(request)

            return RedirectResponse(flow["return_to"], status_code=302)

        @router.get("/logout")
        @router.post("/logout")
        def logout(request: Request) -> RedirectResponse:
            tokens = _read_state(request).get("tokens") or {}
            # Wipe LumoAuth state but leave any unrelated session keys alone.
            _clear_state(request)
            if not cfg.end_session_on_logout or not tokens:
                return RedirectResponse(cfg.post_logout_redirect, status_code=302)
            # Revoke the refresh token (this also revokes the access tokens
            # issued with it), then end the LumoAuth session too. Otherwise the
            # next sign-in completes at once, without the sign-in page.
            cfg._revoke(tokens)
            return RedirectResponse(
                cfg.end_session_url(
                    id_token_hint=tokens.get("id_token"),
                    post_logout_redirect_uri=_absolute_url(request, cfg.post_logout_redirect),
                ),
                status_code=302,
            )

        return router


# ─── Dependencies ──────────────────────────────────────────────────────────


def get_current_user(request: Request) -> Optional[User]:
    """FastAPI dependency. Returns the signed-in :class:`User` or ``None``.

    Use ``user: Optional[User] = Depends(get_current_user)`` for routes
    that want optional auth, or :func:`require_auth` for routes that must
    have an authenticated principal.
    """
    state = _read_state(request)
    raw = state.get("user")
    if not raw:
        return None
    return User(**raw)


def require_auth(scopes: Optional[list[str]] = None) -> Callable[..., Awaitable[User]]:
    """Dependency factory for routes that require auth.

    Raises 401 when there's no signed-in user, 403 when the granted scopes
    are missing one of ``scopes``::

        @app.get("/api/admin")
        def admin(user: User = Depends(require_auth(scopes=["admin:read"]))):
            ...
    """

    async def _dep(request: Request) -> User:
        user = get_current_user(request)
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"error": "unauthenticated"},
            )
        if scopes:
            granted = (_read_state(request).get("tokens", {}).get("scope") or "").split()
            missing = [s for s in scopes if s not in granted]
            if missing:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail={
                        "error": "insufficient_scope",
                        "error_description": f"Missing: {', '.join(missing)}",
                    },
                )
        return user

    return _dep


# ─── Router ────────────────────────────────────────────────────────────────


def lumo_auth_router(
    *,
    base_url: Optional[str] = None,
    organization: Optional[str] = None,
    client_id: str,
    client_secret: Optional[str] = None,
    callback_path: str = "/auth/callback",
    scope: str = "openid profile email",
    post_login_redirect: str = "/",
    post_logout_redirect: str = "/",
    custom_domain: Optional[str] = None,
    end_session_on_logout: bool = True,
) -> APIRouter:
    """Build an APIRouter with /login, /callback, /logout mounted.

    The router is meant to be ``include_router``-ed under a prefix; the
    ``callback_path`` should be the absolute path that LumoAuth will
    redirect back to (it MUST match the OAuth client's registered
    redirect URIs).

    Pass ``base_url`` and ``organization``, or ``custom_domain`` for an
    organization on its own domain (``"auth.acme.com"``). A malformed
    ``custom_domain``, or neither form, raises
    :class:`~lumoauth.LumoAuthConfigError` here.

    ``/logout`` clears the local session, revokes the refresh token and
    sends the browser to LumoAuth's end-session endpoint, which ends the
    LumoAuth session and redirects to ``post_logout_redirect``. A relative
    ``post_logout_redirect`` is made absolute with the address of the
    request; register the result as a post-logout redirect URI of the
    application. ``end_session_on_logout=False`` clears only the local
    session.

    To use the :meth:`LumoAuthFastAPI.access_token` dependency, create a
    :class:`LumoAuthFastAPI` and call its :meth:`~LumoAuthFastAPI.router`.
    """
    return LumoAuthFastAPI(
        base_url=base_url,
        organization=organization,
        client_id=client_id,
        client_secret=client_secret,
        callback_path=callback_path,
        scope=scope,
        post_login_redirect=post_login_redirect,
        post_logout_redirect=post_logout_redirect,
        custom_domain=custom_domain,
        end_session_on_logout=end_session_on_logout,
    ).router()


# ─── Internal helpers ──────────────────────────────────────────────────────


def _read_state(request: Request) -> dict[str, Any]:
    raw = request.session.get(SESSION_KEY)
    return raw if isinstance(raw, dict) else {}


def _write_state(request: Request, state: dict[str, Any]) -> None:
    request.session[SESSION_KEY] = state


def _clear_state(request: Request) -> None:
    if SESSION_KEY in request.session:
        del request.session[SESSION_KEY]


def _absolute_url(request: Request, path: str) -> str:
    """Build an absolute URL on the request's origin (an absolute URL stays as it is)."""
    if path.startswith(("http://", "https://")):
        return path
    if not path.startswith("/"):
        path = "/" + path
    scheme = request.url.scheme
    host = request.url.netloc
    return f"{scheme}://{host}{path}"


_PROMPT_VALUES = frozenset({"none", "login", "consent", "select_account"})
# One acr value: printable ASCII without spaces (RFC 6749 scope-token rules).
_ACR_VALUE = re.compile(r"^[\x21\x23-\x5b\x5d-\x7e]+$")
_MAX_PARAMETER_LENGTH = 1024


def _sign_in_parameters(
    *,
    acr_values: Optional[str],
    max_age: Optional[str],
    resource: Optional[str],
    login_hint: Optional[str],
    prompt: Optional[str],
) -> Tuple[Dict[str, str], Optional[str]]:
    """The allow-listed authorization parameters of one sign-in, checked.

    Returns ``(parameters, None)``, or ``({}, reason)`` for a value that is
    refused. Each of them asks for a stricter sign-in (``acr_values``,
    ``max_age``, ``prompt``), gives a hint (``login_hint``) or names the API
    of the access token (``resource``, which LumoAuth checks against the
    application); none of them can widen what the application may get.
    """
    extra: Dict[str, str] = {}
    for name, value in (("acr_values", acr_values), ("max_age", max_age), ("resource", resource),
                        ("login_hint", login_hint), ("prompt", prompt)):
        if value is None or value == "":
            continue
        if len(value) > _MAX_PARAMETER_LENGTH or any(ord(c) < 0x20 or ord(c) == 0x7F for c in value):
            return {}, f"{name} is too long or holds a control character"
        extra[name] = value
    if "acr_values" in extra:
        values = extra["acr_values"].split(" ")
        if any(not _ACR_VALUE.match(v) for v in values):
            return {}, "acr_values must be values separated by one space"
    if "max_age" in extra:
        if not extra["max_age"].isdigit() or len(extra["max_age"]) > 9:
            return {}, "max_age must be a whole number of seconds"
        extra["max_age"] = str(int(extra["max_age"]))
    if "resource" in extra:
        parts = urlsplit(extra["resource"])
        local = parts.hostname in ("localhost", "127.0.0.1", "::1")
        if parts.scheme not in ("https", "http") or (parts.scheme == "http" and not local) \
                or not parts.netloc or parts.fragment or "#" in extra["resource"]:
            return {}, "resource must be an absolute https URL without a fragment"
    if "prompt" in extra:
        values = extra["prompt"].split(" ")
        if any(v not in _PROMPT_VALUES for v in values) or ("none" in values and len(values) > 1):
            return {}, "prompt must be none, login, consent or select_account"
    return extra, None


def _sanitize_return_to(value: Optional[str], fallback: str) -> str:
    """Open-redirect defence — only allow same-origin paths."""
    if not value or not isinstance(value, str):
        return fallback
    if not value.startswith("/") or value.startswith("//"):
        return fallback
    return value


def _warn_if_cookie_too_large(request: Request) -> None:
    """Log a warning when Starlette's cookie session will be too large to keep.

    A browser drops a cookie larger than 4096 bytes without an error, so the
    sign-in would not stick. Only Starlette's ``SessionMiddleware`` keeps the
    session in the cookie; a server-side session store has no such limit.
    """
    try:
        from starlette.middleware.sessions import SessionMiddleware
    except ImportError:  # pragma: no cover - starlette comes with fastapi
        return
    middleware = getattr(request.app, "user_middleware", None) or []
    found = next((m for m in middleware if getattr(m, "cls", None) is SessionMiddleware), None)
    if found is None:
        return
    options = getattr(found, "kwargs", None) or {}
    name = options.get("session_cookie", "session")
    try:
        encoded = base64.b64encode(json.dumps(dict(request.session)).encode("utf-8"))
    except (TypeError, ValueError):
        return
    # name=value, plus the timestamp and the signature that Starlette adds.
    size = len(name) + 1 + len(encoded) + 35
    if size > _COOKIE_LIMIT_BYTES:
        logger.warning(
            "lumoauth.fastapi: the session cookie is %d bytes, more than the %d bytes that "
            "browsers keep, so this sign-in will not stick. Request fewer scopes, or use a "
            "session store that keeps the data on the server.",
            size,
            _COOKIE_LIMIT_BYTES,
        )

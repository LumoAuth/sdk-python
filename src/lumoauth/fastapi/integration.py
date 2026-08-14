"""Implementation of the FastAPI integration. See ``__init__.py`` for usage."""

from __future__ import annotations

import base64
import hashlib
import os
import secrets
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Optional
from urllib.parse import urlencode

from lumoauth._http import HttpClient
from lumoauth._routes import format_path
from lumoauth.errors import LumoAuthApiError
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


# Session key under which all LumoAuth state lives. Single nested dict so
# the host app can wipe LumoAuth-only state with `del request.session["__lumoauth"]`
# without touching unrelated keys.
SESSION_KEY = "__lumoauth"


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
    """Configuration container for the FastAPI integration.

    Most apps construct this implicitly via :func:`lumo_auth_router`, but
    you can hold a reference if you want to share the same configuration
    between the router and a custom dependency.
    """

    base_url: str
    organization: str
    client_id: str
    client_secret: Optional[str] = None
    callback_path: str = "/auth/callback"
    scope: str = "openid profile email"
    post_login_redirect: str = "/"
    post_logout_redirect: str = "/"
    request_timeout_seconds: float = 10.0
    _auth: Optional[AuthResource] = field(default=None, repr=False, compare=False)

    # ---- Resource wiring ------------------------------------------------

    def auth_resource(self) -> AuthResource:
        """The OAuth resource all HTTP goes through (lazily constructed)."""
        if self._auth is None:
            self._auth = AuthResource(
                HttpClient(
                    self.base_url.rstrip("/"),
                    org_id=self.organization,
                    timeout=self.request_timeout_seconds,
                )
            )
        return self._auth

    # ---- URL helpers ----------------------------------------------------

    def _route_url(self, route: str) -> str:
        _, path = format_path(route, org_id=self.organization)
        return f"{self.base_url.rstrip('/')}{path}"

    def authorize_url(self) -> str:
        return self._route_url("oauth.authorize")

    def token_url(self) -> str:
        return self._route_url("oauth.token")

    def userinfo_url(self) -> str:
        return self._route_url("oauth.userinfo")

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
        def admin(user: User = Depends(require_auth(scopes=["admin"]))):
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
    base_url: str,
    organization: str,
    client_id: str,
    client_secret: Optional[str] = None,
    callback_path: str = "/auth/callback",
    scope: str = "openid profile email",
    post_login_redirect: str = "/",
    post_logout_redirect: str = "/",
) -> APIRouter:
    """Build an APIRouter with /login, /callback, /logout mounted.

    The router is meant to be ``include_router``-ed under a prefix; the
    ``callback_path`` should be the absolute path that LumoAuth will
    redirect back to (it MUST match the OAuth client's registered
    redirect URIs).
    """
    cfg = LumoAuthFastAPI(
        base_url=base_url,
        organization=organization,
        client_id=client_id,
        client_secret=client_secret,
        callback_path=callback_path,
        scope=scope,
        post_login_redirect=post_login_redirect,
        post_logout_redirect=post_logout_redirect,
    )

    router = APIRouter()

    @router.get("/login")
    def login(request: Request, return_to: Optional[str] = None) -> RedirectResponse:
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
        redirect_uri = _absolute_url(request, callback_path)
        safe_return_to = _sanitize_return_to(return_to, post_login_redirect)

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
        sess_state["tokens"] = {
            "access_token": tokens["access_token"],
            "refresh_token": tokens.get("refresh_token"),
            "id_token": tokens.get("id_token"),
            "token_type": tokens.get("token_type", "Bearer"),
            "scope": tokens.get("scope", ""),
        }
        sess_state["user"] = userinfo
        sess_state.pop("flow", None)
        _write_state(request, sess_state)

        return RedirectResponse(flow["return_to"], status_code=302)

    @router.get("/logout")
    @router.post("/logout")
    def logout(request: Request) -> RedirectResponse:
        # Wipe LumoAuth state but leave any unrelated session keys alone.
        if SESSION_KEY in request.session:
            del request.session[SESSION_KEY]
        return RedirectResponse(cfg.post_logout_redirect, status_code=302)

    return router


# ─── Internal helpers ──────────────────────────────────────────────────────


def _read_state(request: Request) -> dict[str, Any]:
    raw = request.session.get(SESSION_KEY)
    return raw if isinstance(raw, dict) else {}


def _write_state(request: Request, state: dict[str, Any]) -> None:
    request.session[SESSION_KEY] = state


def _absolute_url(request: Request, path: str) -> str:
    """Build an absolute URL that respects reverse-proxy headers."""
    scheme = request.url.scheme
    host = request.url.netloc
    return f"{scheme}://{host}{path}"


def _sanitize_return_to(value: Optional[str], fallback: str) -> str:
    """Open-redirect defence — only allow same-origin paths."""
    if not value or not isinstance(value, str):
        return fallback
    if not value.startswith("/") or value.startswith("//"):
        return fallback
    return value

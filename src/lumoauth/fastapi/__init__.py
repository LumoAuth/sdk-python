"""FastAPI integration for LumoAuth.

Mounts three routes — ``/login``, ``/callback``, ``/logout`` — under a
configurable prefix, and exposes a ``get_current_user`` dependency that
populates the signed-in :class:`User` from the Starlette session.

Example::

    from fastapi import FastAPI, Depends
    from starlette.middleware.sessions import SessionMiddleware
    from lumoauth.fastapi import lumo_auth_router, get_current_user, User

    app = FastAPI()
    app.add_middleware(SessionMiddleware, secret_key=os.environ["SESSION_SECRET"])
    app.include_router(
        lumo_auth_router(
            base_url="https://app.lumoauth.dev",
            organization="acme-corp",
            client_id="...",
            client_secret="...",
            callback_path="/auth/callback",
        ),
        prefix="/auth",
    )

    @app.get("/api/me")
    def me(user: User = Depends(get_current_user)):
        return user.model_dump() if user else {"error": "unauthorized"}

The host application MUST mount Starlette's ``SessionMiddleware`` (or any
compatible session backend that exposes ``request.session`` as a dict-like
object). The PKCE verifier and authorization ``state`` are stashed on the
session under ``__lumoauth.flow`` so they survive the redirect to LumoAuth
and back without ever appearing in URLs or cookies.

Resource servers (an MCP server, an API) protect routes with
:func:`require_access_token`, which verifies the incoming LumoAuth access
token locally, including the DPoP binding::

    from lumoauth.fastapi import require_access_token, AccessTokenClaims

    auth = require_access_token(issuer="https://app.lumoauth.dev/orgs/acme/api/v1",
                                resource="https://mcp.example.com/mcp")

    @app.post("/mcp")
    def mcp(claims: AccessTokenClaims = Depends(auth)):
        ...
"""

from __future__ import annotations

from .integration import (
    User,
    LumoAuthFastAPI,
    lumo_auth_router,
    get_current_user,
    require_auth,
)
from .resource import AccessTokenClaims, parse_authorization, require_access_token

__all__ = [
    "User",
    "LumoAuthFastAPI",
    "lumo_auth_router",
    "get_current_user",
    "require_auth",
    "require_access_token",
    "parse_authorization",
    "AccessTokenClaims",
]

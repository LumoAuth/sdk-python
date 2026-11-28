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
and back without ever appearing in URLs. Starlette's ``SessionMiddleware``
keeps the session in a signed cookie that is not encrypted, so the tokens
in it can be read by anyone who gets the cookie, and a browser keeps no
cookie larger than 4096 bytes.

``/logout`` clears the local session and ends the LumoAuth session through
the end-session endpoint (pass ``end_session_on_logout=False`` to clear only
the local session). To call an API with the user's access token, refreshed
when it expires, create the configuration yourself::

    lumo = LumoAuthFastAPI(base_url=..., organization=..., client_id=..., client_secret=...)
    app.include_router(lumo.router(), prefix="/auth")

    @app.get("/api/documents")
    def documents(token: str = Depends(lumo.access_token)):
        ...

Resource servers (an MCP server, an API) protect routes with
:func:`require_access_token`, which verifies the incoming LumoAuth access
token locally, including the DPoP binding::

    from lumoauth.fastapi import require_access_token, AccessTokenClaims

    auth = require_access_token(issuer="https://app.lumoauth.dev/orgs/acme/api/v1",
                                resource="https://mcp.example.com/mcp")

    @app.post("/mcp")
    def mcp(claims: AccessTokenClaims = Depends(auth)):
        ...

An API that personal agents call (Personal Agent Protocol) protects its
routes with :class:`LumoAuthPoppy`. LumoAuth verifies the ``Poppy-Session``
header of each request, and a refusal is relayed to the personal agent
unchanged::

    from lumoauth import LumoAuth, PoppyVerification
    from lumoauth.fastapi import LumoAuthPoppy

    lumo = LumoAuth(org_id="acme-corp", client_id="...", client_secret="...")
    poppy = LumoAuthPoppy(lumo, public_origin="https://shop.example.com")
    poppy.install(app)

    @app.get("/api/orders")
    def orders(who: PoppyVerification = Depends(poppy.session("orders:read"))):
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
from .poppy import (
    LumoAuthPoppy,
    PoppyRefusal,
    PoppyUnavailable,
    PoppyVerification,
    poppy_refusal_handler,
    poppy_refusal_response,
    poppy_unavailable_response,
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
    "LumoAuthPoppy",
    "PoppyRefusal",
    "PoppyUnavailable",
    "PoppyVerification",
    "poppy_refusal_handler",
    "poppy_refusal_response",
    "poppy_unavailable_response",
]

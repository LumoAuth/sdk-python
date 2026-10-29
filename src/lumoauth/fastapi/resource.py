"""Resource-server side of the FastAPI integration: verify incoming LumoAuth tokens.

An MCP server (or any API) built with FastAPI protects a route with
:func:`require_access_token`. The dependency reads the ``Authorization``
header, verifies the token locally with :mod:`lumoauth.verify` (signature
against the organization JWKS, ``iss``, ``aud`` = your resource URI,
``exp``/``nbf``, no test tokens) and, when the token is DPoP-bound, checks
the ``DPoP`` proof of the request. It answers 401 with a
``WWW-Authenticate`` challenge, or 403 ``insufficient_scope``::

    from fastapi import Depends, FastAPI
    from lumoauth.fastapi import require_access_token, AccessTokenClaims

    app = FastAPI()
    auth = require_access_token(
        issuer="https://app.lumoauth.dev/orgs/acme/api/v1",
        resource="https://mcp.example.com/mcp",
    )

    @app.post("/mcp")
    def mcp(claims: AccessTokenClaims = Depends(auth)):
        return {"sub": claims.sub, "scopes": claims.scopes}
"""

from __future__ import annotations

from typing import Any, Awaitable, Callable, Mapping, Optional

from lumoauth.errors import LumoAuthTokenError
from lumoauth.verify import (
    AccessTokenClaims,
    AccessTokenVerifier,
    DpopRequest,
    ReplayCache,
)

try:
    from fastapi import HTTPException, Request, status
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "lumoauth.fastapi requires `fastapi` to be installed. "
        "Add `fastapi` to your dependencies (e.g. `pip install fastapi`)."
    ) from exc

__all__ = ["require_access_token", "parse_authorization", "AccessTokenClaims"]

_SCHEMES = ("bearer", "dpop")


def parse_authorization(value: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    """Split an ``Authorization`` header into ``(scheme, token)``.

    The scheme is returned as ``"Bearer"`` or ``"DPoP"``; anything else
    gives ``(None, None)``.
    """
    if not value or not isinstance(value, str):
        return None, None
    parts = value.strip().split(None, 1)
    if len(parts) != 2 or parts[0].lower() not in _SCHEMES:
        return None, None
    scheme = "DPoP" if parts[0].lower() == "dpop" else "Bearer"
    return scheme, parts[1].strip()


def require_access_token(
    *,
    issuer: str,
    resource: str,
    scopes: Optional[list[str]] = None,
    require_dpop: bool = False,
    verifier: Optional[AccessTokenVerifier] = None,
    jwks: Optional[Mapping[str, Any]] = None,
    fetch: Optional[Callable[[str], Any]] = None,
    clock_skew: float = 60,
    replay_cache: Optional[ReplayCache] = None,
    request_url: Optional[Callable[[Request], str]] = None,
) -> Callable[..., Awaitable[AccessTokenClaims]]:
    """Dependency factory that verifies the request's LumoAuth access token.

    Args:
        issuer: The organization issuer (``…/orgs/{org}/api/v1``).
        resource: This server's resource URI; the token's ``aud`` must hold it.
        scopes: Scopes the route needs; a token missing one gets 403.
        require_dpop: Refuse tokens that are not DPoP-bound.
        verifier: A pre-built :class:`AccessTokenVerifier` to share between
            routes. When given, ``jwks``/``fetch``/``clock_skew``/
            ``replay_cache`` are ignored.
        jwks, fetch, clock_skew, replay_cache: Passed to
            :class:`AccessTokenVerifier`.
        request_url: Builds the public URL of the request for the DPoP
            ``htu`` check (behind a proxy that rewrites the host or scheme).
            Defaults to ``str(request.url)``.

    Returns:
        An async dependency that returns :class:`AccessTokenClaims`.
    """
    token_verifier = verifier or AccessTokenVerifier(
        issuer,
        resource,
        jwks=jwks,
        fetch=fetch,
        clock_skew=clock_skew,
        require_dpop=require_dpop,
        replay_cache=replay_cache,
    )
    if verifier is not None and require_dpop:
        token_verifier.require_dpop = True

    async def _dep(request: Request) -> AccessTokenClaims:
        scheme, token = parse_authorization(request.headers.get("authorization"))
        if not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"error": "invalid_request", "error_description": "Missing access token"},
                headers={"WWW-Authenticate": f'{"DPoP" if require_dpop else "Bearer"} resource="{resource}"'},
            )
        url = request_url(request) if request_url else str(request.url)
        dpop = DpopRequest(
            method=request.method,
            url=url,
            proof=request.headers.get("dpop"),
            scheme=scheme or "Bearer",
        )
        try:
            claims = token_verifier.verify(token, dpop=dpop)
        except LumoAuthTokenError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"error": exc.error, "error_description": exc.message, "code": exc.code},
                headers={"WWW-Authenticate": exc.www_authenticate},
            ) from exc
        if scopes:
            missing = claims.missing_scopes(scopes)
            if missing:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail={
                        "error": "insufficient_scope",
                        "error_description": f"Missing: {', '.join(missing)}",
                    },
                    headers={
                        "WWW-Authenticate": f'{scheme or "Bearer"} error="insufficient_scope", scope="{" ".join(scopes)}"'
                    },
                )
        request.state.lumoauth_claims = claims
        return claims

    return _dep

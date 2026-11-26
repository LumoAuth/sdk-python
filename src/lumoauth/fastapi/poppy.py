"""Personal Agent Protocol for FastAPI: protect the routes that personal agents call.

A personal agent sends the ``Poppy-Session`` header to your API. The
dependency of :class:`LumoAuthPoppy` forwards the method, the public URL and
the protocol headers of each request to LumoAuth, and gives the route the
:class:`~lumoauth.PoppyVerification`::

    import os
    from fastapi import Depends, FastAPI
    from lumoauth import LumoAuth, PoppyVerification
    from lumoauth.fastapi import LumoAuthPoppy

    app = FastAPI()
    lumo = LumoAuth(org_id="acme-corp",
                    client_id=os.environ["LUMOAUTH_CLIENT_ID"],
                    client_secret=os.environ["LUMOAUTH_CLIENT_SECRET"])
    poppy = LumoAuthPoppy(lumo, public_origin=os.environ["PUBLIC_ORIGIN"])
    poppy.install(app)

    @app.get("/api/orders")
    def orders(who: PoppyVerification = Depends(poppy.session("orders:read"))):
        return {"account": who.account.sub, "session": who.session.id}

- A refused request never reaches the route. The personal agent gets the
  response that LumoAuth worded: its status, its headers and its body.
- An SDK error (LumoAuth cannot be reached, or the application's own 401,
  403, 404 or 429) never reaches the route either, and it is never relayed.
  FastAPI answers it with its normal 500.
- The URL is built from ``public_origin`` and the raw path of the request.
  The ``Host`` and ``X-Forwarded-*`` headers are never read.
"""

from __future__ import annotations

from typing import Any, Callable, Mapping, Optional, Union
from urllib.parse import quote

from lumoauth.errors import LumoAuthConfigError, LumoAuthValidationError
from lumoauth.resources.poppy import (
    PoppyVerification,
    ScopeInput,
    build_poppy_verify_body,
    normalize_poppy_public_origin,
)

try:
    from fastapi import Request
    from fastapi.responses import JSONResponse, Response
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "lumoauth.fastapi requires `fastapi` to be installed. "
        "Add `fastapi` to your dependencies (e.g. `pip install fastapi`)."
    ) from exc

__all__ = [
    "LumoAuthPoppy",
    "PoppyRefusal",
    "poppy_refusal_handler",
    "poppy_refusal_response",
]

# Headers that the web server writes itself. A relayed copy would describe
# another message, so these are not copied from the refusal.
_WRITTEN_BY_THE_SERVER = ("content-length", "content-type", "transfer-encoding", "connection")


class PoppyRefusal(Exception):
    """LumoAuth refused the request of a personal agent.

    The dependency of :meth:`LumoAuthPoppy.session` raises it, and the
    handler that :meth:`LumoAuthPoppy.install` registers answers the
    personal agent with ``verification.response``, unchanged.
    """

    def __init__(self, verification: PoppyVerification) -> None:
        super().__init__(f"The request of the personal agent was refused: {verification.error}")
        self.verification = verification


def poppy_refusal_response(verification: PoppyVerification) -> Response:
    """Build the response that the personal agent must get for a refusal.

    The response has the status of ``verification.response``, every one of
    its headers and, when its body is not ``None``, the body as JSON with
    ``Content-Type: application/json``. When the body is ``None`` the
    response has no body and no ``Content-Type``. Nothing else is added.

    Use it when you call ``client.poppy.verify_request()`` yourself::

        who = lumo.poppy.verify_request(request.method, url, request.headers.items())
        if not who.active:
            return poppy_refusal_response(who)

    Raises:
        LumoAuthValidationError: *verification* is not a refusal.
    """
    relay = getattr(verification, "response", None)
    if getattr(verification, "active", None) is not False or relay is None:
        raise LumoAuthValidationError("only a refused verification has a response to relay")
    headers = {
        name: value
        for name, value in relay.headers.items()
        if name.lower() not in _WRITTEN_BY_THE_SERVER
    }
    if relay.body is None:
        return Response(status_code=relay.status, headers=headers)
    return JSONResponse(relay.body, status_code=relay.status, headers=headers)


async def poppy_refusal_handler(request: Request, exc: Exception) -> Response:
    """Exception handler for :class:`PoppyRefusal`: relays the refusal unchanged."""
    return poppy_refusal_response(exc.verification)  # type: ignore[attr-defined]


def _request_target(scope: Mapping[str, Any]) -> Union[str, bytes]:
    """The path of the request as the client sent it.

    ``raw_path`` is the path before percent-decoding and before any router
    prefix or mount point is removed. An ASGI server that gives no
    ``raw_path`` leaves only the decoded path, which is encoded again: an
    encoded reserved character, such as ``%2F``, is then lost.
    """
    raw = scope.get("raw_path")
    if isinstance(raw, (bytes, bytearray)) and raw:
        return bytes(raw)
    return quote(scope.get("path") or "/", safe="/!$&'()*+,;=:@-._~")


class LumoAuthPoppy:
    """Verifies the requests that personal agents send to a FastAPI application.

    Args:
        client: A :class:`~lumoauth.LumoAuth` client with the ``client_id``
            and ``client_secret`` of a confidential application whose
            allowed scopes include ``poppy:verify``.
        public_origin: The address that personal agents call, such as
            ``"https://shop.example.com"``. Read it from your configuration.
            It may carry a base path, for a proxy that removes a path
            prefix. The helper appends the raw path of each request to it
            and never reads the ``Host`` or ``X-Forwarded-*`` headers.

    Raises:
        LumoAuthConfigError: ``public_origin`` is missing or malformed, or
            *client* is not a LumoAuth client.
    """

    def __init__(self, client: Any, *, public_origin: str) -> None:
        self.public_origin: str = normalize_poppy_public_origin(public_origin)
        resource = getattr(client, "poppy", None)
        if not callable(getattr(resource, "verify_request", None)):
            raise LumoAuthConfigError(
                "LumoAuthPoppy needs a LumoAuth client: "
                "LumoAuthPoppy(LumoAuth(client_id=..., client_secret=...), public_origin=...)"
            )
        self.client = client

    def install(self, app: Any) -> None:
        """Register the handler that relays a refusal. Call it once per application.

        Without it a refusal cannot be answered with the exact response, so
        the dependency raises :class:`~lumoauth.LumoAuthConfigError` on
        every request. A mounted sub-application has its own handlers:
        call ``install()`` on the application that serves the routes.
        """
        app.add_exception_handler(PoppyRefusal, poppy_refusal_handler)

    def verify(
        self,
        request: Request,
        *,
        required_scope: ScopeInput = None,
        resource: Optional[str] = None,
        allow_replay: bool = False,
    ) -> PoppyVerification:
        """Verify *request* and return the result, verified or refused.

        The request body is not read. Use this method when you relay the
        refusal yourself, with :func:`poppy_refusal_response`. It makes a
        blocking HTTP call: call it from a ``def`` route or dependency,
        which FastAPI runs in a thread pool.

        Raises:
            LumoAuthError: The call to LumoAuth failed. Never relay this
                error to the personal agent.
        """
        body = build_poppy_verify_body(
            self.public_origin,
            request.method,
            _request_target(request.scope),
            request.scope.get("headers") or [],
            required_scope=required_scope,
            resource=resource,
            allow_replay=allow_replay,
        )
        return self.client.poppy.verify_request(
            body["method"],
            body["url"],
            body["headers"],
            required_scope=body.get("required_scope"),
            resource=body.get("resource"),
            allow_replay=body.get("allow_replay", False),
        )

    def session(
        self,
        required_scope: ScopeInput = None,
        *,
        resource: Optional[str] = None,
        allow_replay: bool = False,
    ) -> Callable[[Request], PoppyVerification]:
        """Dependency factory for a route that personal agents call.

        The dependency returns the :class:`~lumoauth.PoppyVerification` of a
        verified request and also stores it as ``request.state.poppy``.
        A refused request raises :class:`PoppyRefusal`, which the handler
        of :meth:`install` answers. Use one such dependency per route: a
        Session JWT is good for one verification.

        Args:
            required_scope: The scopes that the route needs: a
                space-separated string or a list. A request without an
                access token is then refused with ``account_required``.
            resource: The resource identifier of your service, when it
                takes only tokens issued for it.
            allow_replay: ``True`` accepts a Session JWT that was verified
                before.

        Raises:
            LumoAuthValidationError: An option is malformed. The error is
                raised here, when the route is declared.
        """
        # Check the options now, not at the first request.
        build_poppy_verify_body(
            self.public_origin,
            "GET",
            "/",
            (),
            required_scope=required_scope,
            resource=resource,
            allow_replay=allow_replay,
        )

        def _dep(request: Request) -> PoppyVerification:
            _require_refusal_handler(request)
            verification = self.verify(
                request,
                required_scope=required_scope,
                resource=resource,
                allow_replay=allow_replay,
            )
            if not verification.active:
                raise PoppyRefusal(verification)
            request.state.poppy = verification
            return verification

        return _dep


def _require_refusal_handler(request: Request) -> None:
    handlers = getattr(request.scope.get("app"), "exception_handlers", None)
    if isinstance(handlers, dict) and PoppyRefusal not in handlers:
        raise LumoAuthConfigError(
            "The handler that relays a Personal Agent Protocol refusal is not registered "
            "on this application. Call poppy.install(app) on the FastAPI application "
            "that serves this route."
        )

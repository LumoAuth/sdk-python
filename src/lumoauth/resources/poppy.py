"""Personal Agent Protocol: verify the requests that personal agents send to your API.

A personal agent sends the ``Poppy-Session`` header to *your* API, not to
LumoAuth. Your API forwards the method, the public URL and five protocol
headers to LumoAuth, and LumoAuth answers who the request is from, or the
exact HTTP response that the personal agent must get.

The three calls authenticate with HTTP Basic: the client id and secret of a
confidential application whose allowed scopes include ``poppy:verify``. They
never send the client's bearer token or API key.

See https://docs.lumoauth.dev/agents/personal-agent-protocol-verify
"""

from __future__ import annotations

import base64
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union
from urllib.parse import urlsplit

from lumoauth._http import HttpClient
from lumoauth.errors import (
    LumoAuthApiError,
    LumoAuthConfigError,
    LumoAuthValidationError,
)

logger = logging.getLogger("lumoauth.poppy")

__all__ = [
    "POPPY_FORWARDED_HEADERS",
    "POPPY_VERIFY_SCOPE",
    "PoppyAccount",
    "PoppyResource",
    "PoppyResponse",
    "PoppySessionInfo",
    "PoppySessionStatus",
    "PoppyVerification",
    "build_poppy_verify_body",
    "normalize_poppy_public_origin",
]

#: The request headers that LumoAuth reads. No other header is ever sent.
POPPY_FORWARDED_HEADERS: Tuple[str, ...] = (
    "poppy-session",
    "poppy-version",
    "poppy-extensions",
    "authorization",
    "dpop",
)

#: The scope that the calling application needs among its allowed scopes.
POPPY_VERIFY_SCOPE = "poppy:verify"

_SESSION_STATUSES = ("active", "ended", "unknown")
_ABSOLUTE_FORM = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*://[^/?#]*")
_QUERY_OR_FRAGMENT = re.compile(r"[?#]")
_HEADER_NAME = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_HEADER_VALUE_FORBIDDEN = re.compile(r"[\x00\r\n]")

HeaderInput = Union[Mapping[Any, Any], Iterable[Tuple[Any, Any]]]
ScopeInput = Union[str, Sequence[str], None]


# ── Result types ──────────────────────────────────────────────────────


@dataclass(frozen=True)
class PoppySessionInfo:
    """The Session of a verified request.

    ``id`` is LumoAuth's id of the Session: store your own Session state,
    such as a cart, under it. ``is_new`` is ``True`` when this request
    started the Session (the ``new`` member of the answer).
    """

    id: int
    sid: str
    is_new: bool
    started_at: str


@dataclass(frozen=True)
class PoppyAccount:
    """The account of a signed-in request: whose access token the request carried.

    ``sub`` is the id of the user in your LumoAuth organization. ``scope``
    is the space-separated scope string of the access token and ``scopes``
    the same values as a tuple. ``token_type`` is ``"Bearer"`` or ``"DPoP"``.
    """

    sub: str
    scope: str
    scopes: Tuple[str, ...]
    aud: Tuple[str, ...]
    exp: int
    token_type: str

    def has_scope(self, scope: str) -> bool:
        """Whether the access token carries *scope* (exact comparison)."""
        return scope in self.scopes


@dataclass(frozen=True)
class PoppyResponse:
    """The HTTP response that the personal agent must get for a refused request.

    Relay it unchanged: ``status``, every header of ``headers`` and, when
    ``body`` is not ``None``, the body as JSON with
    ``Content-Type: application/json``. When ``body`` is ``None`` the answer
    has no body and no ``Content-Type``.
    """

    status: int
    headers: Dict[str, str]
    body: Optional[Dict[str, Any]]


@dataclass(frozen=True)
class PoppyVerification:
    """Answer of :meth:`PoppyResource.verify_request`.

    ``active`` is ``True`` for a verified request. Then ``client_id``,
    ``user_id``, ``session``, ``signed_in``, ``version`` and ``extensions``
    are set, and ``account`` is set when the request carried a valid access
    token.

    ``active`` is ``False`` for a refusal. A refusal is a normal result, not
    an error. Then ``error`` and ``response`` are set: answer the personal
    agent with ``response``, unchanged. ``scope`` names the scopes that the
    refusal asks for, when it asks for any.

    ``raw`` is the decoded answer of LumoAuth.
    """

    active: bool
    # A verified request.
    client_id: Optional[str] = None
    client_name: Optional[str] = None
    user_id: Optional[str] = None
    agent_id: Optional[str] = None
    session: Optional[PoppySessionInfo] = None
    signed_in: bool = False
    account: Optional[PoppyAccount] = None
    version: Optional[str] = None
    extensions: Dict[str, str] = field(default_factory=dict)
    # A refusal.
    error: Optional[str] = None
    error_description: Optional[str] = None
    scope: Optional[str] = None
    response: Optional[PoppyResponse] = None
    raw: Dict[str, Any] = field(default_factory=dict, repr=False, compare=False)


@dataclass(frozen=True)
class PoppySessionStatus:
    """Answer of :meth:`PoppyResource.get_session_status`.

    ``status`` is ``"active"``, ``"ended"``, or ``"unknown"`` when no Session
    has that ``sid``. ``account`` is the id of the account that the Session
    used, or ``None``. ``signed_in`` is ``True`` while the Session is active,
    it used an account, and the personal agent still holds a valid refresh
    token for that account.
    """

    status: str
    user_id: Optional[str] = None
    agent_id: Optional[str] = None
    account: Optional[str] = None
    signed_in: bool = False
    last_seen_at: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict, repr=False, compare=False)


# ── The request body (pure functions, no I/O) ─────────────────────────


def normalize_poppy_public_origin(public_origin: Any) -> str:
    """Check a public origin and return it without trailing slashes.

    The public origin is the address that personal agents call, such as
    ``https://shop.example.com``. It may carry a base path. It comes from
    your configuration, never from the ``Host`` header of a request.

    Raises:
        LumoAuthConfigError: The value is missing, or it is not an
            ``http(s)`` URL with a host and without query, fragment or
            credentials.
    """
    if not isinstance(public_origin, str) or not public_origin.strip():
        raise LumoAuthConfigError(
            "public_origin is required: the address that personal agents call, "
            "such as 'https://shop.example.com'. Read it from your configuration, "
            "never from the Host header."
        )
    origin = public_origin.strip().rstrip("/")
    try:
        parts = urlsplit(origin)
        valid = (
            parts.scheme.lower() in ("http", "https")
            and bool(parts.hostname)
            and parts.username is None
            and parts.password is None
            and "?" not in origin
            and "#" not in origin
            and not re.search(r"\s", origin)
        )
        if valid:
            parts.port  # noqa: B018 - raises ValueError for a port that is not a number
    except ValueError:
        valid = False
    if not valid:
        raise LumoAuthConfigError(
            "invalid public_origin: use the http(s) address that personal agents call, "
            "such as 'https://shop.example.com', without query, fragment or credentials"
        )
    return origin


def _text(value: Any, what: str) -> str:
    if isinstance(value, (bytes, bytearray)):
        # Header bytes as an ASGI server gives them.
        return bytes(value).decode("latin-1")
    if isinstance(value, str):
        return value
    raise LumoAuthValidationError(f"{what} must be a string")


def _header_pairs(headers: Any) -> Iterable[Tuple[Any, Any]]:
    if headers is None:
        return ()
    if isinstance(headers, Mapping):
        return headers.items()
    if isinstance(headers, (str, bytes, bytearray)):
        raise LumoAuthValidationError("headers must be a mapping or a list of (name, value) pairs")
    return headers


def _forwarded_headers(headers: Any) -> Dict[str, str]:
    """Keep only the protocol headers, under lower-case names.

    A header that the request repeats becomes one value joined with ``", "``.
    A missing or empty header is left out.
    """
    found: Dict[str, List[str]] = {}
    try:
        pairs = list(_header_pairs(headers))
    except TypeError as exc:
        raise LumoAuthValidationError(
            "headers must be a mapping or a list of (name, value) pairs"
        ) from exc
    for pair in pairs:
        try:
            name, value = pair
        except (TypeError, ValueError) as exc:
            raise LumoAuthValidationError(
                "headers must be a mapping or a list of (name, value) pairs"
            ) from exc
        key = _text(name, "a header name").strip().lower()
        if key not in POPPY_FORWARDED_HEADERS:
            continue
        # Some frameworks give the values of a repeated header as a list.
        values = value if isinstance(value, (list, tuple)) else (value,)
        for item in values:
            if item is None:
                continue
            # Never name the value in an error: it may be a credential.
            text = _text(item, f"the value of the '{key}' header")
            if text.strip():
                found.setdefault(key, []).append(text.strip())
    return {name: ", ".join(found[name]) for name in POPPY_FORWARDED_HEADERS if name in found}


def _scope_string(required_scope: Any) -> str:
    if required_scope is None:
        return ""
    if isinstance(required_scope, str):
        return " ".join(required_scope.split())
    if isinstance(required_scope, (list, tuple)):
        scopes: List[str] = []
        for scope in required_scope:
            if not isinstance(scope, str):
                raise LumoAuthValidationError(
                    "required_scope must be a string or a list of strings"
                )
            scopes.extend(scope.split())
        return " ".join(scopes)
    raise LumoAuthValidationError("required_scope must be a string or a list of strings")


def _without_query(url: str) -> str:
    return _QUERY_OR_FRAGMENT.split(url, 1)[0]


def _request_path(target: Any) -> str:
    """The raw path of a request target, without query and fragment."""
    if isinstance(target, (bytes, bytearray)):
        # The raw path as an ASGI server gives it. A byte outside printable
        # ASCII is percent-encoded, so that the URL stays ASCII.
        path = "".join(chr(b) if 0x21 <= b <= 0x7E else f"%{b:02X}" for b in bytes(target))
    else:
        path = _text(target if target is not None else "", "target")
    # absolute-form (RFC 9112 section 3.2.2): drop the scheme and the authority.
    match = _ABSOLUTE_FORM.match(path)
    if match:
        path = path[match.end():]
    path = _without_query(path)
    # The path always starts with "/", so that the request can never change
    # the host of the URL that the public origin names.
    return path if path.startswith("/") else "/" + path


def _verify_body(
    method: Any,
    url: str,
    headers: Any,
    required_scope: Any,
    resource: Any,
    allow_replay: Any,
) -> Dict[str, Any]:
    if not isinstance(method, str) or not method.strip():
        raise LumoAuthValidationError("method is required: the method of the incoming request")
    if allow_replay is not None and not isinstance(allow_replay, bool):
        raise LumoAuthValidationError("allow_replay must be True or False")
    if resource is not None and not isinstance(resource, str):
        raise LumoAuthValidationError("resource must be a string")

    body: Dict[str, Any] = {
        "method": method.strip().upper(),
        "url": url,
        "headers": _forwarded_headers(headers),
    }
    scope = _scope_string(required_scope)
    if scope:
        body["required_scope"] = scope
    if resource:
        body["resource"] = resource
    if allow_replay is True:
        body["allow_replay"] = True
    return body


def build_poppy_verify_body(
    public_origin: str,
    method: str,
    target: Union[str, bytes],
    headers: HeaderInput,
    *,
    required_scope: ScopeInput = None,
    resource: Optional[str] = None,
    allow_replay: bool = False,
) -> Dict[str, Any]:
    """Build the JSON body of ``poppy.verify_request`` for an incoming request.

    A pure function: it does no I/O. The framework helpers call it, and you
    can call it for a framework that the SDK has no helper for.

    - ``method`` is upper-cased.
    - ``url`` is *public_origin* without trailing slashes, followed by the
      raw path of *target*. The query and the fragment are dropped. An empty
      path is ``/``. The URL is never built from the ``Host`` header.
    - ``headers`` holds only the headers of :data:`POPPY_FORWARDED_HEADERS`,
      matched without regard to case and sent under lower-case names. A
      repeated header becomes one value joined with ``", "``. A missing or
      empty header is left out. No cookie and no API key is ever sent.
    - ``required_scope`` is a space-separated string; a list is joined with
      one space. It is left out when no scope is needed.
    - ``resource`` is sent only when given, and ``allow_replay`` only as
      ``True``.

    Args:
        public_origin: The address that personal agents call, from your
            configuration, such as ``"https://shop.example.com"``. It may
            carry a base path.
        method: The method of the incoming request.
        target: The request target as the client sent it: the raw path,
            with or without the query (``"/api/orders?page=2"``). Do not
            pass a decoded path or a path relative to a mount point.
        headers: The headers of the incoming request: a mapping, or a list
            of ``(name, value)`` pairs. A list keeps repeated headers.
        required_scope: The scopes that the operation needs.
        resource: The resource identifier of your service, when it takes
            only tokens issued for it.
        allow_replay: ``True`` accepts a Session JWT that was verified before.

    Raises:
        LumoAuthConfigError: *public_origin* is missing or malformed.
        LumoAuthValidationError: Another argument is malformed.
    """
    origin = normalize_poppy_public_origin(public_origin)
    return _verify_body(
        method, origin + _request_path(target), headers, required_scope, resource, allow_replay
    )


# ── The answer ────────────────────────────────────────────────────────


def _unexpected(what: str) -> LumoAuthValidationError:
    # Fail closed. The message names the member, never a value of the answer.
    return LumoAuthValidationError(
        f"unexpected answer from LumoAuth's Personal Agent Protocol endpoint: {what}"
    )


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _optional_text(body: Mapping[str, Any], key: str) -> Optional[str]:
    value = body.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise _unexpected(f"'{key}' is not a string")
    return value


def _required_text(body: Mapping[str, Any], key: str) -> str:
    value = body.get(key)
    if not isinstance(value, str) or value == "":
        raise _unexpected(f"'{key}' is missing")
    return value


def _parse_account(value: Any) -> Optional[PoppyAccount]:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise _unexpected("'account' is not an object")
    scope = value.get("scope")
    aud = value.get("aud")
    exp = value.get("exp")
    if not isinstance(scope, str):
        raise _unexpected("'account.scope' is not a string")
    if not isinstance(aud, list) or not all(isinstance(a, str) for a in aud):
        raise _unexpected("'account.aud' is not a list of strings")
    if not _is_int(exp):
        raise _unexpected("'account.exp' is not an integer")
    return PoppyAccount(
        sub=_required_text(value, "sub"),
        scope=scope,
        scopes=tuple(scope.split()),
        aud=tuple(aud),
        exp=exp,
        token_type=_required_text(value, "token_type"),
    )


def _parse_extensions(value: Any) -> Dict[str, str]:
    if value is None or value == []:
        return {}
    if not isinstance(value, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in value.items()
    ):
        raise _unexpected("'extensions' is not a map of name to version")
    return dict(value)


def _parse_verified(body: Dict[str, Any]) -> PoppyVerification:
    session = body.get("session")
    if not isinstance(session, dict):
        raise _unexpected("a verified result has no 'session'")
    if not _is_int(session.get("id")):
        raise _unexpected("'session.id' is not an integer")
    if not isinstance(session.get("new"), bool):
        raise _unexpected("'session.new' is not a boolean")
    info = PoppySessionInfo(
        id=session["id"],
        sid=_required_text(session, "sid"),
        is_new=session["new"],
        started_at=_required_text(session, "started_at"),
    )
    signed_in = body.get("signed_in")
    if not isinstance(signed_in, bool):
        raise _unexpected("'signed_in' is not a boolean")
    account = _parse_account(body.get("account"))
    if signed_in != (account is not None):
        raise _unexpected("'signed_in' and 'account' disagree")
    return PoppyVerification(
        active=True,
        client_id=_required_text(body, "client_id"),
        client_name=_optional_text(body, "client_name"),
        user_id=_required_text(body, "user_id"),
        agent_id=_optional_text(body, "agent_id"),
        session=info,
        signed_in=signed_in,
        account=account,
        version=_required_text(body, "version"),
        extensions=_parse_extensions(body.get("extensions")),
        raw=body,
    )


def _parse_refusal(body: Dict[str, Any]) -> PoppyVerification:
    response = body.get("response")
    if not isinstance(response, dict):
        raise _unexpected("a refusal has no 'response' to relay")
    status = response.get("status")
    # A refusal is an error answer. A status outside 400-599 is never relayed.
    if not _is_int(status) or not 400 <= status <= 599:
        raise _unexpected("'response.status' is not an HTTP error status")
    headers = response.get("headers")
    if headers == []:  # an empty map, as some JSON encoders write it
        headers = {}
    if not isinstance(headers, dict):
        raise _unexpected("'response.headers' is not a map")
    for name, value in headers.items():
        if not isinstance(name, str) or not _HEADER_NAME.match(name):
            raise _unexpected("'response.headers' has a malformed header name")
        if not isinstance(value, str) or _HEADER_VALUE_FORBIDDEN.search(value):
            raise _unexpected("'response.headers' has a malformed header value")
    relay_body = response.get("body")
    if relay_body is not None and not isinstance(relay_body, dict):
        raise _unexpected("'response.body' is neither a JSON object nor null")
    return PoppyVerification(
        active=False,
        error=_required_text(body, "error"),
        error_description=_optional_text(body, "error_description"),
        scope=_optional_text(body, "scope"),
        response=PoppyResponse(status=status, headers=dict(headers), body=relay_body),
        raw=body,
    )


def _parse_verification(body: Any) -> PoppyVerification:
    """Turn a 200 answer into a result, or raise.

    A 200 answer that is not exactly a verified result or a well-formed
    refusal raises. It is never returned as verified.
    """
    if not isinstance(body, dict):
        raise _unexpected("it is not a JSON object")
    active = body.get("active")
    if active is True:
        return _parse_verified(body)
    if active is False:
        return _parse_refusal(body)
    raise _unexpected("'active' is not a boolean")


def _parse_session_status(body: Any) -> PoppySessionStatus:
    if not isinstance(body, dict):
        raise _unexpected("it is not a JSON object")
    status = body.get("status")
    if status not in _SESSION_STATUSES:
        raise _unexpected("'status' is not 'active', 'ended' or 'unknown'")
    signed_in = body.get("signed_in")
    if not isinstance(signed_in, bool):
        raise _unexpected("'signed_in' is not a boolean")
    return PoppySessionStatus(
        status=status,
        user_id=_optional_text(body, "user_id"),
        agent_id=_optional_text(body, "agent_id"),
        account=_optional_text(body, "account"),
        signed_in=signed_in,
        last_seen_at=_optional_text(body, "last_seen_at"),
        raw=body,
    )


# ── The resource ──────────────────────────────────────────────────────


def _session_reference(personal_agent: Any, sid: Any) -> Dict[str, str]:
    if not isinstance(personal_agent, str) or not personal_agent.strip():
        raise LumoAuthValidationError(
            "personal_agent is required: the client_id of the personal agent, "
            "as the verification result gave it"
        )
    if not isinstance(sid, str) or not sid.strip():
        raise LumoAuthValidationError("sid is required: the Session ID")
    return {"personal_agent": personal_agent, "sid": sid}


class PoppyResource:
    """Personal Agent Protocol: Session verification for your own API.

    - :meth:`verify_request`: ask LumoAuth who a request of a personal
      agent is from.
    - :meth:`get_session_status`: look a Session up between requests.
    - :meth:`end_session`: end a Session.

    The calls authenticate with HTTP Basic: the ``client_id`` and
    ``client_secret`` of the :class:`~lumoauth.LumoAuth` client, which must
    belong to a confidential application whose allowed scopes include
    ``poppy:verify``. The client's bearer token and API key are not sent.
    """

    def __init__(
        self,
        http: HttpClient,
        *,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
    ) -> None:
        self._http = http
        self._client_id = client_id or None
        self._client_secret = client_secret or None

    # ── Transport ─────────────────────────────────────────────────────

    def _basic(self) -> str:
        if not self._client_id or not self._client_secret:
            raise LumoAuthConfigError(
                "Personal Agent Protocol calls need a client id and a client secret: "
                "pass client_id and client_secret to LumoAuth(...), or set "
                "LUMOAUTH_CLIENT_ID and LUMOAUTH_CLIENT_SECRET. Use a confidential "
                f"application whose allowed scopes include '{POPPY_VERIFY_SCOPE}'."
            )
        # The raw values: the server does not percent-decode them.
        pair = f"{self._client_id}:{self._client_secret}".encode("utf-8")
        return "Basic " + base64.b64encode(pair).decode("ascii")

    def _post(self, route: str, payload: Dict[str, Any]) -> Any:
        authorization = self._basic()
        # auth=False plus an explicit Authorization header: the client's
        # bearer token, API key and DPoP key stay out of this call. The
        # credentials never go in the JSON body. A redirect is an error: the
        # body holds the personal agent's headers and must go nowhere else.
        resp = self._http.call(
            route,
            json=payload,
            headers={
                "Authorization": authorization,
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            auth=False,
            raw=True,
            allow_redirects=False,
        )
        if resp.status_code != 200:
            # 401, 403, 404, 429 and every other error status are about the
            # calling application itself. They raise the usual API errors.
            self._http._handle(resp)
            raise LumoAuthApiError(
                f"unexpected HTTP {resp.status_code} from LumoAuth",
                status_code=resp.status_code,
            )
        return self._http._parse_body(resp)

    # ── Calls ─────────────────────────────────────────────────────────

    def verify_request(
        self,
        method: str,
        url: str,
        headers: HeaderInput,
        *,
        required_scope: ScopeInput = None,
        resource: Optional[str] = None,
        allow_replay: bool = False,
    ) -> PoppyVerification:
        """Ask LumoAuth who a request of a personal agent is from.

        Pass the request as your API received it. You may pass all its
        headers: the SDK sends only the five protocol headers
        (:data:`POPPY_FORWARDED_HEADERS`), so no cookie and no API key
        leaves your service. Verify each request once: a Session JWT is
        good for one verification unless you pass ``allow_replay=True``.

        Args:
            method: The method of the incoming request.
            url: The public URL that the personal agent called, built from
                your configured public origin and the raw path. The SDK
                drops a query and a fragment. Never build it from the
                ``Host`` header; :func:`build_poppy_verify_body` shows the
                rules.
            headers: The headers of the incoming request: a mapping, or a
                list of ``(name, value)`` pairs.
            required_scope: The scopes that the operation needs: a
                space-separated string or a list.
            resource: The resource identifier of your service, when it
                takes only tokens issued for it.
            allow_replay: ``True`` accepts a Session JWT that was verified
                before.

        Returns:
            :class:`PoppyVerification`. ``active`` is ``True`` for a
            verified request. A refusal returns ``active=False`` with the
            ``response`` to relay unchanged, and does not raise.

        Raises:
            LumoAuthConfigError: The client has no client id and secret.
            LumoAuthValidationError: An argument is malformed, or LumoAuth
                answered 200 with something that is neither a verified
                result nor a well-formed refusal.
            LumoAuthAuthenticationError: 401, the application did not
                authenticate.
            LumoAuthPermissionDeniedError: 403, the application lacks the
                ``poppy:verify`` scope.
            LumoAuthNotFoundError: 404, unknown organization, or the
                protocol is switched off.
            LumoAuthRateLimitError: 429, with ``retry_after``.

        The errors are about your own application. Never relay them to the
        personal agent: answer it with a 5xx status.
        """
        if not isinstance(url, str) or not url.strip():
            raise LumoAuthValidationError(
                "url is required: the public address that the personal agent called"
            )
        public_url = _without_query(url.strip())
        try:
            if urlsplit(public_url).path == "":
                public_url += "/"  # an empty path is "/"
        except ValueError as exc:
            raise LumoAuthValidationError("url is not a valid URL") from exc
        payload = _verify_body(
            method, public_url, headers, required_scope, resource, allow_replay
        )
        answer = self._post("poppy.verifyRequest", payload)
        result = _parse_verification(answer)
        # Never log header values: they are credentials.
        logger.debug(
            "Personal Agent Protocol verification: %s",
            "verified" if result.active else f"refused ({result.error})",
        )
        return result

    def get_session_status(self, personal_agent: str, sid: str) -> PoppySessionStatus:
        """Look a Session up when the personal agent sent no request.

        A website that joined a browser to a Session asks this on each page
        request, so that a sign-out or an ended Session takes effect at once.

        Args:
            personal_agent: The ``client_id`` of the personal agent, as the
                verification result gave it.
            sid: The Session ID (``session.sid`` of the verification result).

        Returns:
            :class:`PoppySessionStatus`. An unknown Session is a result with
            ``status="unknown"``, not an error.

        Raises:
            LumoAuthValidationError: An argument is empty. No request is sent.
            LumoAuthConfigError: The client has no client id and secret.
        """
        payload = _session_reference(personal_agent, sid)
        return _parse_session_status(self._post("poppy.getSessionStatus", payload))

    def end_session(self, personal_agent: str, sid: str) -> bool:
        """End a Session. The user stays signed in.

        Later requests with this ``sid`` are refused with ``session_ended``,
        and the personal agent starts a new Session.

        Returns:
            ``True`` when this call ended the Session, ``False`` when the
            Session had ended before.

        Raises:
            LumoAuthValidationError: An argument is empty. No request is sent.
            LumoAuthConfigError: The client has no client id and secret.
            LumoAuthNotFoundError: 404, no Session has this ``sid``.
        """
        payload = _session_reference(personal_agent, sid)
        body = self._post("poppy.endSession", payload)
        if not isinstance(body, dict) or not isinstance(body.get("ended"), bool):
            raise _unexpected("'ended' is not a boolean")
        return body["ended"]

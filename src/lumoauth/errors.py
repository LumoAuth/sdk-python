"""LumoAuth SDK error taxonomy.

Mirrors the JS SDK's error hierarchy (same names and codes):

    LumoAuthError
    ├── LumoAuthApiError            (any non-2xx HTTP response)
    │   ├── LumoAuthAuthenticationError   (401, code AUTHENTICATION_ERROR)
    │   ├── LumoAuthPermissionDeniedError (403, code PERMISSION_DENIED; required_scopes)
    │   ├── LumoAuthNotFoundError         (404, code NOT_FOUND)
    │   └── LumoAuthRateLimitError        (429, code RATE_LIMITED)
    ├── LumoAuthValidationError     (bad input / unexpected response shape)
    │   └── LumoAuthTokenError      (an access token or DPoP proof failed local verification; code names why)
    ├── LumoAuthConfigError         (missing or invalid configuration)
    ├── LumoAuthNetworkError        (transport failure: DNS, timeout, TLS, …)
    ├── LumoAuthApprovalDeniedError
    ├── LumoAuthApprovalTimeoutError
    ├── LumoAuthApprovalNotDeliveredError (code APPROVAL_NOT_DELIVERED; reason)
    └── LumoAuthBudgetExceededError

Backwards compatibility: earlier releases of this SDK raised bare
``ValueError`` / ``RuntimeError`` (and let ``requests`` transport errors
propagate).  To keep existing ``except`` clauses working, some classes
multiply-inherit from the builtin they replaced:

- ``LumoAuthApiError`` is also a ``RuntimeError``
- ``LumoAuthConfigError`` and ``LumoAuthValidationError`` are also ``ValueError``
- ``LumoAuthNetworkError`` is also a ``ConnectionError``
"""

from __future__ import annotations

from typing import Any, List, Optional

__all__ = [
    "LumoAuthError",
    "LumoAuthApiError",
    "LumoAuthAuthenticationError",
    "LumoAuthPermissionDeniedError",
    "LumoAuthNotFoundError",
    "LumoAuthRateLimitError",
    "LumoAuthValidationError",
    "LumoAuthTokenError",
    "LumoAuthConfigError",
    "LumoAuthNetworkError",
    "LumoAuthApprovalDeniedError",
    "LumoAuthApprovalTimeoutError",
    "LumoAuthApprovalNotDeliveredError",
    "LumoAuthBudgetExceededError",
]


class LumoAuthError(Exception):
    """Base class for all LumoAuth SDK errors."""

    def __init__(self, message: str, code: str = "LUMOAUTH_ERROR") -> None:
        super().__init__(message)
        self.message = message
        self.code = code


class LumoAuthApiError(LumoAuthError, RuntimeError):
    """The server returned a non-2xx HTTP response."""

    def __init__(
        self,
        message: str,
        code: str = "API_ERROR",
        status_code: Optional[int] = None,
        body: Any = None,
    ) -> None:
        super().__init__(message, code)
        self.status_code = status_code
        self.body = body


class LumoAuthAuthenticationError(LumoAuthApiError):
    """401 — the access token / API key is missing, invalid, or expired."""

    def __init__(
        self,
        message: str = "Authentication failed — check your credentials.",
        code: str = "AUTHENTICATION_ERROR",
        status_code: int = 401,
        body: Any = None,
    ) -> None:
        super().__init__(message, code, status_code, body)


class LumoAuthPermissionDeniedError(LumoAuthApiError):
    """403 — the authenticated principal is not allowed to do this.

    When the credential lacks a scope that the route needs, the server answers
    ``{"error": "forbidden", "message": "Insufficient scope: …", "status": 403,
    "details": {"required_scopes": ["authz:read"], "granted_scopes": […]}}``.
    ``required_scopes`` lists the scopes it named; it is empty for a plain
    permission denial.
    """

    def __init__(
        self,
        message: str = "Permission denied.",
        code: str = "PERMISSION_DENIED",
        status_code: int = 403,
        body: Any = None,
    ) -> None:
        super().__init__(message, code, status_code, body)
        self.required_scopes: List[str] = _required_scopes(body)


def _required_scopes(body: Any) -> List[str]:
    if not isinstance(body, dict):
        return []
    details = body.get("details")
    if not isinstance(details, dict):
        return []
    scopes = details.get("required_scopes")
    if not isinstance(scopes, list):
        return []
    return [s for s in scopes if isinstance(s, str) and s]


class LumoAuthNotFoundError(LumoAuthApiError):
    """404 — the requested resource does not exist."""

    def __init__(
        self,
        message: str = "Resource not found.",
        code: str = "NOT_FOUND",
        status_code: int = 404,
        body: Any = None,
    ) -> None:
        super().__init__(message, code, status_code, body)


class LumoAuthRateLimitError(LumoAuthApiError):
    """429 — rate limited.  ``retry_after`` holds the server's hint (seconds)."""

    def __init__(
        self,
        message: str = "Rate limited — retry later.",
        code: str = "RATE_LIMITED",
        status_code: int = 429,
        body: Any = None,
        retry_after: Optional[float] = None,
    ) -> None:
        super().__init__(message, code, status_code, body)
        self.retry_after = retry_after


class LumoAuthValidationError(LumoAuthError, ValueError):
    """Client-side validation failed (bad input or unexpected response shape)."""

    def __init__(self, message: str, issues: Optional[List[Any]] = None) -> None:
        super().__init__(message, "VALIDATION_ERROR")
        self.issues: List[Any] = issues or []


class LumoAuthTokenError(LumoAuthValidationError):
    """An access token or DPoP proof failed local verification.

    Raised by :func:`lumoauth.verify.verify_access_token`. ``code`` is one of
    the stable ``TOKEN_*`` / ``DPOP_*`` values (``TOKEN_EXPIRED``,
    ``TOKEN_WRONG_AUDIENCE``, ``DPOP_REQUIRED``, ``DPOP_REPLAYED``, …), so a
    resource server can log or map it without parsing the message.
    ``www_authenticate`` is a ready-made challenge value for a 401 answer.
    """

    def __init__(
        self,
        message: str,
        code: str = "TOKEN_INVALID",
        *,
        scheme: str = "Bearer",
        error: str = "invalid_token",
    ) -> None:
        super().__init__(message)
        self.code = code
        self.scheme = scheme
        self.error = error

    @property
    def www_authenticate(self) -> str:
        description = self.message.replace('"', "'")
        return f'{self.scheme} error="{self.error}", error_description="{description}"'


class LumoAuthConfigError(LumoAuthError, ValueError, RuntimeError):
    """A required configuration option is missing or invalid.

    Also subclasses ``ValueError`` (missing-credential errors used to be
    ``ValueError``) and ``RuntimeError`` (missing-token / missing-task state
    errors used to be ``RuntimeError``) so legacy ``except`` clauses keep
    working.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message, "CONFIG_ERROR")


class LumoAuthNetworkError(LumoAuthError, ConnectionError):
    """A network request failed before an HTTP response was received."""

    def __init__(self, message: str, cause: Any = None) -> None:
        super().__init__(message, "NETWORK_ERROR")
        self.cause = cause


class LumoAuthApprovalDeniedError(LumoAuthError):
    """A human approver denied the requested action."""

    def __init__(self, message: str = "Approval denied.") -> None:
        super().__init__(message, "APPROVAL_DENIED")


class LumoAuthApprovalTimeoutError(LumoAuthError):
    """An approval request expired before a human responded."""

    def __init__(self, message: str = "Approval timed out.") -> None:
        super().__init__(message, "APPROVAL_TIMEOUT")


class LumoAuthApprovalNotDeliveredError(LumoAuthError):
    """No push prompt reached the user, so the approval cannot happen now.

    ``reason`` says why:

    - ``"email_fallback_sent"``: the server answered 202. The user has no
      enrolled push device, so LumoAuth sent them a plain email notice
      (it holds no approval link). The server gives the same answer when the
      user does not exist. There is no approval token to poll.
    - ``"no_enrolled_device"``: the server answered 428. The user has no
      enrolled push device, and the email notice could not be sent.

    ``task_id`` echoes the task id when the response carries one.
    """

    def __init__(
        self,
        message: str = "The approval request was not delivered to the user.",
        reason: Optional[str] = None,
        task_id: Optional[str] = None,
        status_code: Optional[int] = None,
        body: Any = None,
    ) -> None:
        super().__init__(message, "APPROVAL_NOT_DELIVERED")
        self.reason = reason
        self.task_id = task_id
        self.status_code = status_code
        self.body = body


class LumoAuthBudgetExceededError(LumoAuthError):
    """The agent's token/spend budget is exhausted."""

    def __init__(self, message: str = "Budget exceeded.") -> None:
        super().__init__(message, "BUDGET_EXCEEDED")

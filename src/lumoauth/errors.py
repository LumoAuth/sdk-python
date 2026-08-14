"""LumoAuth SDK error taxonomy.

Mirrors the JS SDK's error hierarchy (same names and codes):

    LumoAuthError
    ├── LumoAuthApiError            (any non-2xx HTTP response)
    │   ├── LumoAuthAuthenticationError   (401, code AUTH_ERROR)
    │   ├── LumoAuthPermissionDeniedError (403, code PERMISSION_DENIED)
    │   ├── LumoAuthNotFoundError         (404, code NOT_FOUND)
    │   └── LumoAuthRateLimitError        (429, code RATE_LIMITED)
    ├── LumoAuthValidationError     (bad input / unexpected response shape)
    ├── LumoAuthConfigError         (missing or invalid configuration)
    ├── LumoAuthNetworkError        (transport failure: DNS, timeout, TLS, …)
    ├── LumoAuthApprovalDeniedError
    ├── LumoAuthApprovalTimeoutError
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
    "LumoAuthConfigError",
    "LumoAuthNetworkError",
    "LumoAuthApprovalDeniedError",
    "LumoAuthApprovalTimeoutError",
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
        code: str = "AUTH_ERROR",
        status_code: int = 401,
        body: Any = None,
    ) -> None:
        super().__init__(message, code, status_code, body)


class LumoAuthPermissionDeniedError(LumoAuthApiError):
    """403 — the authenticated principal is not allowed to do this."""

    def __init__(
        self,
        message: str = "Permission denied.",
        code: str = "PERMISSION_DENIED",
        status_code: int = 403,
        body: Any = None,
    ) -> None:
        super().__init__(message, code, status_code, body)


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


class LumoAuthBudgetExceededError(LumoAuthError):
    """The agent's token/spend budget is exhausted."""

    def __init__(self, message: str = "Budget exceeded.") -> None:
        super().__init__(message, "BUDGET_EXCEEDED")

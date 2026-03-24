"""Decorators for capability-gated agent methods."""

from __future__ import annotations

from functools import wraps
from typing import Any, Callable, TypeVar

__all__ = ["require_capability"]

F = TypeVar("F", bound=Callable[..., Any])


def require_capability(capability: str) -> Callable[[F], F]:
    """Decorator that gates a method on an agent capability.

    The decorated method's first positional argument (``self``) must be a
    :class:`~lumoauth.LumoAuthAgent` (or subclass) instance.

    Raises:
        PermissionError: If the agent does not possess *capability*.

    Example::

        class MyAgent(LumoAuthAgent):
            @require_capability("tool:search_web")
            def search(self, query: str) -> dict:
                return self.api_request("POST", "/search", data={"q": query}).json()
    """

    def decorator(func: F) -> F:
        @wraps(func)
        def wrapper(self: Any, *args: Any, **kwargs: Any) -> Any:
            if not self.has_capability(capability):
                raise PermissionError(
                    f"Agent lacks required capability: {capability}. "
                    "Update the agent registration to include this capability."
                )
            return func(self, *args, **kwargs)

        return wrapper  # type: ignore[return-value]

    return decorator

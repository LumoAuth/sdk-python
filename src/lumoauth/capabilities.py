"""Agent capability matching, exactly as the LumoAuth server does it.

An agent capability is one of the agent's OAuth scope values, written
``<resource>:<action>`` (``invoices:read``, ``web:search``). LumoAuth
refuses the dot form (``invoices.read``) when a capability is registered or a
scope is requested for its API. The server compares capabilities in one
canonical form and honours two wildcards. Comparing capability strings with
``==`` or ``in`` gets both wrong: a dotted permission slug such as
``invoices.read`` compares equal to ``invoices:read``, and ``invoices:*``
covers ``invoices:read``. Use these functions instead.

* **Canonical form** (used only to compare). Trimmed, ASCII letters
  lower-cased, every ``.`` turned into ``:``, runs of ``:`` collapsed, ``:``
  trimmed from both ends. A ``-`` is part of a name
  (``pull-requests:comment``), not a separator, so ``invoices-read`` is not
  ``invoices:read``.
* **Wildcards.** ``*`` covers every action. A name that ends in ``:*`` covers
  every action under that prefix, at any depth, but not the prefix itself:
  ``invoices:*`` covers ``invoices:read`` and ``invoices:read:draft``, not
  ``invoices``. A ``*`` anywhere else is an ordinary character.

The cases in ``sdk-contract/vectors/agent-capabilities.json`` are checked
against the server's own matcher, and ``tests/test_capabilities.py`` checks
this module against the same cases.
"""

from __future__ import annotations

import re
from typing import Iterable

__all__ = ["normalize_capability", "capability_covers", "any_capability_covers"]

WILDCARD = "*"
SEPARATOR = ":"

# PHP's trim() default set: space, tab, LF, CR, NUL, vertical tab.
_TRIM = " \t\n\r\0\x0b"
_ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")
_SEPARATORS = re.compile(r":{2,}")


def normalize_capability(capability: str) -> str:
    """Return *capability* in the server's canonical form.

    ``"Invoices.Read"`` and ``"invoices::read"`` both become
    ``"invoices:read"``; ``"invoices-read"`` stays ``"invoices-read"``.
    Only ASCII letters are lower-cased, as on the server.
    """
    normalized = capability.strip(_TRIM).translate(_ASCII_LOWER)
    normalized = normalized.replace(".", SEPARATOR)
    normalized = _SEPARATORS.sub(SEPARATOR, normalized)
    return normalized.strip(SEPARATOR)


def capability_covers(capability: str, action: str) -> bool:
    """Whether one capability covers an action, in any spelling of either.

    ``capability_covers("users:*", "USERS.DELETE")`` is ``True``;
    ``capability_covers("invoices:*", "invoices")`` and
    ``capability_covers("users:*", "users-delete")`` are ``False``.
    """
    capability = normalize_capability(capability)
    action = normalize_capability(action)
    if not capability or not action:
        return False
    if capability == WILDCARD or capability == action:
        return True
    if capability.endswith(SEPARATOR + WILDCARD):
        return action.startswith(capability[:-1])
    return False


def any_capability_covers(capabilities: Iterable[object], action: str) -> bool:
    """Whether any capability in the list covers *action*. Non-strings are ignored."""
    return any(isinstance(c, str) and capability_covers(c, action) for c in capabilities)

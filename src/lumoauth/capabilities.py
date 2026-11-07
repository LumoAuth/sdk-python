"""Agent capability matching, exactly as the LumoAuth server does it.

The server stores every capability in one form and matches it with two
wildcards. Comparing capability strings with ``==`` or ``in`` gets both wrong:
``tool:search_web`` is stored as ``tool.search_web``, and ``invoices.*``
covers ``invoices.read``. Use these functions instead.

* **Stored form.** Trimmed, ASCII letters lower-cased, ``:`` and ``-`` turned
  into ``.``, runs of ``.`` collapsed, ``.`` trimmed from both ends.
* **Wildcards.** ``*`` covers every action. A name that ends in ``.*`` covers
  every action under that prefix, at any depth, but not the prefix itself:
  ``invoices.*`` covers ``invoices.read`` and ``invoices.read.draft``, not
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

# PHP's trim() default set: space, tab, LF, CR, NUL, vertical tab.
_TRIM = " \t\n\r\0\x0b"
_ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")
_DOTS = re.compile(r"\.{2,}")


def normalize_capability(capability: str) -> str:
    """Return *capability* in the form that the server stores.

    ``"Invoices:Read"`` and ``"invoices-read"`` both become ``"invoices.read"``.
    Only ASCII letters are lower-cased, as on the server.
    """
    normalized = capability.strip(_TRIM).translate(_ASCII_LOWER)
    normalized = normalized.replace(":", ".").replace("-", ".")
    normalized = _DOTS.sub(".", normalized)
    return normalized.strip(".")


def capability_covers(capability: str, action: str) -> bool:
    """Whether one capability covers an action, in any spelling of either.

    ``capability_covers("users:*", "USERS-DELETE")`` is ``True``;
    ``capability_covers("invoices.*", "invoices")`` is ``False``.
    """
    capability = normalize_capability(capability)
    action = normalize_capability(action)
    if not capability or not action:
        return False
    if capability == WILDCARD or capability == action:
        return True
    if capability.endswith(".*"):
        return action.startswith(capability[:-1])
    return False


def any_capability_covers(capabilities: Iterable[object], action: str) -> bool:
    """Whether any capability in the list covers *action*. Non-strings are ignored."""
    return any(isinstance(c, str) and capability_covers(c, action) for c in capabilities)

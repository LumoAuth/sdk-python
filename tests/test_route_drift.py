"""Drift detection: every route in lumoauth._routes must exist in the OpenAPI spec.

Loads ``server/openapi.json`` (fallback ``api-clients/openapi.json``) from the
monorepo and asserts that each ``(method, path)`` pair in ``ROUTES`` appears in
the spec after normalizing placeholder names (``{org_id}`` vs ``{orgId}`` etc.).

Routes the server serves but the spec does not document are tracked in
``KNOWN_DRIFT`` so they stay visible without failing the suite.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

import pytest

from lumoauth._routes import ROUTES

# Resolved relative to this file (tests/ -> sdk-python/ -> monorepo root) so the
# suite works from any checkout location; LUMO_OPENAPI_PATH overrides.
_MONOREPO_ROOT = Path(__file__).resolve().parents[2]
SPEC_CANDIDATES = [
    *([Path(os.environ["LUMO_OPENAPI_PATH"])] if os.environ.get("LUMO_OPENAPI_PATH") else []),
    _MONOREPO_ROOT / "server" / "openapi.json",
    _MONOREPO_ROOT / "api-clients" / "openapi.json",
]

# Routes whose exact (method, path) is NOT present in the OpenAPI spec but is
# known to work against the live server.  Keep these working; revisit when the
# spec (Workstream A post-processing) catches up.
KNOWN_DRIFT = {
    # Served at the instance root; the spec only documents the org-scoped
    # variant /orgs/{orgId}/api/v1/.well-known/aauth-issuer.
    "wellknown.aauth_issuer",
}

_PLACEHOLDER = re.compile(r"\{[^}]+\}")


def _normalize(path: str) -> str:
    """Collapse placeholder names so {org_id} and {orgId} compare equal."""
    return _PLACEHOLDER.sub("{}", path)


def _load_spec_pairs():
    for candidate in SPEC_CANDIDATES:
        if candidate.is_file():
            spec = json.loads(candidate.read_text())
            pairs = set()
            for path, ops in spec.get("paths", {}).items():
                for method in ops:
                    if method.lower() in ("get", "post", "put", "delete", "patch", "options", "head"):
                        pairs.add((method.upper(), _normalize(path)))
            return pairs, candidate
    return None, None


SPEC_PAIRS, SPEC_FILE = _load_spec_pairs()

pytestmark = pytest.mark.skipif(
    SPEC_PAIRS is None,
    reason=(
        "openapi.json not found (looked in $LUMO_OPENAPI_PATH, "
        f"{_MONOREPO_ROOT / 'server'} and {_MONOREPO_ROOT / 'api-clients'})"
    ),
)


@pytest.mark.parametrize("name", sorted(set(ROUTES) - KNOWN_DRIFT))
def test_route_exists_in_openapi_spec(name):
    method, path = ROUTES[name]
    pair = (method.upper(), _normalize(path))
    assert pair in SPEC_PAIRS, (
        f"Route '{name}' → {method} {path} not found in {SPEC_FILE}. "
        "Either the SDK path drifted from the server, or this is intentional "
        "drift that belongs in KNOWN_DRIFT."
    )


@pytest.mark.parametrize("name", sorted(KNOWN_DRIFT))
def test_known_drift_is_still_absent_from_spec(name):
    """If a KNOWN_DRIFT route shows up in the spec, promote it out of the set."""
    method, path = ROUTES[name]
    pair = (method.upper(), _normalize(path))
    assert pair not in SPEC_PAIRS, (
        f"Route '{name}' now exists in {SPEC_FILE} — remove it from KNOWN_DRIFT."
    )

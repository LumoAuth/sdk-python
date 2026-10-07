"""Conformance against the cross-SDK contract (``sdk-contract/``).

* Every route in ``lumoauth._routes`` exists in ``routes.json`` (same method,
  placeholder names ignored). Route *names* differ by design (the contract
  uses the JS/Go spelling); paths are what must agree.
* Every contract route in a namespace this SDK claims (``features.json``) is
  registered, unless listed in ``known_missing_routes`` with a reason.
* ``lumoauth.errors`` carries the contract's names, codes, statuses and
  parent chain.

Skips when the contract is not checked out next to ``sdk-python``
(``LUMO_SDK_CONTRACT`` overrides).
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

import pytest

from lumoauth import errors
from lumoauth._routes import ROUTES

_CANDIDATES = [
    *([Path(os.environ["LUMO_SDK_CONTRACT"])] if os.environ.get("LUMO_SDK_CONTRACT") else []),
    Path(__file__).resolve().parents[2] / "sdk-contract",
]
CONTRACT = next((c for c in _CANDIDATES if (c / "routes.json").is_file()), None)
pytestmark = pytest.mark.skipif(CONTRACT is None, reason="sdk-contract not found")


def _norm(path: str) -> str:
    return re.sub(r"\{[^}]+\}", "{}", path)


def _load(name: str) -> dict:
    assert CONTRACT is not None
    return json.loads((CONTRACT / name).read_text())


def test_registry_is_a_subset_of_the_contract() -> None:
    known = {(r["method"], _norm(r["path"])) for r in _load("routes.json")["routes"]}
    for name, (method, path) in ROUTES.items():
        assert (method, _norm(path)) in known, f"{name} ({method} {path}) is not in sdk-contract/routes.json"


def test_claimed_namespaces_are_fully_covered() -> None:
    contract = _load("routes.json")
    me = _load("features.json")["sdks"]["python"]
    have = {(m, _norm(p)) for m, p in ROUTES.values()}
    allowed = me.get("known_missing_routes", {})
    for r in contract["routes"]:
        if r["namespace"] not in me["namespaces"]:
            continue
        present = (r["method"], _norm(r["path"])) in have
        if r["name"] in allowed:
            assert not present, f"{r['name']} is listed in known_missing_routes but ROUTES has it — remove the entry"
        else:
            assert present, f"contract route {r['name']} ({r['method']} {r['path']}) is missing from lumoauth._routes"


def _instantiate(name: str):
    cls = getattr(errors, name)
    if name in ("LumoAuthError", "LumoAuthApiError", "LumoAuthValidationError", "LumoAuthConfigError", "LumoAuthNetworkError"):
        return cls("m")
    return cls()


def test_error_taxonomy_matches_the_contract() -> None:
    for spec in _load("errors.json")["errors"]:
        assert hasattr(errors, spec["name"]), f"{spec['name']} missing"
        e = _instantiate(spec["name"])
        assert e.code == spec["code"], f"{spec['name']} code"
        if spec["status"] is not None:
            assert e.status_code == spec["status"], f"{spec['name']} status"
        if spec["parent"]:
            assert isinstance(e, getattr(errors, spec["parent"])), f"{spec['name']} extends {spec['parent']}"
        assert isinstance(e, Exception)

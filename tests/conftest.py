"""Shared test helpers — a fake requests.Session and response factory."""

from __future__ import annotations

import json as jsonlib
from typing import Any, Dict, List, Optional, Tuple

import pytest


class FakeResponse:
    """Minimal stand-in for requests.Response."""

    def __init__(
        self,
        status_code: int = 200,
        payload: Any = None,
        *,
        text: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        self.status_code = status_code
        self._payload = payload
        self.headers = {"content-type": "application/json", **(headers or {})}
        if text is not None:
            self.text = text
        elif payload is not None:
            self.text = jsonlib.dumps(payload)
        else:
            self.text = ""

    def json(self) -> Any:
        if self._payload is None:
            raise ValueError("No JSON body")
        return self._payload

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            import requests

            raise requests.HTTPError(f"HTTP {self.status_code}", response=self)


class FakeSession:
    """Records every request and replays queued responses."""

    def __init__(self) -> None:
        self.calls: List[Tuple[str, str, Dict[str, Any]]] = []
        self.responses: List[FakeResponse] = []
        self.default_response = FakeResponse(200, {})

    def queue(self, *responses: FakeResponse) -> None:
        self.responses.extend(responses)

    def request(self, method: str, url: str, **kwargs: Any) -> FakeResponse:
        self.calls.append((method, url, kwargs))
        if self.responses:
            return self.responses.pop(0)
        return self.default_response

    # Convenience accessors -------------------------------------------------

    @property
    def last(self) -> Tuple[str, str, Dict[str, Any]]:
        return self.calls[-1]


@pytest.fixture()
def fake_session(monkeypatch: pytest.MonkeyPatch) -> FakeSession:
    """Patch requests.Session inside the SDK's HTTP layer with a recorder."""
    session = FakeSession()
    monkeypatch.setattr("lumoauth._http.requests.Session", lambda: session)
    return session

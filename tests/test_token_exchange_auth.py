"""Client authentication on the token exchange (``client.auth.token_exchange``)."""

from __future__ import annotations

import base64

import pytest

from conftest import FakeResponse, FakeSession
from lumoauth import LumoAuth
from lumoauth.errors import LumoAuthValidationError
from lumoauth.resources.auth import TOKEN_EXCHANGE_GRANT

BASE = "https://app.lumoauth.dev"
ORG = "acme-corp"
TOKEN_URL = f"{BASE}/orgs/{ORG}/api/v1/oauth/token"


def _exchange(fake_session: FakeSession, **options):
    fake_session.queue(FakeResponse(200, {"access_token": "exchanged", "token_type": "Bearer"}))
    # An API key is configured, and the token endpoint must never get it.
    LumoAuth(base_url=BASE, org_id=ORG, api_key="lmk_secret").auth.token_exchange(
        "user-token", resource="https://api.example.com", **options
    )
    method, url, kw = fake_session.last
    assert (method, url) == ("POST", TOKEN_URL)
    assert "X-API-Key" not in kw["headers"]
    return kw


def test_agent_exchange_sends_no_client_authentication(fake_session: FakeSession):
    kw = _exchange(fake_session, actor_token="agent-token")
    assert "Authorization" not in kw["headers"]
    assert kw["data"] == {
        "grant_type": TOKEN_EXCHANGE_GRANT,
        "subject_token": "user-token",
        "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "actor_token": "agent-token",
        "actor_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "resource": "https://api.example.com",
    }


def test_client_secret_basic_is_the_default(fake_session: FakeSession):
    kw = _exchange(fake_session, client_id="client_1", client_secret="s3cr3t")
    expected = "Basic " + base64.b64encode(b"client_1:s3cr3t").decode()
    assert kw["headers"]["Authorization"] == expected
    assert "client_secret" not in kw["data"] and "client_id" not in kw["data"]


def test_client_secret_post(fake_session: FakeSession):
    kw = _exchange(fake_session, client_id="client_1", client_secret="s3cr3t", client_auth_method="client_secret_post")
    assert "Authorization" not in kw["headers"]
    assert (kw["data"]["client_id"], kw["data"]["client_secret"]) == ("client_1", "s3cr3t")


def test_private_key_jwt(fake_session: FakeSession):
    kw = _exchange(fake_session, client_id="client_1", client_assertion="eyJ.assertion.sig")
    assert "Authorization" not in kw["headers"]
    assert kw["data"]["client_id"] == "client_1"
    assert kw["data"]["client_assertion_type"] == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    assert kw["data"]["client_assertion"] == "eyJ.assertion.sig"


def test_client_id_alone_is_sent_in_the_form(fake_session: FakeSession):
    kw = _exchange(fake_session, client_id="client_1")
    assert kw["data"]["client_id"] == "client_1" and "Authorization" not in kw["headers"]


@pytest.mark.parametrize(
    "options",
    [
        {"client_id": "client_1", "client_secret": "s", "client_assertion": "a"},
        {"client_secret": "s"},
        {"client_assertion": "a"},
        {"client_id": "client_1", "client_secret": "s", "client_auth_method": "tls_client_auth"},
    ],
)
def test_refused_combinations_send_nothing(fake_session: FakeSession, options):
    with pytest.raises(LumoAuthValidationError):
        LumoAuth(base_url=BASE, org_id=ORG).auth.token_exchange("user-token", **options)
    assert fake_session.calls == []


def test_dpop_proof_with_basic_authentication(fake_session: FakeSession):
    pytest.importorskip("cryptography")
    from lumoauth.dpop import DpopProofSigner

    kw = _exchange(fake_session, client_id="client_1", client_secret="s3cr3t", dpop=DpopProofSigner())
    assert kw["headers"]["Authorization"].startswith("Basic ")
    assert kw["headers"]["DPoP"].count(".") == 2

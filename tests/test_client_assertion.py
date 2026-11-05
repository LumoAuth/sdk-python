"""private_key_jwt client assertions (RFC 7523) and the agent sign-in that uses them."""

from __future__ import annotations

import json
import time

import pytest

pytest.importorskip("cryptography")

from conftest import FakeResponse, FakeSession  # noqa: E402
from lumoauth import CLIENT_ASSERTION_TYPE, ClientAssertionSigner, LumoAuthAgent  # noqa: E402
from lumoauth._jose import public_key_from_jwk, split_jws, verify  # noqa: E402
from lumoauth.client_assertion import issuer_for  # noqa: E402
from lumoauth.errors import LumoAuthConfigError, LumoAuthValidationError  # noqa: E402

BASE = "https://auth.example.com"
ORG = "acme-corp"
ISSUER = f"{BASE}/orgs/{ORG}/api/v1"
AGENT_ID = "agt_0123456789abcdef"

TOKEN_RESPONSE = {"access_token": "at-1", "token_type": "Bearer", "expires_in": 3600, "scope": "invoices.read"}


def _clear_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in (
        "LUMOAUTH_URL", "LUMOAUTH_ORG_ID", "AGENT_CLIENT_ID", "AGENT_CLIENT_SECRET",
        "AGENT_PRIVATE_KEY", "AGENT_KEY_ID",
    ):
        monkeypatch.delenv(var, raising=False)


@pytest.mark.parametrize("alg", ["ES256", "ES384", "ES512", "EdDSA", "RS256", "PS256"])
def test_assertion_has_the_claims_the_server_checks_and_verifies(alg: str) -> None:
    signer = ClientAssertionSigner.generate(alg, key_id="k1")
    before = int(time.time())

    token = signer.create(AGENT_ID, ISSUER)

    header, claims, signing_input, signature = split_jws(token)
    assert header == {"alg": alg, "typ": "client-authentication+jwt", "kid": "k1"}
    assert claims["iss"] == claims["sub"] == AGENT_ID
    assert claims["aud"] == ISSUER
    assert before <= claims["iat"] <= claims["exp"] - 60 + 1
    assert claims["exp"] - claims["iat"] == 60
    assert len(claims["jti"]) >= 16
    jwk = signer.public_jwk()
    assert jwk["kid"] == "k1" and jwk["alg"] == alg and jwk["use"] == "sig"
    assert "d" not in jwk
    assert verify(public_key_from_jwk(jwk), alg, signing_input, signature)


def test_every_assertion_has_a_new_jti() -> None:
    signer = ClientAssertionSigner.generate()
    jtis = {split_jws(signer.create(AGENT_ID, ISSUER))[1]["jti"] for _ in range(20)}
    assert len(jtis) == 20


def test_pem_round_trip_and_jwks() -> None:
    signer = ClientAssertionSigner.generate("ES256", key_id="k1")
    loaded = ClientAssertionSigner.from_pem(signer.to_pem(), key_id="k1")
    assert loaded.public_jwk() == signer.public_jwk()
    assert loaded.jwks() == {"keys": [signer.public_jwk()]}


def test_invalid_algorithm_lifetime_and_rsa_size_are_refused() -> None:
    from cryptography.hazmat.primitives.asymmetric import rsa

    with pytest.raises(LumoAuthValidationError):
        ClientAssertionSigner(ClientAssertionSigner.generate("ES256")._private_key, alg="ES384")
    with pytest.raises(LumoAuthValidationError):
        ClientAssertionSigner(ClientAssertionSigner.generate("ES256")._private_key, lifetime=601)
    with pytest.raises(LumoAuthValidationError):
        ClientAssertionSigner(rsa.generate_private_key(public_exponent=65537, key_size=1024))
    with pytest.raises(LumoAuthValidationError):
        ClientAssertionSigner.generate("HS256")


def test_issuer_for_matches_the_discovery_issuer_form() -> None:
    assert issuer_for(BASE + "/", ORG) == ISSUER


def test_agent_authenticates_with_an_assertion_and_no_secret(
    fake_session: FakeSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clear_env(monkeypatch)
    monkeypatch.setenv("AGENT_CLIENT_SECRET", "left-over-secret")
    signer = ClientAssertionSigner.generate("EdDSA", key_id="agent-key")
    agent = LumoAuthAgent(base_url=BASE, org_id=ORG, client_id=AGENT_ID, private_key=signer)
    fake_session.queue(FakeResponse(200, TOKEN_RESPONSE))

    assert agent.authenticate() is True

    method, url, kwargs = fake_session.last
    assert method == "POST" and url == f"{ISSUER}/oauth/token"
    data = kwargs["data"]
    assert data["grant_type"] == "client_credentials"
    assert data["client_id"] == AGENT_ID
    assert data["client_assertion_type"] == CLIENT_ASSERTION_TYPE
    assert "client_secret" not in data, "one authentication method per request"
    header, claims, signing_input, signature = split_jws(data["client_assertion"])
    assert header["kid"] == "agent-key"
    assert claims["aud"] == ISSUER
    assert verify(public_key_from_jwk(signer.public_jwk()), "EdDSA", signing_input, signature)
    assert agent.access_token == "at-1"


def test_agent_reads_a_pem_key_and_kid_from_the_environment(
    fake_session: FakeSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clear_env(monkeypatch)
    signer = ClientAssertionSigner.generate("ES256")
    monkeypatch.setenv("LUMOAUTH_URL", BASE)
    monkeypatch.setenv("LUMOAUTH_ORG_ID", ORG)
    monkeypatch.setenv("AGENT_CLIENT_ID", AGENT_ID)
    monkeypatch.setenv("AGENT_PRIVATE_KEY", signer.to_pem())
    monkeypatch.setenv("AGENT_KEY_ID", "env-key")

    agent = LumoAuthAgent()
    header = split_jws(agent.client_assertion())[0]

    assert header == {"alg": "ES256", "typ": "client-authentication+jwt", "kid": "env-key"}


def test_custom_issuer_is_the_audience(fake_session: FakeSession, monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_env(monkeypatch)
    agent = LumoAuthAgent(
        base_url="https://auth.acme.com", org_id=ORG, client_id=AGENT_ID,
        private_key=ClientAssertionSigner.generate(), issuer="https://auth.acme.com",
    )
    assert split_jws(agent.client_assertion())[1]["aud"] == "https://auth.acme.com"


def test_secret_and_private_key_together_are_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_env(monkeypatch)
    with pytest.raises(LumoAuthConfigError):
        LumoAuthAgent(base_url=BASE, org_id=ORG, client_id=AGENT_ID, client_secret="s", private_key=ClientAssertionSigner.generate())


def test_agent_without_secret_or_key_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_env(monkeypatch)
    with pytest.raises(LumoAuthConfigError):
        LumoAuthAgent(base_url=BASE, org_id=ORG, client_id=AGENT_ID)


def test_client_credentials_needs_exactly_one_method(fake_session: FakeSession) -> None:
    from lumoauth import LumoAuth

    client = LumoAuth(base_url=BASE, org_id=ORG)
    with pytest.raises(LumoAuthValidationError):
        client.auth.client_credentials(AGENT_ID)
    with pytest.raises(LumoAuthValidationError):
        client.auth.client_credentials(AGENT_ID, "secret", client_assertion="a.b.c")

    fake_session.queue(FakeResponse(200, TOKEN_RESPONSE))
    client.auth.client_credentials(AGENT_ID, client_assertion="a.b.c")
    assert json.loads(json.dumps(fake_session.last[2]["data"])) == {
        "grant_type": "client_credentials",
        "client_id": AGENT_ID,
        "client_assertion_type": CLIENT_ASSERTION_TYPE,
        "client_assertion": "a.b.c",
    }

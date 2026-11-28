"""Local verification of LumoAuth JIT tokens (``lumoauth.verify.verify_jit_token``).

The rules are the same as in lumoauth-fastmcp and @lumoauth/mcp.
"""

from __future__ import annotations

import json
import time
from typing import Any, Dict, Optional

import pytest

pytest.importorskip("cryptography", reason="JIT verification needs cryptography")

from cryptography.hazmat.primitives.asymmetric import ec, rsa  # noqa: E402

from lumoauth import JitTokenVerifier, verify_jit_token  # noqa: E402
from lumoauth._jose import b64url_encode, public_jwk, sign  # noqa: E402
from lumoauth.errors import LumoAuthConfigError, LumoAuthTokenError  # noqa: E402
from lumoauth.verify import AccessTokenClaims, org_id_from_issuer  # noqa: E402

ORG = "acme-corp"
ISSUER = f"https://app.lumoauth.dev/orgs/{ORG}/api/v1"
NOW = 1795802400.0
USER = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b"
AGENT = "agt_research-bot"

RSA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
EC_KEY = ec.generate_private_key(ec.SECP256R1())
JWKS = {
    "keys": [
        dict(public_jwk(RSA_KEY.public_key()), kid="acme-corp-rs256-1", use="sig", alg="RS256"),
        dict(public_jwk(EC_KEY.public_key()), kid="acme-corp-es256-1", use="sig"),
    ]
}
DETAILS = [{"type": "file_access", "actions": ["read"], "identifier": "report_2024.pdf"}]


def make_token(
    payload: Optional[Dict[str, Any]] = None,
    *,
    header: Optional[Dict[str, Any]] = None,
    key: Any = RSA_KEY,
    alg: str = "RS256",
    **changes: Any,
) -> str:
    """A JIT token in the shape that JwtService::generateJitToken issues."""
    body: Dict[str, Any] = payload or {
        "iss": ISSUER,
        "sub": USER,
        "aud": ORG,
        "iat": int(NOW),
        "nbf": int(NOW),
        "exp": int(NOW) + 600,
        "jti": "9e0c27d4",
        "jit": True,
        "permissions": {
            "agent_id": AGENT,
            "task_id": "task_abc",
            "jit_request_id": "req_1",
            "authorization_details": DETAILS,
            "act": {"sub": f"agent_{AGENT}"},
        },
        "task_id": "task_abc",
    }
    body.update(changes)
    head = header or {"typ": "JWT", "alg": alg, "kid": "acme-corp-rs256-1" if alg.startswith(("RS", "PS")) else "acme-corp-es256-1"}
    signing_input = f"{b64url_encode(json.dumps(head).encode())}.{b64url_encode(json.dumps(body).encode())}"
    return f"{signing_input}.{b64url_encode(sign(key, alg, signing_input.encode()))}"


def caller(sub: str = USER, actor: Optional[str] = f"agent_{AGENT}") -> AccessTokenClaims:
    return AccessTokenClaims(
        sub=sub, iss=ISSUER, aud=("https://api.example.com",), exp=int(NOW) + 600,
        scopes=(), is_agent=actor is None and sub.startswith("agent_"), capabilities=(),
        act={"sub": actor} if actor else None,
    )


def verify(token: str, **kwargs: Any):
    kwargs.setdefault("issuer", ISSUER)
    return verify_jit_token(token, jwks=JWKS, now=NOW, **kwargs)


# ── Accepted ──────────────────────────────────────────────────────────


def test_a_delegated_approval_is_accepted_for_its_caller():
    claims = verify(make_token(), caller=caller())
    assert claims.subject == USER and claims.agent_id == AGENT
    assert claims.authorization_details == tuple(DETAILS)
    assert (claims.task_id, claims.request_id, claims.jti, claims.exp) == ("task_abc", "req_1", "9e0c27d4", int(NOW) + 600)
    assert claims.covers("file_access", actions=["read"], identifier="report_2024.pdf")
    assert not claims.covers("file_access", actions=["delete"], identifier="report_2024.pdf")
    assert not claims.covers("file_access", actions=["read"], identifier="other.pdf")
    assert not claims.covers("payment")


def test_an_agents_own_approval_is_accepted_for_the_agent():
    token = make_token(sub=f"agent_{AGENT}", permissions={"agent_id": AGENT, "authorization_details": DETAILS})
    claims = verify(token, caller=caller(sub=f"agent_{AGENT}", actor=None))
    assert claims.subject == f"agent_{AGENT}"


@pytest.mark.parametrize("alg,key", [("RS256", RSA_KEY), ("PS256", RSA_KEY), ("ES256", EC_KEY)])
def test_allowed_algorithms(alg, key):
    jwks = {"keys": [dict(k) for k in JWKS["keys"]]}
    jwks["keys"][0].pop("alg")  # the RSA key serves RS256 and PS256 here
    token = make_token(key=key, alg=alg)
    assert verify_jit_token(token, issuer=ISSUER, jwks=jwks, now=NOW).agent_id == AGENT


def test_typ_any_case_audience_list_and_wildcards():
    token = make_token(header={"typ": "jwt", "alg": "RS256", "kid": "acme-corp-rs256-1"}, aud=["other", ORG])
    claims = verify(token)
    assert claims.subject == USER
    wide = make_token(permissions={"agent_id": AGENT, "authorization_details": [{"type": "*", "actions": ["*"], "identifier": "*"}]})
    assert verify(wide).covers("payment", actions=["approve"], identifier="INV-1")


def test_org_id_comes_from_the_issuer():
    assert org_id_from_issuer(ISSUER) == ORG
    assert org_id_from_issuer("https://auth.acme.com") is None
    assert JitTokenVerifier(ISSUER, jwks=JWKS).org_id == ORG


def test_custom_domain_needs_the_org_id():
    with pytest.raises(LumoAuthConfigError):
        JitTokenVerifier(custom_domain="auth.acme.com", jwks=JWKS)
    verifier = JitTokenVerifier(custom_domain="auth.acme.com", org_id=ORG, jwks=JWKS)
    token = make_token(iss="https://auth.acme.com")
    assert verifier.verify(token, now=NOW).agent_id == AGENT


# ── Refused ───────────────────────────────────────────────────────────


def _refused(token: str, code: str = "JIT_TOKEN_INVALID", **kwargs: Any) -> str:
    with pytest.raises(LumoAuthTokenError) as caught:
        verify(token, **kwargs)
    assert caught.value.code == code
    return caught.value.message


@pytest.mark.parametrize(
    "header",
    [
        {"typ": "at+jwt", "alg": "RS256", "kid": "acme-corp-rs256-1"},
        {"alg": "RS256", "kid": "acme-corp-rs256-1"},
        {"typ": "JWT", "alg": "HS256", "kid": "acme-corp-rs256-1"},
        {"typ": "JWT", "alg": "none", "kid": "acme-corp-rs256-1"},
        {"typ": "JWT", "alg": "RS256"},
    ],
)
def test_wrong_header_is_refused(header):
    _refused(make_token(header=header))


@pytest.mark.parametrize(
    "changes",
    [
        {"iss": "https://app.lumoauth.dev/orgs/other/api/v1"},
        {"aud": "other-org"},
        {"aud": "https://api.example.com"},
        {"jit": "true"},
        {"jit": False},
        {"exp": int(NOW) - 61},
        {"exp": "later"},
        {"nbf": int(NOW) + 3600},
        {"iat": int(NOW) + 3600},
        {"sub": ""},
        {"permissions": "file_access"},
        {"permissions": {"authorization_details": DETAILS}},
        {"permissions": {"agent_id": AGENT, "authorization_details": []}},
        {"permissions": {"agent_id": AGENT, "authorization_details": [{"actions": ["read"]}]}},
    ],
)
def test_wrong_claims_are_refused(changes):
    _refused(make_token(**changes))


def test_top_level_authorization_details_are_not_read():
    payload_without = make_token(
        permissions={"agent_id": AGENT}, authorization_details=DETAILS
    )
    _refused(payload_without)


def test_a_forged_signature_is_refused():
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    assert "signature" in _refused(make_token(key=other))


def test_an_unknown_kid_is_refused():
    _refused(make_token(header={"typ": "JWT", "alg": "RS256", "kid": "nope"}))


def test_the_key_must_fit_the_algorithm():
    # The RSA key is declared RS256: a PS256 token with it is refused.
    _refused(make_token(alg="PS256"))
    # An EC token that names the RSA key.
    _refused(make_token(key=EC_KEY, alg="ES256", header={"typ": "JWT", "alg": "ES256", "kid": "acme-corp-rs256-1"}))


def test_an_access_token_is_no_approval():
    access = make_token(header={"typ": "at+jwt", "alg": "RS256", "kid": "acme-corp-rs256-1"}, aud="https://api.example.com")
    _refused(access)


@pytest.mark.parametrize(
    "who",
    [
        caller(sub="someone-else"),  # another user
        caller(actor="agent_agt_other"),  # another agent for the same user
        caller(actor=None),  # the user's own token: no agent
        caller(sub=f"agent_{AGENT}", actor=None),  # the agent's own call with a delegated approval
    ],
)
def test_an_approval_of_another_caller_is_refused(who):
    _refused(make_token(), "JIT_TOKEN_NOT_FOR_CALLER", caller=who)


def test_an_agents_own_approval_is_refused_in_a_call_for_a_user():
    own = make_token(sub=f"agent_{AGENT}", permissions={"agent_id": AGENT, "authorization_details": DETAILS})
    _refused(own, "JIT_TOKEN_NOT_FOR_CALLER", caller=caller())


def test_a_bound_actor_must_be_the_caller_agent():
    token = make_token(permissions={"agent_id": AGENT, "authorization_details": DETAILS, "act": {"sub": "agent_agt_other"}})
    _refused(token, "JIT_TOKEN_NOT_FOR_CALLER", caller=caller())

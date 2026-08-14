"""Request shapes for the authz resources: permissions, zanzibar, abac."""

from __future__ import annotations

import pytest

from conftest import FakeResponse, FakeSession
from lumoauth import LumoAuth
from lumoauth.errors import LumoAuthConfigError, LumoAuthValidationError

BASE = "https://auth.example.com"
ORG = "acme-corp"


@pytest.fixture()
def client(fake_session: FakeSession) -> LumoAuth:
    return LumoAuth(base_url=BASE, org_id=ORG, api_key="lk_test")


# ── permissions ───────────────────────────────────────────────────────


def test_permissions_check(client, fake_session):
    fake_session.queue(FakeResponse(200, {"allowed": True, "permission": "document.edit"}))
    assert client.permissions.check("document.edit") is True

    method, url, kwargs = fake_session.last
    assert (method, url) == ("POST", f"{BASE}/api/v1/authz/check")
    assert kwargs["json"] == {"permission": "document.edit"}
    assert kwargs["headers"]["X-API-Key"] == "lk_test"


def test_permissions_check_with_context_and_user_id(client, fake_session):
    fake_session.queue(FakeResponse(200, {"allowed": False}))
    allowed = client.permissions.check(
        "document.edit", {"document_id": 456}, user_id="user-9"
    )
    assert allowed is False
    _, _, kwargs = fake_session.last
    assert kwargs["json"] == {
        "permission": "document.edit",
        "context": {"document_id": 456},
        "user_id": "user-9",
    }


def test_permissions_check_detailed_returns_full_dict(client, fake_session):
    payload = {"allowed": True, "permission": "p", "user_id": 1}
    fake_session.queue(FakeResponse(200, payload))
    assert client.permissions.check_detailed("p") == payload


def test_permissions_check_bulk(client, fake_session):
    payload = {"results": {"a": True, "b": False}, "user_id": 1}
    fake_session.queue(FakeResponse(200, payload))
    assert client.permissions.check_bulk(["a", "b"]) == payload

    method, url, kwargs = fake_session.last
    assert (method, url) == ("POST", f"{BASE}/api/v1/authz/check-bulk")
    assert kwargs["json"] == {"permissions": ["a", "b"]}


def test_permissions_check_any_and_all(client, fake_session):
    fake_session.queue(
        FakeResponse(200, {"allowed": True, "permissions": ["a", "b"]}),
        FakeResponse(200, {"allowed": False, "permissions": ["a", "b"]}),
    )
    assert client.permissions.check_any(["a", "b"]) is True
    assert client.permissions.check_all(["a", "b"]) is False

    any_call, all_call = fake_session.calls
    assert any_call[1] == f"{BASE}/api/v1/authz/check-any"
    assert all_call[1] == f"{BASE}/api/v1/authz/check-all"
    assert any_call[2]["json"] == {"permissions": ["a", "b"]}


def test_permissions_list_and_slugs(client, fake_session):
    payload = {
        "user_id": 1,
        "permissions": [
            {"slug": "document.edit", "description": None, "source": "role"},
            {"slug": "document.read", "description": None, "source": "role"},
        ],
        "count": 2,
    }
    fake_session.queue(FakeResponse(200, payload), FakeResponse(200, payload))
    assert client.permissions.list() == payload
    method, url, _ = fake_session.last
    assert (method, url) == ("GET", f"{BASE}/api/v1/authz/permissions")
    assert client.permissions.list_slugs() == {"document.edit", "document.read"}


def test_permissions_validation(client):
    with pytest.raises(LumoAuthValidationError):
        client.permissions.check("")
    with pytest.raises(LumoAuthValidationError):
        client.permissions.check_bulk([])


# ── zanzibar ──────────────────────────────────────────────────────────


def test_zanzibar_check(client, fake_session):
    fake_session.queue(FakeResponse(200, {"allowed": True, "object": "document:1",
                                          "relation": "viewer", "subject": "user:alice"}))
    assert client.zanzibar.check("document:1", "viewer", "user:alice") is True

    method, url, kwargs = fake_session.last
    assert (method, url) == ("POST", f"{BASE}/api/v1/authz/zanzibar/check")
    assert kwargs["json"] == {
        "object": "document:1",
        "relation": "viewer",
        "subject": "user:alice",
    }


def test_zanzibar_sugar_helpers(client, fake_session):
    for _ in range(5):
        fake_session.queue(FakeResponse(200, {"allowed": True}))
    assert client.zanzibar.is_viewer("doc:1", "user:a") is True
    assert client.zanzibar.is_editor("doc:1", "user:a") is True
    assert client.zanzibar.is_owner("doc:1", "user:a") is True
    assert client.zanzibar.is_member("team:eng", "user:a") is True
    assert client.zanzibar.is_admin("org:acme", "user:a") is True

    relations = [call[2]["json"]["relation"] for call in fake_session.calls]
    assert relations == ["viewer", "editor", "owner", "member", "admin"]


def test_zanzibar_validates_tuple_format(client):
    with pytest.raises(LumoAuthValidationError):
        client.zanzibar.check("not-namespaced", "viewer", "user:alice")
    with pytest.raises(LumoAuthValidationError):
        client.zanzibar.check("doc:1", "viewer", "alice")
    with pytest.raises(LumoAuthValidationError):
        client.zanzibar.check("doc:1", "", "user:alice")


# ── abac ──────────────────────────────────────────────────────────────


def test_abac_check_is_org_scoped_and_camel_cased(client, fake_session):
    decision = {"allowed": True, "reason": "Policy matched"}
    fake_session.queue(FakeResponse(200, decision))
    result = client.abac.check(
        "document", "read", "doc-123", context={"resource": {"classification": "internal"}}
    )
    assert result == decision

    method, url, kwargs = fake_session.last
    assert (method, url) == ("POST", f"{BASE}/orgs/{ORG}/api/v1/abac/check")
    assert kwargs["json"] == {
        "resourceType": "document",
        "action": "read",
        "resourceId": "doc-123",
        "context": {"resource": {"classification": "internal"}},
    }


def test_abac_is_allowed_shorthand(client, fake_session):
    fake_session.queue(FakeResponse(200, {"allowed": False, "reason": "no policy"}))
    assert client.abac.is_allowed("api", "execute") is False
    _, _, kwargs = fake_session.last
    assert kwargs["json"] == {"resourceType": "api", "action": "execute"}


def test_abac_check_bulk_translates_snake_case(client, fake_session):
    fake_session.queue(FakeResponse(200, {"results": []}))
    client.abac.check_bulk([
        {"resource_type": "document", "resource_id": "doc-1", "action": "read"},
        {"resourceType": "api", "action": "execute"},
    ])
    _, url, kwargs = fake_session.last
    assert url == f"{BASE}/orgs/{ORG}/api/v1/abac/check-bulk"
    assert kwargs["json"] == {
        "requests": [
            {"resourceType": "document", "resourceId": "doc-1", "action": "read"},
            {"resourceType": "api", "action": "execute"},
        ]
    }


def test_abac_attribute_endpoints(client, fake_session):
    fake_session.queue(
        FakeResponse(200, {"department": "engineering"}),
        FakeResponse(204, None, text=""),
        FakeResponse(200, {"classification": "confidential"}),
        FakeResponse(204, None, text=""),
        FakeResponse(200, [{"slug": "department", "dataType": "string"}]),
    )

    assert client.abac.get_my_attributes() == {"department": "engineering"}
    assert fake_session.calls[0][:2] == ("GET", f"{BASE}/orgs/{ORG}/api/v1/abac/my-attributes")

    client.abac.set_user_attribute("user-123", "department", "engineering")
    method, url, kwargs = fake_session.calls[1]
    assert (method, url) == (
        "PUT", f"{BASE}/orgs/{ORG}/api/v1/abac/users/user-123/attributes/department"
    )
    assert kwargs["json"] == {"value": "engineering"}

    client.abac.get_resource_attributes("document", "doc-123")
    assert fake_session.calls[2][:2] == (
        "GET", f"{BASE}/orgs/{ORG}/api/v1/abac/resources/document/doc-123/attributes"
    )

    client.abac.set_resource_attribute("document", "doc-123", "classification", "secret")
    method, url, kwargs = fake_session.calls[3]
    assert (method, url) == (
        "PUT",
        f"{BASE}/orgs/{ORG}/api/v1/abac/resources/document/doc-123/attributes/classification",
    )
    assert kwargs["json"] == {"value": "secret"}

    defs = client.abac.get_attribute_definitions("user")
    assert defs == [{"slug": "department", "dataType": "string"}]
    method, url, kwargs = fake_session.calls[4]
    assert (method, url) == ("GET", f"{BASE}/orgs/{ORG}/api/v1/abac/attribute-definitions")
    assert kwargs["params"] == {"type": "user"}


def test_abac_path_params_are_url_quoted(client, fake_session):
    fake_session.queue(FakeResponse(204, None, text=""))
    client.abac.set_user_attribute("user/../admin", "dept", "x")
    _, url, _ = fake_session.last
    assert "user%2F..%2Fadmin" in url


def test_abac_requires_org_id(fake_session, monkeypatch):
    monkeypatch.delenv("LUMOAUTH_ORG_ID", raising=False)
    client = LumoAuth(base_url=BASE, api_key="lk_test")  # no org_id
    with pytest.raises(LumoAuthConfigError):
        client.abac.check("document", "read")

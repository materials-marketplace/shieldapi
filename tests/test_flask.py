"""Tests for shieldapi Flask decorators."""

import pytest
from flask import Flask

from shieldapi.frameworks.flask import (
    admin_required,
    has_scope,
    login_required,
    role_required,
)

from .mock import MESSAGE, register_mock, register_mock_non_admin

app = Flask(__name__)


@app.get("/login")
@login_required
def login_view():
    return MESSAGE


@app.get("/admin")
@login_required
@admin_required
def admin_view():
    return MESSAGE


@app.get("/editor")
@login_required
@role_required("editor")
def editor_view():
    return MESSAGE


@app.get("/scoped")
@login_required
@has_scope(["profile"])
def scoped_view():
    return MESSAGE


@pytest.fixture
def client():
    return app.test_client()


def test_login_required_valid_token(client, requests_mock):
    register_mock(requests_mock)
    response = client.get("/login", headers={"Authorization": "Bearer 123"})
    assert response.status_code == 200
    assert response.json == MESSAGE


def test_login_required_no_token(client, requests_mock):
    register_mock(requests_mock)
    response = client.get("/login")
    assert response.status_code == 401


def test_login_required_invalid_token(client, requests_mock):
    """Inactive token must be rejected with 401."""
    register_mock(requests_mock)
    # Override introspect to return inactive
    import os

    realm = os.environ["KEYCLOAK_REALM_NAME"]
    host = os.environ["KEYCLOAK_HOST"]
    requests_mock.post(
        f"{host}realms/{realm}/protocol/openid-connect/token/introspect",
        json={"active": False},
    )
    response = client.get("/login", headers={"Authorization": "Bearer expired"})
    assert response.status_code == 401


def test_admin_required_with_admin_role(client, requests_mock):
    """Token with admin role in realm_access should pass."""
    register_mock(requests_mock)
    response = client.get("/admin", headers={"Authorization": "Bearer 123"})
    assert response.status_code == 200
    assert response.json == MESSAGE


def test_admin_required_without_admin_role(client, requests_mock):
    """Token without admin role should be rejected with 403."""
    register_mock_non_admin(requests_mock)
    response = client.get("/admin", headers={"Authorization": "Bearer 123"})
    assert response.status_code == 403


def test_admin_required_no_token(client, requests_mock):
    register_mock(requests_mock)
    response = client.get("/admin")
    assert response.status_code == 401


def test_role_required_with_matching_role(client, requests_mock):
    """Token with the required role (client-level) should pass."""
    import os

    register_mock(requests_mock)
    # The mock introspect grants resource_access.testshield.roles = ["admin", "user"]
    # but not "editor". Override to add editor.
    realm = os.environ["KEYCLOAK_REALM_NAME"]
    host = os.environ["KEYCLOAK_HOST"]
    requests_mock.post(
        f"{host}realms/{realm}/protocol/openid-connect/token/introspect",
        json={
            "active": True,
            "realm_access": {"roles": []},
            "resource_access": {"testshield": {"roles": ["editor"]}},
            "scope": "profile email",
        },
    )
    response = client.get("/editor", headers={"Authorization": "Bearer 123"})
    assert response.status_code == 200


def test_role_required_without_matching_role(client, requests_mock):
    """Token lacking the required role should be rejected with 403."""
    register_mock_non_admin(requests_mock)
    response = client.get("/editor", headers={"Authorization": "Bearer 123"})
    assert response.status_code == 403


def test_has_scope_with_scope_present(client, requests_mock):
    register_mock(requests_mock)
    response = client.get("/scoped", headers={"Authorization": "Bearer 123"})
    assert response.status_code == 200


def test_has_scope_missing_scope(client, requests_mock):
    """Token without required scope should be rejected with 403."""
    import os

    register_mock(requests_mock)
    realm = os.environ["KEYCLOAK_REALM_NAME"]
    host = os.environ["KEYCLOAK_HOST"]
    requests_mock.post(
        f"{host}realms/{realm}/protocol/openid-connect/token/introspect",
        json={"active": True, "scope": "email"},
    )
    response = client.get("/scoped", headers={"Authorization": "Bearer 123"})
    assert response.status_code == 403


def test_check_role_realm_access(requests_mock):
    """check_role finds roles in realm_access.roles."""
    from shieldapi.keycloak_utils import check_role

    register_mock(requests_mock)
    assert check_role("123", "admin") is True


def test_check_role_resource_access(requests_mock):
    """check_role finds roles in resource_access.<client>.roles."""
    import os

    from shieldapi.keycloak_utils import check_role

    register_mock(requests_mock)
    realm = os.environ["KEYCLOAK_REALM_NAME"]
    host = os.environ["KEYCLOAK_HOST"]
    requests_mock.post(
        f"{host}realms/{realm}/protocol/openid-connect/token/introspect",
        json={
            "active": True,
            "realm_access": {"roles": []},
            "resource_access": {"my-client": {"roles": ["superuser"]}},
        },
    )
    assert check_role("123", "superuser") is True


def test_check_role_flat_roles_field(requests_mock):
    """check_role also handles legacy flat roles field."""
    import os

    from shieldapi.keycloak_utils import check_role

    register_mock(requests_mock)
    realm = os.environ["KEYCLOAK_REALM_NAME"]
    host = os.environ["KEYCLOAK_HOST"]
    requests_mock.post(
        f"{host}realms/{realm}/protocol/openid-connect/token/introspect",
        json={"active": True, "roles": ["legacy-role"]},
    )
    assert check_role("123", "legacy-role") is True


def test_check_role_absent(requests_mock):
    """check_role returns False when the role is not present anywhere."""
    from shieldapi.keycloak_utils import check_role

    register_mock_non_admin(requests_mock)
    assert check_role("123", "admin") is False


def test_check_role_inactive_token(requests_mock):
    """check_role returns False for an inactive token."""
    import os

    from shieldapi.keycloak_utils import check_role

    register_mock(requests_mock)
    realm = os.environ["KEYCLOAK_REALM_NAME"]
    host = os.environ["KEYCLOAK_HOST"]
    requests_mock.post(
        f"{host}realms/{realm}/protocol/openid-connect/token/introspect",
        json={"active": False},
    )
    assert check_role("123", "admin") is False


def test_flask_keycloak_called_once(requests_mock):
    """Verify exactly one Keycloak call is made per request."""
    register_mock(requests_mock)
    client = app.test_client()
    client.get("/login", headers={"Authorization": "Bearer 123"})
    host_list = [resp.hostname for resp in requests_mock.request_history]
    assert host_list.count("example_keycloak.org") == 1

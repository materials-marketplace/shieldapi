"""Pytest fixtures for registering mock responses."""

import os

from requests_mock import Mocker

MESSAGE = {"message": "Hello World"}
VARIABLES = dict(
    KEYCLOAK_HOST="http://example_keycloak.org/auth/",
    KEYCLOAK_REALM_NAME="my_realm",
    KEYCLOAK_CLIENT_ID="testshield",
    KEYCLOAK_CLIENT_SECRET="123a",
    KEYCLOAK_REALM_ADMIN_USER="admin",
    KEYCLOAK_REALM_ADMIN_PASSWORD="passwd",
    KEYCLOAK_VERIFY_HOST="True",
)

# Realistic Keycloak introspect payload — roles live under realm_access and
# resource_access, not at the top level.
INTROSPECT_RESPONSE = dict(
    active=True,
    realm_access={"roles": ["default-roles-myrealm", "app-user", "admin"]},
    resource_access={
        "testshield": {"roles": ["admin", "user"]},
        "account": {"roles": ["manage-account", "view-profile"]},
        "shieldapi": {"roles": ["admin"]},
    },
    scope="profile email client_roles",
    preferred_username="admin",
    sub="test-user-id",
)

INTROSPECT_NON_ADMIN = dict(
    active=True,
    realm_access={"roles": ["default-roles-myrealm", "app-user"]},
    resource_access={
        "testshield": {"roles": ["user"]},
        "account": {"roles": ["manage-account", "view-profile"]},
    },
    scope="profile email client_roles",
    preferred_username="user1",
    sub="non-admin-user-id",
)

INTROSPECT_INACTIVE = dict(active=False)


def register_mock(requests_mock: Mocker, var: dict = VARIABLES) -> None:
    """Register mock HTTP responses for a Keycloak server.

    Args:
        requests_mock: requests_mock Mocker instance.
        var: Environment variable overrides (defaults to VARIABLES).
    """
    os.environ.update(**var)
    realm_name = var["KEYCLOAK_REALM_NAME"]
    responses = [
        dict(
            path=f"realms/{realm_name}/protocol/openid-connect/token",
            method="post",
            json=dict(
                access_token="123",
                expires_in=300,
                refresh_expires_in=1800,
                refresh_token="abc",
                token_type="Bearer",
                session_state=None,
                scope="profile email client_roles",
            ),
        ),
        dict(
            path=f"realms/{realm_name}/protocol/openid-connect/token/introspect",
            method="post",
            json=INTROSPECT_RESPONSE,
        ),
        dict(
            path=f"realms/{realm_name}/protocol/openid-connect/userinfo",
            method="post",
            json=dict(
                sub="test-user-id",
                email_verified=False,
                preferred_username="admin",
            ),
        ),
    ]
    for route in responses:
        path = var["KEYCLOAK_HOST"] + route["path"]
        requests_mock.register_uri(route["method"], path, json=route["json"])


def register_mock_inactive(requests_mock: Mocker, var: dict = VARIABLES) -> None:
    """Register mock that returns an inactive (expired) introspection result."""
    os.environ.update(**var)
    realm_name = var["KEYCLOAK_REALM_NAME"]
    path = (
        var["KEYCLOAK_HOST"]
        + f"realms/{realm_name}/protocol/openid-connect/token/introspect"
    )
    requests_mock.register_uri("post", path, json=INTROSPECT_INACTIVE)


def register_mock_non_admin(requests_mock: Mocker, var: dict = VARIABLES) -> None:
    """Register mock responses for a non-admin user."""
    os.environ.update(**var)
    realm_name = var["KEYCLOAK_REALM_NAME"]
    responses = [
        dict(
            path=f"realms/{realm_name}/protocol/openid-connect/token/introspect",
            method="post",
            json=INTROSPECT_NON_ADMIN,
        ),
        dict(
            path=f"realms/{realm_name}/protocol/openid-connect/userinfo",
            method="post",
            json=dict(
                sub="non-admin-user-id",
                email_verified=False,
                preferred_username="user1",
            ),
        ),
    ]
    for route in responses:
        path = var["KEYCLOAK_HOST"] + route["path"]
        requests_mock.register_uri(route["method"], path, json=route["json"])

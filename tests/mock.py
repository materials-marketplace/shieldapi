"""Pytest fixtures for regitering mock responses."""

import os

from requests_mock import Mocker

MESSAGE = {"message": "Hello World"}
VARIABLES = dict(
    KEYCLOAK_HOST="http://example_keycloak.org/auth/",
    KEYCLOAK_REALM_NAME="my_realm",
    KEYCLOAK_CLIENT_ID="testshield",
    KEYCLOAK_CLIENT_SECRET_KEY="123a",
    KEYCLOAK_REALM_ADMIN_USER="admin",
    KEYCLOAK_REALM_ADMIN_PASSWORD="passwd",
    KEYCLOAK_VERIFY_HOST="True",
)


def register_mock(requests_mock: Mocker, var: dict = VARIABLES) -> None:
    """
    Register mock HTTP responses for a Keycloak server using the requests_mock library.

    Args:
    - requests_mock: An instance of the Mocker class from the requests_mock library.
    - var: A dictionary containing environment variables used to configure the Keycloak server.
      It must contain the following keys:
      - KEYCLOAK_HOST: the URL of the Keycloak server (e.g., "http://example_keycloak.org/auth/").
      - KEYCLOAK_REALM_NAME: the name of the Keycloak realm to use.
      - KEYCLOAK_CLIENT_SECRET: the client secret for the Keycloak client.
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
            json=dict(
                active=True,
                roles=["admin"],
                scope="profile email client_roles",
            ),
        ),
        dict(
            path=f"realms/{realm_name}/protocol/openid-connect/userinfo",
            method="post",
            json=dict(
                sub="123",
                email_verified=False,
                roles=["admin"],
                preferred_username="admin",
            ),
        ),
    ]
    for route in responses:
        path = var["KEYCLOAK_HOST"] + route["path"]
        requests_mock.register_uri(route["method"], path, json=route["json"])

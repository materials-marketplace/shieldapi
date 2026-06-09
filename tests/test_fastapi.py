"""Pytest fixture for testing shieldapi in fastapi"""

import re

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from shieldapi.frameworks.fastapi import (
    AuthTokenBearer,
    OptionalAuthTokenBearer,
    depends_auth_token_bearer,
    get_optional_user_id,
    get_optional_user_roles,
    get_user_id,
    get_user_roles,
    is_admin,
    is_optional_admin,
    require_self_or_role,
)
from shieldapi.keycloak_utils import make_auth_header

from .mock import (
    MESSAGE,
    register_mock,
    register_mock_inactive,
    register_mock_non_admin,
)


@pytest.fixture(scope="function", params=["dependency", "helper"])
def make_dependency(requests_mock, request: pytest.FixtureRequest):
    if request.param == "dependency":
        return AuthTokenBearer()
    elif request.param == "helper":
        return depends_auth_token_bearer


@pytest.fixture(scope="function")
def fastapi_client(requests_mock, make_dependency):
    """
    Pytest fixture for receiving a test client
    """

    app = FastAPI(dependencies=[Depends(make_dependency)])

    @app.get("/login")
    def test_login():
        """
        Return an arbitrary message
        for testing the callback to the Keycloak-mock."""
        return MESSAGE

    with TestClient(app) as testclient:
        yield testclient


@pytest.fixture
def client(fastapi_client, requests_mock):
    """
    In fastapi < 0.92.0, the testclient directly uses requests.
    Since the keycloak-mock is overwriting the requests-module for the time of
    the pytest, we have to tell the mock that it should use 'requests' as usual
    for the route for which we would like to test the login (see @app.get('/login')).
    We are stating this by calling 'register_mock' with the method of the route, the
    regex of the testclient-baseurl and setting 'real_http'=True.
    !This is also why the testclient also appears in the 'request_history' of the mock!
    """
    from fastapi import __version__
    from semver import VersionInfo

    register_mock(requests_mock)
    current_version = VersionInfo.parse(__version__)
    min_version = VersionInfo.parse("0.92.0")
    if VersionInfo.compare(current_version, min_version) == -1:
        base_url = re.escape(str(fastapi_client.base_url))
        base_url_re = re.compile(rf"{base_url}(/.*)?")
        requests_mock.register_uri("get", base_url_re, real_http=True)
    return fastapi_client


def test_fastapi(client, requests_mock):
    """
    Pytest for access token validation through Keycloak-mock.
    """
    headers = {"Authorization": "Bearer 123"}
    response = client.get("login", headers=headers)  # calls keycloak-mock
    host_list = [resp.hostname for resp in requests_mock.request_history]
    assert host_list.count("example_keycloak.org") == 1  # called 1x keycloak-mock
    assert response.json() == MESSAGE


def test_fastapi_login(client, requests_mock):
    """
    Test login function for receiving access token from Keycloak-mock.
    """
    header = make_auth_header("foo", "bar")  # calls keycloak-mock
    assert type(header) == dict
    assert header.get("Authorization") == "Bearer 123"
    response = client.get("login", headers=header)  # calls keycloak-mock
    host_list = [resp.hostname for resp in requests_mock.request_history]
    assert host_list.count("example_keycloak.org") == 2  # called 2x keycloak-mock
    assert response.json() == MESSAGE


def _make_self_or_role_app():
    app = FastAPI()

    @app.get("/users/{user_id}")
    def get_user(user_id: str, token: str = Depends(require_self_or_role("admin"))):
        return {"user_id": user_id}

    return app


def test_require_self_or_role_admin_access(requests_mock):
    """Admin role grants access regardless of user_id path param."""
    register_mock(requests_mock)
    with TestClient(_make_self_or_role_app()) as client:
        # INTROSPECT_RESPONSE has admin role and sub="test-user-id"
        response = client.get(
            "/users/other-user", headers={"Authorization": "Bearer 123"}
        )
    assert response.status_code == 200
    assert response.json() == {"user_id": "other-user"}


def test_require_self_or_role_self_access(requests_mock):
    """Non-admin user can access a path whose user_id matches their own sub."""
    register_mock_non_admin(requests_mock)
    with TestClient(_make_self_or_role_app()) as client:
        # INTROSPECT_NON_ADMIN has no admin role and sub="non-admin-user-id"
        response = client.get(
            "/users/non-admin-user-id", headers={"Authorization": "Bearer 123"}
        )
    assert response.status_code == 200
    assert response.json() == {"user_id": "non-admin-user-id"}


def test_require_self_or_role_forbidden(requests_mock):
    """Non-admin user is blocked when user_id path param does not match their sub."""
    register_mock_non_admin(requests_mock)
    with TestClient(_make_self_or_role_app()) as client:
        response = client.get(
            "/users/other-user", headers={"Authorization": "Bearer 123"}
        )
    assert response.status_code == 403


# ---------------------------------------------------------------------------
# OptionalAuthTokenBearer
# ---------------------------------------------------------------------------


def _make_optional_bearer_app():
    optional = OptionalAuthTokenBearer()

    app = FastAPI()

    @app.get("/resource")
    async def resource(token=Depends(optional)):
        return {"anonymous": token is None}

    return app


def test_optional_bearer_no_token(requests_mock):
    """No Authorization header returns None from the dependency (anonymous access)."""
    register_mock(requests_mock)
    with TestClient(_make_optional_bearer_app()) as client:
        response = client.get("/resource")
    assert response.status_code == 200
    assert response.json() == {"anonymous": True}


def test_optional_bearer_valid_token(requests_mock):
    """Valid Bearer token passes through; the dependency returns a non-None value."""
    register_mock(requests_mock)
    with TestClient(_make_optional_bearer_app()) as client:
        response = client.get("/resource", headers={"Authorization": "Bearer 123"})
    assert response.status_code == 200
    assert response.json() == {"anonymous": False}


def test_optional_bearer_invalid_token(requests_mock):
    """Inactive/expired token raises HTTP 401 even for the optional bearer."""
    register_mock_inactive(requests_mock)
    with TestClient(
        _make_optional_bearer_app(), raise_server_exceptions=False
    ) as client:
        response = client.get("/resource", headers={"Authorization": "Bearer expired"})
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# Generic dependency chain
# ---------------------------------------------------------------------------


def _make_dep_chain_app():
    app = FastAPI()

    @app.get("/whoami")
    def whoami(
        user_id=Depends(get_user_id),
        roles=Depends(get_user_roles),
        admin=Depends(is_admin),
    ):
        return {"user_id": user_id, "roles": roles, "admin": admin}

    @app.get("/optional")
    def optional_whoami(
        user_id=Depends(get_optional_user_id),
        roles=Depends(get_optional_user_roles),
        admin=Depends(is_optional_admin),
    ):
        return {"user_id": user_id, "roles": roles, "admin": admin}

    return app


def test_dep_chain_authenticated(requests_mock):
    """Authenticated request resolves correct user_id, shieldapi roles, and admin flag."""
    register_mock(requests_mock)
    with TestClient(_make_dep_chain_app()) as client:
        response = client.get("/whoami", headers={"Authorization": "Bearer 123"})
    assert response.status_code == 200
    data = response.json()
    assert data["user_id"] == "test-user-id"
    assert "admin" in data["roles"]
    assert data["admin"] is True


def test_dep_chain_optional_anonymous(requests_mock):
    """Anonymous request yields None user_id, empty roles, and admin=False."""
    register_mock(requests_mock)
    with TestClient(_make_dep_chain_app()) as client:
        response = client.get("/optional")
    assert response.status_code == 200
    data = response.json()
    assert data["user_id"] is None
    assert data["roles"] == []
    assert data["admin"] is False


def test_dep_chain_optional_authenticated(requests_mock):
    """Optional endpoints resolve identically to required ones for authenticated users."""
    register_mock(requests_mock)
    with TestClient(_make_dep_chain_app()) as client:
        response = client.get("/optional", headers={"Authorization": "Bearer 123"})
    assert response.status_code == 200
    data = response.json()
    assert data["user_id"] == "test-user-id"
    assert data["admin"] is True

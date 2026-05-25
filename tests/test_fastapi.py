"""Pytest fixture for testing shieldapi in fastapi"""

import re

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from shieldapi.frameworks.fastapi import AuthTokenBearer, depends_auth_token_bearer
from shieldapi.keycloak_utils import make_auth_header

from .mock import MESSAGE, register_mock


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

"""Pytest fixture for testing shieldapi in flask"""

from flask import Flask

from shieldapi.frameworks.flask import login_required

from .mock import MESSAGE, register_mock

app = Flask(__name__)


@app.get("/login")
@login_required
def login():
    """Arbitrary login route"""
    return MESSAGE


def test_flask(mock_introspect, requests_mock):
    """Pytest for token verification through Keycloak-mock."""
    register_mock(requests_mock)
    client = app.test_client()
    headers = {"Authorization": "Bearer 123"}
    response = client.get("login", headers=headers)  # calls keycloak-mock
    host_list = [resp.hostname for resp in requests_mock.request_history]
    assert host_list.count("example_keycloak.org") == 1  # called 1x keycloak-mock
    assert response.json == MESSAGE

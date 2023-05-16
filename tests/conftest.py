import pytest


def _mock_active_token(token_info: dict) -> bool:
    """Make a mock for checking if token is active."""
    return bool(token_info["active"])


@pytest.fixture(scope="function")
def mock_introspect(mocker):
    """Make a mock for checking if token is active."""
    import shieldapi.keycloak_utils as utils

    mocker_intro = mocker.MagicMock()
    with mocker.patch.object(utils, "_check_active_token", mocker_intro):
        mocker_intro.side_effect = _mock_active_token
        yield mocker_intro

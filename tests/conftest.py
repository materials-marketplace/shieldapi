import pytest


def _mock_active_token(token_info: dict) -> bool:
    """Make a mock for checking if token is active."""
    return bool(token_info["active"])


@pytest.fixture(scope="function")
def mock_introspect(mocker):
    """Make a mock for checking if token is active."""
    mocker_intro = mocker.MagicMock()
    mocker_intro.side_effect = _mock_active_token
    yield mocker_intro

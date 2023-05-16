"""Pytest for `keycloak_utils` of the shieldapi package."""
import os
import warnings
from ast import literal_eval
from typing import Any, Dict, List, Optional

import pytest

from shieldapi.keycloak_utils import _get_value, get_keycloak_admin, get_keycloak_openid

from .mock import register_mock


def warning_raised(
    func: callable,
    match: str,
    args: List[Any] = [],
    kwargs: Dict[str, Any] = {},
    expected: Optional[Any] = None,
) -> None:
    with warnings.catch_warnings(record=True) as w:
        if expected is not None:
            assert func(*args, **kwargs) == expected
        else:
            func(*args, **kwargs)
        assert len(w) == 1
        warning = w.pop()
        assert issubclass(warning.category, UserWarning)
        assert match in str(warning.message)


def no_warning_raised(
    func: callable,
    args: List[Any] = [],
    kwargs: Dict[str, Any] = {},
    expected: Optional[Any] = None,
) -> None:
    with warnings.catch_warnings(record=True) as w:
        if expected is not None:
            assert func(*args, **kwargs) == expected
        else:
            func(*args, **kwargs)
        assert len(w) == 0


@pytest.mark.parametrize("var", [1, "a", 0.1, True, False, None])
@pytest.mark.parametrize("env_var", ["True", "False", None])
def test__get_value_bool(var, env_var, requests_mock):
    """Pytest for `_get_value` with a <bool> as Python-object."""
    register_mock(requests_mock)
    key = "KEYCLOAK_REALM_NAME"
    if env_var:
        os.environ[key] = env_var
    else:
        os.environ.pop(key)
    if var is None and env_var is None:
        match = f"Both the kwarg and the env-variable for '{key}' are None."
        with pytest.raises(ValueError, match=match):
            no_warning_raised(_get_value, args=(var, key), expected=var)
    elif isinstance(var, bool) and env_var or (var and env_var):
        match = f"Both the kwarg ({var}) and the env-variable for '{key}' ({env_var}) are assigned."
        warning_raised(_get_value, match, args=(var, key), expected=var)


@pytest.mark.parametrize("func", [get_keycloak_openid, get_keycloak_admin])
def test_keycloak_warning(func, requests_mock):
    """Pytest for `get_keycloak_openid` and `get_keycloak_admin` with
    both not None-typed values."""
    match = f"Both the kwarg (http://example_keycloak.org/auth/) and the env-variable for 'KEYCLOAK_HOST'"
    register_mock(requests_mock)
    warning_raised(
        func, match, kwargs={"server_url": "http://example_keycloak.org/auth/"}
    )


@pytest.mark.parametrize("func", [get_keycloak_openid, get_keycloak_admin])
def test_keycloak_valueerror(func, requests_mock):
    """Pytest for `get_keycloak_openid` and `get_keycloak_admin` with
    both None-typed values."""
    register_mock(requests_mock)
    match = "Both the kwarg and the env-variable for 'KEYCLOAK_REALM_NAME'"
    os.environ.pop("KEYCLOAK_REALM_NAME")
    with pytest.raises(ValueError, match=match):
        no_warning_raised(func)


@pytest.mark.parametrize("var", [True, False, None])
@pytest.mark.parametrize(
    "test_input", ["3+5", "0.1", "0.0.1", "true", "foo", "[0,0]", "(0,0)", "{'a': 'b'}"]
)
@pytest.mark.parametrize("func", [get_keycloak_openid, get_keycloak_admin])
def test_keycloak_typeerror_bool(var, test_input, func, requests_mock):
    """Pytest for `get_keycloak_openid` and `get_keycloak_admin` with
    `KEYCLOAK_VERIFY_HOST`."""
    register_mock(requests_mock)
    os.environ["KEYCLOAK_VERIFY_HOST"] = test_input
    match = "Env-variable 'KEYCLOAK_VERIFY_HOST' valued"
    if not isinstance(var, bool):
        with pytest.raises(TypeError, match=match):
            no_warning_raised(func)
    else:
        match = f"Both the kwarg ({var}) and the env-variable for 'KEYCLOAK_VERIFY_HOST' ({test_input}) are assigned."
        warning_raised(func, match, kwargs={"verify": var})


@pytest.mark.parametrize("var", [True, False, None])
@pytest.mark.parametrize("env_var", ["True", "False", None])
@pytest.mark.parametrize("func", [get_keycloak_openid, get_keycloak_admin])
def test_keycloak_warning_bool(var, env_var, func, requests_mock):
    """Pytest for `get_keycloak_openid` and `get_keycloak_admin` with
    `KEYCLOAK_VERIFY_HOST`."""
    register_mock(requests_mock)
    if env_var:
        os.environ["KEYCLOAK_VERIFY_HOST"] = env_var
    else:
        os.environ.pop("KEYCLOAK_VERIFY_HOST")

    if isinstance(var, bool) and env_var:
        match = f"Both the kwarg ({var}) and the env-variable for 'KEYCLOAK_VERIFY_HOST' ({env_var}) are assigned."
        warning_raised(func, match, kwargs={"verify": var})
    elif var is None and env_var is None:
        match = (
            "Both the kwarg and the env-variable for 'KEYCLOAK_VERIFY_HOST' are None."
        )
        with pytest.raises(ValueError, match=match):
            no_warning_raised(func, kwargs={"verify": var})
    else:
        no_warning_raised(func, kwargs={"verify": var})

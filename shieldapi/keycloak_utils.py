"""Functions for interacting with a Keycloak-client."""

import os
import warnings
from ast import literal_eval
from typing import Any, Optional, Tuple, Union

from keycloak import KeycloakAdmin, KeycloakOpenID


def get_keycloak_openid(
    server_url: Optional[str] = None,
    realm_name: Optional[str] = None,
    client_id: Optional[str] = None,
    client_secret_key: Optional[str] = None,
    verify: Optional[bool] = None,
) -> KeycloakOpenID:
    """
    Creates a KeycloakOpenID instance using the provided parameters or environment variables.

    Kwargs:
        server_url (Optional[str]):
            The URL of the Keycloak server. If not provided, the value from the environment variable
            KEYCLOAK_HOST will be used.
        realm_name (Optional[str]):
            The name of the realm in Keycloak. If not provided, the value from the environment variable
            KEYCLOAK_REALM_NAME will be used.
        client_id (Optional[str]):
            The id of the client in Keycloak. If not provided, the value from the environment
            variable KEYCLOAK_CLIENT_ID will be used.
        client_secret_key (Optional[str]):
            The client secret key for the client in Keycloak. If not provided, the value from the environment
            variable KEYCLOAK_CLIENT_SECRET_KEY will be used.
        verify (Optional[bool]):
            Controls whether SSL certificates are verified for HTTPS requests. If set to False, SSL
            verification is disabled. If set to a string, it should be the path to a CA_BUNDLE file or
            a directory containing certificates of trusted CA.

    Returns:
        KeycloakOpenID: An object for communicating with Keycloak via OpenID Connect.

    Raises:
        KeyError: If any required environment variables are missing.
    """

    return KeycloakOpenID(
        server_url=_get_value(server_url, "KEYCLOAK_HOST"),
        realm_name=_get_value(realm_name, "KEYCLOAK_REALM_NAME"),
        client_id=_get_value(client_id, "KEYCLOAK_CLIENT_ID"),
        client_secret_key=_get_value(client_secret_key, "KEYCLOAK_CLIENT_SECRET_KEY"),
        verify=_eval_bool(verify, "KEYCLOAK_VERIFY_HOST"),
    )


def get_keycloak_admin(
    server_url: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    realm_name: Optional[str] = None,
    verify: Optional[bool] = None,
) -> KeycloakAdmin:
    """Create and return a KeycloakAdmin object with the provided credentials.

    Kwargs:
        server_url (Optional[str]):
            The URL of the Keycloak server. If not provided, the value from the environment variable
            KEYCLOAK_HOST will be used.
        username (Optional[str]):
            The username to log in with. If not provided, the value from the environment variable
            KEYCLOAK_REALM_ADMIN_USER will be used.
        password (Optional[str]):
            The password to log in with. If not provided, the value from the environment variable
            KEYCLOAK_REALM_ADMIN_PASSWORD will be used.
        realm_name (Optional[str]):
            The name of the realm in Keycloak. If not provided, the value from the environment variable
            KEYCLOAK_REALM_NAME will be used.
        verify (Optional[bool]):
            Controls whether SSL certificates are verified for HTTPS requests. If set to False, SSL
            verification is disabled. If set to a string, it should be the path to a CA_BUNDLE file or
            a directory containing certificates of trusted CA.

    Returns:
        KeycloakAdmin:
            An object with the provided credentials.

    Raises:
        KeyError:
            If any required environment variables are missing.
    """
    return KeycloakAdmin(
        server_url=_get_value(server_url, "KEYCLOAK_HOST"),
        username=_get_value(username, "KEYCLOAK_REALM_ADMIN_USER"),
        password=_get_value(password, "KEYCLOAK_REALM_ADMIN_PASSWORD"),
        realm_name=_get_value(realm_name, "KEYCLOAK_REALM_NAME"),
        verify=_eval_bool(verify, "KEYCLOAK_VERIFY_HOST"),
    )


def _get_value(var: Any, env_var: str) -> Any:
    """Check if both, a Python-object and the corresponding
    env-variable are `None` or not. If both not `None`, a warning
    is raised. If the Python-object is `None`, it returns the
    value of the env-variable, even if it is `None`. If the Python-object
    is an instance of type <bool>, the env-variable will be neglected,
    even if not `None`.

    Args:
        var (Any):
            Python-object passed to the respective upstream function.
        env_var (str):
            Name of the corresponding environmental variable.
    Returns:
        Any: The value of the Python-object (preferred) or its respective env-variable.
        The latter can also resolve into a `None`, if not set.

    Raises:
       UserWarning: If both variables are not `None`.

       ValueError: If both variables are `None` or if the Python-object is `False`
       and env-variable not `None`.
    """
    env = os.environ.get(env_var)
    if var and env:
        message = f"""Both the kwarg and the env-variable for `{env_var}` are assigned.
        Note that the argument takes precedence over the env-variable."""
        warnings.warn(UserWarning(message))
    elif isinstance(var, bool) and env:
        message = f"""Both the kwarg and the env-variable for `{env_var}` are assigned.
        The kwarg is of type `bool` and valued `{var}` whereas the env-variable is set
        to `{env}`. Note that the argument takes precedence over the env-variable."""
        warnings.warn(UserWarning(message))
    elif var is None and env is None:
        message = f"""Both the kwarg and the env-variable for `{env_var}` are `None`.
        Please assign one of them to a value."""
        raise ValueError(message)
    if isinstance(var, bool):
        return var
    else:
        return var or env


def _eval_bool(var: Any, env_var: str) -> Optional[bool]:
    """Execute the `_get_value`-helper function and evaluate if
    the value of the environment variable is a string matching to a bool.

    Args:
        var (Any):
            Python-object passed to the respective upstream function.
        env_var (str):
            Name of the corresponding environmental variable.
    Returns:
        Optional[bool]:
            The evaluated value of the environment variable as a boolean, or None
            if the environment variable does not exist.
    Raises:
        TypeError: If the value of the environmental variable cannot be evaluated or it
        can be evaluated but is not an instance of <bool>.
    """
    boolean = _get_value(var, env_var)
    if isinstance(boolean, str):
        try:
            value = literal_eval(boolean)
            assert isinstance(value, bool)
            return value
        except (ValueError, AssertionError, SyntaxError):
            message = f"""Env-variable `{env_var}` valued `{boolean}` is not a boolean.
            Must be valued `True` or `False`."""
            raise TypeError(message)
    elif isinstance(boolean, bool):
        return boolean


def check_token_validity(
    access_token: str,
    server_url: Optional[str] = None,
    realm_name: Optional[str] = None,
    client_id: Optional[str] = None,
    client_secret_key: Optional[str] = None,
    verify: Optional[bool] = None,
) -> str:
    """Check if the given access token is valid.

    Args:
        access_token: str
            The access token to check.
    Kwargs:
        server_url (Optional[str]):
            The URL of the Keycloak server. If not provided, the value from the environment variable
            KEYCLOAK_HOST will be used.
        realm_name (Optional[str]):
            The name of the realm in Keycloak. If not provided, the value from the environment variable
            KEYCLOAK_REALM_NAME will be used.
        client_id (Optional[str]):
            The id of the client in Keycloak. If not provided, the value from the environment
            variable KEYCLOAK_CLIENT_ID will be used.
        client_secret_key (Optional[str]):
            The client secret key for the client in Keycloak. If not provided, the value from the environment
            variable KEYCLOAK_CLIENT_SECRET_KEY will be used.
        verify (Optional[bool]):
            Controls whether SSL certificates are verified for HTTPS requests. If set to False, SSL
            verification is disabled. If set to a string, it should be the path to a CA_BUNDLE file or
            a directory containing certificates of trusted CA.

    Returns:
        str: If the token is valid, returns the string "valid". Otherwise, returns the string "Invalid Token".
    """
    token_info = get_keycloak_openid(
        server_url, realm_name, client_id, client_secret_key, verify
    ).introspect(access_token)

    if not token_info.json()["active"]:
        return "Invalid Token"
    return "valid"


def check_useraccount_access(
    access_token: str,
    server_url: Optional[str] = None,
    realm_name: Optional[str] = None,
    client_id: Optional[str] = None,
    client_secret_key: Optional[str] = None,
    verify: Optional[bool] = None,
) -> str:
    """
    Check if an access token has the 'openid' scope.

    Args:
        access_token: str
            The access token to check.
    Kwargs:
        server_url (Optional[str]):
            The URL of the Keycloak server. If not provided, the value from the environment variable
            KEYCLOAK_HOST will be used.
        realm_name (Optional[str]):
            The name of the realm in Keycloak. If not provided, the value from the environment variable
            KEYCLOAK_REALM_NAME will be used.
        client_id (Optional[str]):
            The id of the client in Keycloak. If not provided, the value from the environment
            variable KEYCLOAK_CLIENT_ID will be used.
        client_secret_key (Optional[str]):
            The client secret key for the client in Keycloak. If not provided, the value from the environment
            variable KEYCLOAK_CLIENT_SECRET_KEY will be used.
        verify (Optional[bool]):
            Controls whether SSL certificates are verified for HTTPS requests. If set to False, SSL
            verification is disabled. If set to a string, it should be the path to a CA_BUNDLE file or
            a directory containing certificates of trusted CA.

    Returns:
        str: A string indicating whether or not the access token has the 'openid' scope.
    """
    token_info = get_keycloak_openid(
        server_url, realm_name, client_id, client_secret_key, verify
    ).introspect(access_token)
    granted_scope = token_info.json()["scope"].split()
    if "openid" not in granted_scope:
        return "openid scope not granted!", 401
    return "Has access!", 200


def login(
    username: str,
    password: str,
    server_url: Optional[str] = None,
    realm_name: Optional[str] = None,
    client_id: Optional[str] = None,
    client_secret_key: Optional[str] = None,
    verify: Optional[bool] = None,
) -> str:
    """
    Logs in the user with the given username and password and generates an access token.

    Args:
        username (Optional[str]):
            The username to authenticate with.
        password (Optional[str]):
            The password to authenticate with.
    Kwargs:
        server_url (Optional[str]):
            The URL of the Keycloak server. If not provided, the value from the environment variable
            KEYCLOAK_HOST will be used.
        realm_name (Optional[str]):
            The name of the realm in Keycloak. If not provided, the value from the environment variable
            KEYCLOAK_REALM_NAME will be used.
        client_id (Optional[str]):
            The id of the client in Keycloak. If not provided, the value from the environment
            variable KEYCLOAK_CLIENT_ID will be used.
        client_secret_key (Optional[str]):
            The client secret key for the client in Keycloak. If not provided, the value from the environment
            variable KEYCLOAK_CLIENT_SECRET_KEY will be used.
        verify (Optional[Union[bool, str]]):
            Controls whether SSL certificates are verified for HTTPS requests. If set to False, SSL
            verification is disabled. If set to a string, it should be the path to a CA_BUNDLE file or
            a directory containing certificates of trusted CA.

    Returns:
        str:
            If successful, returns a string representing the access token. Otherwise, returns
            a tuple containing the status code and an error message.
    """
    token = get_keycloak_openid(
        server_url, realm_name, client_id, client_secret_key, verify
    ).token(username=username, password=password)
    if not token.get("access_token") and token.get("token_type"):
        return 401, "Token could not be generated. Please contact the admin."
    else:
        return f"{token.get('token_type')} {token.get('access_token')}"


def make_auth_header(
    username: str,
    password: str,
    server_url: Optional[str] = None,
    realm_name: Optional[str] = None,
    client_id: Optional[str] = None,
    client_secret_key: Optional[str] = None,
    verify: Optional[bool] = None,
) -> Union[int, Tuple[int, str]]:
    """
    Logs into the Keycloak server and generates an access token using the given credentials.

    Args:
        username (Optional[str]):
            The username to authenticate with.
        password (Optional[str]):
            The password to authenticate with.
    Kwargs:
        server_url (Optional[str]):
            The URL of the Keycloak server. If not provided, the value from the environment variable
            KEYCLOAK_HOST will be used.
        realm_name (Optional[str]):
            The name of the realm in Keycloak. If not provided, the value from the environment variable
            KEYCLOAK_REALM_NAME will be used.
        client_id (Optional[str]):
            The id of the client in Keycloak. If not provided, the value from the environment
            variable KEYCLOAK_CLIENT_ID will be used.
        client_secret_key (Optional[str]):
            The client secret key for the client in Keycloak. If not provided, the value from the environment
            variable KEYCLOAK_CLIENT_SECRET_KEY will be used.
        verify (Optional[bool]):
            Controls whether SSL certificates are verified for HTTPS requests. If set to False, SSL
            verification is disabled. If set to a string, it should be the path to a CA_BUNDLE file or
            a directory containing certificates of trusted CA.

    Returns:
        Union[int, Tuple[int, str]]:
            If successful, a string containing the access token in the form of "{token_type} {access_token}".
            Otherwise, a tuple containing a status code and an error message.

    """
    credentials = login(
        username, password, server_url, realm_name, client_id, client_secret_key, verify
    )
    if type(credentials) == str:
        return {"Authorization": credentials}
    else:
        return credentials

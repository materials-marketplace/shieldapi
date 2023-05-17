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
    client_secret: Optional[str] = None,
    verify: Optional[bool] = None,
) -> KeycloakOpenID:
    """
    Creates a KeycloakOpenID instance using the provided parameters or environment variables.

    Kwargs:
        server_url (Optional[str]):
            The URL of the Keycloak server. If missing, $KEYCLOAK_HOST  or 'http://keycloak:8080/auth/' will be used.
        realm_name (Optional[str]):
            The name of the realm in Keycloak. If missing, $KEYCLOAK_REALM_NAME will be used.
        client_id (Optional[str]):
            The id of the client in Keycloak. If missing, $KEYCLOAK_CLIENT_ID or 'shieldapi' will be used.
        client_secret (Optional[str]):
            The client secret key for the client in Keycloak. If missing, $KEYCLOAK_CLIENT_SECRET will be used.
        verify (Optional[bool]):
            Controls whether SSL certificates are verified for HTTPS requests. If set to False, SSL
            verification is disabled. If set to a string, it should be the path to a CA_BUNDLE file or
            a directory containing certificates of trusted CA.

    Returns:
        KeycloakOpenID: An object for communicating with Keycloak via OpenID Connect.

    Raises:
        KeyError: If any required values are missing.
    """

    return KeycloakOpenID(
        server_url=_get_value(
            server_url, "KEYCLOAK_HOST", "http://keycloak:8080/auth/"
        ),
        realm_name=_get_value(realm_name, "KEYCLOAK_REALM_NAME"),
        client_id=_get_value(client_id, "KEYCLOAK_CLIENT_ID", "shieldapi"),
        client_secret_key=_get_value(client_secret, "KEYCLOAK_CLIENT_SECRET"),
        verify=_get_value(verify, "KEYCLOAK_VERIFY_HOST", True, True),
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
            The URL of the Keycloak server. If missing, $KEYCLOAK_HOST or 'http://keycloak:8080/auth/' will be used.
        username (Optional[str]):
            The username to log in with. If missing, $KEYCLOAK_REALM_ADMIN_USER will be used.
        password (Optional[str]):
            The password to log in with. If missing, $KEYCLOAK_REALM_ADMIN_PASSWORD will be used.
        realm_name (Optional[str]):
            The name of the realm in Keycloak. If missing, $KEYCLOAK_REALM_NAME will be used.
        verify (Optional[bool]):
            Controls whether SSL certificates are verified for HTTPS requests. If set to False, SSL
            verification is disabled. If set to a string, it should be the path to a CA_BUNDLE file or
            a directory containing certificates of trusted CA.

    Returns:
        KeycloakAdmin:
            An object with the provided credentials.

    Raises:
        KeyError:
            If any required values are missing.
    """
    return KeycloakAdmin(
        server_url=_get_value(
            server_url, "KEYCLOAK_HOST", "http://keycloak:8080/auth/"
        ),
        username=_get_value(username, "KEYCLOAK_REALM_ADMIN_USER"),
        password=_get_value(password, "KEYCLOAK_REALM_ADMIN_PASSWORD"),
        realm_name=_get_value(realm_name, "KEYCLOAK_REALM_NAME"),
        verify=_get_value(verify, "KEYCLOAK_VERIFY_HOST", True, True),
    )


def _get_value(
    param: Any,
    env_var: str,
    default: Optional[Any] = None,
    boolean: Optional[bool] = False,
) -> Any:
    """Get a value by following the assignment priority.

    Parameters take priority over environment variables and defaults.
    An error is raised if no values are defined.

    Args:
        var (Any):
            parameter passed to the respective upstream function.
        env_var (str):
            Name of the corresponding environmental variable.
        default (Optional[Any]):
            Default value when no others are provided
        boolean (Optional[bool]):
            Whether the expected values is a boolean
    Returns:
        Any: The value of the Python-object (preferred) or its respective env-variable.
        The latter can also resolve into a `None`, if not set.

    Raises:
       UserWarning: If both the parameter and env-variable are set.
       ValueError: If both the parameter and env-variable are None, or a boolean
    """
    env = os.environ.get(env_var)

    if (param or isinstance(param, bool)) and env:
        message = f"""Both the kwarg ({param}) and the env-variable for '{env_var}' ({env}) are assigned.
        Note that the argument takes precedence over the env-variable."""
        warnings.warn(UserWarning(message))
    elif param is None and env is None and default is None:
        message = f"""Both the kwarg and the env-variable for '{env_var}' are None.
        Please assign one of them to a value."""
        raise ValueError(message)

    if isinstance(param, bool):
        return param
    else:
        if boolean and env:
            try:
                env = literal_eval(env)
                if not isinstance(env, bool):
                    raise ValueError
            except (ValueError, SyntaxError):
                message = (
                    f"The '{env_var}' env-var valued '{env}' must be 'True' or 'False'."
                )
                print(message, flush=True)
                raise TypeError(message)
        return param or env or default


def check_role(token: str, role: str) -> bool:
    """Check if a token contains a certain role

    Args:
        token (str): token from a user
        role (str): role to be checked

    Returns:
        bool: whether the token contains the role
    """
    token_info = get_keycloak_openid().introspect(token)
    valid_token = _check_active_token(token_info)
    if valid_token:
        return "roles" in token_info and role in token_info["roles"]
    return False


def check_token_validity(
    access_token: str,
    server_url: Optional[str] = None,
    realm_name: Optional[str] = None,
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None,
    verify: Optional[bool] = None,
) -> bool:
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
        client_secret (Optional[str]):
            The client secret key for the client in Keycloak. If not provided, the value from the environment
            variable KEYCLOAK_CLIENT_SECRET will be used.
        verify (Optional[bool]):
            Controls whether SSL certificates are verified for HTTPS requests. If set to False, SSL
            verification is disabled. If set to a string, it should be the path to a CA_BUNDLE file or
            a directory containing certificates of trusted CA.

    Returns:
        bool: Whether the token is valid.
    """
    token_info = get_keycloak_openid(
        server_url, realm_name, client_id, client_secret, verify
    ).introspect(access_token)

    return _check_active_token(token_info)


def _check_active_token(token_info) -> bool:
    """Checks if a given token introspect information is marked as valid

    Args:
        token_info (Any): output from the introspect request

    Returns:
        bool: Whether the token is valid
    """
    return bool(token_info["active"])


def check_useraccount_access(
    access_token: str,
    server_url: Optional[str] = None,
    realm_name: Optional[str] = None,
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None,
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
        client_secret (Optional[str]):
            The client secret key for the client in Keycloak. If not provided, the value from the environment
            variable KEYCLOAK_CLIENT_SECRET will be used.
        verify (Optional[bool]):
            Controls whether SSL certificates are verified for HTTPS requests. If set to False, SSL
            verification is disabled. If set to a string, it should be the path to a CA_BUNDLE file or
            a directory containing certificates of trusted CA.

    Returns:
        str: A string indicating whether or not the access token has the 'openid' scope.
    """
    token_info = get_keycloak_openid(
        server_url, realm_name, client_id, client_secret, verify
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
    client_secret: Optional[str] = None,
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
        client_secret (Optional[str]):
            The client secret key for the client in Keycloak. If not provided, the value from the environment
            variable KEYCLOAK_CLIENT_SECRET will be used.
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
        server_url, realm_name, client_id, client_secret, verify
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
    client_secret: Optional[str] = None,
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
        client_secret (Optional[str]):
            The client secret key for the client in Keycloak. If not provided, the value from the environment
            variable KEYCLOAK_CLIENT_SECRET will be used.
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
        username,
        password,
        server_url,
        realm_name,
        client_id,
        client_secret,
        verify,
    )
    if type(credentials) == str:
        return {"Authorization": credentials}
    else:
        return credentials

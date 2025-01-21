"""Functions for interacting with a Keycloak-client."""

import os
import warnings
from ast import literal_eval
from typing import Any, Optional, Tuple, Union

from keycloak import KeycloakAdmin, KeycloakOpenID

from shieldapi import logger


def print_env_vars():
    env_vars = {
        "KEYCLOAK_HOST": os.environ.get("KEYCLOAK_HOST"),
        "KEYCLOAK_REALM_NAME": os.environ.get("KEYCLOAK_REALM_NAME"),
        "KEYCLOAK_CLIENT_ID": os.environ.get("KEYCLOAK_CLIENT_ID"),
        "KEYCLOAK_CLIENT_SECRET": os.environ.get("KEYCLOAK_CLIENT_SECRET"),
        "KEYCLOAK_VERIFY_HOST": os.environ.get("KEYCLOAK_VERIFY_HOST"),
        "KEYCLOAK_REALM_ADMIN_USER": os.environ.get("KEYCLOAK_REALM_ADMIN_USER"),
        "KEYCLOAK_REALM_ADMIN_PASSWORD": os.environ.get(
            "KEYCLOAK_REALM_ADMIN_PASSWORD"
        ),
    }

    logger.info("Environment variables received:")

    for key, value in env_vars.items():
        if value and key in {"KEYCLOAK_CLIENT_SECRET", "KEYCLOAK_REALM_ADMIN_PASSWORD"}:
            masked_value = value[:4] + "*" * (len(value) - 4)
            logger.info(f"{key}: {masked_value}")
        else:
            logger.info(f"{key}: {value}")


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
    logger.debug("Creating KeycloakOpenID instance")
    return KeycloakOpenID(
        server_url=_get_value(
            server_url, "KEYCLOAK_HOST", "http://keycloak:8080/auth/"
        ),
        realm_name=_get_value(realm_name, "KEYCLOAK_REALM_NAME"),
        client_id=_get_value(client_id, "KEYCLOAK_CLIENT_ID", "shieldapi"),
        client_secret_key=_get_value(client_secret, "KEYCLOAK_CLIENT_SECRET"),
        verify=_get_value(verify, "KEYCLOAK_VERIFY_HOST", False, True),
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
    logger.debug("Creating KeycloakAdmin instance")
    return KeycloakAdmin(
        server_url=_get_value(
            server_url, "KEYCLOAK_HOST", "http://keycloak:8080/auth/"
        ),
        username=_get_value(username, "KEYCLOAK_REALM_ADMIN_USER"),
        password=_get_value(password, "KEYCLOAK_REALM_ADMIN_PASSWORD"),
        realm_name=_get_value(realm_name, "KEYCLOAK_REALM_NAME"),
        verify=_get_value(verify, "KEYCLOAK_VERIFY_HOST", False, True),
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
        logger.warning(message)
    elif param is None and env is None and default is None:
        message = f"""Both the kwarg and the env-variable for '{env_var}' are None.
        Please assign one of them to a value."""
        logger.error(message)
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
                logger.error(message)
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
    logger.info(f"Checking role '{role}' for token")
    token_info = get_keycloak_openid().introspect(token)
    if bool(token_info["active"]):
        has_role = "roles" in token_info and role in token_info["roles"]
        logger.debug(f"Token has role '{role}': {has_role}")
        return has_role
    return False


def check_token_validity(
    access_token: str, validate_with_auth_server: Optional[bool] = True
) -> bool:
    """Check if the given access token is valid.

    Args:
        access_token: str
            The access token to check.
        validate_with_auth_server: boolean
            Indicates whether the validation is done through the server.

    Returns:
        bool: Whether the token is valid.
    """
    logger.info("Checking token validity")
    keycloak_openid = get_keycloak_openid()

    valid = False
    if validate_with_auth_server:
        token_info = keycloak_openid.introspect(access_token)
        valid = bool(token_info["active"])
    else:
        try:
            get_keycloak_openid().decode_token(access_token, validate=True)
            valid = True
        except Exception as e:
            logger.warning(f"AuthTokenBearer.__call__: Token validation failed: {e}")
    logger.debug(f"Token validity: {valid}")
    return valid


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
    logger.info("Checking user account access")
    token_info = get_keycloak_openid(
        server_url, realm_name, client_id, client_secret, verify
    ).introspect(access_token)
    granted_scope = token_info.json()["scope"].split()
    if "openid" not in granted_scope:
        message = "OpenID scope was not granted"
        logger.warning(message)
        return message, 401
    message = "Access granted"
    logger.info(message)
    return message, 200


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
    logger.info("Logging in user")
    token = get_keycloak_openid(
        server_url, realm_name, client_id, client_secret, verify
    ).token(username=username, password=password)
    if not token.get("access_token") and token.get("token_type"):
        message = "Token could not be generated. Please contact the admin."
        logger.error(message)
        return 401, message
    else:
        token_str = f"{token.get('token_type')} {token.get('access_token')}"
        logger.info("Token generated successfully")
        return token_str


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
    logger.info("Making authentication header")
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
        logger.info("Authentication header created successfully")
        return {"Authorization": credentials}
    else:
        logger.error("Failed to create authentication header")
        return credentials


def get_userinfo(token) -> dict:
    """
    Returns the user information from the access token.

    Args:
        token: str
            The access token of the user.

    Returns:
        dict:
            The user information.
    """
    userinfo = get_keycloak_openid().userinfo(token)
    logger.debug(f"get_userinfo: Retrieved user info {userinfo}")
    return userinfo


def get_current_user() -> str:
    """
    Get the current logged in user.

    Returns:
        str:
            The user ID.
    """
    user_info = get_userinfo()
    if not user_info:
        logger.warning("get_current_user: No user info available")
        return ""
    user_id = user_info.get("sub", "")
    logger.debug(f"get_current_user: Current user ID {user_id}")
    return user_id

"""Functions for interacting with a Keycloak-client."""

import os
import warnings
from ast import literal_eval
from typing import Any, Dict, Optional, Tuple, Union

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
    """Create a KeycloakOpenID instance from parameters or environment variables.

    Kwargs:
        server_url: Keycloak server URL. Falls back to $KEYCLOAK_HOST.
        realm_name: Realm name. Falls back to $KEYCLOAK_REALM_NAME.
        client_id: OIDC client ID. Falls back to $KEYCLOAK_CLIENT_ID.
        client_secret: Client secret. Falls back to $KEYCLOAK_CLIENT_SECRET.
        verify: TLS verification. Falls back to $KEYCLOAK_VERIFY_HOST (default False).
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
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None,
    realm_name: Optional[str] = None,
    verify: Optional[bool] = None,
    use_service_account: Optional[bool] = None,
) -> KeycloakAdmin:
    """Create a KeycloakAdmin instance from parameters or environment variables.

    Kwargs:
        server_url: Keycloak server URL. Falls back to $KEYCLOAK_HOST.
        username: Admin username. Falls back to $KEYCLOAK_REALM_ADMIN_USER.
        password: Admin password. Falls back to $KEYCLOAK_REALM_ADMIN_PASSWORD.
        client_id: Client ID for service account auth. Falls back to $KEYCLOAK_CLIENT_ID.
        client_secret: Client secret for service account auth. Falls back to $KEYCLOAK_CLIENT_SECRET.
        realm_name: Realm name. Falls back to $KEYCLOAK_REALM_NAME.
        verify: TLS verification. Falls back to $KEYCLOAK_VERIFY_HOST (default False).
        use_service_account: Use client credentials instead of user/password.
            Falls back to $KEYCLOAK_USE_SERVICE_ACCOUNT (default False).
    """
    logger.debug("Creating KeycloakAdmin instance")
    use_service_account = _get_value(
        use_service_account, "KEYCLOAK_USE_SERVICE_ACCOUNT", False, True
    )
    if use_service_account:
        logger.debug("Using Service Account for Admin authentication")
        admin = KeycloakAdmin(
            server_url=_get_value(
                server_url, "KEYCLOAK_HOST", "http://keycloak:8080/auth/"
            ),
            client_id=_get_value(client_id, "KEYCLOAK_CLIENT_ID"),
            client_secret_key=_get_value(client_secret, "KEYCLOAK_CLIENT_SECRET"),
            realm_name=_get_value(realm_name, "KEYCLOAK_REALM_NAME"),
            verify=_get_value(verify, "KEYCLOAK_VERIFY_HOST", False, True),
        )
    else:
        logger.debug("Using Custom User Account for Admin authentication")
        admin = KeycloakAdmin(
            server_url=_get_value(
                server_url, "KEYCLOAK_HOST", "http://keycloak:8080/auth/"
            ),
            username=_get_value(username, "KEYCLOAK_REALM_ADMIN_USER"),
            password=_get_value(password, "KEYCLOAK_REALM_ADMIN_PASSWORD"),
            realm_name=_get_value(realm_name, "KEYCLOAK_REALM_NAME"),
            verify=_get_value(verify, "KEYCLOAK_VERIFY_HOST", False, True),
        )
    return admin


def _get_value(
    param: Any,
    env_var: str,
    default: Optional[Any] = None,
    boolean: Optional[bool] = False,
) -> Any:
    """Return param, falling back to env_var, then default.

    Emits a UserWarning when both param and env_var are set (param wins).
    Raises ValueError when all three are None.
    Raises TypeError when boolean=True and the env_var value is not 'True'/'False'.
    """
    env = os.environ.get(env_var)

    if (param or isinstance(param, bool)) and env:
        message = (
            f"Both the kwarg ({param}) and the env-variable for '{env_var}' ({env}) are assigned. "
            f"Note that the argument takes precedence over the env-variable."
        )
        warnings.warn(UserWarning(message))
        logger.warning(message)
    elif param is None and env is None and default is None:
        message = (
            f"Both the kwarg and the env-variable for '{env_var}' are None. "
            f"Please assign one of them to a value."
        )
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
    """Return True if the token grants the given role.

    Keycloak's token introspection endpoint returns roles in two locations:
    - realm_access.roles  (realm-level roles)
    - resource_access.<client>.roles  (client-level roles)

    A flat top-level ``roles`` field is also checked for compatibility with
    Keycloak deployments that include a custom protocol mapper.

    Args:
        token: Raw access token string.
        role: Role name to check.
    """
    logger.info(f"Checking role '{role}' for token")
    token_info = get_keycloak_openid().introspect(token)
    if not bool(token_info.get("active")):
        logger.debug("Token is inactive")
        return False

    # Flat roles field (custom protocol mapper or older Keycloak configs)
    if role in token_info.get("roles", []):
        logger.debug(f"Role '{role}' found in flat roles field")
        return True

    # Realm-level roles
    if role in token_info.get("realm_access", {}).get("roles", []):
        logger.debug(f"Role '{role}' found in realm_access.roles")
        return True

    # Client-level roles across all resource_access entries
    for client, client_data in token_info.get("resource_access", {}).items():
        if role in client_data.get("roles", []):
            logger.debug(f"Role '{role}' found in resource_access.{client}.roles")
            return True

    logger.debug(f"Role '{role}' not found in token")
    return False


def check_token_validity(
    access_token: str, validate_with_auth_server: Optional[bool] = True
) -> bool:
    """Return True if the access token is currently valid.

    Args:
        access_token: The access token to check.
        validate_with_auth_server: When True (default), validates via Keycloak
            introspection. When False, validates the JWT signature locally
            (requires JWKS key configuration).
    """
    logger.info("Checking token validity")
    keycloak_openid = get_keycloak_openid()

    valid = False
    if validate_with_auth_server:
        token_info = keycloak_openid.introspect(access_token)
        valid = bool(token_info.get("active"))
    else:
        try:
            get_keycloak_openid().decode_token(access_token, validate=True)
            valid = True
        except Exception as e:
            logger.warning(f"check_token_validity: Token validation failed: {e}")
    logger.debug(f"Token validity: {valid}")
    return valid


def check_useraccount_access(
    access_token: str,
    server_url: Optional[str] = None,
    realm_name: Optional[str] = None,
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None,
    verify: Optional[bool] = None,
) -> Tuple[str, int]:
    """Return (message, status_code) indicating whether the token has 'openid' scope.

    Args:
        access_token: The access token to check.
    Kwargs: See get_keycloak_openid for remaining parameters.
    """
    logger.info("Checking user account access")
    token_info = get_keycloak_openid(
        server_url, realm_name, client_id, client_secret, verify
    ).introspect(access_token)
    granted_scope = token_info.get("scope", "").split()
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
) -> Union[str, Tuple[int, str]]:
    """Authenticate with Keycloak and return a Bearer token string.

    Returns ``"Bearer <access_token>"`` on success, or ``(status_code, message)``
    on failure.

    Args:
        username: Keycloak username.
        password: Keycloak password.
    Kwargs: See get_keycloak_openid for remaining parameters.
    """
    logger.info("Logging in user")
    token = get_keycloak_openid(
        server_url, realm_name, client_id, client_secret, verify
    ).token(username=username, password=password)
    if not token.get("access_token") or not token.get("token_type"):
        message = "Token could not be generated. Please contact the admin."
        logger.error(message)
        return 401, message
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
) -> Union[Dict[str, str], Tuple[int, str]]:
    """Return an ``Authorization`` header dict, or ``(status_code, message)`` on failure.

    Args:
        username: Keycloak username.
        password: Keycloak password.
    Kwargs: See get_keycloak_openid for remaining parameters.
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
    if isinstance(credentials, str):
        logger.info("Authentication header created successfully")
        return {"Authorization": credentials}
    logger.error("Failed to create authentication header")
    return credentials


def get_userinfo(token: str) -> dict:
    """Return the userinfo claims from Keycloak for the given access token.

    Args:
        token: Raw access token string.
    """
    userinfo = get_keycloak_openid().userinfo(token)
    logger.debug(f"get_userinfo: Retrieved user info {userinfo}")
    return userinfo


def get_current_user() -> str:
    """Return the Keycloak user ID (``sub``) for the current request token."""
    user_info = get_userinfo()
    if not user_info:
        logger.warning("get_current_user: No user info available")
        return ""
    user_id = user_info.get("sub", "")
    logger.debug(f"get_current_user: Current user ID {user_id}")
    return user_id

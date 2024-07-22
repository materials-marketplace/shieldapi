"""Functions and decorators for shieldapi in Flask."""

from functools import wraps
from typing import Callable, List

from flask import abort, request

from shieldapi import logger
from shieldapi.keycloak_utils import (
    check_role,
    check_token_validity,
    get_keycloak_openid,
)


def get_access_token():
    """
    Returns the access token from the Authorization header of the request.

    Returns:
        str:
            The access token.
    """
    auth_header = request.headers.get("Authorization", default="")
    if not auth_header or "Bearer" not in auth_header:
        logger.warning("get_access_token: Missing or invalid Authorization header")
        return ""
    token = auth_header.split()[1]
    logger.debug(f"get_access_token: Extracted token {token}")
    return token


def login_required(fn: Callable) -> Callable:
    """
    Decorator that checks if the user is logged in.

    Args:
        fn (Callable):
            The function to be decorated.

    Returns:
        Callable:
            The decorated function.
    """

    @wraps(fn)
    def decorated_view(*args, **kwargs):
        access_token = get_access_token()
        if not access_token:
            logger.warning("login_required: Access token is missing")
            abort(401)

        valid = check_token_validity(access_token)
        if not valid:
            logger.warning("login_required: Access token is invalid or expired")
            abort(401)

        logger.info("login_required: User is logged in")
        return fn(*args, **kwargs)

    return decorated_view


def admin_required(fn: Callable) -> Callable:
    """
    Decorator that checks if the user is an admin.

    Args:
        fn (Callable):
            The function to be decorated.

    Returns:
        Callable:
            The decorated function.
    """

    @wraps(fn)
    def decorated_view(*args, **kwargs):
        access_token = get_access_token()
        if not access_token:
            logger.warning("admin_required: Access token is missing")
            abort(401)

        if not check_role(access_token, "admin"):
            logger.warning("admin_required: User does not have admin role")
            abort(403)

        logger.info("admin_required: User is an admin")
        return fn(*args, **kwargs)

    return decorated_view


def role_required(role: str) -> Callable:
    """
    Decorator that limits access to users with a certain role.

    Args:
        role (str):
            The required role.

    Returns:
        Callable:
            The decorator function.
    """

    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def restricted_function(*args, **kwargs):
            access_token = get_access_token()
            if not access_token:
                logger.warning(
                    f"role_required: Access token is missing for role {role}"
                )
                abort(401)

            if not check_role(access_token, role):
                logger.warning(
                    f"role_required: User does not have required role {role}"
                )
                abort(403)

            logger.info(f"role_required: User has required role {role}")
            res = f(*args, **kwargs)

            return res

        return restricted_function

    return decorator


def has_scope(scope_list: List[str]) -> Callable:
    """
    Decorator that limits access to the applications which have been
    granted the required scopes.

    Args:
        scope_list (List[str]):
            The list of required scopes.

    Returns:
        Callable:
            The decorator function.
    """

    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def restricted_function(*args, **kwargs):
            token = get_access_token()
            if not token:
                logger.warning("has_scope: Access token is missing")
                return None

            token_info = get_keycloak_openid().introspect(token)
            if not token_info.json()["active"]:
                logger.warning("has_scope: Access token is inactive")
                return None

            granted_scope = token_info.json()["scope"].split()
            for requested_scope in scope_list:
                if requested_scope not in granted_scope:
                    logger.warning(
                        f"has_scope: Required scope {requested_scope} not granted"
                    )
                    return None

            logger.info("has_scope: All required scopes are granted")
            res = f(*args, **kwargs)

            return res

        return restricted_function

    return decorator

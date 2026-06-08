"""Decorators for protecting Flask endpoints with Keycloak authentication."""

from functools import wraps
from typing import Callable, List

from flask import abort, request

from shieldapi import logger
from shieldapi.keycloak_utils import (
    check_role,
    check_token_validity,
    get_keycloak_openid,
)


def get_access_token() -> str:
    """Extract the Bearer token from the Authorization request header.

    Returns an empty string when the header is missing or malformed.
    """
    auth_header = request.headers.get("Authorization", default="")
    if not auth_header or "Bearer" not in auth_header:
        logger.warning("get_access_token: Missing or invalid Authorization header")
        return ""
    token = auth_header.split()[1]
    logger.debug(f"get_access_token: Extracted token {token}")
    return token


def login_required(fn: Callable) -> Callable:
    """Decorator: reject requests without a valid Keycloak Bearer token (401)."""

    @wraps(fn)
    def decorated_view(*args, **kwargs):
        access_token = get_access_token()
        if not access_token:
            logger.warning("login_required: Access token is missing")
            abort(401)

        if not check_token_validity(access_token):
            logger.warning("login_required: Access token is invalid or expired")
            abort(401)

        logger.info("login_required: User is logged in")
        return fn(*args, **kwargs)

    return decorated_view


def admin_required(fn: Callable) -> Callable:
    """Decorator: reject requests where the token does not carry the 'admin' role (403).

    Checks realm_access.roles, resource_access.<client>.roles, and any flat
    top-level 'roles' field in the Keycloak introspection response.
    Must be stacked inside login_required so the token is already validated.
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
    """Decorator factory: reject requests missing the given Keycloak role (403).

    Checks realm_access.roles, resource_access.<client>.roles, and any flat
    top-level 'roles' field in the Keycloak introspection response.
    Must be stacked inside login_required so the token is already validated.

    Args:
        role: The Keycloak role name that the caller must hold.
    """

    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def restricted_function(*args, **kwargs):
            access_token = get_access_token()
            if not access_token:
                logger.warning(
                    f"role_required: Access token is missing for role '{role}'"
                )
                abort(401)

            if not check_role(access_token, role):
                logger.warning(
                    f"role_required: User does not have required role '{role}'"
                )
                abort(403)

            logger.info(f"role_required: User has required role '{role}'")
            return f(*args, **kwargs)

        return restricted_function

    return decorator


def has_scope(scope_list: List[str]) -> Callable:
    """Decorator factory: reject requests where the token lacks any listed OAuth scope (403).

    Args:
        scope_list: OAuth scopes that must all be present in the token.
    """

    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def restricted_function(*args, **kwargs):
            token = get_access_token()
            if not token:
                logger.warning("has_scope: Access token is missing")
                abort(401)

            token_info = get_keycloak_openid().introspect(token)
            if not bool(token_info.get("active")):
                logger.warning("has_scope: Access token is inactive")
                abort(401)

            granted_scope = token_info.get("scope", "").split()
            for requested_scope in scope_list:
                if requested_scope not in granted_scope:
                    logger.warning(
                        f"has_scope: Required scope '{requested_scope}' not granted"
                    )
                    abort(403)

            logger.info("has_scope: All required scopes are granted")
            return f(*args, **kwargs)

        return restricted_function

    return decorator

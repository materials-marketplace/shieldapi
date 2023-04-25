"""functions and decorators for shieldapi in Flask."""
from functools import wraps
from typing import Callable, List

from flask import abort, request

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
        return ""
    return auth_header.split()[1]


def get_userinfo() -> dict:
    """
    Returns the user information from the access token.

    Returns:
        dict:
            The user information.
    """
    token = get_access_token()
    userinfo = get_keycloak_openid().userinfo(token)
    return userinfo


def get_current_user() -> str:
    """
    Get the current logged in user.

    Returns:
        str:
            The user ID.
    """
    user_info = get_userinfo()
    return user_info["sub"]


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
            abort(401)

        valid = check_token_validity(access_token)

        if not valid:
            abort(401)

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
            abort(401)

        if not check_role(access_token, "admin"):
            abort(403)

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
                abort(401)

            if not check_role(access_token, role):
                abort(403)

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
                return None

            token_info = get_keycloak_openid().introspect(token)

            if not token_info.json()["active"]:
                return None

            granted_scope = token_info.json()["scope"].split()
            for requested_scope in scope_list:
                if requested_scope not in granted_scope:
                    return None

            res = f(*args, **kwargs)

            return res

        return restricted_function

    return decorator

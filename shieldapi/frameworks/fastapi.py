"""Dependencies and classes for shieldapi in FastAPI."""

import os
from typing import Optional

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPBasic, HTTPBasicCredentials, HTTPBearer
from pydantic import BaseModel

from shieldapi import logger
from shieldapi.keycloak_utils import (
    check_role,
    check_token_validity,
    get_keycloak_openid,
    get_token_sub,
    login,
)

_ADMIN_ROLE = "admin"
_ROLES_PATH = ("resource_access", "shieldapi", "roles")


class Auth(str):
    """A custom type to represent the authentication token"""

    pass


class Token(BaseModel):
    """
    A Pydantic model to represent the access token and its type.
    """

    access_token: str
    token_type: str


class AuthTokenBearer(HTTPBearer):
    """
    A subclass of HTTPBearer that validates and extracts the authentication token
    from the request header.
    """

    async def __call__(self, request: Request) -> Auth:
        """
        Overrides the __call__ method of the parent class to validate and extract
        the authentication token from the request header.

        Args:
            request (Request):
                The incoming request object.

        Returns:
            Auth:
                The authentication token as a string in the "Bearer {token}" format.

        Raises:
            HTTPException:
                If the authentication token is missing or expired.
        """
        logger.debug("AuthTokenBearer.__call__: Starting token extraction")
        auth = await super().__call__(request=request)

        if not auth.credentials:
            logger.warning("AuthTokenBearer.__call__: Missing access token")
            raise HTTPException(
                status_code=401,
                detail="An access token is expected but has not been provided",
            )

        if not check_token_validity(auth.credentials):
            logger.warning(f"AuthTokenBearer.__call__: Token validation failed")
            raise HTTPException(status_code=401, detail="Token validation failed")
        return f"Bearer {auth.credentials}"


class OptionalAuthTokenBearer(HTTPBearer):
    """Like AuthTokenBearer but returns None for requests with no Authorization header.

    A present but invalid/expired token still raises HTTP 401 so callers cannot
    accidentally downgrade to anonymous access with a stale credential.
    """

    def __init__(self, **kwargs):
        super().__init__(auto_error=False, **kwargs)

    async def __call__(self, request: Request) -> Optional[Auth]:
        auth = await super().__call__(request=request)
        if auth is None:
            return None
        if not auth.credentials:
            raise HTTPException(
                status_code=401,
                detail="An access token is expected but has not been provided",
            )
        if not check_token_validity(auth.credentials):
            logger.warning("OptionalAuthTokenBearer.__call__: Token validation failed")
            raise HTTPException(status_code=401, detail="Token validation failed")
        return f"Bearer {auth.credentials}"


class BasicLoginCredentials(HTTPBasicCredentials):
    """
    A subclass of HTTPBasicCredentials that extracts the basic auth credentials and
    gets an access token from Keycloak using the login function.

    Attributes:
        username (str):
            The username from the basic auth header.
        password (str):
            The password from the basic auth header.

    Raises:
        HTTPException:
            If the authentication credentials are invalid.
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        logger.debug(
            f"BasicLoginCredentials.__init__: Initialized with username={self.username}"
        )

    @property
    def token(self, **kwargs) -> Auth:
        """
        Authenticates with Keycloak using the login function, and returns
        the access token as a string in the "Bearer {token}" format.

        Returns:
            Auth:
                The authentication token as a string in the "Bearer {token}" format.

        Raises:
            HTTPException:
                If the authentication credentials are invalid.
        """
        logger.debug(
            f"BasicLoginCredentials.token: Attempting login for username={self.username}"
        )
        token = login(self.username, self.password)
        if isinstance(token, tuple):
            logger.error(
                f"BasicLoginCredentials.token: Invalid credentials for username={self.username}"
            )
            raise HTTPException(status_code=token[0], detail=token[1])
        else:
            logger.info(
                f"BasicLoginCredentials.token: Login successful for username={self.username}"
            )
            return token


class BasicLogin(HTTPBasic):
    """
    A subclass of HTTPBasic that extracts the basic auth credentials and
    gets an access token from Keycloak using the login function.

    Returns:
        Auth:
            The authentication token as a string in the "Bearer {token}" format.

    Raises:
        HTTPException:
            If the authentication credentials are invalid.
    """

    async def __call__(self, request: Request) -> Auth:
        """
        Extracts the basic auth credentials from the request header, passes them to the
        `login` function to get an access token from Keycloak, and returns the access
        token as a string in the "Bearer {token}" format.

        Args:
            request (Request):
                The HTTP request containing the basic auth header.

        Returns:
            Auth:
                The authentication token as a string in the "Bearer {token}" format.

        Raises:
            HTTPException:
                If the authentication credentials are invalid.
        """
        logger.debug("BasicLogin.__call__: Extracting credentials from request")
        log = await super().__call__(request=request)
        logger.debug(
            f"BasicLogin.__call__: Credentials extracted for username={log.username}"
        )
        token = login(log.username, log.password)
        if isinstance(token, tuple):
            logger.error(
                f"BasicLogin.__call__: Invalid credentials for username={log.username}"
            )
            raise HTTPException(status_code=token[0], detail=token[1])
        else:
            logger.info(
                f"BasicLogin.__call__: Login successful for username={log.username}"
            )
            return token


async def depends_basic_login(request: Request) -> Auth:
    """
    A helper function that returns the token by instantiating
    an BasicLogin-dependency with values retrieved from
    environment variables and by calling the instance with
    the incoming request-object.

    Parameters:
    - request (Request): The incoming request object.

    Returns:
        Auth:
            A custom str-type representing the access token.
    """
    logger.debug("depends_basic_login: Creating BasicLogin instance")
    basic = BasicLogin(
        scheme_name=os.environ.get("AUTH_BEARER_SCHEME_NAME"),
    )
    logger.debug("depends_basic_login: Calling BasicLogin instance with request")
    return await basic(request)


async def depends_auth_token_bearer(request: Request) -> Auth:
    """
    A helper function that returns the token by instantiating
    an AuthTokenBearer-dependency with values retrieved from
    environment variables and by calling the instance with
    the incoming request-object.

    Parameters:
    - request (Request): The incoming request object.

    Returns:
        Auth:
            A custom str-type representing the access token.
    """
    logger.debug("depends_auth_token_bearer: Creating AuthTokenBearer instance")
    bearer = AuthTokenBearer(
        bearerFormat=os.environ.get("AUTH_TOKEN_BEARER_FORMAT"),
        scheme_name=os.environ.get("AUTH_BEARER_SCHEME_NAME"),
        description=os.environ.get("AUTH_BEARER_DESCRIPTION"),
    )
    logger.debug(
        "depends_auth_token_bearer: Calling AuthTokenBearer instance with request"
    )
    return await bearer(request)


def require_self_or_role(role: str):
    """Return a FastAPI dependency that allows access to the user themselves or holders of ``role``.

    The dependency checks whether the requesting user has ``role`` (unconditional
    access) or whether the token subject matches the ``user_id`` path parameter.
    Returns the raw token string on success and raises HTTP 403 otherwise.

    Args:
        role: Role name that grants unconditional access.
    """

    async def dependency(request: Request) -> str:
        token_with_bearer = await depends_auth_token_bearer(request)
        raw_token = token_with_bearer.split(" ", 1)[1]
        if check_role(raw_token, role):
            return raw_token
        user_id = request.path_params.get("user_id")
        if user_id and get_token_sub(raw_token) == user_id:
            return raw_token
        raise HTTPException(
            status_code=403,
            detail=f"Requires '{role}' role or matching user_id",
        )

    return dependency


# ---------------------------------------------------------------------------
# Generic Keycloak FastAPI dependency chain
#
# These can be imported directly into any FastAPI service that uses shieldapi:
#
#   from shieldapi.frameworks.fastapi import (
#       get_access_token, get_userinfo, get_user_id, get_user_roles, is_admin,
#       get_optional_access_token, get_optional_userinfo,
#       get_optional_user_id, get_optional_user_roles, is_optional_admin,
#   )
# ---------------------------------------------------------------------------


def get_access_token(request: Request) -> str:
    """Extract the raw Bearer token string from the Authorization header, or '' if absent."""
    auth_header = request.headers.get("Authorization", default="")
    if not auth_header or "Bearer" not in auth_header:
        return ""
    return auth_header.split()[1]


def get_userinfo(token: str = Depends(get_access_token)) -> dict:
    """Introspect the token against Keycloak and return the userinfo dict."""
    return get_keycloak_openid().introspect(token)


def get_user_roles(userinfo: dict = Depends(get_userinfo)):
    """Return the list of shieldapi realm roles from the introspection result."""
    d = userinfo
    for key in _ROLES_PATH:
        d = d.get(key, {})
    return d if isinstance(d, list) else []


def get_user_id(userinfo: dict = Depends(get_userinfo)) -> str:
    """Return the Keycloak subject (user UUID) from the introspection result."""
    return userinfo.get("sub")


def is_admin(roles=Depends(get_user_roles)) -> bool:
    """Return True when the caller holds the 'admin' shieldapi role."""
    return _ADMIN_ROLE in roles


def get_optional_access_token(request: Request) -> Optional[str]:
    """Like get_access_token but returns None when no Authorization header is present."""
    auth_header = request.headers.get("Authorization", default="")
    if not auth_header or "Bearer" not in auth_header:
        return None
    return auth_header.split()[1]


def get_optional_userinfo(
    token: Optional[str] = Depends(get_optional_access_token),
) -> Optional[dict]:
    """Introspect the token when present; return None for anonymous requests."""
    if token is None:
        return None
    return get_keycloak_openid().introspect(token)


def get_optional_user_roles(userinfo: Optional[dict] = Depends(get_optional_userinfo)):
    """Return roles for an authenticated caller, or [] for anonymous."""
    if userinfo is None:
        return []
    d = userinfo
    for key in _ROLES_PATH:
        d = d.get(key, {})
    return d if isinstance(d, list) else []


def get_optional_user_id(
    userinfo: Optional[dict] = Depends(get_optional_userinfo),
) -> Optional[str]:
    """Return the subject UUID for an authenticated caller, or None for anonymous."""
    if userinfo is None:
        return None
    return userinfo.get("sub")


def is_optional_admin(roles=Depends(get_optional_user_roles)) -> bool:
    """Return True when the caller holds the 'admin' role; False for anonymous."""
    return _ADMIN_ROLE in roles

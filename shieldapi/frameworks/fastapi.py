"""Dependencies and classes for shieldapi in FastAPI."""
import os

from fastapi import HTTPException, Request
from fastapi.security import HTTPBasic, HTTPBasicCredentials, HTTPBearer
from pydantic import BaseModel

from shieldapi.keycloak_utils import get_keycloak_openid, login


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
        auth = await super().__call__(request=request)

        if not auth.credentials:
            raise HTTPException(
                status_code=401,
                detail="An access token is expected but has not been provided",
            )

        token_info = get_keycloak_openid().introspect(auth.credentials)
        if not token_info["active"]:
            raise HTTPException(status_code=401, detail="The access token is expired")

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
        token = login(self.username, self.password)
        if len(token) == 2:
            raise HTTPException(status_code=token[0], detail=token[1])
        else:
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
        log = await super().__call__(request=request)
        token = login(log.username, log.password)
        if len(token) == 2:
            raise HTTPException(status_code=token[0], detail=token[1])
        else:
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
    basic = BasicLogin(
        scheme_name=os.environ.get("AUTH_BEARER_SCHEME_NAME"),
    )
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
    bearer = AuthTokenBearer(
        bearerFormat=os.environ.get("AUTH_TOKEN_BEARER_FORMAT"),
        scheme_name=os.environ.get("AUTH_BEARER_SCHEME_NAME"),
        description=os.environ.get("AUTH_BEARER_DESCRIPTION"),
    )
    return await bearer(request)

# ShieldAPI

The `shieldapi` package provides utilities for implementing authentication/authorization mechanism through a Keycloak-backend in Python web applications, such as FastAPI and Flask. It includes functionality for managing user accounts, token authentication, and role-based access control.

## Authors

- Yoav Nahshon (yoav.nahshon@iwm.fraunhofer.de)
- Pablo De Andres (pablo.de.andres@iwm.fraunhofer.de)
- Matthias Büschelberger (matthias.bueschelberger@iwm.fraunhofer.de)
- Treesa Joseph (treesa.joseph@sintef.no)
- Thomas Hagelien (thomas.f.hagelien@sintef.no)
- Simon Adorf

## Installation

You can install the package using pip:

```bash
pip install shieldapi
```

## Prerequisites

### Keycloak

In order to set up Keycloak authentication for a Flask or FastAPI app using the shieldapi package, there are some prerequisites that must be met:

1. *Install Keycloak* - Keycloak can be downloaded from the official Keycloak website. After downloading, follow the installation instructions to install Keycloak on your machine. Alternatively, you may use use a [Docker image](https://www.keycloak.org/getting-started/getting-started-docker).

1. *Create a realm* - A realm is a container for a set of users, authentication methods, and client applications. To create a realm in Keycloak, log in to the Keycloak Admin Console, click on "Add Realm", and fill in the necessary details. For more information on creating realms, see the official Keycloak documentation.

1. *Create a client* - A client is an entity that can request authorization and/or authentication services from Keycloak. To create a client in Keycloak, go to the "Clients" tab in the Keycloak Admin Console, click "Create", and fill in the necessary details. For more information on creating clients, see the official Keycloak documentation.

1. *Create a client scope* - A client scope defines a set of client-level roles that can be granted to users. To create a client scope in Keycloak, go to the "Client Scopes" tab in the Keycloak Admin Console, click "Create", and fill in the necessary details. For more information on creating client scopes, see the official Keycloak documentation.

1. *Create a user* - A user is an entity that can authenticate to Keycloak and access client applications. To create a user in Keycloak, go to the "Users" tab in the Keycloak Admin Console, click "Add User", and fill in the necessary details. For more information on creating users, see the official Keycloak documentation.

1. *Create a role* - A role is a set of permissions that can be granted to users or clients. To create a role in Keycloak, go to the "Roles" tab in the Keycloak Admin Console, click "Add Role", and fill in the necessary details. For more information on creating roles, see the official Keycloak documentation.

1. *Assign roles to client scope* - To grant permissions to users or clients, roles must be assigned to client scopes. To assign roles to a client scope in Keycloak, go to the "Client Scopes" tab in the Keycloak Admin Console, click on the client scope you created in step 4, and then click on the "Mappings" tab. From there, you can assign roles to the client scope.

### Environmental variables

In order to successfully enable the callback for the token-generation and token-verification, make sure that the following environmental variables are set correctly.

| Variable name                   | Description                                                                                                | Example value                          |
| ------------------------------- | ---------------------------------------------------------------------------------------------------------- | -------------------------------------- |
| `KEYCLOAK_HOST`                 | Hostname of the the Keycloak instance                                                                      | "http://localhost:8080"                |
| `KEYCLOAK_REALM_NAME`           | Realm name you set under step 2 in the previous chapter                                                    | "my_realm"                             |
| `KEYCLOAK_CLIENT_ID`            | Client ID you created under step 3.                                                                        | "shieldapi"                            |
| `KEYCLOAK_CLIENT_SECRET`        | Client secret you created under step 3 (`access_type` should be set to "confidential").                    | "1169a83e-a237-40ad-90db-8b8d4848de09" |
| `KEYCLOAK_VERIFY_HOST`          | Controls whether SSL certificates are verified for HTTPS requests. Default is set to `False`.              | "True"                                 |
| `KEYCLOAK_REALM_ADMIN_USER`     | User name of the realm admin, if any action shall be performed as admin in your Flask/FastAPI application. | "admin"                                |
| `KEYCLOAK_REALM_ADMIN_PASSWORD` | Password of the realm admin, if any action shall be performed as admin in your Flask/FastAPI application.  | "admin_password"                       |
| `SKIP_ENV_CHECK`                | Optional. If set, skips the check for mandatory environment variables during startup.                      | "1"                                    |

#### Note
- If `SKIP_ENV_CHECK` is set, the application will bypass the mandatory environment variable checks during startup. This is useful for development or testing scenarios where not all variables are needed.

## Usage with Flask

There are several decorators which can be included into the Flask app for authentication of endpoints.

A few examples are listed here:

### login_required

To use the `login_required` decorator, simply decorate any Flask route functions that require authentication. The decorator checks if the user is logged in by checking the access token, and aborts the request with a 401 Unauthorized error if the access token is not found or expired. If the access token is valid, the route function is executed normally.

```py
from flask import Flask
from shieldapi.frameworks.flask import login_required

app = Flask(__name__)

@app.route('/protected_endpoint')
@login_required
def hello_world():
    return 'Hello, World!'

if __name__ == '__main__':
    app.run()
```

Run the flask app with a *WSGI* server (recommended for production).

If the service is up and running, access the endpoint of the service as a client:

```py
import requests

ACCESS_TOKEN = "your_access_token_here"
URL = "http://localhost:5000/protected_endpoint"

headers = {"Authorization": f"Bearer {ACCESS_TOKEN}"}

# GET request to the root endpoint
response = requests.get(URL, headers=headers)
print(response.text) # prints 'Hello, World!'
```

### admin_required

This is a Flask decorator that checks if the user is an admin. The decorator extracts the access token from the request header and verifies that the token is valid and active. It then checks if the user has the "admin" role in the token's roles claim. If any of these checks fail, the decorator raises a 401 Unauthorized or a 403 Forbidden error.

Example:

```py
from flask import Flask
from shieldapi.frameworks.flask import admin_required

app = Flask(__name__)

@app.route('/')
def index():
    return 'Home Page'

@app.route('/admin')
@admin_required
def admin_view():
    return 'Admin Dashboard'

if __name__ == '__main__':
    app.run(debug=True)

```

In this example, the `admin_view()` function can only be accessed by users who have the "`admin`" role in their access token. If a user without the "`admin`" role tries to access the view, a 403 Forbidden error will be raised.

### has_scope

The `has_scope` function creates a decorator that limits access to the applications which have been granted the required scopes. The decorator takes in a list of required scopes and checks if the user's access token includes all of these scopes. If not, the user is denied access.

To use this decorator, you can simply add the `@has_scope` decorator above the route function for which you want to restrict access based on scopes. The decorator takes the list of required scopes as an argument.

For example:

```py
from flask import Flask
from shieldapi.frameworks.flask import has_scope

app = Flask(__name__)

@app.route('/admin')
@has_scope(['admin'])
def admin():
    # code to handle admin requests
```

In this example, the `admin()` function will only be accessible to users who have been granted the "`admin`" scope in their access token. If the user's access token does not include the "`admin`" scope, the restricted_function in the decorator will return None and the user will be denied access

### get_userinfo

The `get_userinfo` function is used in a Flask application to retrieve the user information from an access token.

To use this function, you should first obtain an access token, typically by using a decorator such as `admin_required` or `has_scope`, which would decorate the route or method where the user information is needed.

Once the access token is obtained, you can call the `get_userinfo` function to retrieve the user information from the token.

The function returns a dictionary containing the user information, such as the user's email, name, and other attributes that were included in the access token.

## Usage with FastAPI

There are several FastAPI-dependency classes which are provided by the package.

A few examples are listed here:

### AuthTokenBearer

To use the `AuthTokenBearer` HTTPBearer subclass in your FastAPI application, you can add it as a dependency to your API route functions that require authentication. Here's an example of how to use it:

```py
from fastapi import FastAPI, Depends
from shieldapi.frameworks.fastapi import AuthTokenBearer

app = FastAPI()

# Create an instance of the AuthTokenBearer class
auth_bearer = AuthTokenBearer()

# Define a protected route that requires authentication
@app.get("/protected_endpoint")
async def protected_route(auth: str = Depends(auth_bearer)):
    # Use the authentication token to access protected resources
    return {"message": "This resource is protected"}
```

In this example, the `AuthTokenBearer` instance auth_bearer is added as a dependency to the protected_route function. This ensures that the route is protected and can only be accessed by authenticated users.

When a request is made to the protected_route, FastAPI will call the `__call__` method of the `AuthTokenBearer` instance to validate and extract the authentication token from the request header. If the token is missing or expired, an HTTPException will be raised.

To use the `AuthTokenBearer` subclass with Keycloak authentication, you will need to configure your Keycloak server URL and realm name in the `get_keycloak_openid()` function in the `shieldapi.keycloak_utils` module. Additionally, you will need to define the appropriate Keycloak roles and permissions in your application to control access to protected resources.

Note that this subclass assumes that the authentication token is passed in the `"Bearer {token}"` format in the request header. If your application uses a different format, you may need to modify the `__call__` method to extract the token in the correct format.

For exemplary usage, run the FastAPI app with a *WSGI* server (recommended for production) or with a `TestClient` (recommended for production only).

If the service is up and running, access the endpoint of the service as a client:

```py
import requests

ACCESS_TOKEN = "your_access_token_here"
URL = "http://localhost:8080/protected_endpoint"

headers = {"Authorization": f"Bearer {ACCESS_TOKEN}"}

# GET request to the root endpoint
response = requests.get(URL, headers=headers)
print(response.json()) # prints: {"message": "This resource is protected"}
```

### depends_auth_token_bearer

Alternatively to the `AuthTokenBearer` above, the helper function `depends_auth_token_bearer` can be used:

```py
from fastapi import FastAPI, Depends
from shieldapi.frameworks.fastapi import depends_auth_token_bearer

app = FastAPI()

# Define a protected route that requires authentication
@app.get("/protected_endpoint")
async def protected_route(auth: str = Depends(depends_auth_token_bearer)):
    # Use the authentication token to access protected resources
    return {"message": "This resource is protected"}
```

### BasicLoginCredentials

`BasicLoginCredentials` is a subclass of `HTTPBasicCredentials` that authenticates the user using Basic Authentication and retrieves an access token from Keycloak using the `login` function. If the authentication credentials are valid, it returns the authentication token as a string in the `"Bearer {token}"` format.

Here's an example of how to use `BasicLoginCredentials` for authentication in FastAPI:

```py
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import HTTPBasic
from shieldapi.frameworks.fastapi import BasicLoginCredentials

app = FastAPI()

security = HTTPBasic()

@app.get("/protected_endpoint")
async def protected_route(login: BasicLoginCredentials = Depends(security)):
    """
    This route is protected and authentication with user/password in order
    to generate a token.
    """
    if not login.token:
        raise HTTPException(
            status_code=401,
            detail="Invalid authentication credentials"
        )

    # Perform some action with the token here
    return {"message": "Authenticated successfully!"}
```

In the example above, the `protected_endpoint` is protected by the `BasicLoginCredentials` dependency. When a request is made to this route, `FastAPI` will extract the Authorization header with the basic authentication credentials. The `BasicLoginCredentials` dependency will then authenticate with Keycloak using these credentials and return the authentication token as a string in the `"Bearer {token}"` format. If the authentication credentials are invalid, it will raise an `HTTPException` with status code 401 and the message `"Invalid authentication credentials"`. Once the token is authenticated, the function can perform some action with the token before returning a response to the client.

> Note: The major difference between **BasicLoginCredentials**  and **BasicLogin**-dependency is that the latter one needs to be instantiated before injected as dependency into an endpoint or application. **BasicLogin** simply returns a `str` with the token whereas **BasicLoginCredentials** return the full request-object with username and password.

For exemplary usage, run the FstAPI app with a *WSGI* server (recommended for production) or with a `TestClient` (recommended for production only).

If the service is up and running, access the endpoint of the service as a client:

```py
import requests

URL = "http://localhost:8080/protected_endpoint"

username = "your_username"
password = "your_password"

response = requests.get(URL, auth=(username, password))
print(response.json())  # prints: {"message": "Authenticated successfully!"}
```

### BasicLogin

`BasicLogin` is a subclass of `HTTPBasic` that extracts the username and password from the HTTP basic authentication header, and uses them to get an access token from Keycloak using the login function. The returned access token is then used to authenticate the request.

Example:

```py
from fastapi import FastAPI, Depends
from shieldapi.frameworks.fastapi import BasicLogin

app = FastAPI()

security = BasicLogin()

@app.get("/protected_endpoint")
async def get_user(token: str = Depends(security)):
    """
    This route is protected and authentication with user/password in order
    to generate a token.
    """
    if not token:
        raise HTTPException(
            status_code=401,
            detail="Invalid authentication credentials"
        )
    # Perform some action with the token here
    return {"message": "Authenticated successfully!"}
```

In this example, `BasicLogin` is used as a dependency of the `protected_endpoint` function. When the function is called, `BasicLogin` will extract the basic auth credentials from the request header, pass them to the login function to get an access token from Keycloak, and return the access token as a string in the `"Bearer {token}"` format. The token parameter of the protected_route function will contain the authentication token as a string in the `"Bearer {token}"` format.

For exemplary usage, run the FstAPI app with a *WSGI* server (recommended for production) or with a `TestClient` (recommended for production only).

If the service is up and running, access the endpoint of the service as a client:

```py
import requests

URL = "http://localhost:8080/protected_endpoint"

username = "your_username"
password = "your_password"

response = requests.get(URL, auth=(username, password))
print(response.json())  # prints: {"message": "Authenticated successfully!"}
```

### depends_basic_login

Alternatively to the `BasicLogin` above, the helper function `depends_basic_login` can be used:

```py
from fastapi import FastAPI, Depends
from shieldapi.frameworks.fastapi import depends_basic_login

app = FastAPI()

# Define a protected route that requires authentication
@app.get("/protected_endpoint")
async def protected_route(auth: str = Depends(depends_basic_login)):
    # Use the authentication token to access protected resources
    return {"message": "This resource is protected"}
```

## Contributing

Contributions in the form of issues, comments, and pull request are very welcome.

To make code contributions, please fork this repository, and then create a pull request.
For development you will need to setup a Python environment (with a recent Python version), install the development requirements, and the pre-commit hooks with:

```bash
pip install .[dev]
pre-commit install
```

## Tests

Tests for this repository are implemented via [pytest](https://pytest.org/).
To run these tests, first install the test dependencies with

```bash
pip install '.[tests]'
```

and then run the tests with the `pytest` command.

## For maintainers

To create a new release, clone the repository, install development dependencies with `pip install -e '.[dev]'`, and then execute `bumpver update --[major|minor|patch]`.
This will:

1. Create a tagged release with bumped version and push it to the repository.
1. Trigger a GitHub actions workflow that creates a GitHub release and publishes it on PyPI.

Additional notes:

- The project follows semantic versioning.
- Use the `--dry` option to preview the release change.

## Acknowledgements

This work is supported by the MarketPlace project funded by [Horizon 2020](https://ec.europa.eu/programmes/horizon2020/) under the H2020-NMBP-25-2017 call (Grant No. 760173).

## License

The code is licensed under BSD-3-Clause.
Copyright © 2025 Materials MarketPlace

import logging
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("shieldapi")


def check_mandatory_env_vars():
    """
    Checks if all mandatory environment variables are set.
    Raises an EnvironmentError if any are missing.
    """
    mandatory_vars = [
        "KEYCLOAK_HOST",
        "KEYCLOAK_REALM_NAME",
        "KEYCLOAK_CLIENT_ID",
        "KEYCLOAK_CLIENT_SECRET",
    ]

    missing_vars = [var for var in mandatory_vars if not os.environ.get(var)]

    if missing_vars:
        logger.critical(
            "Missing mandatory environment variables: %s", ", ".join(missing_vars)
        )


check_mandatory_env_vars()

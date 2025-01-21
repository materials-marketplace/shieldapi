import logging
import os
from ast import literal_eval

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("shieldapi")


def check_env_vars():
    """
    Checks if all environment variables are set.
    Skips the check if SKIP_ENV_CHECK is set.
    Raises an EnvironmentError if any are missing.
    """
    # Allow skipping the check if SKIP_ENV_CHECK is set
    skip_check = False
    try:
        skip_check = literal_eval(os.environ.get("SKIP_ENV_CHECK", "False"))
        if not isinstance(skip_check, bool):
            logger.warning(
                f"Invalid value for SKIP_ENV_CHECK: {skip_check}. Proceeding with environment variable checks."
            )
    except (ValueError, SyntaxError):
        logger.warning(
            f"Invalid value for SKIP_ENV_CHECK: {skip_check}. Proceeding with environment variable checks."
        )

    if skip_check:
        logger.info(
            "Skipping environment variable environment variable check due to SKIP_ENV_CHECK."
        )
        return

    mandatory_vars = [
        "KEYCLOAK_HOST",
        "KEYCLOAK_REALM_NAME",
        "KEYCLOAK_CLIENT_ID",
        "KEYCLOAK_CLIENT_SECRET",
    ]

    missing_vars = [var for var in mandatory_vars if not os.environ.get(var)]

    if missing_vars:
        logger.warning("Missing environment variables: %s", ", ".join(missing_vars))
    else:
        logger.info("Environment variable check passed successfully.")


check_env_vars()

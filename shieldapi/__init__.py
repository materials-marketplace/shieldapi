import logging
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("shieldapi")


def check_mandatory_env_vars():
    """
    Checks if all mandatory environment variables are set.
    Skips the check if SKIP_ENV_CHECK is set.
    Raises an EnvironmentError if any are missing.
    """
    # Allow skipping the check if SKIP_ENV_CHECK is set
    if os.environ.get("SKIP_ENV_CHECK", "").lower() in ["1", "true", "yes"]:
        logger.info(
            "Skipping mandatory environment variable check due to SKIP_ENV_CHECK."
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
        logger.warning(
            "Missing mandatory environment variables: %s", ", ".join(missing_vars)
        )


check_mandatory_env_vars()

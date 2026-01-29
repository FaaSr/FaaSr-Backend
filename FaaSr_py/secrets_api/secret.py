import logging
import os
from typing import Any

logger = logging.getLogger(__name__)


def faasr_secret_gh(secret_name: str) -> str:
    """
    Retrieves a secret from the GitHub Actions secret store.

    Arguments:
        secret_name: str -- name of the secret to retrieve

    Returns:
        str -- the secret value

    Raises:
        KeyError: If secret is not found in environment variables
    """
    secret_value = os.getenv(secret_name)
    if secret_value is None:
        err_msg = f"faasr_secret: Secret '{secret_name}' not found in environment variables"
        logger.error(err_msg)
        raise KeyError(err_msg)
    return secret_value


def faasr_secret(faasr_payload: dict[str, Any], secret_name: str) -> str:
    """
    Retrieves a secret from the compute server's secret store.

    Arguments:
        faasr_payload: FaaSr payload dict
        secret_name: str -- name of the secret to retrieve

    Returns:
        str -- the secret value

    Raises:
        ValueError: If secret_name is empty
        RuntimeError: If compute server type cannot be determined
        KeyError: If secret is not found in environment (GitHub Actions)
        NotImplementedError: If compute server is not GitHub Actions
    """
    # Validate secret name
    if not secret_name:
        err_msg = "faasr_secret: secret_name cannot be empty"
        logger.error(err_msg)
        raise ValueError(err_msg)

    # Get current function name
    current_action = faasr_payload.get("FunctionInvoke", "")
    if not current_action:
        err_msg = "faasr_secret: Cannot determine current function from payload"
        logger.error(err_msg)
        raise RuntimeError(err_msg)

    # Get action configuration
    try:
        action_config = faasr_payload["ActionList"][current_action]
    except KeyError:
        err_msg = f"faasr_secret: Function {current_action} not found in ActionList"
        logger.error(err_msg)
        raise RuntimeError(err_msg)

    # Get server name
    try:
        server_name = action_config["FaaSServer"]
    except KeyError:
        err_msg = f"faasr_secret: FaaSServer not found for function {current_action}"
        logger.error(err_msg)
        raise RuntimeError(err_msg)

    # Get server type
    try:
        server_config = faasr_payload["ComputeServers"][server_name]
        server_type = server_config["FaaSType"]
    except KeyError:
        err_msg = f"faasr_secret: Compute server {server_name} not found or missing FaaSType"
        logger.error(err_msg)
        raise RuntimeError(err_msg)

    # Handle different compute server types
    match server_type:
        case "GitHubActions":
            return faasr_secret_gh(secret_name)
        case _:
            # Other compute servers are not yet supported
            err_msg = (
                f"faasr_secret: Compute server type '{server_type}' is not supported. "
                f"Only GitHubActions is currently supported."
            )
            logger.error(err_msg)
            raise NotImplementedError(err_msg)

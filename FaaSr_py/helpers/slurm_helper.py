import base64
import json
import logging
import time
from datetime import datetime

import requests

logger = logging.getLogger(__name__)


def validate_jwt_token(token):
    """
    Validates JWT tokens for SLURM authentication
    Checks token format, decodes payload, and verifies expiration

    Arguments:
        token: str -- JWT token string to validate
    Returns:
        dict: {"valid": bool, "error": str}
    """
    if not token or not token.startswith("eyJ"):
        return {"valid": False, "error": "Invalid token format"}

    try:
        # Decode JWT payload
        parts = token.split(".")
        if len(parts) < 2:
            return {"valid": False, "error": "Malformed JWT token"}

        payload = parts[1]
        # Add padding if necessary
        padding = 4 - (len(payload) % 4)
        if padding != 4:
            payload += "=" * padding

        # Decode base64
        decoded_bytes = base64.b64decode(payload)
        decoded_json = decoded_bytes.decode("utf-8")
        payload_data = json.loads(decoded_json)

        # Check expiration
        if payload_data.get("exp"):
            current_time = time.time()
            if current_time >= payload_data["exp"]:
                exp_time = datetime.fromtimestamp(payload_data["exp"])
                return {"valid": False, "error": f"Token expired at {exp_time}"}

        return {"valid": True, "error": None}

    except Exception as e:
        return {"valid": False, "error": f"Token validation error: {str(e)}"}


def create_job_script(faasr, original_function,actionname, environment_vars):
    """
    Create SLURM job script for FaaSr execution

    Arguments:
        faasr: FaaSrPayload -- workflow payload
        actionname: str -- name of the action
    Returns:
        str: job script content
    """
    
    action_containers = faasr.get("ActionContainers", {})
    if original_function in action_containers and action_containers[original_function]:
        container_image = action_containers[original_function]
    else:
        container_image = "faasr/slurm-r:latest"

    env_exports = ""
    docker_env_flags = ""

    if environment_vars:
        env_exports += "\n# Set environment variables\n"
        for key, value in environment_vars.items():

            escaped_value = str(value).replace("'", "'\"'\"'").replace("$", "\\$")

            env_exports += f"export {key}='{escaped_value}'\n"

            docker_env_flags += f"  -e {key} \\\n"

    script_lines = [
        "#!/bin/bash",
        f"#SBATCH --job-name={actionname}",
        f"#SBATCH --output={actionname}-%j.out",
        f"#SBATCH --error={actionname}-%j.err",
        "#SBATCH --exclusive",
        "",
        f'echo "Starting FaaSr job: {actionname}"',
        'echo "Job ID: $SLURM_JOB_ID"',
        'echo "Node: $SLURMD_NODENAME"',
        'echo "Time: $(date)"',
        "",
        env_exports,
        "",
        'echo "Environment variables set:"',
        'echo "PAYLOAD_URL: $PAYLOAD_URL"',
        'echo "OVERWRITTEN length: ${#OVERWRITTEN}"',
        'echo "FAASR_PLATFORM: $FAASR_PLATFORM"',
        "",
        f'echo "Using container image: {container_image}"',
        "",
        "docker run --rm --network=host \\",
        docker_env_flags.rstrip(" \\\n") + " \\",
        f"  {container_image}",
        "",
        f'echo "FaaSr job completed: {actionname}"',
        'echo "End time: $(date)"',
    ]

    return "\n".join(script_lines)


def get_resource_requirements(faasr, original_function, server_info):
    """
    Extract resource requirements for a function with fallback hierarchy:
    Function-level → Server-level → Default values

    Arguments:
        faasr: FaaSrPayload -- workflow payload
        actionname: str -- name of the action/function
        server_info: dict -- server configuration information
    Returns:
        dict: resource requirements
    """
    action_list = faasr.get("ActionList", {})
    action_config = action_list.get(original_function, {})

    # Function-level resources (highest priority)
    function_resources = action_config.get("Resources", {})

    # Extract with fallback hierarchy: Function → Server → Default
    config = {
        "partition": (
            function_resources.get("Partition")
            or server_info.get("Partition")
            or "faasr"
        ),
        "nodes": (function_resources.get("Nodes") or server_info.get("Nodes") or 1),
        "tasks": (function_resources.get("Tasks") or server_info.get("Tasks") or 1),
        "cpus_per_task": (
            function_resources.get("CPUsPerTask") or server_info.get("CPUsPerTask") or 1
        ),
        "memory_mb": (
            function_resources.get("Memory") or server_info.get("Memory") or 1024
        ),
        "time_limit": (
            function_resources.get("TimeLimit") or server_info.get("TimeLimit") or 60
        ),
        "working_dir": (
            function_resources.get("WorkingDirectory")
            or server_info.get("WorkingDirectory")
            or "/tmp"
        ),
    }

    return config


def make_slurm_request(
    endpoint, method="GET", headers=None, body=None, token=None, username=None
):
    """
    Helper function to send HTTP requests to SLURM REST API

    Arguments:
        endpoint: str -- full URL endpoint
        method: str -- HTTP method
        headers: dict -- HTTP headers
        body: dict -- request body (optional)
        token: str -- JWT token from server configuration
        username: str -- username from server configuration
    Returns:
        requests.Response: HTTP response object
    """

    if headers is None:
        headers = {}

    if not token or not token.strip():
        logger.error(
            "SLURM token is required - server will close connection without authentication"
        )
        raise ValueError("SLURM token is required for authentication")

    token = token.strip()
    if not token.startswith("eyJ"):
        logger.error(
            f"Token doesn't look like JWT (should start with 'eyJ'): {token[:10]}..."
        )
        raise ValueError("Invalid JWT token format")

    headers["X-SLURM-USER-TOKEN"] = token
    headers["X-SLURM-USER-NAME"] = username or "ubuntu"
    headers["Accept"] = "application/json"

    if method.upper() == "POST":
        headers["Content-Type"] = "application/json"

        if method.upper() == "GET":
            response = requests.get(url=endpoint, headers=headers, timeout=30)
        elif method.upper() == "POST":
            response = requests.post(
                url=endpoint, headers=headers, json=body, timeout=30
            )
        elif method.upper() == "PUT":
            response = requests.put(
                url=endpoint, headers=headers, json=body, timeout=30
            )
        elif method.upper() == "DELETE":
            response = requests.delete(url=endpoint, headers=headers, timeout=30)
        else:
            raise ValueError(f"Unsupported HTTP method: {method}")

        return response

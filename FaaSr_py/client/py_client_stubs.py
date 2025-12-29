import sys

import requests


def faasr_put_file(
    local_file, remote_file, server_name="", local_folder=".", remote_folder="."
):
    """
    Uploads a file to the FaaSr server
    """
    request_json = {
        "ProcedureID": "faasr_put_file",
        "Arguments": {
            "local_file": str(local_file),
            "remote_file": str(remote_file),
            "server_name": server_name,
            "local_folder": str(local_folder),
            "remote_folder": str(remote_folder),
        },
    }
    r = requests.post("http://127.0.0.1:8000/faasr-action", json=request_json)
    try:
        response = r.json()
        if response.get("Success", False):
            return True
        else:
            err_msg = '{"faasr_put_file": "Request to FaaSr RPC failed"}'
            print(err_msg)
            sys.exit(1)
    except Exception as e:
        err_msg = (
            f'{{"faasr_put_file": "Failed to parse response from FaaSr RPC -- {e}"}}'
        )
        print(err_msg)
        sys.exit(1)


def faasr_get_file(
    local_file, remote_file, server_name="", local_folder=".", remote_folder="."
):
    """
    Downloads a file from the FaaSr server
    """
    request_json = {
        "ProcedureID": "faasr_get_file",
        "Arguments": {
            "local_file": str(local_file),
            "remote_file": str(remote_file),
            "server_name": server_name,
            "local_folder": str(local_folder),
            "remote_folder": str(remote_folder),
        },
    }
    r = requests.post("http://127.0.0.1:8000/faasr-action", json=request_json)
    try:
        response = r.json()
        if response.get("Success", False):
            return True
        else:
            err_msg = '{"faasr_get_file": "Request to FaaSr RPC failed"}'
            print(err_msg)
            sys.exit(1)
    except Exception as e:
        err_msg = (
            f'{{"faasr_get_file": "Failed to parse response from FaaSr RPC -- {e}"}}'
        )
        print(err_msg)
        sys.exit(1)


def faasr_delete_file(remote_file, server_name="", remote_folder=""):
    """
    Deletes a file from the FaaSr server
    """
    request_json = {
        "ProcedureID": "faasr_delete_file",
        "Arguments": {
            "remote_file": str(remote_file),
            "server_name": server_name,
            "remote_folder": str(remote_folder),
        },
    }
    r = requests.post("http://127.0.0.1:8000/faasr-action", json=request_json)
    try:
        response = r.json()
        if response.get("Success", False):
            return True
        else:
            err_msg = '{"faasr_delete_file": "Request to FaaSr RPC failed"}'
            print(err_msg)
            sys.exit(1)
    except Exception as e:
        err_msg = (
            f'{{"faasr_delete_file": "Failed to parse response from FaaSr RPC -- {e}"}}'
        )
        print(err_msg)
        sys.exit(1)


def faasr_log(log_message):
    """
    Logs a message to the FaaSr server log
    """
    if not log_message:
        err_msg = "{py_client_stub: ERROR -- faasr_log called with empty log_message}"
        print(err_msg)
        sys.exit(1)
    request_json = {
        "ProcedureID": "faasr_log",
        "Arguments": {"log_message": log_message},
    }
    r = requests.post("http://127.0.0.1:8000/faasr-action", json=request_json)
    try:
        response = r.json()
        if response.get("Success", False):
            return True
        else:
            err_msg = '{"faasr_log": "Request to FaaSr RPC failed"}'
            print(err_msg)
            sys.exit(1)
    except Exception as e:
        err_msg = f'{{"faasr_log": "Failed to parse response from FaaSr RPC -- {e}"}}'
        print(err_msg)
        sys.exit(1)


def faasr_get_folder_list(server_name="", prefix=""):
    """
    Get the list of folders from the FaaSr server
    """
    request_json = {
        "ProcedureID": "faasr_get_folder_list",
        "Arguments": {"server_name": server_name, "prefix": str(prefix)},
    }
    r = requests.post("http://127.0.0.1:8000/faasr-action", json=request_json)
    try:
        response = r.json()
        return response["Data"]["folder_list"]
    except Exception as e:
        err_msg = f"{{py_client_stub: failed to get folder list from server -- {e}}}"
        print(err_msg)
        sys.exit(1)


def faasr_rank():
    """
    Get the rank and max rank of the current function as a namedtuple (rank, max_rank)
    """
    request_json = {"ProcedureID": "faasr_rank", "Arguments": {}}
    r = requests.post("http://127.0.0.1:8000/faasr-action", json=request_json)
    try:
        response = r.json()
        return response["Data"]
    except Exception as e:
        err_msg = f"{{py_client_stub: failed to get rank from server -- {e}}}"
        print(err_msg)
        sys.exit(1)


def faasr_get_s3_creds():
    """
    Get S3 credentials from the server

    Returns:
        dict -- S3 credentials
    """
    request_json = {"ProcedureID": "faasr_get_s3_creds", "Arguments": {}}
    r = requests.post("http://127.0.0.1:8000/faasr-action", json=request_json)
    try:
        response = r.json()
        return response["Data"]["s3_creds"]
    except Exception as e:
        err_msg = (
            f"{{faasr_get_s3_creds: failed to get S3 credentials from server -- {e}}}"
        )
        print(err_msg)
        sys.exit(1)


def faasr_secret(secret_name: str) -> str:
    """
    Get a secret from the compute server's secret store

    Arguments:
        secret_name: str -- name of the secret to retrieve

    Returns:
        str -- the secret value
    """
    if not secret_name:
        err_msg = "{py_client_stub: ERROR -- faasr_secret called with empty secret_name}"
        print(err_msg)
        sys.exit(1)

    request_json = {
        "ProcedureID": "faasr_secret",
        "Arguments": {"secret_name": secret_name},
    }

    r = requests.post("http://127.0.0.1:8000/faasr-action", json=request_json)

    try:
        response = r.json()
        if response.get("Success", False):
            return response["Data"]["secret_value"]
        else:
            err_msg = '{"faasr_secret": "Request to FaaSr RPC failed"}'
            print(err_msg)
            sys.exit(1)
    except Exception as e:
        err_msg = (
            f'{{"faasr_secret": "Failed to parse response from FaaSr RPC -- {e}"}}'
        )
        print(err_msg)
        sys.exit(1)


def faasr_invocation_id():
    """
    Get the invocation ID of the current function

    Returns:
        str -- invocation ID
    """
    request_json = {"ProcedureID": "faasr_invocation_id", "Arguments": {}}
    r = requests.post("http://127.0.0.1:8000/faasr-action", json=request_json)
    try:
        response = r.json()
        return response["Data"]["invocation_id"]
    except Exception as e:
        err_msg = (
            f"{{faasr_invocation_id: failed to get invocation ID from server -- {e}}}"
        )
        print(err_msg)
        sys.exit(1)


def faasr_return(return_value=None):
    """
    Returns the result of the user function to the FaaSr server
    Arguments:
        return_value: bool -- the return value of the user function
    """
    return_json = {"FunctionResult": return_value}
    r = requests.post("http://127.0.0.1:8000/faasr-return", json=return_json)
    try:
        response = r.json()
        if response.get("Success", False):
            sys.exit(0)
        else:
            err_msg = '{"faasr_return": "Request to FaaSr RPC failed"}'
            print(err_msg)
            sys.exit(1)
    except Exception as e:
        err_msg = (
            f'{{"faasr_return": "Failed to parse response from FaaSr RPC -- {e}"}}'
        )
        print(err_msg)
        sys.exit(1)


def faasr_exit(message=None, error=True, traceback=None):
    exit_json = {"Error": error, "Message": message, "Traceback": traceback}
    r = requests.post("http://127.0.0.1:8000/faasr-exit", json=exit_json)
    try:
        response = r.json()
        if response.get("Success", False):
            sys.exit(0)
        else:
            err_msg = '{"faasr_exit": "Request to FaaSr RPC failed"}'
            print(err_msg)
            sys.exit(1)
    except Exception as e:
        err_msg = f'{{"faasr_exit": "Failed to parse response from FaaSr RPC -- {e}"}}'
        print(err_msg)
        sys.exit(1)

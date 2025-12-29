import logging
from pathlib import Path

from FaaSr_py.client.py_client_stubs import (
    faasr_delete_file,
    faasr_exit,
    faasr_get_file,
    faasr_get_folder_list,
    faasr_get_s3_creds,
    faasr_log,
    faasr_put_file,
    faasr_rank,
    faasr_return,
)
from FaaSr_py.config.debug_config import global_config
from FaaSr_py.helpers.py_func_helper import (
    faasr_import_function,
    faasr_import_function_walk,
    local_wrap,
)

logger = logging.getLogger(__name__)


def run_py_function(faasr, func_name, args, func_path=None):
    """
    Entry for Python function process

    Arguments:
        faasr: FaaSr payload instance
        func_name: name of function to run
        args: arguments for function (dict)
    """
    try:
        if global_config.USE_LOCAL_USER_FUNC:
            func_path = Path(global_config.LOCAL_FUNCTION_PATH).resolve()
            func_name = global_config.LOCAL_FUNCTION_NAME

            user_function = faasr_import_function(func_path, func_name)
        else:
            user_function = faasr_import_function_walk(
                func_name, directory=f"/tmp/functions/{faasr['InvocationID']}"
            )
    except Exception as e:
        err_msg = f"failed to get user functions -- error: {e}"
        faasr_exit(err_msg)

    # Ensure user function is present
    if not user_function:
        err_msg = f"{{py_user_func_entry.py: cannot find function {func_name}}}"
        faasr_exit(err_msg)

    # Add FaaSr client stubs to user function's namespace
    user_function.__globals__["faasr_put_file"] = faasr_put_file
    user_function.__globals__["faasr_get_file"] = faasr_get_file
    user_function.__globals__["faasr_delete_file"] = faasr_delete_file
    user_function.__globals__["faasr_get_folder_list"] = faasr_get_folder_list
    user_function.__globals__["faasr_log"] = faasr_log
    user_function.__globals__["faasr_rank"] = faasr_rank
    user_function.__globals__["faasr_get_s3_creds"] = faasr_get_s3_creds

    try:
        if global_config.USE_LOCAL_USER_FUNC:
            print(f"using local function {global_config.LOCAL_FUNCTION_NAME}")
            result = local_wrap(user_function)(**global_config.LOCAL_FUNC_ARGS)
        else:
            result = user_function(**args)
    except Exception as e:
        import traceback

        traceback = traceback.format_exc()
        faasr_exit(message=str(e), traceback=traceback)

    faasr_return(result)

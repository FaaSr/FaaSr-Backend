import importlib
import logging
import os
import sys
import uuid

logger = logging.getLogger(__name__)


def local_wrap(function):
    """
    Wraps stdout of debug function
    """

    def formatting(*args, **kwargs):
        print("-----------------LOCAL FUNC OUTPUT-----------------")
        print(f"ARGS: {args}")
        print(f"KWARGS: {kwargs}")
        result = function(*args, **kwargs)
        print("---------------------------------------------------")
        return result

    return formatting


def faasr_import_function(path, func_name):
    """
    Returns a function object given name and absolute path

    Arguments:
        path: str -- absolute path to local function
        func_name: str -- name of function to import
    Returns:
        function: function object | None
    """
    if not path.exists():
        raise FileNotFoundError("ERROR -- path to local function does not exist")

    # load module
    module_name = str(uuid.uuid4())
    spec = importlib.util.spec_from_file_location(module_name, str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    # get function
    for name, obj in module.__dict__.items():
        if name == func_name and callable(obj):
            return obj

    return None


def faasr_import_function_walk(func_name, directory="."):
    """
    Walks directory until it finds function

    Arguments:
        func_name: str -- name of function to import
        directory: str -- directory to walk
    Returns:
        function: function object | None
    """
    ignore_files = [
        "test_gh_invoke.py",
        "test.py",
        "func_test.py",
        "faasr_start_invoke_helper.py",
        "faasr_start_invoke_openwhisk.py",
        "faasr_start_invoke_aws-lambda.py",
        "faasr_start_invoke_github_actions.py",
    ]
    directory = os.path.abspath(directory)

    if directory not in sys.path:
        sys.path.insert(0, directory)

    for root, _, files in os.walk(directory):
        py_files = [file for file in files if file.endswith(".py")]
        for f in py_files:
            if f not in ignore_files:
                logger.info(f"Source python file {f}")
                try:
                    rel_path = os.path.relpath(root, directory)
                    if rel_path == ".":
                        # file is in the base directory
                        module_name = os.path.splitext(f)[0]
                    else:
                        # file is in a subdirectory
                        module_path = os.path.join(rel_path, os.path.splitext(f)[0])
                        module_name = module_path.replace(os.path.sep, ".")

                    module = importlib.import_module(module_name)

                    # return func
                    for name, obj in module.__dict__.items():
                        if name == func_name and callable(obj):
                            return obj

                except ImportError as e:
                    # Safely skip import errors when walking through files that the current function
                    # may not depend on. Still log a warning for debugging purposes.
                    logger.warning(f"Skipping {f} due to import error: {e}")
                except Exception as e:
                    logger.error(
                        f"Python file {f} has following source error: {str(e)}"
                    )
                    sys.exit(1)
    return None


def source_packages(namespace, packages):
    """
    Sources packages

    Arguments:
        namespace: __globals__ namespace of function to source packages to
        packages: list of package names
    """
    if not isinstance(packages, list):
        packages = [packages]

    for package in packages:
        try:
            namespace[package] = importlib.import_module(package)
            logger.info(f"Successfully imported package {package}")
        except ImportError as e:
            logger.error(f"Failed to import package {package} -- {e}")
            sys.exit(1)

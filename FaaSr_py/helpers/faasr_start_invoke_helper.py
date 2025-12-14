import base64
import logging
import os
import re
import shutil
import subprocess
import sys
import tarfile

import requests

from FaaSr_py.config.debug_config import global_config

logger = logging.getLogger(__name__)


def faasr_get_github_clone(faasr_payload, url, base_dir=None):
    """
    Downloads a github repo clone from the repo's url

    Arguments:
        url: HTTPS url to git repo
        base_dir: directory to which GitHub repo should be cloned
    """
    if not base_dir:
        base_dir = f"/tmp/functions/{faasr_payload['InvocationID']}"

    pattern = r"([^/]+/[^/]+)\.git$"
    match = re.search(pattern, url)
    if not match:
        raise ValueError(
            f"Invalid GitHub URL: {url} — expected to end in owner/repo.git"
        )

    repo_name = match.group(1)
    repo_path = os.path.join(base_dir, repo_name)

    if os.path.isdir(repo_path):
        shutil.rmtree(repo_path)

    result = subprocess.run(["git", "clone", "--depth=1", url, repo_path], text=True)
    if result.returncode != 0:
        raise RuntimeError(f"Git clone failed for {url}")

    return repo_path


def faasr_get_github(faasr_source, path, token=None):
    """
    Downloads a repo specified by a github path [username/repo] to a tarball file

    Arguments:
        faasr_source: payload dict (FaaSr)
        path: username/repo/path to file
        token: GitHub PAT
    """
    parts = path.split("/")

    # split full path
    if path.startswith("https://github.com"):
        if len(parts) < 7:
            err_msg = "invalid github url (check GitHub url for function)"

        username = parts[3]
        reponame = parts[4]

        if len(parts) > 7:
            path = "/".join(parts[7:])
        else:
            path = None
    else:
        # split partial path
        # ensure path has two parts [username/repo]
        if len(parts) < 2:
            err_msg = "github path should contain at least two parts"
            logger.error(err_msg)
            sys.exit(1)

        # construct gh url
        username = parts[0]
        reponame = parts[1]

        if len(parts) > 2:
            path = "/".join(parts[2:])
        else:
            path = None

    repo = f"{username}/{reponame}"

    url = f"https://api.github.com/repos/{repo}/tarball"
    tar_name = f"/tmp/{reponame}.tar.gz"
    parent_dir = os.path.dirname(tar_name)

    if not os.path.isdir(parent_dir):
        os.makedirs(parent_dir, exist_ok=True)

    headers = {
        "Accept": "application/vnd.github.v3+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "Authorization": f"Bearer {token}" if token else None,
    }

    # send get request
    response = requests.get(
        url,
        headers=headers,
        stream=True,
    )

    # if the response code is 200 (successful), then write repo to tarball file
    if response.status_code == 200:
        with open(tar_name, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)

        with tarfile.open(tar_name) as tar:
            root_dir = tar.getnames()[0]
            extract_base = f"/tmp/functions/{faasr_source['InvocationID']}"
            os.makedirs(extract_base, exist_ok=True)

            if path:
                extract_path = os.path.join(root_dir, path)
                members = [
                    mem for mem in tar.getmembers() if mem.name.startswith(extract_path)
                ]
                tar.extractall(path=extract_base, members=members)
            else:
                tar.extractall(path=extract_base)
        os.remove(tar_name)

        if path:
            logger.info(f"Successfully downloaded GitHub repo sub folder: {path}")
        else:
            logger.info(f"Successfully downloaded GitHub repo: {repo}")
    else:
        try:
            err_response = response.json()
            message = err_response.get("message")
        except Exception:
            message = "invalid or no response from GH"
        logger.error(message)
        sys.exit(1)


def faasr_get_github_raw(token, path):
    """
    Gets the contents of a single file on GitHub

    Arguments:
        token: GitHub PAT
        path: username/repo/path to file

    Returns:
        Raw GitHub file (UTF-8 string)
    """
    # split full url
    if path.startswith("https://github.com"):
        parts = path.split("/")

        if len(parts) < 7 or parts[5] != "blob":
            err_msg = "invalid github url (check GitHub url for function)"

        username = parts[3]
        reponame = parts[4]
        branch = parts[6]
        filepath = "/".join(parts[7:])
    else:
        # split owner/repo/path
        parts = path.split("/")
        if len(parts) < 3:
            err_msg = "github path should contain at least three parts"
            logger.error(err_msg)
            sys.exit(1)

        username = parts[0]
        reponame = parts[1]
        branch = parts[2]
        filepath = "/".join(parts[3:])

    url = f"https://api.github.com/repos/" f"{username}/{reponame}/contents/{filepath}"
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "Authorization": f"Bearer {token}" if token else None,
    }

    response = requests.get(url, headers=headers, params={"ref": branch})

    if response.status_code == 200:
        logger.debug(f"Successfully fetched raw file from GitHub: {path}")
        data = response.json()
        content = data.get("content", "")
        decoded_bytes = base64.b64decode(content)
        decoded_string = decoded_bytes.decode("utf-8")
        return decoded_string
    else:
        try:
            err_response = response.json()
            message = err_response.get("message")
        except Exception:
            message = "invalid or no response from GH"
        logger.error(f"Failed to fetch raw file from GitHub: {path} -- {message}")
        sys.exit(1)


def faasr_install_git_repos(faasr_source, gits, token):
    """
    Downloads content from git repo(s)

    Arguments:
        faasr_source: faasr payload (FaaSr)
        gits: paths repos or files to download
        token: GitHub PAT
    """
    if isinstance(gits, str):
        gits = {gits}
    if not gits:
        logger.info("No git repo dependency")
    else:
        # download content from each path
        for path in gits:
            # if path is a repo, clone the repo
            if path.startswith("https://github.com") and len(path.split("/")) == 5:
                logger.info(f"Cloning GitHub repo: {path}")
                faasr_get_github_clone(faasr_source, path)
            else:
                # if path is a python file, download
                file_name = os.path.basename(path)
                if (file_name.lower().endswith(".py") or file_name.lower().endswith(".r")
                ):
                    logger.info(f"Get file: {file_name}")
                    content = faasr_get_github_raw(token, path)
                    target_dir = f"/tmp/functions/{faasr_source['InvocationID']}"
                    if not os.path.exists(target_dir):
                        os.makedirs(target_dir, exist_ok=True)
                    # write fetched file to disk
                    with open(os.path.join(target_dir, file_name), "w") as f:
                        f.write(content)
                else:
                    # if the path is a non-python file, download the repo
                    logger.info(f"Get git repo files: {path}")
                    faasr_get_github(faasr_source, path, token)


def faasr_pip_install(package):
    """
    Pip installs a single PyPI package
    """
    # run pip install [package] command
    if not package:
        logger.info("No PyPI package dependency")
    else:
        command = ["pip", "install", "--no-input", package]
        subprocess.run(command, text=True)


def faasr_install_cran(package, lib_path=None):
    """
    Installs a single CRAN package non-interactively
    """
    if not package:
        logger.info("No CRAN package dependency")
        return

    logger.info(f"Installing CRAN package: {package}")
    lib_path = lib_path or "/tmp/Rlibs"
    os.makedirs(lib_path, exist_ok=True)

    command = [
        "Rscript",
        "-e",
        f'.libPaths(c("{lib_path}", .libPaths())); '
        f'install.packages("{package}", lib="{lib_path}", '
        f'repos="https://cloud.r-project.org", verbose=TRUE)',
    ]

    result = subprocess.run(command, text=True, capture_output=True)

    if result.returncode != 0:
        logger.error(
            f"Failed to install {package}:\n"
            f"std err: {result.stderr}\n"
            f"std out: {result.stdout}"
        )
        raise RuntimeError(f"Install failed for {package}")
    else:
        logger.info(f"Successfully installed {package}")


def faasr_pip_gh_install(path):
    """
    Installs a single package specified via a github path (name/path) using pip
    """
    parts = path.split("/")
    if len(parts) < 2:
        logger.error("GitHub path should contain at least two parts")
        sys.exit(1)

    # construct gh url
    username = parts[0]
    reponame = parts[1]
    repo = f"{username}/{reponame}"
    gh_url = f"git+https://github.com/{repo}.git"

    command = ["pip", "install", "--no-input", gh_url]
    subprocess.run(command, text=True)


def faasr_install_git_packages(gh_packages, type, lib_path=None):
    """
    Install a list of git packages
    """
    if not gh_packages:
        logger.info("No git package dependency")
    else:
        # install each package
        for package in gh_packages:
            logger.info(f"Install GitHub package {package}")
            if type == "Python":
                faasr_pip_gh_install(package)
            elif type == "R":
                if lib_path:
                    lib_path = f'"{lib_path}"'
                else:
                    lib_path = ".libPaths()[1]"
                command = [
                    "Rscript",
                    "-e",
                    (
                        f"withr::with_libpaths("
                        f'new="{lib_path}", '
                        f'code=quote(devtools::install_github("{package}", force=TRUE)))'
                    ),
                ]
                res = subprocess.run(command, text=True)
                if res.returncode != 0:
                    logger.info("STDOUT:", res.stdout)
                    logger.info("STDERR:", res.stderr)
                    raise RuntimeError(f"Installation failed for {package}")


def copy_local_files(faasr_source, gits):
    """Copies local files to /tmp/functions/[InvocationID]"""
    if not gits:
        return

    if isinstance(gits, str):
        gits = [gits]

    for f in gits:
        if os.path.isfile(f):
            func_folder = f"/tmp/functions/{faasr_source['InvocationID']}"

            dest = os.path.join(func_folder, f)

            if not os.path.isdir(os.path.dirname(dest)):
                os.makedirs(os.path.dirname(dest), exist_ok=True)

            shutil.copy(f, dest)
        else:
            logger.error(f"FunctionLocalFile not found: {f}")
            sys.exit(1)


def faasr_func_dependancy_install(faasr_source, action):
    """
    Installs the dependencies for an action's function

    Arguments:
        faasr_source: faasr payload (FaaSr)
        action: name of current action
    """
    func_type, func_name = action["Type"], action["FunctionName"]

    # get token if present
    token = os.getenv("GH_PAT")

    if not token:
        logger.warning(
            "No GitHub token used. May hit rate limits when installing functions."
        )

    if not global_config.USE_LOCAL_USER_FUNC:
        # get files from git repo
        if "FunctionGitRepo" in faasr_source:
            remote_gits = faasr_source["FunctionGitRepo"].get(func_name)
        else:
            remote_gits = None

        if "FunctionLocalFile" in faasr_source:
            local_gits = faasr_source.get("FunctionLocalFile").get(func_name)
        else:
            local_gits = None

        if remote_gits and local_gits:
            err_msg = "Cannot have both FunctionGitRepo and FunctionLocalFile"
            logger.critical(err_msg)
            raise RuntimeError(err_msg)

        if remote_gits:
            # get gh functions
            faasr_install_git_repos(faasr_source, remote_gits, token)
        else:
            # copy local files to /tmp/functions/{InvocationID}
            copy_local_files(faasr_source, local_gits)

    if "PyPIPackageDownloads" in faasr_source and func_type == "Python":
        if "PyPIPackageDownloads" in faasr_source and func_type == "Python":
            pypi_packages = faasr_source["PyPIPackageDownloads"].get(func_name)
            if pypi_packages:
                for package in pypi_packages:
                    faasr_pip_install(package)

    elif "FunctionCRANPackage" in faasr_source and func_type == "R":
        if "FunctionCRANPackage" in faasr_source:
            cran_packages = faasr_source["FunctionCRANPackage"].get(func_name)

        lib_path = "/tmp/Rlibs"
        os.makedirs(lib_path, exist_ok=True)

        if cran_packages:
            for package in cran_packages:
                faasr_install_cran(package, lib_path)

        logger.debug(f"Packages in /tmp/Rlibs: {os.listdir('/tmp/Rlibs')}")

    # install gh packages
    if "FunctionGitHubPackage" in faasr_source:
        if func_name in faasr_source["FunctionGitHubPackage"]:
            gh_packages = faasr_source["FunctionGitHubPackage"].get(func_name)
            if gh_packages:
                if func_type == "Python":
                    faasr_install_git_packages(gh_packages, func_type)
                elif func_type == "R":
                    faasr_install_git_packages(gh_packages, func_type, "/tmp/Rlibs")
                else:
                    err_msg = "Invalid function type: {func_type}"
                    logger.critical(err_msg)
                    raise RuntimeError(err_msg)

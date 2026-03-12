import json
import logging
import random
import sys
import os
import uuid
import botocore
from datetime import datetime
from pathlib import Path

import boto3

from FaaSr_py.config.debug_config import global_config
from FaaSr_py.helpers.faasr_lock import faasr_acquire, faasr_release
from FaaSr_py.helpers.faasr_start_invoke_helper import faasr_get_github_raw
from FaaSr_py.helpers.graph_functions import check_dag, validate_json
from FaaSr_py.helpers.s3_helper_functions import (
    get_default_log_boto3_client,
    get_invocation_folder,
    get_logging_server,
)

logger = logging.getLogger(__name__)


class FaaSrPayload:
    """
    - Workflow is union of base workflow (from github) and overwritten fields

    - The URL points to a GitHub file containing the workflow JSON
    - and follows the form {username}/{repo}/{path}.

    - Methods to validate the workflow, replace secrets, check S3 data stores,
    - init log, and self-abort.

    Top level changes (e.g. faasr_obj["FunctionInvoke"] = some_func)
    are tracked in self.overwritten and the scheduler will
    propgates these changes to the next functions in the workflow
    """

    def __init__(self, url, overwritten=None, token=None):
        # without PAT, larger workflows run the risk
        # of hitting rate limits when fetching payload
        if token is None:
            token = os.getenv("GH_PAT")

        if overwritten is None:
            self._overwritten = {}
        else:
            self._overwritten = overwritten

        self.url = url

        # fetch payload from gh
        logger.debug(f"Fetching workflow from GitHub URL: {url}")
        raw_payload = faasr_get_github_raw(token=token, path=url)
        self._base_workflow = json.loads(raw_payload)

        # validate payload against schema
        if global_config.SKIP_SCHEMA_VALIDATE:
            logger.info("SKIPPING SCHEMA VALIDATION")
        elif validate_json(self._base_workflow):
            pass
        else:
            raise ValueError("Payload validation error")

        # add rank to log file if present
        if self._overwritten.get("FunctionRank"):
            self.log_file = f"{self['FunctionInvoke']}({self['FunctionRank']}).txt"
        else:
            self.log_file = f"{self['FunctionInvoke']}.txt"

    def __getitem__(self, key):
        if key in self._overwritten:
            return self._overwritten[key]
        elif key in self._base_workflow:
            return self._base_workflow[key]
        raise KeyError(key)

    def __setitem__(self, key, value):
        self._overwritten[key] = value

    def __delitem__(self, key):
        present = False
        if key in self._overwritten:
            del self._overwritten[key]
            present = True
        if key in self._base_workflow:
            del self._base_workflow[key]
            present = True
            return
        if not present:
            raise KeyError(f"{key} not found in FaaSrPayload")

    def __contains__(self, item):
        return item in self._base_workflow or item in self._overwritten

    def __it__(self):
        return iter(self.get_complete_workflow().items())

    def get(self, key, default=None):
        if key in self._overwritten:
            return self._overwritten[key]
        elif key in self._base_workflow:
            return self._base_workflow[key]
        return default

    @property
    def overwritten(self):
        return self._overwritten

    @property
    def base_workflow(self):
        return self._base_workflow

    def get_complete_workflow(self):
        temp_dict = self._base_workflow.copy()
        for key, val in self._overwritten.items():
            temp_dict[key] = val
        return temp_dict

    def replace_secrets(self, secrets):
        """
        Fills credentials using secrets dict. Key names are derived from computeserver/datastore
        names

        Example keys:
        OW
            OW_APIkey
        AWS
            AWS_AccessKey
            AWS_SecretKey
        GCP
            GCP_SecretKey
        SLURM
            SLURM_Token
        Kubernetes
            K8s_Token
        GH
            GH_PAT
        Minio
            Minio_AccessKey
            Minio_SecretKey
        """

        def _get(key: str):
            val = secrets.get(key)
            if val is None:
                logger.warning(f"{key} is missing from provided secrets")
            return val

        for name, fields in self["ComputeServers"].items():
            faas_type = fields["FaaSType"]

            match faas_type:
                case "GitHubActions":
                    pat = _get(f"{name}_PAT")
                    self._base_workflow["ComputeServers"][name]["Token"] = pat

                case "Lambda":
                    access_key = _get(f"{name}_AccessKey")
                    secret_key = _get(f"{name}_SecretKey")
                    self._base_workflow["ComputeServers"][name][
                        "AccessKey"
                    ] = access_key
                    self._base_workflow["ComputeServers"][name][
                        "SecretKey"
                    ] = secret_key

                case "GoogleCloud":
                    secret_key = _get(f"{name}_SecretKey")
                    self._base_workflow["ComputeServers"][name][
                        "SecretKey"
                    ] = secret_key

                case "SLURM":
                    token = _get(f"{name}_Token")
                    self._base_workflow["ComputeServers"][name]["Token"] = token

                case "OpenWhisk":
                    api_key = _get(f"{name}_APIkey")
                    self._base_workflow["ComputeServers"][name]["APIkey"] = api_key

                case "Kubernetes":
                    token = _get(f"{name}_Token")
                    self._base_workflow["ComputeServers"][name]["Token"] = token

                case _:
                    logger.warning(f"Unknown FaaSType for {name}: {faas_type}")

        for name, fields in self["DataStores"].items():
            access_key = _get(f"{name}_AccessKey")
            secret_key = _get(f"{name}_SecretKey")
            self._base_workflow["DataStores"][name]["AccessKey"] = access_key
            self._base_workflow["DataStores"][name]["SecretKey"] = secret_key

        if "VMConfig" in self._base_workflow:
            vm_config = self._base_workflow["VMConfig"]
            vm_name = vm_config.get("Name")
            
            if vm_name:
                provider = vm_config.get("Provider", "AWS")
                
                if provider == "AWS":
                    access_key = _get(f"{vm_name}_AccessKey")
                    secret_key = _get(f"{vm_name}_SecretKey")
                    
                    if access_key:
                        self._base_workflow["VMConfig"]["AccessKey"] = access_key
                    if secret_key:
                        self._base_workflow["VMConfig"]["SecretKey"] = secret_key

    def s3_check(self):
        """
        Ensures that all of the S3 data stores are valid and reachable
        """
        # Iterate through all of the data stores
        for server in self["DataStores"].keys():
            # Get the endpoint and region
            server_endpoint = self["DataStores"][server].get("Endpoint")
            server_region = self["DataStores"][server]["Region"]
            # Ensure that endpoint is a valid http address
            if server_endpoint and not server_endpoint.startswith("http"):
                error_message = f"Invalid data store server endpoint {server}"
                logger.error(error_message)
                sys.exit(1)

            # If the region is empty, then use defualt 'us-east-1'
            if not server_region:
                self["DataStores"][server]["Region"] = "us-east-1"

            if self["DataStores"][server].get("Anonymous", False):
                # Handle anonymous access with unsigned signature for public buckets
                logger.info(f"Using anonymous access for S3 server: {server}")
                if server_endpoint:
                    s3_client = boto3.client(
                        "s3",
                        region_name=server_region,
                        endpoint_url=server_endpoint,
                        config=botocore.config.Config(signature_version=botocore.UNSIGNED)
                    )
                else:
                    s3_client = boto3.client(
                        "s3",
                        region_name=server_region,
                        config=botocore.config.Config(signature_version=botocore.UNSIGNED)
                    )
            else:
                # Authenticated access
                if server_endpoint:
                    s3_client = boto3.client(
                        "s3",
                        aws_access_key_id=self["DataStores"][server]["AccessKey"],
                        aws_secret_access_key=self["DataStores"][server]["SecretKey"],
                        region_name=server_region,
                        endpoint_url=server_endpoint,
                    )
                else:
                    s3_client = boto3.client(
                        "s3",
                        aws_access_key_id=self["DataStores"][server]["AccessKey"],
                        aws_secret_access_key=self["DataStores"][server]["SecretKey"],
                        region_name=server_region,
                    )
            # Use boto3 head bucket to ensure that the
            # bucket exists and that we have acces to it
            try:
                s3_client.head_bucket(Bucket=self["DataStores"][server]["Bucket"])
            except Exception as e:
                err_message = f"S3 server {server} failed with message: {e}"
                logger.exception(err_message, stack_info=True)
                sys.exit(1)

    def _generate_invocation_timestamp(self):
        """
        Generate InvocationTimestamp for entry point.
        Always called to ensure timestamp exists regardless of ID source.
        """

        # Only generate if not already present
        if not self.get("InvocationTimestamp"):
            current_timestamp = datetime.now()
            default_format = "%Y-%m-%dT%H-%M-%S"
            format_timestamp = current_timestamp.strftime(default_format)
            self["InvocationTimestamp"] = format_timestamp
            logger.info(f"Generated InvocationTimestamp: {format_timestamp}")
        else:
            logger.info(
                f"Using existing InvocationTimestamp: {self['InvocationTimestamp']}"
            )

    def _generate_invocation_id(self):
        """Generate InvocationID for entry point"""

        # Generate InvocationID based on configuration
        if self.get("InvocationIDFromDate"):
            # Use format to derive ID from timestamp
            date_format = self["InvocationIDFromDate"]
            timestamp_str = self["InvocationTimestamp"]
            current_timestamp = datetime.strptime(timestamp_str, "%Y-%m-%dT%H-%M-%S")

            try:
                derived_id = current_timestamp.strftime(date_format)
                self["InvocationID"] = derived_id
                logger.info(
                    f"Generated InvocationID from format '{date_format}': {derived_id}"
                )
            except ValueError as e:
                # Raise custom exception with clear context
                error_msg = (
                    f"FaaSr Configuration Error: Invalid date format '{date_format}' "
                    f"in InvocationIDFromDate. {str(e)}"
                )
                logger.error(error_msg)
                raise ValueError(error_msg)
        else:
            ID = uuid.uuid4()
            self["InvocationID"] = str(ID)
            logger.info(f"Generated default UUID : {ID}")
        logger.info(f" InvocationID: {self['InvocationID']}")

    def init_log_folder(self):
        """
        Initializes a faasr log folder if one has not already been created
        """
        logger.debug("Initializing log folder")

        self._generate_invocation_timestamp()

        invocation_id = self.get("InvocationID", "")
        if not invocation_id or invocation_id.strip() == "":
            self._generate_invocation_id()


        faasr_msg = f"InvocationID for the workflow: {self['InvocationID']}"
        logger.info(faasr_msg)

        if self["FaaSrLog"] is None or self["FaaSrLog"] == "":
            self["FaaSrLog"] = "FaaSrLog"

        # Get path to log
        log_folder = get_invocation_folder(self)

        if global_config.USE_LOCAL_FILE_SYSTEM:
            log_folder.mkdir(parents=True, exist_ok=True)
            file_count = sum(1 for p in log_folder.iterdir() if p.is_file())
            if file_count != 0:
                err_msg = f"InvocationID already exists: {self['InvocationID']}"
                logger.error(err_msg)
                sys.exit(1)
        else:
            target_s3 = get_logging_server(self)
            s3_log_info = self["DataStores"][target_s3]
            s3_client = get_default_log_boto3_client(self)

            # Check contents of log folder
            check_log_folder = s3_client.list_objects_v2(
                Prefix=str(log_folder), Bucket=s3_log_info["Bucket"]
            )

            # If there already is a log, log error and abort; otherwise, create log
            if (
                "Contents" in check_log_folder
                and len(check_log_folder["Contents"]) != 0
            ):
                err_msg = f"InvocationID already exists: {self['InvocationID']}"
                logger.error(err_msg)
                sys.exit(1)

    def abort_on_multiple_invocations(self, pre):
        """
        Invoked when the current function has multiple predecessors
        and aborts if they have not finished or the current function instance was not
        the first to write to the candidate set
        """
        id_folder = get_invocation_folder(self)

        if global_config.USE_LOCAL_FILE_SYSTEM:
            log_folder = Path(global_config.LOCAL_FILE_SYSTEM_DIR) / id_folder
            for func in pre:
                done_file = log_folder / f"function_completions/{func}.done"
                if not done_file.exists():
                    logger.error(
                        f"Missing .done file for predecessor: {func} — aborting."
                    )
                    sys.exit(0)

            # Check candidate set
            self.check_candidate_set(id_folder)
        else:
            target_s3 = get_logging_server(self)
            s3_log_info = self["DataStores"][target_s3]

            # Get boto3 client for default data store
            s3_client = get_default_log_boto3_client(self)

            # First, we check if all of the other predecessor actions are done
            # To do this, we check a file called func.done in S3
            # and see if all of the other actions have written that they are "done"
            # If all predecessor's are not finished, then this action aborts
            s3_list_object_response = s3_client.list_objects_v2(
                Bucket=s3_log_info["Bucket"], Prefix=str(id_folder)
            )
            s3_contents = s3_list_object_response.get("Contents", [])

            s3_object_keys = []
            for object in s3_contents:
                if "Key" in object:
                    s3_object_keys.append(object["Key"])

            for func in pre:
                # check if all of the predecessor func.done objects exist
                done_file = f"{id_folder}/function_completions/{func}.done"

                # if .done does not exist for a function,
                # then the current function is still waiting for
                # a predecessor and must abort
                if done_file not in s3_object_keys:
                    logger.error(
                        f"Missing .done file for predecessor: {func} — aborting."
                    )
                    sys.exit(0)

            # Check candidate set
            self.check_candidate_set(id_folder, s3_log_info, s3_client)

    def check_candidate_set(self, id_folder, s3_log_info=None, s3_client=None):
        """
        This code is reached only if all predecessors are done.
        Now, we need to select only one action to proceed.
        We use a weak spinlock implementation over S3 to implement atomic
        read/modify/write operations and avoid a race condition.

        Between lock acquire and release, we do the following:
        1) download the "FunctionInvoke.candidate" file from S3.
        2) append a random number to the local file, which is generated by this Action
        3) upload the file back to the S3 bucket
        4) download the file from S3
        5) if the current action was the first to write to candidate set, it "wins"
           and other actions abort
        """
        faasr_acquire(self)

        random_number = random.randint(1, 2**31 - 1)
        candidate_filename = f"{self['FunctionInvoke']}.candidate"
        candidate_path = Path(id_folder) / candidate_filename

        if global_config.USE_LOCAL_FILE_SYSTEM:
            candidate_full_path = (
                Path(global_config.LOCAL_FILE_SYSTEM_DIR) / candidate_path
            )
            candidate_full_path.parent.mkdir(parents=True, exist_ok=True)

            with candidate_full_path.open("a") as cf:
                cf.write(str(random_number) + "\n")

            final_candidate_path = candidate_full_path
        else:
            candidate_download_path = Path("/tmp") / candidate_path
            candidate_download_path.parent.mkdir(parents=True, exist_ok=True)

            # If exists in S3, download
            s3_response = s3_client.list_objects_v2(
                Bucket=s3_log_info["Bucket"], Prefix=str(candidate_path)
            )
            if "Contents" in s3_response and s3_response["Contents"]:
                s3_client.download_file(
                    Bucket=s3_log_info["Bucket"],
                    Key=str(candidate_path),
                    Filename=str(candidate_download_path),
                )

            with candidate_download_path.open("a") as cf:
                cf.write(str(random_number) + "\n")

            with candidate_download_path.open("rb") as cf:
                s3_client.put_object(
                    Bucket=s3_log_info["Bucket"], Key=str(candidate_path), Body=cf
                )

            # Re-download to verify
            s3_client.download_file(
                Bucket=s3_log_info["Bucket"],
                Key=str(candidate_path),
                Filename=str(candidate_download_path),
            )

            final_candidate_path = candidate_download_path

        # Release lock
        faasr_release(self)

        # Read first line and compare
        if not final_candidate_path.exists():
            logger.error(f"Candidate file missing after write: {final_candidate_path}")
            sys.exit(1)

        with final_candidate_path.open("r") as f:
            first_line = int(f.readline().strip())

        if random_number != first_line:
            logger.error("Not the last trigger invoked — random number does not match")
            sys.exit(0)

    def start(self):
        # Verifies that the faasr payload is a DAG, meaning that there is no cycles
        # If the payload is a DAG, then
        # this function returns a predecessor list for the workflow
        # If the payload is not a DAG, then the action aborts
        pre = check_dag(self)

        # Verfies the validity of S3 data stores,
        # checking the server status and ensuring that the specified bucket exists
        # If any of the S3 endpoints are invalid
        # or any data store server are unreachable, the action aborts
        self.s3_check()

        # Initialize log if this is the first action in the workflow
        if len(pre) == 0:
            self.init_log_folder()

        # If there are more than 1 predecessor,
        # then only the final action invoked will sucessfully run
        # This function validates that the current action
        # is the last invocation; otherwise, it aborts
        if len(pre) > 1:
            self.abort_on_multiple_invocations(pre)

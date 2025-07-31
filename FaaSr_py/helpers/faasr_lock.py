import random
import time
import logging
import sys

from pathlib import Path

from FaaSr_py.helpers.s3_helper_functions import (
    get_default_log_boto3_client,
    get_logging_server,
    get_invocation_folder,
)


logger = logging.getLogger(__name__)


def faasr_rsm(faasr_payload):
    """
    RSM for lock

    Arguments:
        faasr_payload: payload dict (FaaSr)

    Returns:
        bool: True if lock acquired (lock file placed in s3), false otherwise
    """
    # set env for flag and lock
    flag_content = random.randint(1, 2**31 - 1)
    invocation_folder = get_invocation_folder(faasr_payload)
    flag_path = invocation_folder / Path(faasr_payload['FunctionInvoke']) / "flag"
    flag_name = flag_path / str(flag_content)
    lock_name = invocation_folder / Path(faasr_payload['FunctionInvoke']) / "lock"

    # set s3 client
    logging_datastore = get_logging_server(faasr_payload)
    target_s3 = faasr_payload["DataStores"][logging_datastore]
    s3_client = get_default_log_boto3_client(faasr_payload)

    cnt = 0
    max_cnt = 4
    max_wait = 13

    while True:
        # Put an object with the name log/functionname/flag/{random_intger} into the S3 bucket
        try:
            s3_client.put_object(Key=str(flag_name), Bucket=target_s3["Bucket"])
        except Exception as e:
            err_msg = f"failed to upload flag to S3 -- MESSAGE: {e}"
            logger.exception(err_msg, stack_info=True)
            sys.exit(1)

        # If someone has a flag, then delete flag and try again
        if anyone_else_interested(s3_client, target_s3, flag_path, flag_name):
            s3_client.delete_object(Bucket=target_s3["Bucket"], Key=str(flag_name))
            if cnt > max_cnt:
                time.sleep(2**max_cnt)
                cnt += 1
                # If faasr_rsm exceeds the max time to acquire, then it returns false
                if cnt > max_wait:
                    err_msg = "Lock Timeout"
                    logger.error(err_msg)
                    sys.exit(1)
            else:
                time.sleep(2**cnt)
                cnt += 1
        else:
            # Check if a lock exists. If it does, then return false; otherwise, write lock to S3
            check_lock = s3_client.list_objects_v2(
                Bucket=target_s3["Bucket"], Prefix=str(lock_name)
            )
            if "Contents" not in check_lock or len(check_lock["Contents"]) == 0:
                s3_client.put_object(
                    Bucket=target_s3["Bucket"], Key=str(lock_name), Body=str(flag_content)
                )
                s3_client.delete_object(Bucket=target_s3["Bucket"], Key=str(flag_name))
                return True
            else:
                s3_client.delete_object(Bucket=target_s3["Bucket"], Key=str(flag_name)) 
                logger.info("FAILED TO ACQUIRE S3 LOCK")
                return False


def faasr_acquire(faasr):
    """
    Acquire S3 lock

    Arguments:
        faasr: FaaSr payload dict
    Returns:
        bool: True if lock acquired, False otherwise
    """
    # Call faasr_rsm to get a lock
    lock = faasr_rsm(faasr)
    cnt = 0
    max_cnt = 4
    max_wait = 13
    while True:
        # If the lock is true (acquired), then break out of while loop
        if lock:
            return True
        else:
            # "Spin" until a lock is acquired or a timeout occurs
            if cnt > max_cnt:
                logger.info("MAX SPIN WAIT PERIOD")
                time.sleep(2**max_cnt)
                cnt += 1
                if cnt > max_wait:
                    err_msg = "LOCK ACQUIRE TIMEOUT"
                    logger.error(err_msg)
                    sys.exit(1)
            else:
                logger.info("LOCK SPINNING")
                time.sleep(2**cnt)
                cnt += 1
        # Attempt to acquire lock
        lock = faasr_rsm(faasr)


def faasr_release(faasr_payload):
    """
    Release lock by deleting the lock file from s3

    Arguments:
        faasr_payload: payload dict (FaaSr)
    """
    # The lock file is in the form {FaaSrLog}/{InvocationID}/{FunctionInvoke}/lock
    invocation_folder = get_invocation_folder(faasr_payload)
    lock_name = invocation_folder / Path(faasr_payload['FunctionInvoke']) / "lock"

    # Get the faasr logging server from payload
    logging_datastore = get_logging_server(faasr_payload)
    target_s3 = faasr_payload["DataStores"][logging_datastore]
    s3_client = get_default_log_boto3_client(faasr_payload)

    # Delete the lock from S3
    s3_client.delete_object(Bucket=target_s3["Bucket"], Key=str(lock_name))


def anyone_else_interested(boto3_client, target_s3, flag_path, flag_name):
    """
    Check flags to see whether or not other
    functions are trying to acquire the lock

    Arguments:
        boto3_client: boto3 client object
        flag_path: path to dir holding flags in s3
        flag_name: name of current function's flag

    Returns:
        bool -- True if other flags are present in S3, False if not
    """

    # Get a list of flag names
    check_pool = boto3_client.list_objects_v2(
        Bucket=target_s3["Bucket"], Prefix=str(flag_path)
    )

    pool = [x["Key"] for x in check_pool["Contents"]]
    # If our flag is in S3 and is the only one, return false
    if flag_name in pool and len(pool) == 1:
        return False
    else:
        return True

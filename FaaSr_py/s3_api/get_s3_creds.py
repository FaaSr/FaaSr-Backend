import logging
import sys

logger = logging.getLogger(__name__)


def faasr_get_s3_creds(faasr_payload, server_name=""):
    """
    Returns S3 credentials. Used to setup Apache PyArrow and Arrow instances.

    Arguments:
        faasr_payload: FaaSr payload dict
        server_name: str -- name of S3 data store to get credentials from
    Returns:
        dict: A dict with the fields
        (bucket, region, endpoint, secret_key, access_key, anonymous)
    """
    # fetch server name if one is not provided
    if server_name == "":
        server_name = faasr_payload["DefaultDataStore"]

    # ensure that server name provided is valid
    if server_name not in faasr_payload["DataStores"]:
        logger.error(f"Invalid data server name: {server_name}")
        sys.exit(1)

    target_s3 = faasr_payload["DataStores"][server_name]

    if not target_s3.get("Anonymous") or len(target_s3["Anonymous"]) == 0:
        anonymous = False
    else:
        match (target_s3["Anonymous"].lower()):
            case "true":
                anonymous = True
            case "false":
                anonymous = False
            case _:
                anonymous = False

    # if the connection is anonymous, don't return keys
    if anonymous:
        secret_key = None
        access_key = None
    else:
        try:
            secret_key = target_s3["SecretKey"]
            access_key = target_s3["AccessKey"]
        except KeyError as e:
            logger.error(f"Missing key in S3 data store: {e}")
            sys.exit(1)

    endpoint = target_s3.get("Endpoint")
    if not endpoint or endpoint == "":
        # Construct default AWS S3 endpoint from region
        region = target_s3["Region"]
        endpoint = f"https://s3.{region}.amazonaws.com"


    # return credentials as namedtuple
    return {
        "bucket": target_s3["Bucket"],
        "region": target_s3["Region"],
        "endpoint": endpoint,
        "secret_key": secret_key,
        "access_key": access_key,
        "anonymous": anonymous,
    }

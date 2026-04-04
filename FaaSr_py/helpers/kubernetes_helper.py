import base64
import json
import logging
import time
from datetime import datetime

import requests

logger = logging.getLogger(__name__)

def validate_jwt_token(token):
    """
    Validates JWT tokens for Kubernetes authentication
    Checks token format and decodes the payload
    
    Arguments:
        token: str -- JWT token string to validate
    Returns:
        dict: {"valid": bool, "error": str}
    """

    if not token or not token.startswith("eyJ"):
        return {"valid": False, "error": "Invalid token format"}
    
    try:
        # Decode the payload
        parts = token.split(".")
        if len(parts) < 2:
            return {"valid": False, "error": "JWT is malformed"}
        
        payload = parts[1]
        # Add padding
        padding = 4 - (len(payload) % 4)
        if padding != 4:
            payload += "=" * padding
        
        # Decode base64
        decoded_bytes = base64.b64decode(payload)
        decoded_json = decoded_bytes.decode("utf-8")
        payload_data = json.loads(decoded_json)

        if (not payload_data.get("iss") or payload_data["iss"] != "kubernetes/serviceaccount" or not payload_data.get("kubernetes.io/serviceaccount/namespace") or not payload_data.get("kubernetes.io/serviceaccount/secret.name")):
            return {"valid": False, "error": "Invalid Kubernetes secret format"}
        
        return {"valid": True, "error": None}
    
    except Exception as e:
        return {"valid": False, "error": "Unable to decode the JWT token payload"}
    

def make_kubernetes_request(
    endpoint, method="GET", headers=None, body=None, token=None, certificate=None, username=None
):
    """
    Helper function to send HTTPS requests to the Kubernetes REST API
    
    Arguments:
        endpoint: str -- full URL endpoint
        method: str -- HTTP method
        headers: dict -- HTTP headers
        body: dict -- request body (optional)
        token: str -- JWT token from server configuration
        username: str -- username from server configuration
    Returns:
        requests.Response: HTTP response
    """

    if headers is None:
        headers = {}
    
    if not token or not token.strip():
        logger.error(
            "Kubernetes token is required - server will close connection without authentication"
        )
        raise ValueError("Kubernetes token is required for authentication")
    
    token = token.strip()
    if not token.startswith("eyJ"):
        logger.error(
            f"Token doesn't look like JWT (it should start with 'eyJ'): {token[:10]}..."
        )
        raise ValueError("Invalid JWT token format")
    
    headers["Authorization"] = f"Bearer {token}"
    headers["Accept"] = "application/json"

    if (method.upper() == "POST"):
        headers["Content-Type"] = "application/json"

    # If the certificate is specified, include it

    request_session = requests.Session()
    
    if (certificate):
        request_session.verify = certificate

    if (method.upper() == "GET"):
        response = request_session.get(url=endpoint, headers=headers, timeout=30)
    elif (method.upper() == "POST"):
        response = request_session.post(url=endpoint, headers=headers, json=body, timeout=30)
    elif (method.upper() == "PUT"):
        response = request_session.put(url=endpoint, headers=headers, json=body, timeout=30)
    elif (method.upper() == "DELETE"):
        response = request_session.delete(url=endpoint, headers=headers, timeout=30)
    else:
        raise ValueError(f"Unsupported HTTP method: {method}")
    
    return response



def validate_certificate(certificate):
    """
    Test that the certificate is in the correct format, and if it is base64 encoded, decode it to the proper format 

    Args:
        certificate: The string representing the certificate from the workflow

    Returns:
        bool: Determines whether the operation was successful or not
        bool: Determines whether the certificate should be updated in the FaaSrPayload. Ideally, if the certificate is b64 encoded, it is only decoded once, and then just used by every subsequent call
        string: The validated, or decoded certificate
    """

    if ("-----BEGIN CERTIFICATE-----" in certificate and "-----END CERTIFICATE-----" in certificate):
        return (True, False, certificate)

    else:
        certificate = base64.b64decode(certificate).decode('utf-8')
        if (certificate and "-----BEGIN CERTIFICATE-----" in certificate and "-----END CERTIFICATE-----" in certificate):
           return (True, True, certificate)

    return (False, False, None) 
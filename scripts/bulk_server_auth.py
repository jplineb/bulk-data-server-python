import requests
import jwt
import time
import json
import logging
import re
from typing import Dict, List
from jwcrypto import jwk
import os

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Load JWS keys from the JSON file
def load_jws_keys(file_path: str) -> Dict:
    with open(file_path, 'r') as file:
        return json.load(file)

# Load the connection info - get from app
def load_connection_info(file_path: str) -> Dict:
    with open(file_path, 'r') as file:
        return json.load(file)

def get_access_token(client_id: str, token_url: str, jws_keys: Dict) -> Dict[str, str]:
    # Create JWT claims
    now = int(time.time())
    claims = {
        "iss": client_id,  # Issuer
        "sub": client_id,  # Subject
        "aud": token_url,  # Audience
        "exp": now + 300,  # Expiration (5 minutes from now)
        "iat": now,  # Issued at
        "jti": str(int(time.time() * 1000))  # Unique identifier
    }

    # Get the private key from jws_keys
    private_key_dict = next(
        (key for key in jws_keys["keys"] if "sign" in key.get("key_ops", [])),
        None
    )
    if not private_key_dict:
        logging.error("No signing key found in jws_keys")
        raise ValueError("No signing key found in jws_keys")

    # Convert JWK to PEM format using jwcrypto
    key = jwk.JWK(**private_key_dict)
    private_key_pem = key.export_to_pem(private_key=True, password=None).decode('utf-8')  # Ensure PEM is a string

    # Create the JWT
    assertion = jwt.encode(
        claims,
        private_key_pem,
        algorithm="RS384",  # Ensure the algorithm is supported
        headers={"kid": private_key_dict["kid"]}
    )

    # Debug: Log the JWT for inspection
    logging.debug("JWT Assertion: %s", assertion)

    # Check the structure of the JWT (should have 3 parts)
    token_parts = assertion.split('.')
    logging.debug("JWT Structure (Parts): %d parts", len(token_parts))
    if len(token_parts) != 3:
        logging.warning("JWT does not have 3 parts!")
        return None

    # Prepare the token request
    token_request_data = {
        "grant_type": "client_credentials",
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": assertion,
        "scope": "system/Patient.read"
    }

    # Debug: Log the request data
    logging.debug("Token Request Data: %s", token_request_data)

    # Set headers for the request
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }

    # Make the token request
    response = requests.post(token_url, data=token_request_data, headers=headers)
    
    # Debug: Log the response status and content
    logging.debug("Response Status Code: %d", response.status_code)
    logging.debug("Response Content: %s", response.content)

    response.raise_for_status()

    return response.json()

def get_authorized_headers(access_token: str) -> Dict[str, str]:
    """
    Create headers with Bearer token authentication
    
    Args:
        access_token: The OAuth2 access token
        
    Returns:
        Dict containing authorization headers
    """
    return {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/fhir+json"
    }

def export_patient_data(headers: Dict[str, str], patient_id: str, export_url: str) -> str:
    # Prepare the request payload
    payload = {
        "resourceType": "Parameters",
        "parameter": [
            {
                "name": "_type",
                "valueString": "Patient"
            },
            {
                "name": "patient",
                "valueReference": {
                    "reference": f"Patient/{patient_id}"
                }
            }
        ]
    }

    # Set additional headers
    headers.update({
        "Prefer": "respond-async",
        "Content-Type": "application/json"
    })

    # Make the POST request
    response = requests.post(export_url, headers=headers, json=payload)
    
    # Log the response
    logging.info("Export Request Response Status: %d", response.status_code)
    logging.debug("Export Request Response Content: %s", response.content)

    response.raise_for_status()

    # Extract the status URL from the JSON response
    response_json = response.json()
    status_url = None
    if "issue" in response_json and response_json["issue"]:
        diagnostics = response_json["issue"][0].get("diagnostics", "")
        # Use regex to extract the URL from the diagnostics message
        url_match = re.search(r'"(http[^"]+)"', diagnostics)
        if url_match:
            status_url = url_match.group(1)
        else:
            logging.error("Status URL not found in the response diagnostics: %s", diagnostics)

    return status_url

def check_export_status(status_url: str, headers: Dict[str, str]) -> List[str]:
    """
    Check the status of the export and return download URLs when ready.
    Returns a list of URLs to download the exported data.
    """
    while True:
        # Make a GET request to the status URL
        response = requests.get(status_url, headers=headers)
        logging.info("Status Check Response Status: %d", response.status_code)
        
        # If status is 202, the export is still processing
        if response.status_code == 202:
            logging.info("Export still processing, waiting 5 seconds...")
            time.sleep(5)
            continue
            
        response.raise_for_status()
        
        # If we get here, the export is complete
        if response.status_code == 200:
            response_json = response.json()
            logging.debug("Status Check Response Content: %s", response.content)
            
            # Get the output URLs from the response
            output = response_json.get("output", [])
            if not output:
                logging.warning("No output files in export response")
                return []
                
            return [file["url"] for file in output]
            
        return []

def download_exported_data(urls: List[str], headers: Dict[str, str], output_dir: str = "exported_data"):
    """
    Download the exported data from the provided URLs.
    """
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    for url in urls:
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            
            # Generate filename from URL
            filename = os.path.join(output_dir, f"export_{hash(url)}.json")
            
            # Save the downloaded data
            with open(filename, 'wb') as f:
                f.write(response.content)
                
            logging.info(f"Downloaded export file to: {filename}")
            
            # Log the contents for debugging
            logging.debug(f"File contents: {response.content.decode('utf-8')}")
            
        except Exception as e:
            logging.error(f"Error downloading from {url}: {e}")

def search_patients(headers: Dict[str, str], base_url: str, search_params: Dict[str, str] = None) -> Dict:
    """
    Search for patients using the FHIR search API
    
    Args:
        headers: Authorization headers
        base_url: Base URL for the FHIR server
        search_params: Optional dictionary of search parameters
        
    Returns:
        Dict containing the search results
    """
    # Construct the search URL
    search_url = f"{base_url}/Patient"
    
    # Make the GET request with search parameters
    response = requests.get(search_url, headers=headers, params=search_params)
    
    # Log the response
    logging.info("Patient Search Response Status: %d", response.status_code)
    logging.debug("Patient Search Response Content: %s", response.content)
    
    response.raise_for_status()
    return response.json()

if __name__ == "__main__":
    try:
        # Connection details
        connection_info = load_connection_info('client_connection_info.json')
        base_url = connection_info["base_url"]
        client_id = connection_info["client_id"]
        token_url = connection_info["token_url"]
        export_url = f"{base_url}/Patient/$export"
        
        # Load the jws keys
        jws_keys = load_jws_keys('jws_keys.json')
        
        # Get the access token
        token_response = get_access_token(client_id, token_url, jws_keys)
        if not token_response:
            logging.error("Failed to generate a valid JWT.")
            exit(1)
        access_token = token_response["access_token"]
        
        # Use the token to make an authorized request
        headers = get_authorized_headers(access_token)
        
        # Bulk export
        patient_id = "58c297c4-d684-4677-8024-01131d93835e" 
        status_url = export_patient_data(headers, patient_id, export_url)
        
        if status_url:
            download_urls = check_export_status(status_url, headers)
            if download_urls:
                download_exported_data(download_urls, headers)
            else:
                logging.error("No download URLs available")
        
        # Now try the patient search API
        # search_params = {
        #     # "_count": "10",  # Limit results
        #     # "_sort": "birthdate",  # Sort by birthdate
        #     "identifier": f"https://github.com/synthetichealth/synthea | {patient_id}",
        # }
        
        # search_results = search_patients(headers, base_url, search_params)
        # logging.info("Found %d patients", len(search_results.get("entry", [])))
        
    except Exception as e:
        logging.error("Error: %s", e)


import jwt
import datetime
import uuid
import base64
import requests
import re
import argparse
import logging
import sys
import json
import xml.dom.minidom
import http.client as http_client
from pprint import pformat
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.hazmat.primitives import hashes

def print_response(text):
    try:
        logging.debug(f"Received JSON: {pformat(json.loads(text))}")
    except:
        try:
            logging.debug(f"Received XML: {xml.dom.minidom.parseString(text).toprettyxml()}")
        except:
            logging.debug(f"Received Text: {text}")


def http_get(url,headers):
    r=requests.get(url,headers = headers)
    print_response(r.text)
    r.raise_for_status()
    return(r)

def http_post(url,headers,data):
    r=requests.post(url,headers = headers,data=data)
    print_response(r.text)
    r.raise_for_status()
    return(r)

parser=argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,allow_abbrev=False,description="ISE Intune Test Tool")
parser.add_argument("-a",metavar="<appid>",help="Azure Client or App ID",required=True)
parser.add_argument("-t",metavar="<tenantid>",help="Azure Tenant ID",required=True)
parser.add_argument("-c",metavar="<certfile>",help="Path to certificate file",type=argparse.FileType("rb"),required=True)
parser.add_argument("-k",metavar="<keyfile>",help="Path to key file",type=argparse.FileType("rb"),required=True)
parser.add_argument("-n",help="Use V2.0 endpoint. ISE 3.3, ISE 3.2p4+ and ISE 3.1p8+",action="store_true",default=False)
lookup_group=parser.add_mutually_exclusive_group(required=True)
lookup_group.add_argument("-i",help="Get MDM Info",action="store_true")
lookup_group.add_argument("-l",help="List all non-compliant devices",action="store_true")
lookup_group.add_argument("-q",metavar="<id>",help="Query Intune by Device ID (GUID or MAC)")
parser.add_argument("-d",metavar="<level>",help="Debug level. 1-Warning (default), 2-Verbose, 3-Debug",type=int,default=1,choices=[1,2,3])
args=parser.parse_args()

tenant_id=args.t
client_id=args.a

if args.q:
    if re.search(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",args.q,re.IGNORECASE):
        device_id=args.q
        api_ver=3
        query_criteria="guid"
    elif re.search(r"^[0-9a-f]{2}[:\-][0-9a-f]{2}[:\-][0-9a-f]{2}[:\-][0-9a-f]{2}[:\-][0-9a-f]{2}[:\-][0-9a-f]{2}$|^[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}$|^[0-9a-f]{12}$",args.q,re.IGNORECASE):
        device_id=re.sub(r"[\.:\-]","",args.q).upper()
        if args.n:
            api_ver=3
            query_criteria="macaddress"
        else:
            api_ver=2
    else:
        parser.error("Invalid device identifier specified in -q. Accepted MAC formats: HHHHHHHHHHHH, HH:HH:HH:HH:HH:HH, HH-HH-HH-HH-HH-HH and HHHH.HHHH.HHHH.")

debug_level=[logging.WARNING,logging.INFO,logging.DEBUG][args.d-1]
if args.d==3:
	http_client.HTTPConnection.debuglevel = 1
logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s',level=debug_level)
requests_log=logging.getLogger("requests.packages.urllib3")
requests_log.setLevel(debug_level)
requests_log.propagate=True

logging.info(f"Attempting to load certificate from {args.c.name}")
cert = x509.load_pem_x509_certificate(args.c.read(), default_backend())
logging.debug("Getting Base64 certificate string")
cert_der = cert.public_bytes(encoding=serialization.Encoding.DER)
cert_pem = base64_encoded_certificate = base64.b64encode(cert_der).decode()
logging.debug("Calculating SHA1 Thumbprint")
thumbprint = cert.fingerprint(hashes.SHA1())
thumbprint_text=thumbprint.hex()
logging.debug(f"Thumbprint in hex: {thumbprint_text}")

thumbprint_base64 = base64.b64encode(thumbprint).decode()
logging.debug(f"Thumbprint in binary, base64-encoded: {thumbprint_base64}")

logging.info(f"Attempting to load private key from {args.k.name}")
private_key = serialization.load_pem_private_key(
    args.k.read(),
    password=None,
    backend=default_backend()
)

logging.debug(f"Generating JWT client assertion payload")
now = datetime.datetime.utcnow()
payload = {
    'aud': f'https://login.microsoftonline.com/{tenant_id}/oauth2/token',
    'iss': client_id,
    'sub': client_id,
    'iat': now,
    'exp': now + datetime.timedelta(minutes=5),
    'jti': str(uuid.uuid4()),
}
logging.debug(f"Assertion payload: {pformat(payload)}")

logging.debug(f"Generating assertion")
jwt_token = jwt.encode(
    payload,
    private_key,
    algorithm='RS256',
    headers={
        "x5t": thumbprint_base64,
        "x5c": [cert_pem]
        }
)
logging.debug(f"Assertion: {jwt_token}")

logging.info("Attempting to get bearer token for graph.microsoft.com")
if args.n:
    r=http_post(f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
                    {},
                    {
                        "client_info": "1",
                        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                        "grant_type": "client_credentials",
                        "scope": "https://graph.microsoft.com/.default openid profile offline_access",
                        "client_id": client_id,
                        "client_assertion": jwt_token,

                    }) 
else:
    r=http_post(f"https://login.microsoftonline.com/{tenant_id}/oauth2/token",
                    {},
                    {
                        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                        "resource": "https://graph.microsoft.com",
                        "grant_type": "client_credentials",
                        "scope": "openid",
                        "client_assertion": jwt_token
                    })
try:
    graph_token=r.json()["access_token"]
except:
    logging.error("Unable to get token")
    sys.exit(1)

logging.debug(f"API Token: {graph_token}")
logging.debug(f"Decoded: {pformat(jwt.decode(graph_token,options={'verify_signature':False}))}")

logging.info("Attempting to retrieve API endpoints")
endpoints=http_get("https://graph.microsoft.com//v1.0/servicePrincipals/appId=0000000a-0000-0000-c000-000000000000/endpoints",
                       {
                           "Authorization": f"Bearer {graph_token}"
                       })
try:
    for endpoint in endpoints.json()["value"]:
        if endpoint["providerName"]=="NACAPIService":
            v2endpoint=endpoint["uri"]
        if endpoint["providerName"]=="ComplianceRetrievalService":
            v3endpoint=endpoint["uri"]
except:
    logging.error("Unable to get endpoints")
    sys.exit(1)

logging.info(f"API Version 2 Endpoint: {v2endpoint}")
logging.info(f"API Version 3 Endpoint: {v3endpoint}")

logging.info("Attempting to get bearer token api.manage.microsoft.com")

if args.n:
    r=http_post(f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
                    {},
                    data={
                        "client_info": "1",
                        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                        "grant_type": "client_credentials",
                        "scope": "openid https://api.manage.microsoft.com//.default profile offline_access",
                        "client_id": client_id,
                        "client_assertion": jwt_token
                    })
else:
    r=http_post(f"https://login.microsoftonline.com/{tenant_id}/oauth2/token",
                    {},
                    data={
                        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                        "resource": "https://api.manage.microsoft.com/",
                        "grant_type": "client_credentials",
                        "scope": "openid",
                        "client_assertion": jwt_token
                    })

try:
    api_token=r.json()["access_token"]
except:
    logging.error("Unable to get token")
    sys.exit(1)

logging.debug(f"API Token: {api_token}")
logging.debug(f"Decoded: {pformat(jwt.decode(api_token,options={'verify_signature':False}))}")

headers={
    "Authorization": f"Bearer {api_token}",
    "Accept": "application/xml"
}

if args.l:
    logging.info("Attempting to retrieve all Non-Compliant devices")
    r=http_get(f"{v3endpoint}/cisco/devices/?paging=0&querycriteria=compliance&value=false&deviceidentifier=guid&filter=all",headers)
elif args.i:
    logging.info("Attempting to get API Version 2 Information")
    r2=http_get(f"{v2endpoint}/ciscoise/mdminfo/?ise_api_version=2",headers)
    logging.info("Attempting to get API Version 3 Information")
    r3=http_get(f"{v3endpoint}/ciscoise/mdminfo/?ise_api_version=3",headers)
elif api_ver==2:
    logging.info(f"Attempting to query V2 endpoint for {device_id}")
    r=http_get(f"{v2endpoint}/ciscodeviceinfo/mdm/api/devices/?paging=0&querycriteria=macaddress&value={device_id}&filter=all",headers)
else:
    logging.info(f"Attempting to query V3 endpoint for {device_id}")
    r=http_get(f"{v3endpoint}/cisco/devices/?paging=0&querycriteria={query_criteria}&value={device_id}&filter=all",headers)

try:
    if args.i:
        print(f"Version 2 Info:\n{xml.dom.minidom.parseString(r2.text).toprettyxml()}")
        print(f"Version 3 Info:\n{xml.dom.minidom.parseString(r3.text).toprettyxml()}")
    else:
        print(xml.dom.minidom.parseString(r.text).toprettyxml())
except:
    logging.error("Failed to process the output")
    sys.exit(1)

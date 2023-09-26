#!/usr/bin/env python3
import requests
import ipaddress
import logging
import json
import sys
import argparse
import urllib3

def validip(ip):
	try:
		ipaddress.ip_address(ip)
	except ValueError:
		msg="%s is not a valid IP"%ip
		raise argparse.ArgumentTypeError(msg)
	return(ip)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
parser=argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,allow_abbrev=False,description="""Add PassiveID Mapping via REST API

Example: passiveid-rest.py -n psn1.company.com --apiuser api --apipassword api --user jsmith --ip 1.2.3.4 --domain=example.com --verbose"""
)
parser.add_argument("-n",help="ISE PSN running Passive ID REST API Provider",required=True)
parser.add_argument("-a",help="REST API Username",required=True)
parser.add_argument("-p",help="REST API Password",required=True)
parser.add_argument("-d",help="User domain",required=True)
parser.add_argument("-u",help="Username to be added",required=True)
parser.add_argument("-i",help="IP address of the user",type=validip,required=True)
parser.add_argument("-v",help="Display more details",action="store_true")
args=parser.parse_args()
logFormatter='%(asctime)s - %(levelname)s - %(message)s'
logging.basicConfig(format=logFormatter, level=logging.DEBUG if args.v else logging.ERROR)
logger=logging.getLogger(__name__)
logger.info("Attempting to retrive Authentication Token")
try:
	tokenfile=open('.passiveid_token.txt','r')
	authtoken=tokenfile.read()
	tokenfile.close()
	logger.info("Authentication Token retrieved")
except:
	logger.info("Authentication Token not cached")
	authtoken="none"

mapping={
	"domain":args.d,
	"srcIpAddress":args.i,
	"user":args.u
}

while True:
	logger.info("Attempting to add mapping")
	headers={'X-auth-access-token':authtoken}
	logger.debug("Headers: %s"%headers)
	logger.debug("Posting: %s"%json.dumps(mapping))
	try:
		r=requests.post(f"https://{args.n}:9094/api/identity/v1/identity/useridentity",
			headers=headers,
			data=json.dumps(mapping),
			verify=False)
	except Exception as e:
		logger.error(f"Connection to PSN failed: {e}")
		break
	if r.status_code==201:
		logger.info(f"Mapping created: {r.text}")
		break
	elif r.status_code==401:
		logger.info("Authentication Token not valid. Attempting to refresh")
		try:
			r=requests.post(f"https://{args.n}:9094/api/fmi_platform/v1/identityauth/generatetoken",
				auth=(args.a,args.p),
				verify=False)
		except Exception as e:
			logger.error(f"Connection to PSN failed: {e}")
			break
		if r.status_code==204:
			authtoken=r.headers['X-auth-access-token']
			tokenfile=open('.passiveid_token.txt','w')
			tokenfile.write(authtoken)
			tokenfile.close()
			logger.info("Authentication Token retrieved. Saved to .passiveod_token.txt")
		else:
			logger.error("Unable to get Authentication Token")
			break
	else:
		logger.error("Unknown response %d"%r.status_code)
		break
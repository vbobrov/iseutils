#!/usr/bin/env python3
import requests
import logging
import json
import re
import sys
import argparse
import http.client as http_client
from base64 import b64encode

def b64(input_string):
	return b64encode(input_string.encode()).decode()

def ise_post(url,query=None,**kwargs):
	global ise_session,ise_base_url,logging
	if query:
		cookies={"_QPC_":b64(query)}
	else:
		cookies={}
	logging.debug(f"POST query {query} to {ise_base_url}/{url}")
	response=ise_session.post(f"{ise_base_url}/{url}",cookies=cookies,**kwargs)
	response.raise_for_status()
	return response

def ise_get(url,query=None):
	global ise_session,ise_base_url,logging
	if query:
		headers={"_QPH_":b64(query)}
	else:
		headers={}
	logging.debug(f"GET query {query} to {ise_base_url}/{url}")
	response=ise_session.get(f"{ise_base_url}/{url}",headers=headers)
	response.raise_for_status()
	return response

def confirm(default_answer):
	answer=default_answer
	while not answer in ["yes","no"]:
		answer=input("(yes/no): ")
	return answer
parser=argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,allow_abbrev=False,description="ISE Certificate Import Tool")
parser.add_argument("-l",help="List all certificates. Other option ignored.",action="store_true")
parser.add_argument("-i",metavar="<isenode>",help="ISE Node FQDN or IP address",required=True)
parser.add_argument("-a",metavar="<username>",help="GUI Admin username.",required=True)
parser.add_argument("-p",metavar="<password>",help="GUI Admin password.",required=True)
parser.add_argument("-c",metavar="<certfile>",help="Path to certificate file.",type=argparse.FileType("r"))
parser.add_argument("-k",metavar="<keyfile>",help="Path to key file.",type=argparse.FileType("r"))
parser.add_argument("-e",metavar="<keypassword>",help="Key encryption password.")
parser.add_argument("-n",metavar="<node>",help="Node list to install certificate. Space separated",nargs="+")
parser.add_argument("-u",metavar="<use>",help="Certificate uses (admin,portal,eap,pxgrid,dtls). Space separated. For portal, a non-default tag is specified with portal:<tag>",nargs="*")
parser.add_argument("-d",metavar="<level>",help="Debug level. 1-Warnig, 2-Verbose, 3-Debug",type=int,default=1,choices=[1,2,3])
parser.add_argument("-y",help="Accept all warnings without prompts",action="store_const",const="yes")
args=parser.parse_args()
if not args.l:
	errors=""
	if not args.n:
		errors+="  -n missing. At least one node required\n"
	if not args.c:
		errors+="  -c missing. Certificate required\n"
	if not args.k:
		errors+="  -k missing. Private key required\n"
	if not args.e:
		errors+="  -e missing. Key encryption password required\n"
	if errors:
		parser.error(f"\n{errors}")
debug_level=[logging.WARNING,logging.INFO,logging.DEBUG][args.d-1]
if args.d==3:
	http_client.HTTPConnection.debuglevel = 1
logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s',level=debug_level)
requests_log = logging.getLogger("requests.packages.urllib3")
requests_log.setLevel(debug_level)
requests_log.propagate=True
username=args.a
password=args.p
ise_pan=args.i
import_nodes=args.n
import_uses=args.u if args.u else []
pem_file=args.c
pvk_file=args.k
key_password=args.e
import_confirmations={
	"verify-replace-duplicate":"crudStub.isCertificateReplacementConfirmed",
	"verify-replace-portal-tag":"crudStub.isPortalTagReplacementConfirmed",
	"verify-replace-wildcard":"crudStub.allowWildcardCerts",
	"warning-expiry-398": "crudStub.isExpiry398"
}
valid_cert_uses={
	"portal":"crudStub.portalCertificate",
	"admin":"crudStub.managementInterfaceCertificate",
	"dtls":"crudStub.dtls",
	"eap":"crudStub.eapCertificate",
	"pxgrid":"crudStub.xgridCertificate"
}
if not args.l:
	cert_uses={}
	for import_use in import_uses:
		try:
			cert_uses[valid_cert_uses[import_use.split(":")[0]]]="on"
			if "portal" in import_use:
				if re.match(r"portal:(.+)",import_use):
					portal_tag=re.match(r"portal:(.+)",import_use)[1]
				else:
					portal_tag="Default Portal Certificate Group"
		except:
			parser.error(f"Invalid certificate use: {import_use}")
	import_uses=[use.split(":")[0] for use in import_uses]
ise_base_url=f"https://{ise_pan}/admin"
ise_session=requests.Session()
ise_session.verify=False
logging.debug("Loading login page")
response=ise_session.get(f"{ise_base_url}/login.jsp")
logging.debug("Attempting to login")
response=ise_session.post(f"{ise_base_url}/LoginAction.do",data={
	'username':username,
	'password':password,
	'rememberme':'on',
	'name':username,
	'authType':'Internal',
	'newPassword':'',
	'xeniaUrl':'',
	'locale':'en',
	'hasSelectedLocale':'false',
	'destinationURL':''
})
try:
	ise_verion=re.match(r'.*<div id="softwareVersion" style="display:none">([0-9\.]+)</div>.*',response.text,re.S)[1]
except:
	logging.error("Login failed")
	sys.exit(1)
try:
	ise_patches=re.match(r'.*<div id="patch" style="display:none">([0-9\,]+)</div>.*',response.text,re.S)[1].split(",")
	ise_patch=max([int(i) for i in ise_patches])
except:
	ise_patch=0
csrf_token=re.match(r".*OWASP_CSRFTOKEN=([0-9A-Z\-]+).*",response.text,re.S)[1]
pan_hostname=re.match(r'.*"theHostName" : "([^"]+)",.*',response.text,re.S)[1]
logging.info("Login successful")
logging.info(f"PAN Hostname is {pan_hostname}")
logging.info(f"ISE Version {ise_verion} Patch {ise_patch}")
logging.debug(f"CSRF Token is {csrf_token}")
ise_session.headers.update({'OWASP_CSRFTOKEN':csrf_token})
response=ise_session.get(f"{ise_base_url}/systemCertificatesAction.do",headers={'_QPH_':b64('command=loadGridData')})
cert_node_list=json.loads(response.text.replace("'",'"'))['items']
if args.l:
	cert_report='''+---------------+----------------------------------------+---------------------+-------------------+-----------+-----------+
|   ISE Node    |               Protocol                 |   Issued To         |    Issued By      | Valid From| Valid To  |
+---------------+----------------------------------------+---------------------+-------------------+-----------+-----------+\n'''
	for node_idx in range(0,len(cert_node_list)):
		cert_node=cert_node_list[node_idx]['friendlyName']
		if node_idx==0:
			cert_list=cert_node_list[node_idx]['items']
		else:
			response=ise_session.get(f"{ise_base_url}/systemCertificatesAction.do",headers={'_QPH_':b64(f"command=expandNode&nodeId={cert_node}")})
			cert_list=json.loads(response.text.replace("'",'"'))['items']
		for cert in cert_list:
			cert_report+=f"|{cert_node:<15}|{cert['protocol'][:40]:<40}|{cert['issuedTo'][:20]:<20}|{cert['issuedBy'][:20]:<20}|{cert['validFromDateOnly'][5:]:>11}|{cert['validToDateOnly'][5:]:>11}|\n"
		cert_report+='+---------------+----------------------------------------+---------------------+-------------------+-----------+-----------+\n'
	print(cert_report)
else:
	valid_nodes=[node["friendlyName"] for node in cert_node_list]
	logging.debug(f"Valid ISE nodes: {','.join(valid_nodes)}")
	logging.debug("Getting portag group tags")
	response=ise_session.get(f"{ise_base_url}/addCSRAction.do",headers={'_QPH_':b64('command=getPortalCertificateGroupTags')})
	portal_tags=[tag["groupTag"] for tag in json.loads(response.text.replace("'",'"'))['items'][1:]]
	if "portal" in import_uses:
		if not portal_tag in portal_tags:
			logging.debug(f"New portal tag {portal_tag} specified. Asking for confirmation.")
			print(f"Create new portal tag {portal_tag}?")
			if confirm(args.y)=="yes":
				logging.debug("New portal tag confirmed")
				cert_uses["crudStub.groupTagDD"]="add-group-tag"
				cert_uses["crudStub.groupTag"]=portal_tag
			else:
				logging.error("New portal tag rejected")
				sys.exit(1)
		else:
			logging.debug(f"Using existing portal tag {portal_tag}")
			cert_uses["crudStub.groupTagDD"]=portal_tag
	logging.debug("Getting certificate list")
	wildcard=False
	for import_node in import_nodes:
		if not import_node in valid_nodes:
			logging.error(f"Skipping invalid ISE node {import_node}")
			continue
		confirmations={}
		while True:
			if wildcard and import_node!=pan_hostname:
				logging.warning(f"Skipping non-PAN node {import_node} for wildcard certificate")
			logging.info(f"Attempting to import certificate on {import_node}")
			response=ise_session.post(f"{ise_base_url}/importCertificateAction.do",data={
				**{
					'addOperation':'importCertificate',
					'fipsMode':'off',
					'crudStub.selectedNodes':import_node,
					'crudStub.privateKeyPassword':key_password,
					'OWASP_CSRFTOKEN':csrf_token
				},
				**confirmations,
				**cert_uses
				},
				files=[
					('crudStub.certFileToUpload',(pem_file.name,open(pem_file.name,'rb'),'application/x-x509-ca-cert')),
					('crudStub.keyFileToUpload',(pvk_file.name,open(pvk_file.name,'rb'),'application/octet-stream'))
				],
				cookies={'_QPC_':b64(f"command=addSubmit&OWASP_CSRFTOKEN={csrf_token}&nodeId={import_node}")})
			import_status=json.loads(re.match(r"<html><head></head><body><textarea>(.*)</textarea></body></html>",response.text)[1])
			import_messages=import_status["messages"]
			logging.debug(f"Import Status: {import_status}")
			if import_status["status"]=="passed":
				if len(import_messages)==1:
					logging.warning(f"Certificate Successfully Imported on {import_node}: {import_messages[0]}")
					break
				elif len(import_messages)>1:
					if import_messages[1]=="list-parameter-flag":
						domain_object=import_status["domainObject"]
						logging.info(f"Certificate Imported on {import_node} with warnings: {import_messages[0]} {','.join(domain_object)}")
						break
					elif "verify-" in import_messages[1] or "warning-" in import_messages[0]:
						logging.info("Import warning confirmation required")
						if "verify-" in import_messages[1]:
							prompt_text=import_messages[0]
							prompt_key=import_messages[1]
						else:
							prompt_text=import_messages[1]
							prompt_key=import_messages[0]
						if prompt_key=="verify-replace-wildcard":
							wildcard=True
							logging.debug("Wildcard certificate detected")
						print(prompt_text)
						try:
							if import_messages[2]=="list-parameter-flag":
								domain_object=import_status["domainObject"]
								print(",".join(domain_object))
						except:
							pass
						if confirm(args.y)=="yes":
							logging.info("Import warning accepted")
							confirmations[import_confirmations[prompt_key]]="on"
						else:
							logging.warning(f"Import warming rejected. Import aborted")
							break
					else:
						logging.info(f"Certificate Successfully Imported on {import_node}: {':'.join(import_messages)}")
						break
				else:
					logging.error("Unexpected condition occured")
					break
			else:
				logging.error(f"Import failed: {import_messages[0]}")
				break

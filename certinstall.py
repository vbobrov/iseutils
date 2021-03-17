#!/usr/bin/env python3
import requests
import logging
import json
import re
import sys
import argparse
import urllib3
import http.client as http_client
from base64 import b64encode

def b64(input_string):
	return b64encode(input_string.encode()).decode()

def ise_post(url,query=None,**kwargs):
	global ise_session,ise_base_url,logging,cookie_param
	logging.debug(f"POST query {query} to {ise_base_url}/{url}")
	if cookie_param:
		if query:
			cookies={"_QPC_":b64(query)}
		else:
			cookies={}
		response=ise_session.post(f"{ise_base_url}/{url}",cookies=cookies,**kwargs)
	else:
		response=ise_session.post(f"{ise_base_url}/{url}?{query}",**kwargs)
	response.raise_for_status()
	return response

def ise_get(url,query=None):
	global ise_session,ise_base_url,logging,cookie_param
	logging.debug(f"GET query {query} to {ise_base_url}/{url}")
	if cookie_param:
		if query:
			headers={"_QPH_":b64(query)}
		else:
			headers={}
		response=ise_session.get(f"{ise_base_url}/{url}",headers=headers)
	else:
		response=ise_session.get(f"{ise_base_url}/{url}?{query}")
	response.raise_for_status()
	return response

def confirm(default_answer):
	answer=default_answer
	if default_answer:
		print(f"(yes/no): {default_answer} (auto)")
	else:
		while not answer in ["yes","no"]:
			answer=input("(yes/no): ")
	return answer

parser=argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,allow_abbrev=False,description="ISE Certificate Import Tool")
parser.add_argument("-l",help="List all certificates. Requires -i, -a and -p. Other options are ignored.",action="store_true")
parser.add_argument("-i",metavar="<isenode>",help="ISE Node FQDN or IP address",required=True)
parser.add_argument("-a",metavar="<username>",help="GUI Admin username.",required=True)
parser.add_argument("-p",metavar="<password>",help="GUI Admin password.",required=True)
parser.add_argument("-c",metavar="<certfile>",help="Path to certificate file.",type=argparse.FileType("r"))
parser.add_argument("-k",metavar="<keyfile>",help="Path to key file.",type=argparse.FileType("r"))
parser.add_argument("-e",metavar="<keypassword>",help="Key encryption password.")
parser.add_argument("-n",metavar="<node>",help="Node list to install certificate. Space separated. Specify keyword all to include all nodes in the deployment.",nargs="+")
parser.add_argument("-u",metavar="<use>",help="Certificate uses (admin,portal,eap,pxgrid,dtls). Space separated. For portal, a non-default tag is specified with portal:<tag>",nargs="*")
parser.add_argument("-r",help="Prevent node restart if required. Use with caution.",action="store_false",default=True)
parser.add_argument("-y",help="Accept all warnings without prompts",action="store_const",const="yes")
parser.add_argument("-d",metavar="<level>",help="Debug level. 1-Warning (default), 2-Verbose, 3-Debug",type=int,default=1,choices=[1,2,3])
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
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
ise_session=requests.Session()
ise_session.headers.update({"referer":ise_base_url})
ise_session.verify=False
cookie_param=False
logging.debug("Determining cookie based query passing")
response=ise_get("JavaScriptServlet")
if re.match(r".*_QPH_.*",response.text,re.S):
	cookie_param=True
	logging.debug("Using cookie based parameters. 2.4+")
else:
	logging.debug("Using query strings parameters. <2.4")
logging.debug("Loading login page")
response=ise_get(f"{ise_base_url}/login.jsp")
logging.debug("Attempting to login")
response=ise_post("LoginAction.do",data={
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
except TypeError:
	logging.error("ISE Login failed")
	sys.exit(1)
try:
	ise_patches=re.match(r'.*<div id="patch" style="display:none">([0-9\,]+)</div>.*',response.text,re.S)[1].split(",")
	ise_patch=max([int(i) for i in ise_patches])
except TypeError:
	ise_patch=0
csrf_token=re.match(r".*OWASP_CSRFTOKEN=([0-9A-Z\-]+).*",response.text,re.S)[1]
pan_hostname=re.match(r'.*"theHostName" : "([^"]+)",.*',response.text,re.S)[1]
logging.info("Login successful")
logging.info(f"PAN Hostname is {pan_hostname}")
logging.info(f"ISE Version {ise_verion} Patch {ise_patch}")
logging.debug(f"CSRF Token is {csrf_token}")
ise_session.headers.update({"OWASP_CSRFTOKEN":csrf_token,"X-Requested-With":"XMLHttpRequest, OWASP CSRFGuard Project"})
logging.debug(f"Getting certificate list for {pan_hostname}")
response=ise_get("systemCertificatesAction.do",query="command=loadGridData")
cert_node_list=json.loads(response.text.replace("'",'"'))['items']
if args.l:
	cert_report='''+---------------+----------------------------------------+--------------------+--------------------+-----------+-----------+
|   ISE Node    |               Protocol                 |   Issued To        |    Issued By       | Valid From| Valid To  |
+---------------+----------------------------------------+--------------------+--------------------+-----------+-----------+\n'''
	for node_idx in range(0,len(cert_node_list)):
		cert_node=cert_node_list[node_idx]['friendlyName']
		if node_idx==0:
			cert_list=cert_node_list[node_idx]['items']
		else:
			logging.debug(f"Getting certificate list for {cert_node}")
			response=ise_get("systemCertificatesAction.do",query=f"command=expandNode&nodeId={cert_node}")
			cert_list=json.loads(response.text.replace("'",'"'))['items']
		for cert in cert_list:
			cert_report+=f"|{cert_node:<15}|{cert['protocol'][:40]:<40}|{cert['issuedTo'][:20]:<20}|{cert['issuedBy'][:20]:<20}|{cert['validFromDateOnly'][5:]:>11}|{cert['validToDateOnly'][5:]:>11}|\n"
		cert_report+='+---------------+----------------------------------------+--------------------+--------------------+-----------+-----------+\n'
	print(cert_report)
else:
	valid_nodes=[node["friendlyName"] for node in cert_node_list]
	if "all" in import_nodes:
		import_nodes=valid_nodes
	logging.debug(f"Valid ISE nodes: {','.join(valid_nodes)}")
	if "portal" in import_uses:
		logging.debug("Getting portag group tags")
		response=ise_get("addCSRAction.do",query="command=getPortalCertificateGroupTags")
		portal_tags=[tag["groupTag"] for tag in json.loads(response.text.replace("'",'"'))['items'][1:]]
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
	logging.debug("Getting deployment nodes")
	response=ise_get("deploymentAction.do",query="command=loadGridData")
	node_fqdns={node["hostName"]:node["fqdn"] for node in json.loads(response.text.replace("'",'"'))['items']}
	wildcard=False
	for import_node in import_nodes:
		logging.warning(f"Attempting to install on {import_node}")
		if not import_node in valid_nodes:
			logging.error(f"Skipping invalid ISE node {import_node}")
			continue
		confirmations={}
		while True:
			if wildcard and import_node!=pan_hostname:
				logging.warning(f"Skipping non-PAN node {import_node} for wildcard certificate")
				break
			logging.info(f"Attempting to import certificate on {import_node}")
			response=ise_post("importCertificateAction.do",data={
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
				query=f"command=addSubmit&OWASP_CSRFTOKEN={csrf_token}&nodeId={import_node}")
			import_status=json.loads(re.match(r"<html><head></head><body><textarea>(.*)</textarea></body></html>",response.text)[1])
			import_messages=import_status["messages"]
			logging.debug(f"Import Status: {import_status}")
			prompt_key=None
			additional_info=""
			prompt_message=""
			node_restart=False
			for message in import_messages:
				if message=="list-parameter-flag":
					additional_info=",".join(import_status["domainObject"])
				elif "warning-" in message or "verify-" in message:
					prompt_key=message
				elif message=="restart required":
					node_restart=args.r
				else:
					prompt_message+=message+" "
			prompt_message+=f" {additional_info}"
			if import_status["status"]=="passed":
				if prompt_key:
					try:
						logging.info(f"Import warning confirmation {prompt_key} required")
						wildcard=wildcard or prompt_key=="verify-replace-wildcard"
						print(prompt_message)
						if confirm(args.y)=="yes":
							logging.info("Import warning accepted")
							confirmations[import_confirmations[prompt_key]]="on"
						else:
							logging.warning(f"Import warming rejected. Import aborted")
							break
					except KeyError:
						logging.error(f"Unexpected prompt. {prompt_message} {prompt_key}.")
						break
				else:
					logging.warning(f"Certificate Successfully Imported on {import_node}: {prompt_message}")
					if node_restart:
						logging.debug(f"Restart required on {import_node}")
						response=ise_post("restartAction.do",query=f"command=restartRemoteNode&node={node_fqdns[import_node]}")
						restart_status=json.loads(response.text)
						if restart_status["status"]=="passed":
							logging.warning(f"Restart of {import_node} initiated: {restart_status['messages'][0]}")
						else:
							logging.error(f"Restart of {import_node} failed: {restart_status['messages'][0]}")
					break
			else:
				logging.error(f"Certificate Import failed on {import_node}: {prompt_message}")
				break
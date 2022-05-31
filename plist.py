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
			# starting with version 2.4 query parameters in POSTs are 
			# supplied in _QPC_ cookie, encoded in base64
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
			# starting with version 2.4 query parameters in GETs are 
			# supplied in _QPH_ header, encoded in base64
			headers={"_QPH_":b64(query)}
		else:
			headers={}
		response=ise_session.get(f"{ise_base_url}/{url}",headers=headers)
	else:
		response=ise_session.get(f"{ise_base_url}/{url}?{query}")
	response.raise_for_status()
	return response



parser=argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,allow_abbrev=False,description="ISE plist condition tool (CSCwb95433)")
parser.add_argument("-i",metavar="<isenode>",help="ISE Node FQDN or IP address",required=True)
parser.add_argument("-a",metavar="<username>",help="GUI Admin username",required=True)
parser.add_argument("-p",metavar="<password>",help="GUI Admin password",required=True)
parser.add_argument("-n",metavar="<condition>",help="Condition name",required=True)
parser.add_argument("-f",metavar="<filename>",help="Path to plist file",required=True)
parser.add_argument("-t",metavar="<datatype>",help="Data type (default is String)",required=False,default="String")
parser.add_argument("-k",metavar="<key>",help="Key name",required=True)
parser.add_argument("-v",metavar="<value>",help="Key value",required=True)



parser.add_argument("-d",metavar="<level>",help="Debug level. 1-Warning (default), 2-Verbose, 3-Debug",type=int,default=1,choices=[1,2,3])
args=parser.parse_args()

# using logging levels to control verbosity of messages
debug_level=[logging.WARNING,logging.INFO,logging.DEBUG][args.d-1]
if args.d==3:
	http_client.HTTPConnection.debuglevel = 1
logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s',level=debug_level)
requests_log=logging.getLogger("requests.packages.urllib3")
requests_log.setLevel(debug_level)
requests_log.propagate=True

username=args.a
password=args.p
ise_pan=args.i
ise_base_url=f"https://{ise_pan}/admin"


# using requests sessions to automatically keep track of cookies
ise_session=requests.Session()

# some pages in ISE require referer header
ise_session.headers.update({"referer":ise_base_url})

# disable certificate warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
ise_session.verify=False

# starting with 2.4, query parameters are supplied to ISE in either
# _QPH_ header variable or _QPC_ cookie
# /admin/JavaScriptServlet is one of the pages that contains Javascript code to add _QPH_ header
# using this code to detect which method is used for query strings instead of using ISE version
# this page does not require valid authentication to ISE
cookie_param=False
logging.debug("Determining cookie based query passing")
response=ise_get("JavaScriptServlet")
if re.match(r".*_QPH_.*",response.text,re.S):
	cookie_param=True
	logging.debug("Using cookie based parameters. 2.4+")
else:
	logging.debug("Using query strings parameters. <2.4")

response=ise_post("JavaScriptServlet",headers={"FETCH-CSRF-TOKEN":"1"})
# retrieve CSRF token
csrf_token=re.match(r".*OWASP_CSRFTOKEN:([0-9A-Z\-]+).*",response.text,re.S)[1]
logging.debug(f"CSRF Token is {csrf_token}")

# need to load login page to receive Tomcat session cookies
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
	'destinationURL':'',
    'CSRFTokenNameValue': f'OWASP_CSRFTOKEN={csrf_token}',
    'OWASP_CSRFTOKEN': csrf_token
})

try:
	ise_verion=re.match(r'.*<div id="softwareVersion" style="display:none">([0-9\.]+)</div>.*',response.text,re.S)[1]
except TypeError:
	# assuming failed login if the resulting page doesn't contain ISE version
	logging.error("ISE Login failed")
	sys.exit(1)

try:
	# this field on the page contains comma-separated list of all patches
	# only the highest number will be parsed out
	ise_patches=re.match(r'.*<div id="patch" style="display:none">([0-9\,]+)</div>.*',response.text,re.S)[1].split(",")
	ise_patch=max([int(i) for i in ise_patches])
except TypeError:
	# setting patch to 0 if no patch information included on the home page
	# most likely, no patch is installed in this case
	ise_patch=0



# some ISE pages validate X-Requested-With header
ise_session.headers.update({"OWASP_CSRFTOKEN":csrf_token,"X-Requested-With":"XMLHttpRequest, OWASP CSRFGuard Project"})

pan_hostname=re.match(r'.*"theHostName" : "([^"]+)",.*',response.text,re.S)[1]
logging.info("Login successful")
logging.info(f"PAN Hostname is {pan_hostname}")
logging.info(f"ISE Version {ise_verion} Patch {ise_patch}")

file_condition={
    "fileConditionStub.dbId": "",
    "fileConditionStub.plistOperator": "equals",
    "fileConditionStub.conditionName": args.n ,
    "fileConditionStub.conditionDesc": "",
    "fileConditionStub.osAssigned": "Mac OSX",
    "fileConditionStub.fileType": "FileDate",
    "fileConditionStub.fileTypeMac": "PropertyList",
    "fileConditionStub.fileTypeLinux": "FileDate",
    "fileConditionStub.filePrefix": "NONE",
    "fileConditionStub.filePrefixMac": "root",
    "fileConditionStub.filePrefixLinux": "root",
    "fileConditionStub.fileSuffix": args.f,
    "fileConditionStub.fileExistsOperator": "Exists",
    "fileConditionStub.fileDateType": "Creation Date",
    "fileConditionStub.fileCompOperator": "EarlierThan",
    "fileConditionStub.withinDays": "",
    "fileConditionStub.plistDataType": "String",
    "fileConditionStub.plistKey": args.k,
    "fileConditionStub.plistStringOperator": "equals",
    "fileConditionStub.plistNumberOperator": "equals",
    "fileConditionStub.plistUnspecOperator": "Exists",
    "fileConditionStub.plistVersionOperator": "earlier than",
    "fileConditionStub.plistValue": args.v,
    "fileConditionStub.fileVersion": "",
    "fileConditionStub.fileCrcData": "",
    "fileConditionStub.fileSha256Data": "",
    "fileConditionStub.fileDate": "",
}

response=ise_post("postureFileConditionAction.do","command=createSubmit",data=file_condition)
logging.debug(response.text)
logging.info(json.dumps(json.loads(response.text),indent=2))
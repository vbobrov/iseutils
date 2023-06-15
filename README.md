# iseutils

  These tools provide some helpful functions to interact with ISE

## Installation

    git clone https://github.com/vbobrov/iseutils
    pip install -r requirements.txt

## intune.py

This tool simulates MDM connectivity to Intune the same way as ISE connecting to Intune.

Be sure to check out my post about ISE and Intune integration at https://www.securityccie.net/2023/02/09/intune-for-ise-engineer/

This tool requires the same parameters that ISE uses to reach Intune:
- Tenant ID
- Client ID aka App Registration ID
- Admin Certificate of ISE Node
- Private Key for the Admin certificate. Key must not be password protected.

This tool can perform 4 common functions that are used by ISE
- Get MDM Info Version 2 and 3
- Get a list of all Non-Compliant devices. This is what ISE performs periodicaly at Polling Interval
- Query a single device by MAC address
- Query a single device by GUID

Here is full usage help for the tool:
    usage: intune.py [-h] -a <appid> -t <tenantid> -c <certfile> -k <keyfile> (-i | -l | -q <id>) [-d <level>]

    ISE Intune Test Tool

    options:
    -h, --help     show this help message and exit
    -a <appid>     Azure Client or App ID
    -t <tenantid>  Azure Tenant ID
    -c <certfile>  Path to certificate file
    -k <keyfile>   Path to key file
    -i             Get MDM Info
    -l             List all non-compliant devices
    -q <id>        Query Intune by Device ID (GUID or MAC)
    -d <level>     Debug level. 1-Warning (default), 2-Verbose, 3-Debug

### Example 1 - MDM Info
    python intune.py -i -a ffffffff-051c-425d-9e37-ffffffffffff -t ffffffff-252f-408e-8953-ffffffffffff -c .intune.cer -k .intune.key 
    Version 2 Info:
    <?xml version="1.0" ?>
    <ise_api>
            <name>mdminfo</name>
            <api_version>2</api_version>
            <api_path>/StatelessNacService/ciscodeviceinfo/mdm/api</api_path>
            <redirect_url>https://portal.manage.microsoft.com/networkaccesscontrol/index</redirect_url>
            <query_max_size>100</query_max_size>
            <messaging_support>false</messaging_support>
            <vendor>Microsoft</vendor>
            <product_name>Microsoft Intune</product_name>
            <product_version>5.0</product_version>
    </ise_api>

    Version 3 Info:
    <?xml version="1.0" ?>
    <ise_api xmlns:i="http://www.w3.org/2001/XMLSchema-instance" xmlns="http://schemas.datacontract.org/2004/07/Microsoft.Intune.ResourceAccess.ComplianceRetrievalService.Model">
            <name>mdminfo</name>
            <api_version>3</api_version>
            <api_path>/TrafficGateway/TrafficRoutingService/ResourceAccess/ComplianceRetrievalService/cisco</api_path>
            <redirect_url>https://portal.manage.microsoft.com/networkaccesscontrol/index</redirect_url>
            <query_max_size>100</query_max_size>
            <messaging_support>false</messaging_support>
            <vendor>Microsoft</vendor>
            <product_name>Microsoft Intune</product_name>
            <product_version>5.0</product_version>
    </ise_api>

### Example 2 - Non-Compliant List

    python intune.py -l -a ffffffff-051c-425d-9e37-ffffffffffff -t ffffffff-252f-408e-8953-ffffffffffff -c .intune.cer -k .intune.key
    <?xml version="1.0" ?>
    <ise_api xmlns:i="http://www.w3.org/2001/XMLSchema-instance" xmlns="http://schemas.datacontract.org/2004/07/Microsoft.Intune.ResourceAccess.ComplianceRetrievalService.Model">
            <name>attributes</name>
            <api_version>3</api_version>
            <paging_info>0</paging_info>
            <deviceList>
                    <device>
                            <guid>3eeb9e62-cec9-4dd8-9dd6-74903695a62b</guid>
                            <Attributes>
                                    <guid>3eeb9e62-cec9-4dd8-9dd6-74903695a62b</guid>
                                    <register_status>true</register_status>
                                    <Compliance>
                                            <status>false</status>
                                    </Compliance>
                            </Attributes>
                    </device>
                    <device>
                            <guid>b537124a-cfd8-430e-8143-c0cc074ad3cb</guid>
                            <Attributes>
                                    <guid>b537124a-cfd8-430e-8143-c0cc074ad3cb</guid>
                                    <register_status>true</register_status>
                                    <Compliance>
                                            <status>false</status>
                                    </Compliance>
                            </Attributes>
                    </device>
                    <device>
                            <guid>ee9d3792-6859-4b71-93aa-56aba42581c5</guid>
                            <Attributes>
                                    <guid>ee9d3792-6859-4b71-93aa-56aba42581c5</guid>
                                    <register_status>true</register_status>
                                    <Compliance>
                                            <status>false</status>
                                    </Compliance>
                            </Attributes>
                    </device>
            </deviceList>
    </ise_api>

### Example 3 - Query by MAC

    python intune.py -q 00:50:56:A4:89:5A -a ffffffff-051c-425d-9e37-ffffffffffff -t ffffffff-252f-408e-8953-ffffffffffff -c .intune.cer -k .intune.key
    <?xml version="1.0" ?>
    <ise_api>
            <name>attributes</name>
            <api_version>2</api_version>
            <paging_info>0</paging_info>
            <deviceList>
                    <device>
                            <attributes>
                                    <register_status>true</register_status>
                                    <compliance>
                                            <status>false</status>
                                    </compliance>
                                    <pin_lock_on>false</pin_lock_on>
                                    <model>VMware Virtual Platform</model>
                                    <udid/>
                                    <serial_number>VMware-422461a80090e4c2-0e2c2f2ba2eefe60</serial_number>
                                    <os_version>10.0.19043.2006</os_version>
                            </attributes>
                    </device>
            </deviceList>
    </ise_api>

### Example 4 - Query by GUID

    python intune.py -q ee9d3792-6859-4b71-93aa-56aba42581c5 -a ffffffff-051c-425d-9e37-ffffffffffff -t ffffffff-252f-408e-8953-ffffffffffff -c .intune.cer -k .intune.key
    <?xml version="1.0" ?>
    <ise_api xmlns:i="http://www.w3.org/2001/XMLSchema-instance" xmlns="http://schemas.datacontract.org/2004/07/Microsoft.Intune.ResourceAccess.ComplianceRetrievalService.Model">
            <name>attributes</name>
            <api_version>3</api_version>
            <deviceList>
                    <device>
                            <guid>ee9d3792-6859-4b71-93aa-56aba42581c5</guid>
                            <Attributes>
                                    <guid>ee9d3792-6859-4b71-93aa-56aba42581c5</guid>
                                    <register_status>true</register_status>
                                    <Compliance>
                                            <status>false</status>
                                    </Compliance>
                            </Attributes>
                    </device>
            </deviceList>
    </ise_api>

## certinstall.py

**Note: This tool is no longer needed in ISE 3.0 and above. There are now official APIs to import certificates**

**Disclaimer: This tool simulates required browser transactions to automate certificate installation. This tool will not be supported by Cisco. Use at your own risk.**

**No internal product information was used to develop this tool. It was created exclusively by analyzing interaction between Firefox and ISE using Web Developer Console and simulating the same requests with Python.**

This tool was tested with ISE 2.2 and above. It may work with earlier versions.

This tool can perform most of the system certificate import functions available through ISE GUI.

The tool relies on ISE to perform much of the validation. Some examples of these are: incorrect private key password, lack of certificate chain, conflicting certificates with different uses, etc.

When a certificate is submitted to ISE backend, it replies with errors or warnings that can be seen with the GUI. The warnings are generated one at a time. For example, if a wildcard certificate is being imported which is also used for portal, ISE will responds with wildcard certificate prompt and after it's accepted, it will follow up with portal warning. Some of these warnings require user interaction. This tool will display these warnings at the prompt and ask the user to accept them.

-y option can be specified to automatically accept all the warnings. When -y is specified, the warnings are still shown on the screen, but they don't need to be accepted interactively.

-r option will prevent the nodes from being restarted when required by installation of an Admin certificate or any other reason that may require a restart. Use this option with caution as it is not the expected flow of installing certificates

-n option allows the certificate to be install on multiple nodes. When a wildcard certificate is imported, all nodes except for Primary Admin are skipped. That is because wildcard certificates are shared on all nodes. If Primary Admin node is specified in the list, it is moved to the very end of the list to avoid a restart in the middle of certificate installation. If any invalid nodes are specified, they're silently removed. If no nodes remain after removal, the tool will display an error and exit.

-n accepts *all* as the keyword to include all the nodes in the deployment

if -u option is omitted, the certificate is imported as Not in Use. To specify a non-default portal tag specify portal:***tag***. If the tag doesn't already exist in ISE, a confirmation prompt will be displayed.

-l option will list certificates on all the nodes in the deployment. To fit into a table, some long strings will be trimmed.

This tool requires *python 3* and *requests* module

Here's full usage and options supported.

    usage: certinstall.py [-h] [-l] -i <isenode> -a <username> -p <password> [-c <certfile>] [-k <keyfile>] [-e <keypassword>]
                          [-n <node> [<node> ...]] [-u [<use> [<use> ...]]] [-y] [-d <level>]
    
    ISE Certificate Import Tool
    
    optional arguments:
      -h, --help            show this help message and exit
      -l                    List all certificates. Requires -i, -a and -p. Other options are ignored.
      -i <isenode>          ISE Node FQDN or IP address
      -a <username>         GUI Admin username
      -p <password>         GUI Admin password
      -c <certfile>         Path to certificate file
      -k <keyfile>          Path to key file
      -e <keypassword>      Key encryption password
      -n <node> [<node> ...]
                            Node list to install certificate. Space separated. Specify keyword all to include all nodes in the deployment.
      -u [<use> [<use> ...]]
                            Certificate uses (admin,portal,eap,pxgrid,dtls). Space separated. For portal, a non-default tag is specified with portal:<tag>
      -r                    Prevent node restart if required. Use with caution.
      -y                    Accept all warnings without prompts
      -d <level>            Debug level. 1-Warning (default), 2-Verbose, 3-Debug
### Example 1
Listing installed certificates

    $ ./certinstall.py -l -i vb-ise-pan1.abcd.com -a admin -p password
    
    +---------------+----------------------------------------+---------------------+-------------------+-----------+-----------+
    |   ISE Node    |               Protocol                 |   Issued To         |    Issued By      | Valid From| Valid To  |
    +---------------+----------------------------------------+---------------------+-------------------+-----------+-----------+
    |vb-ise-pan1    |SAML                                    |SAML_vb-ise-pan1.abc|SAML_vb-ise-pan1.abc| 3 Apr 2020| 3 Apr 2021|
    |vb-ise-pan1    |ISE Messaging Service                   |vb-ise-pan1.abcde.co|Certificate Services| 2 Apr 2020| 3 Apr 2030|
    |vb-ise-pan1    |Admin, Portal, EAP Authentication, pxGri|*.abcde.com         |R3                  |22 Jan 2021|22 Apr 2021|
    +---------------+----------------------------------------+---------------------+-------------------+-----------+-----------+
    |vb-ise-psn1    |ISE Messaging Service                   |vb-ise-psn1.abcde.co|Certificate Services| 2 Apr 2020| 3 Apr 2030|
    |vb-ise-psn1    |Not in use                              |vb-ise-psn1.abcde.co|Certificate Services| 2 Apr 2020| 3 Apr 2030|
    |vb-ise-psn1    |Admin, Portal, EAP Authentication, pxGri|*.abcde.com         |R3                  |22 Jan 2021|22 Apr 2021|
    |vb-ise-psn1    |SAML                                    |SAML_vb-ise-pan1.abc|SAML_vb-ise-pan1.abc| 3 Apr 2020| 3 Apr 2021|
    |vb-ise-psn1    |Not in use                              |pxgrid.abcde.com    |abcde-CA            |10 Sep 2020|10 Sep 2022|
    |vb-ise-psn1    |Not in use                              |eap.abcde.com       |abcde-CA            |14 May 2020|14 May 2022|
    +---------------+----------------------------------------+---------------------+-------------------+-----------+-----------+
    |vb-ise-psn2    |Admin, Portal, EAP Authentication, pxGri|*.abcde.com         |R3                  |22 Jan 2021|22 Apr 2021|
    |vb-ise-psn2    |SAML                                    |SAML_vb-ise-pan1.abc|SAML_vb-ise-pan1.abc| 3 Apr 2020| 3 Apr 2021|
    |vb-ise-psn2    |Not in use                              |vb-ise-psn2.abcde.co|Certificate Services| 2 Apr 2020| 3 Apr 2030|
    |vb-ise-psn2    |Not in use                              |eap.abcde.com       |abcde-CA            |14 May 2020|14 May 2022|
    |vb-ise-psn2    |ISE Messaging Service                   |vb-ise-psn2.abcde.co|Certificate Services| 2 Apr 2020| 3 Apr 2030|
    |vb-ise-psn2    |Not in use                              |asa1.abcde.com      |abcde-CA            |20 Apr 2020|20 Apr 2022|
    |vb-ise-psn2    |Not in use                              |pxgrid.abcde.com    |abcde-CA            |10 Sep 2020|10 Sep 2022|
    +---------------+----------------------------------------+---------------------+-------------------+-----------+-----------+
### Example 2
Installing wildcard certificate for EAP and Portal with new tag

    $ ./certinstall.py  -i ise24.abcde.com -a admin -p password -c .wildcard.pem -k .wildcard.pvk -e secret -n all -u eap portal:wildcard
    Create new portal tag wildcard?
    (yes/no): yes
    2021-03-12 22:05:31,937 - WARNING - Attempting to install on ise24
    This Certificate contains wildcard values in Common Name or Subject Alternative Name extension. </br> Please confirm this by selecting the "Allow Wildcard certificate" checkbox
    (yes/no): yes
    2021-03-12 22:05:38,748 - WARNING - Certificate Successfully Imported on ise24: Certificate was added successfully
### Example 3
Failure scenario reported by ISE

    $ ./certinstall.py  -i ise24.abcde.com -a admin -p password -c .le.pem -k .le.pvk -e secret -n all -u admin
    2021-03-12 22:09:44,616 - WARNING - Attempting to install on ise24
    2021-03-12 22:09:45,097 - ERROR - Import failed: Certificate path validation failed. Make sure required Certificate Chain is imported under Trusted Certificates.
### Example 4
Replacing an existing certificate

    $ ./certinstall.py  -i ise24.abcde.com -a admin -p password -c .le.pem -k .le.pvk -e secret -n all -u admin
    2021-03-12 22:19:28,336 - WARNING - Attempting to install on ise24
    This Certificate contains wildcard values in Common Name or Subject Alternative Name extension. </br> Please confirm this by selecting the "Allow Wildcard certificate" checkbox
    (yes/no): yes
    A matching certificate already exists. Please confirm replacement.
    (yes/no): yes
    2021-03-12 22:19:38,073 - WARNING - Certificate Successfully Imported on ise24: Certificate was added successfully:restart required

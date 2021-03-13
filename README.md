# iseutils

  These tools provide some helpful functions to interact with ISE

## certinstall.py

**Disclaimer: This tool simulates required browser transactions to automate certificate installation. This tool will not be supported by Cisco. Use at your own risk.**

**No internal product information was used to develop this tool. It was created exclusively by analyzing interaction between Firefox and ISE using Web Console and simulating the same requests with Python.**

It is compatible with ISE 2.4 and above.

This tool can perform most of the system certificate import functions available through ISE GUI.

The tool relies on ISE to perform much of the validation. Some examples of these are: incorrect private key password, lack of certificate chain, conflicting certificates with different uses, etc.

When a certificate is submitted to ISE backend, it replies with errors or warnings that can be seen with the GUI. The warnings are generated one at a time. For example, if a wildcard certificate is being imported which is also used for portal, ISE will responds with wildcard certificate prompt and after it's accepted, it will follow up with portal warning. Some of these warnings require user interaction. This tool will display these warnings at the prompt and ask the user to accept them.

-y option can be specified to automatically accept all the warnings. When -y is specified, the warnings are still shown on the screen, but they don't need to be accepted interactively.

-n option allows the certificate to be install on multiple nodes. When a wildcard certificate is imported, all nodes except for Primary Admin are skipped. That is because wildcard certificates are shared on all nodes.

-n accepts *all* as the keyword to include all the nodes in the deployment

if -u option is omitted, the certificate is imported as Not in Use. To specify a non-default portal tag specify portal:***tag***. If the tag doesn't already exist in ISE, a confirmation prompt will be displayed.

-l option will list certificates on all the nodes in the deployment. To fit into a table, some long strings will be trimmed.

This tool requires *python 3* and *requests* module

Here's full usage options supported.

    usage: certinstall.py [-h] [-l] -i <isenode> -a <username> -p <password> [-c <certfile>] [-k <keyfile>] [-e <keypassword>]
                          [-n <node> [<node> ...]] [-u [<use> [<use> ...]]] [-y] [-d <level>]
    
    ISE Certificate Import Tool
    
    optional arguments:
      -h, --help            show this help message and exit
      -l                    List all certificates. Requires -i, -a and -p. Other options are ignored.
      -i <isenode>          ISE Node FQDN or IP address
      -a <username>         GUI Admin username.
      -p <password>         GUI Admin password.
      -c <certfile>         Path to certificate file.
      -k <keyfile>          Path to key file.
      -e <keypassword>      Key encryption password.
      -n <node> [<node> ...]
                            Node list to install certificate. Space separated. Specify keyword all to include all nodes in the
                            deployment.
      -u [<use> [<use> ...]]
                            Certificate uses (admin,portal,eap,pxgrid,dtls). Space separated. For portal, a non-default tag is
                            specified with portal:<tag>
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

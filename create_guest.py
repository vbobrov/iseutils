import requests
import os
from datetime import datetime, timedelta
from pprint import pprint

# Defined API parameters
ise_fqdn=os.getenv("ise_fqdn")
api_url=f"https://{ise_fqdn}/ers/config"

# Set API authentication
# ERS credentials are only needed to look up Sponsor portal ID
# This ID can be seen by browsing to the sponsor portal
# URL would look like this: https://ise.example.com:8445/sponsorportal/PortalSetup.action?portal=7a062105-d891-4ff0-9bad-2057583cee46
# 7a062105-d891-4ff0-9bad-2057583cee46 is the portal ID

ers_username=os.getenv("ers_username")
ers_password=os.getenv("ers_password")
sponsor_username=os.getenv("sponsor_username")
sponsor_password=os.getenv("sponsor_password")

# Set guest parameters
guest_type="Daily (default)"
sponsor_portal="Sponsor Portal (default)"

# Retrieve Sponsor portal id
# This step is optional if the portal ID was manually retrived from the URL above
r=requests.get(f"{api_url}/sponsorportal/?filter=name.eq.{sponsor_portal}",
               auth=(ers_username,ers_password),
               headers={
                   "Accept": "application/json"
               },
               verify=False
               )

pprint(r.json())
portal_id=r.json()["SearchResult"]["resources"][0]["id"]

# Set guest information
first_name="John"
last_name="Smith"
email="jsmith@smith.com"
phone="+12345678901"
valid_days=2

current_date = datetime.now()

from_date = current_date.strftime('%m/%d/%Y %H:%M')
to_date = (current_date + timedelta(days=valid_days)).strftime('%m/%d/%Y %H:%M')

guest_json = {
    "GuestUser": {
        "guestType": guest_type,
        "sponsorUserName": sponsor_username,
        "guestInfo": {
            "firstName": first_name,
            "lastName": last_name,
            "emailAddress": email,
            "phoneNumber": phone,
        },
        "guestAccessInfo": {
            "validDays": valid_days,
            "fromDate": from_date,
            "toDate": to_date,
            "location": "San Jose"
        },
        "portalId": portal_id,
    }
}

r=requests.post(f"{api_url}/guestuser",
                auth=(sponsor_username,sponsor_password),
                json=guest_json,
                verify=False
                )

r=requests.get(r.headers["Location"],
                auth=(sponsor_username,sponsor_password),
                headers={
                   "Accept": "application/json"
               },
               verify=False
               )

pprint(r.json())

guest_username=r.json()['GuestUser']['guestInfo']['userName']
guest_password=r.json()['GuestUser']['guestInfo']['password']

print(f"Username: {guest_username}, password: {guest_password}")

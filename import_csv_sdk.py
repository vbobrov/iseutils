import csv
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from ciscoisesdk import IdentityServicesEngineAPI
from ciscoisesdk.exceptions import ApiError

# Function to get endpoint by MAC address
def get_endpoint_by_mac(api, mac_address):
    try:
        search_result = api.endpoint.get_endpoints(filter=f"mac.EQ.{mac_address}").response.SearchResult
        if search_result.resources:
            return search_result.resources[0]
    except ApiError as e:
        print(f"Error retrieving endpoint for MAC {mac_address}: {str(e)}")
    return None

# Function to get group ID by group name, using cache
def get_group_id_by_name(api, group_name, group_id_cache):
    if group_name in group_id_cache:
        return group_id_cache[group_name]

    try:
        search_result = api.endpoint_identity_group.get_endpoint_groups(filter=f"name.EQ.{group_name}").response.SearchResult
        if search_result.resources:
            group_id = search_result.resources[0].id
            group_id_cache[group_name] = group_id
            return group_id
    except ApiError as e:
        print(f"Error retrieving group ID for group name {group_name}: {str(e)}")
    return None

# Function to update endpoint
def update_endpoint(api, endpoint_id, identity_group_id, static_group_assignment):
    try:
        response = api.endpoint.update_endpoint_by_id(
            id=endpoint_id,
            group_id=identity_group_id,
            static_group_assignment=static_group_assignment
        )
        return response
    except ApiError as e:
        print(f"Error updating endpoint {endpoint_id}: {str(e)}")
    return None

# Function to delete an endpoint by ID
def delete_endpoint(api, endpoint_id):
    try:
        api.endpoint.delete_endpoint_by_id(endpoint_id)
    except ApiError as e:
        print(f"Error deleting endpoint with ID {endpoint_id}: {str(e)}")

# Function to create endpoint
def create_endpoint(api, mac_address, identity_group_id, static_group_assignment):
    try:
        response = api.endpoint.create_endpoint(
            mac=mac_address,
            group_id=identity_group_id,
            static_group_assignment=static_group_assignment
        )
        return response
    except ApiError as e:
        print(f"Error creating endpoint {mac_address}: {str(e)}")
    return None

# Function to process each row from the CSV
def process_row(api, row, group_id_cache):
    mac_address = row['MACAddress']
    identity_group_name = row['IdentityGroup']
    static_group_assignment = row['StaticGroupAssignment'].lower()=="true"
    
    # Lookup identity group ID by name using cache
    result = ""
    identity_group_id = get_group_id_by_name(api, identity_group_name, group_id_cache)
    if not identity_group_id:
        return f"Failed to find identity group ID for group name: {identity_group_name}"

    endpoint = get_endpoint_by_mac(api, mac_address)
    if endpoint:
        endpoint_id = endpoint.id
        delete_endpoint(api, endpoint_id)
        result+=f"Deleted Endpoint {mac_address} successfully. "
    response = create_endpoint(api, mac_address, identity_group_id, static_group_assignment)
    if response:
        result+= f"Created endpoint {mac_address} successfully."
    else:
        result+= f"Failed to create endpoint {mac_address}."
    return result

# Main function to process CSV and update/create endpoints
def main(csv_file, isenode, username, password):
    api = IdentityServicesEngineAPI(username=username, password=password, base_url=f"https://{isenode}",verify=False)

    with open(csv_file, mode='r') as file:
        csv_reader = csv.DictReader(file, delimiter=',')
        group_id_cache = {}

        with ThreadPoolExecutor(max_workers=20) as executor:
            future_to_row = {executor.submit(process_row, api, row, group_id_cache): row for row in csv_reader}
            for future in as_completed(future_to_row):
                try:
                    result = future.result()
                    print(result)
                except Exception as exc:
                    print(f"Generated an exception: {exc}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Import CSV data into Cisco ISE using ERS API.')
    parser.add_argument('csv_file', help='Path to the CSV file')
    parser.add_argument('--isenode', required=True, help='ISE node for Cisco ISE ERS API')
    parser.add_argument('--username', required=True, help='Username for Cisco ISE ERS API')
    parser.add_argument('--password', required=True, help='Password for Cisco ISE ERS API')
    
    args = parser.parse_args()
    main(args.csv_file, args.isenode, args.username, args.password)
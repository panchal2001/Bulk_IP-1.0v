import csv
import requests
import json

# Load IP addresses from CSV file
ip_list = []
with open('ip_list.csv', 'r') as csvfile:
    reader = csv.reader(csvfile)
    for row in reader:
        ip_list.append(row[0])

# API keys and URLs for each source
virustotal_api_key = 'YOUR_VIRUSTOTAL_API_KEY'
virustotal_api_url = 'https://www.virustotal.com/api/v3/ip_addresses/'

ibm_xforce_api_key = 'YOUR_IBM_XFORCE_API_KEY'
ibm_xforce_api_url = 'https://api.xforce.ibmcloud.com/ipr/'

abuseipdb_api_key = 'YOUR_ABUSEIPDB_API_KEY'
abuseipdb_api_url = 'https://api.abuseipdb.com/api/v2/check'

# Function to query a threat intelligence source
def query_source(api_url, api_key, ip_address):
    headers = {'x-apikey': api_key}
    params = {'ip': ip_address}
    response = requests.get(api_url, headers=headers, params=params)

    if response.status_code == 200:
        return json.loads(response.text)
    else:
        print(f"Error querying {api_url}: {response.status_code}")
        return None

# Query each source for each IP address
for ip in ip_list:
    # VirusTotal
    virustotal_response = query_source(virustotal_api_url, virustotal_api_key, ip)
    if virustotal_response:
        print(f"VirusTotal results for {ip}:")
        print(virustotal_response)

    # IBM X-Force
    ibm_xforce_response = query_source(ibm_xforce_api_url, ibm_xforce_api_key, ip)
    if ibm_xforce_response:
        print(f"IBM X-Force results for {ip}:")
        print(ibm_xforce_response)

    # AbuseIPDB
    abuseipdb_response = query_source(abuseipdb_api_url, abuseipdb_api_key, ip)
    if abuseipdb_response:
        print(f"AbuseIPDB results for {ip}:")
        print(abuseipdb_response)


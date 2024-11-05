import winrm
import json
import requests
import datetime
import csv
from winrm.protocol import Protocol
import time

# Static values for S1 API
CONSOLEURL = "https://your.console.net/"  # Example: https://your.console.net
APITOKEN = ""  # S1 API Token
APIREQUEST = "/web/api/v2.1/threats"  # The URL of the call. See the API documentation
LIMIT = "5"  # Increase limit to retrieve more alerts per query.
hostname = "f6c0ac62cca14ede91413c8c4551ebd4"  # Using UUID instead of hostname

# WinRM details
hostip = '1.1.1.1'
domain = 'account_domain'
user = 'username'
password = 'password123'

# Load Atomic Red Team test cases
def atomic_indexer():
    atomic_tests = []
    with open('./windows-index.csv', mode='r', newline='') as tests:
        reader = csv.DictReader(tests)
        for row in reader:
            atomic_tests.append(row)
    return atomic_tests

# Run the atomic test on the remote system
def atomic_detection(hostip, domain, user, password, techniqueId, testNumber):
    p = Protocol(
        endpoint=f'https://{hostip}:5986/wsman',
        transport='ntlm',
        username=f'{user}',
        password=f'{password}',
        server_cert_validation='ignore'
    )
    timestamp = datetime.datetime.now().strftime("%Y-%m-%dT%X.%fZ")
    shell_id = p.open_shell()
    command = f"powershell -Command Import-Module 'C:\\AtomicRedTeam\\invoke-atomicredteam\\Invoke-AtomicRedTeam.psd1' -Force; Invoke-AtomicTest '{techniqueId}' -TestNumbers {testNumber}"
    command_id = p.run_command(shell_id, command)
    std_out, std_err, status_code = p.get_command_output(shell_id, command_id)
    p.cleanup_command(shell_id, command_id)
    p.close_shell(shell_id)
    return timestamp

# Retrieve alerts from SentinelOne after the atomic test
def pull_s1_alerts(console_url, api_token, api_request, hostname, timestamp, limit):
    headers = {
        "Content-type": "application/json",
        "Authorization": f"APIToken {api_token}"
    }
    alerts = []
    for _ in range(3):  # Query multiple times to improve detection certainty
        try:
            response = requests.get(
                f"{console_url}{api_request}?limit={limit}&uuid__contains={hostname}&createdAt__gte={timestamp}",
                headers=headers
            )
            response.raise_for_status()
            agents = response.json()
            if 'data' in agents and agents['data']:
                alerts.extend(agents['data'])
        except requests.exceptions.RequestException as e:
            print(f"Error fetching data: {e}")
            break
        except json.JSONDecodeError as e:
            print(f"Error parsing JSON: {e}")
            break
    return alerts

# Match alerts to the Atomic Red Team technique and consolidate results
def json_magic(techniqueId, testNumber, alerts, consolidated_results):
    if not alerts:
        print("No relevant alerts found.")
        return
    
    for alert in alerts:
        indicators = alert.get('indicators', [])
        agentRealtimeInfo = alert.get('agentRealtimeInfo', {})
        threatInfo = alert.get('threatInfo', {})
        mitigationStatus = alert.get('mitigationStatus', [])

        # Initialize lists for detected categories, tactics, techniques, and links
        categories = []
        tactics_name = []
        techniques = []
        links = []

        # Process each indicator and extract details
        for indicator in indicators:
            category = indicator.get('category')
            if category and category not in categories:
                categories.append(category)
            for tactic in indicator.get('tactics', []):
                tactic_name = tactic.get('name')
                if tactic_name and tactic_name not in tactics_name:
                    tactics_name.append(tactic_name)
                for technique in tactic.get('techniques', []):
                    technique_name = technique.get('name')
                    link = technique.get('link')
                    if technique_name and technique_name not in techniques:
                        techniques.append(technique_name)
                    if link and link not in links:
                        links.append(link)

        # Extract agent information
        agentInfo = {
            "computer_name": agentRealtimeInfo.get('agentComputerName', 'N/A'),
            "agentOsName": agentRealtimeInfo.get('agentOsName', 'N/A'),
            "agentUuid": agentRealtimeInfo.get('agentUuid', 'N/A')
        }

        # Check if the specified technique was detected in the techniques list
        detection_match = techniqueId in techniques

        # Extract mitigation data, creating an organized list for each action
        mitigations = []
        for status in mitigationStatus:
            action = status.get('action')
            actionsCounters = status.get('actionsCounters', {})
            if action:
                mitigations.append({
                    "action": action,
                    "failed": actionsCounters.get('failed', 0),
                    "success": actionsCounters.get('success', 0),
                    "status": status.get('status', 'unknown')
                })

        # Extract threat information
        s1_threatInfo = {
            "s1_threatName": threatInfo.get('threatName', 'Unknown'),
            "s1_classification": threatInfo.get('classification', 'Unknown'),
            "s1_detectionType": threatInfo.get('detectionType', 'Unknown'),
            "s1_engines": threatInfo.get('engines', []),
            "mitigatedPreemptively": threatInfo.get('mitigatedPreemptively', False),
            "mitigationStatus": threatInfo.get('mitigationStatus', 'Unknown')
        }

        # Consolidate techniques detected and match status
        techniques_detected = {
            "test_number": testNumber,
            "techniques_detected": techniques,
            "categories_detected": categories,
            "tactics_detected": tactics_name,
            "tactic_links": links,
            "detection_match": detection_match
        }

        # Add all extracted information into the consolidated results
        consolidated_results.append({
            "techniqueId": techniqueId,
            "testNumber": testNumber,
            "alertID": alert.get('id', 'Unknown'),
            "agentInfo": agentInfo,
            "techniques_detected": techniques_detected,
            "S1_threatInfo": s1_threatInfo,
            "mitigations": mitigations,
        })

# Allow time for SentinelOne alerts to populate
def data_pull_delay():
    time.sleep(180)

# Main execution flow
def main():
    consolidated_results = []  # Store all results for a single JSON file
    tests = atomic_indexer()
    for test in tests:
        techn = test['Technique #']
        testNo = test['Test #']
        print(f"Running test for Technique ID: {techn}, Test Number: {testNo}")
        timestamp = atomic_detection(hostip, domain, user, password, techn, testNo)
        data_pull_delay()
        alerts = pull_s1_alerts(CONSOLEURL, APITOKEN, APIREQUEST, hostname, timestamp, LIMIT)
        json_magic(techn, testNo, alerts, consolidated_results)

    # Write consolidated results to a single JSON file for Power BI or other tools
    try:
        with open("consolidated_results.json", "w") as outfile:
            json.dump(consolidated_results, outfile, indent=4)
        print("Consolidated results saved to 'consolidated_results.json'")
    except (IOError, OSError) as e:
        print(f"File write error: {e}")

# Run the main function
main()

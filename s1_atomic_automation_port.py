import winrm
import json
import requests
import datetime
import csv
from winrm.protocol import Protocol


# static values
#s1 api 
CONSOLEURL = "https://your.console.net/" # Example: https://your.console.net
APITOKEN = "" #S1 API Token
APIREQUEST = "/web/api/v2.1/threats" # The URL of the call. See the API documentation
LIMIT = "1" # If required, change the limit of returned data. Max is 1000.
hostname="f6c0ac62cca14ede91413c8c4551ebd4" #currently using uuid rather than hostname

#winrm
hostip = '1.1.1.1'
domain='account_domain'
user = 'username'
password = 'password123'

#todo upon validating the current program works:
# add parralel testing across mutliple machines to decrese test time
# not hard code secrets such as api keys and login creds
# add a hosts file where test machine info can be stored with the below format:
# {IP: "1.1.1.1", s1_uuid: "12345678abcdefg", domain: "account_domain", user: "username", password: "password123"} ...  
# this would allow an easy way of configuring multiple test targets



def atomic_indexer():
    atomic_tests =[]
    with open('./windows-index.csv', mode='r', newline='') as tests:
        reader = csv.DictReader(tests)
        for row in reader:
            atomic_tests.append(row)
    return atomic_tests

def atomic_detination(hostip, domain, user, password, techniqueId, testNumber): #untested
    p = Protocol(
        endpoint=f'https://{hostip}:5986/wsman',
        transport='ntlm',
        username=f'{user}',
        password=f'{password}',
        server_cert_validation='ignore')

    ct = datetime.datetime.now()
    detination_timestamp = ct.strftime("%Y-%m-%dT%X.%fZ")

    shell_id = p.open_shell()
    command = f"powershell -Command Import-Module 'C:\\AtomicRedTeam\\invoke-atomicredteam\\Invoke-AtomicRedTeam.psd1' -Force; Invoke-AtomicTest '{techniqueId}' -TestNumbers {testNumber}"
    
    command_id = p.run_command(shell_id, command)
    std_out, std_err, status_code = p.get_command_output(shell_id, command_id)
    p.cleanup_command(shell_id, command_id)
    p.close_shell(shell_id)
    return(detination_timestamp)


def pull_s1_alert(CONSOLEURL, APITOKEN, APIREQUEST, hostname, detination_timestamp, limit): #semi-untested

    #request headers
    headers = {
    "Content-type": "application/json",
    "Authorization": "APIToken " + APITOKEN
    }
    try:
        response = requests.get(...)
        response.raise_for_status()  # Raises an error for bad HTTP responses
        agents = response.json()
        formated = json.dumps(agents, indent=4)
    except requests.exceptions.RequestException as e:
        print(f"Error fetching data: {e}")
        return None
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON: {e}")
        return None
    return(formated)

def json_magic(techniqueId, testNumber, data):
    if data is None:
        print("No data received from SentinelOne alert.")
        return
    
    try:
        # Ensure 'data' key exists and contains at least one element
        if 'data' not in data or len(data['data']) == 0:
            print("Data format is incorrect or empty. Expected 'data' key with at least one entry.")
            return
        
        # Extract nested information with default empty values if keys are missing
        indicators = data['data'][0].get('indicators', [])
        agentRealtimeInfo = data['data'][0].get('agentRealtimeInfo', {})
        threatInfo = data['data'][0].get('threatInfo', {})
        mitigationStatus = data['data'][0].get('mitigationStatus', [])

        categorys = []
        tactics_name = []
        techniques1 = []
        links = []

        # Pull indicator properties
        for indicator in indicators:
            if indicator.get('category') and indicator['category'] not in categorys:
                categorys.append(indicator['category'])
            for tactics in indicator.get('tactics', []):
                if tactics.get('name') and tactics['name'] not in tactics_name:
                    tactics_name.append(tactics['name'])
                for technique in tactics.get('techniques', []):
                    if technique.get('name') and technique['name'] not in techniques1:
                        techniques1.append(technique['name'])
                    if technique.get('link') and technique['link'] not in links:
                        links.append(technique['link'])

        # Extract agent info with default empty values for missing keys
        agentInfo = {
            "computer_name": agentRealtimeInfo.get('agentComputerName', 'N/A'),
            "agentOsName": agentRealtimeInfo.get('agentOsName', 'N/A'),
            "agentUuid": agentRealtimeInfo.get('agentUuid', 'N/A')
        }
        print(agentInfo)  # Debugging information, if necessary

        # Check if the technique is detected
        detected = techniqueId in techniques1

        # Pull mitigation data with checks for nested keys
        mitigations = dict(action=[])
        for e in mitigationStatus:
            action = e.get('action')
            actionsCounters = e.get('actionsCounters', {})
            if action:
                actions_entry = {
                    action: {
                        'failed': actionsCounters.get('failed', 0),
                        'success': actionsCounters.get('success', 0),
                        'status': e.get('status', 'unknown')
                    }
                }
                mitigations['action'].append(actions_entry)

        # Pull threat info with fallback for missing data
        s1_threatInfo = {
            "s1_threatName": threatInfo.get('threatName', 'Unknown'),
            "s1_classification": threatInfo.get('classification', 'Unknown'),
            "s1_detectionType": threatInfo.get('detectionType', 'Unknown'),
            "s1_engines": threatInfo.get('engines', []),
            "mitigatedPreemptively": threatInfo.get('mitigatedPreemptively', False),
            "mitigationStatus": threatInfo.get('mitigationStatus', 'Unknown')
        }

        # Construct detected techniques
        techniques_detected = {
            "test number": testNumber,
            "techniques_detected": techniques1,
            "categorys__detected": categorys,
            "tactic_name_detected": tactics_name,
            "tactic_links": links,
            "detection_match": detected,
        }

        # Final result structure
        results = {
            techniqueId: [{
                "alertID": data['data'][0].get('id', 'Unknown'),
                "techniques_detected": techniques_detected,
                "S1_threatInfo": s1_threatInfo,
                "mitigations": mitigations,
            }]
        }

        # Serialize and write to file with error handling
        results1 = json.dumps(results, indent=4)
        with open("results.json", "w") as outfile:
            outfile.write(results1)

    except KeyError as e:
        print(f"Key error: {e} - data structure might have unexpected format.")
    except (IOError, OSError) as e:
        print(f"File write error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

    results1=(json.dumps(results, indent=4))
    with open("results.json", "w") as outfile:
        outfile.write(results1)

def data_pull_delay():
    time.sleep(180) # sleep for 3 minutes to wait for alert to be created in S1


tests = atomic_indexer()
for e in tests:
    techn = e['Technique #']
    testNo= e['Test #']
    detination_time=atomic_detination(hostip, domain, user, password, techn, testNo) #untested
    data_pull_delay()
    data=pull_s1_alert(CONSOLEURL, APITOKEN, APIREQUEST, hostname, detination_time, limit) #untested
    json_magic(techn, testNo, data) #functionality tested but not with live api data

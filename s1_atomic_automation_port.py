import winrm
import json
import requests
import datetime
import csv

# static values
#s1 api 
CONSOLEURL = "https://[s1_tenent].sentinelone.net/" # Example: https://your.console.net
APITOKEN = "" #S1 API Token
APIREQUEST = "/web/api/v2.1/threats" # The URL of the call. See the API documentation
LIMIT = "1" # If required, change the limit of returned data. Max is 1000.
hostname="device_uuid" #currently using uuid rather than hostname

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
    with open('./windows-index.csv', mode='r', newline='') as tests: #uses this atomic red test csv https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/Indexes/Indexes-CSV/windows-index.csv
        reader = csv.DictReader(tests)
        for row in reader:
            atomic_tests.append(row)
    return atomic_tests

def atomic_detination(hostip, domain, user, password, techniqueId, testNumber): #untested
    p = Protocol(
        endpoint='https://{hostip}:5986/wsman',
        transport='ntlm',
        username=r'{domain}\{user}',
        password='{password}',
        server_cert_validation='ignore')

    ct = datetime.datetime.now()
    detination_timestamp = ct.strftime("%Y-%m-%dT%X.%fZ")

    shell_id = p.open_shell()
    command="powershell -Command Import-Module 'C:\\AtomicRedTeam\\invoke-atomicredteam\\Invoke-AtomicRedTeam.psd1' -Force; Invoke-AtomicTest '${techniqueId}' -TestNumbers ${testNumber}'"
    
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
    #sent the request
    response = requests.get(CONSOLEURL + APIREQUEST + "?limit=" + LIMIT + "&uuid__contains=" + hostname +"&createdAt__gte=" + detination_timestamp, headers=headers)
    #format the response
    agents = response.json()
    formated = json.dumps(agents, indent=4)

    return(formated)

def json_magic(techniqueId, testNumber, data):
    indicators = data['data'][0]['indicators']
    agentRealtimeInfo = data['data'][0]['agentRealtimeInfo']
    threatInfo = data['data'][0]['threatInfo']
    mitigationStatus = data['data'][0]['mitigationStatus']
    # could be worth moving this into a 3d dict 
    categorys = []
    tactics_name = []
    techniques1 = []
    links = []  

    #pull indicator properties 
    for indicator in indicators:
        if (indicator['category'] not in categorys):
            categorys.append(indicator['category'])
        for tactics in indicator['tactics']:
            if (tactics['name'] not in tactics_name):
                tactics_name.append(tactics['name'])
            for technique in tactics['techniques']:
                if (technique['name'] not in techniques1):
                    techniques1.append(technique['name'])
                if (technique['link'] not in links):
                    links.append(technique['link'])

    agentInfo = {
        "computer_name": agentRealtimeInfo['agentComputerName'],
        "agentOsName": agentRealtimeInfo['agentOsName'],
        "agentUuid": agentRealtimeInfo['agentUuid']
    }
    # print(agentInfo)


    detected = False
    if (techniqueId in techniques1):
        detected=True
        # print("true")


    #pulls mitigation data
    mitigations = dict(action=[])
    for e in mitigationStatus:
        actions_entry={
            e['action']:{
            'failed': e['actionsCounters']['failed'],
            'success': e['actionsCounters']['success'],
            'status': e['status']
            }
        }
        mitigations['action'].append(actions_entry)


    #pulls S1_threatInfo from data
    s1_threatInfo={
    "s1_threatName": threatInfo['threatName'],
    "s1_classification": threatInfo['classification'],
    "s1_detectionType": threatInfo['detectionType'],
    "s1_engines": threatInfo['engines'],
    "mitigatedPreemptively": threatInfo['mitigatedPreemptively'],
    "mitigationStatus": threatInfo['mitigationStatus']
    }

    #pulls techniques_detected from data

    techniques_detected ={
        "test number" : testNumber,
        "techniques_detected" : techniques1,
        "categorys__detected" : categorys,
        "tactic_name_detected" : tactics_name,
        "tactic_links" : links,
        "detection_match" : detected,
    }

    results = {
        techniqueId :[{
        "alertID": data['data'][0]['id'],
        "techniques_detected" : techniques_detected,
        "S1_threatInfo": s1_threatInfo,
        "mitigations": mitigations,
        }]
    }

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

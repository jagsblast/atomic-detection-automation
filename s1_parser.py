import json



#test data
techniqueId = "T1574.001"
testNumber = 1



# replace this with the api response
with open("response.json", "r") as in_file:
    data = json.load(in_file)

# end of test data
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
    print(results1)




json_magic(techniqueId, testNumber, data)


# with open("results.json", "w") as outfile:
#     outfile.write(results1)


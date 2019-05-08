import requests
import json
import os
import getpass
import argparse
from tabulate import tabulate

from dateutil.parser import parse as parsetime
from datetime import datetime

import requests.packages.urllib3
requests.packages.urllib3.disable_warnings()

parser = argparse.ArgumentParser(description="Small Utility to Check Upgrade Readiness")

parser.add_argument("-u", "--user", type=str, required=True, help="Remote Username")
parser.add_argument("-a", "--apic", type=str, required=True, help="APIC URI: ex. https://10.0.0.1")


args = parser.parse_args()

#Base URL
base_url = "https://" + args.apic + "/api/"

#Assemble Login URL
login_url = base_url + "aaaLogin.json" 
#+ args.format

#Login Body Post
login = {"aaaUser": {"attributes": {"name":args.user, "pwd":getpass.getpass(prompt='APIC Password:')}}}


#Post the Login
apic = requests.Session()
login_post = apic.post(login_url, data=json.dumps(login), verify=False)

encryption_url = base_url + "node/class/pkiExportEncryptionKey.json"

#pkiExportEncryptionKey
encryption_req = apic.get(encryption_url, verify=False)

encryption_status = json.loads(encryption_req.content)
if 'yes' in encryption_status['imdata'][0]['pkiExportEncryptionKey']['attributes']['keyConfigured']:
    print('Encryption Status: Enabled')
if 'no' in encryption_status['imdata'][0]['pkiExportEncryptionKey']['attributes']['keyConfigured']:
    print('Encryption Status: Not Enabled')


##Check for latest config backup? Remote Location?
#node/class/configJob.json?query-target-filter=and(eq(configJob.type,"export"))
export_jobstatus_url = base_url + 'node/class/configJob.json?query-target-filter=and(eq(configJob.type,"export"))&order-by=configJob.lastStepTime|desc'
export_jobstatus_req = apic.get(export_jobstatus_url, verify=False)

export = json.loads(export_jobstatus_req.content)['imdata'][0]['configJob']['attributes']
last_export = parsetime(export['executeTime'])

print('Last Remote Configuration Export: ' + last_export.strftime("%y-%m-%d %I:%M") + 'status: ' + export['details'])

if 'success' not in export['details'].lower():
    print('Ensure you have a remote copy of the Configuration backup before proceeding with an upgrade.')


##Check if Fully Fit
#infraWiNode

cluster_health_url = base_url + "node/class/infraWiNode.json"
cluster_health_req = apic.get(cluster_health_url, verify=False)


#print out view of cluster health from each apic 
apic_health = [['APIC', 'View Of', 'Health']]
for node in json.loads(cluster_health_req.content)['imdata']:
    local_apic = node['infraWiNode']['attributes']['dn'].split('/')[2].split('-')[1]
    foreign_apic = node['infraWiNode']['attributes']['id']  
    health = node['infraWiNode']['attributes']['health']
    apic_health.append([local_apic, foreign_apic, health])
print("Health Status, All APICs should see all other APICs as 'Fully Fit'")
print(tabulate(apic_health, headers='firstrow'))
    
#Faults 
faults_url = base_url + 'node/class/faultInfo.json?query-target-filter=or(eq(faultInfo.severity,"major"),eq(faultInfo.severity,"critical"))'
faults_req = apic.get(faults_url, verify=False)
faults_body = json.loads(faults_req.content)


if 'faultInst' in faults_body['imdata'][0].keys() or 'faultDelegate' in faults_body['imdata'][0].keys():
    print("Total Faults: "+ faults_body['totalCount'])
    faults = {}
    faultsum = [['Fault Code', 'Fault Count', 'More Info']]
    for fault in faults_body['imdata']:
        try:
            code = fault['faultInst']['attributes']['code']

        except KeyError:
            code = fault['faultDelegate']['attributes']['code']

        if code in faults.keys():
            faults[code] += 1
        elif code not in faults.keys():
            faults[code] = 1
    for fault in faults.keys():
        faultsum.append([fault, faults[fault], 'https://'+args.apic+'/doc/html/FAULT-'+fault+'.html' ])

print(tabulate(faultsum, headers='firstrow'))

#Upgrade Path URL - Get Current version
#firmwareRunning
firmware_url = base_url + 'node/class/firmwareRunning.json'
firmware_req = apic.get(firmware_url, verify=False)
firmware = json.loads(firmware_req.content)['imdata'][0]['firmwareRunning']['attributes']['peVer']
print('Currently Running Version: '+ firmware)
if int(firmware[0]) > 3:
    pass
elif int(firmware[0]) < 3:
    print('Current Running version is no longer recommended. Please see the upgrade Matrix tool to plan an upgrade to 3.2.5 or above.')
    print('https://www.cisco.com/c/dam/en/us/td/docs/Website/datacenter/apicmatrix/index.html')
elif int(firmware[2]) < 2:
    print('Current Running version is no longer recommended. Please see the upgrade Matrix tool to plan an upgrade to 3.2.5 or above.')
    print('https://www.cisco.com/c/dam/en/us/td/docs/Website/datacenter/apicmatrix/index.html')




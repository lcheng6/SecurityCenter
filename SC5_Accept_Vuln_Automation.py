import SC5API
import sys
import json
import argparse
import pprint
import requests
import ConfigParser
import urllib2
import CMDBInventory
import VulnAcceptanceList
import time
import csv
import getpass
import logging



#create a SecurityCenterAPI object after signing into security center API
def signin_to_security_center(securityCenterHost, username, password):
    securityCenterURL = 'https://' + securityCenterHost
    securityCenterAPI = SC5API.SecurityCenterAPI()
    securityCenterAPI.set_url(securityCenterURL)
    securityCenterAPI.login(username, password)

    return securityCenterAPI;


argParser = argparse.ArgumentParser(description='Enter your Nessus Security Center host name, uname, and password')
pp = pprint.PrettyPrinter(indent=4);
configParser = ConfigParser.RawConfigParser()
elasticSearchWindowsSearch = "";
elasticSearchNonWindowsSearch = "";

vuln_acceptance_deadline = '06.02.2017'
vuln_acceptance_pattern = '%m.%d.%Y'

#parser.add_argument('--schost', dest = 'hostname', type=str, required=True, help='hostname or IP Address of the Nessus Security Center')
argParser.add_argument('-u', dest = 'user', type=str, required=True, help='Nessus Security Center username')
argParser.add_argument('-p', dest = 'password', type=str, required=False, help='Password')
argParser.add_argument('-c', dest = 'config', type =str, required=True, help='Configuration File')


args = argParser.parse_args()

securityCenterInitData = {}
securityCenterVulnInitData = {}
automationConfiguration = {}

if args.config :
    configFilePath = r'{0}'.format(args.config)
    configParser.read(configFilePath)
    
    #read the Nessus Security Center parameter section
    securityCenterInitData["host"] = configParser.get('NessusSecurityCenterConfig','host')
    
    #read the Security Center Vulnerability Acceptance section
    securityCenterVulnInitData["vulnAcceptanceListFile"] = configParser.get('NessusSecurityCenterVulnAcceptance', 
        'vuln_acceptance_list')

    #read the AutomationConfiguration portion of the log
    automationConfiguration["logging_file"] = configParser.get('AutomationConfiguration', 
        'logging_file')
    automationConfiguration["logging_format"] = configParser.get('AutomationConfiguration', 
        'logging_format')

    #Block of code to get Security Center's password
    if args.password is None :
        nessus_password = getpass.getpass(args.user + " password:")
    else : 
        nessus_password = args.password


#set up basic logging, and logging formatter to add timestamp
logging.basicConfig(filename=automationConfiguration["logging_file"], 
    format=automationConfiguration["logging_format"], 
    level=logging.DEBUG)

#log attempted signin with username
logging.info(args.user + ', attempt login to Nessus Scanner ' + securityCenterInitData["host"])

#Log into Nessus Security Center
securityCenterAPI = signin_to_security_center(securityCenterInitData["host"], args.user, nessus_password)

#log successful signin with username
logging.info(args.user + ', successfully logged to Nessus Scanner ' + securityCenterInitData["host"])

#Read the repositories Nessus Security Center contains, such as QA, Dev, Stage, Prod, etc. 
repos = securityCenterAPI.get_respository_fields();
loggign.info(args.user + ', Nessus Security Center repositories are ' + str(repos))

transformed_repos = securityCenterAPI.transformRepositoriesForAcceptRisk(repos);
logging.debug('Repository data transformed into a format for accept_risk API: ' + str(transformed_repos))


vuln_acceptance_epoch = int(time.mktime(time.strptime(
            vuln_acceptance_deadline, 
            vuln_acceptance_pattern
            )))

vulnList = VulnAcceptanceList.VulnAcceptanceList()

vulnList.read_csv_file(securityCenterVulnInitData["vulnAcceptanceListFile"])
logging.debug('Read acceptance list file ' + str(securityCenterVulnInitData["vulnAcceptanceListFile"]))


for index in [0, 1]: 
    single_csv_vuln = vulnList.get_row_by_index(index)

    logging.info('Read single entry from vulnerability CSV file: ' + str(single_csv_vuln))

    #if the field AcceptRisk is Yes, proceed to enter the risk into the risk acceptance repo
    if (single_csv_vuln["AcceptRisk"].lower() == "yes"):
        logging.info(args.user, " accept Vulnerability API for PlugIn ID " + str(single_csv_vuln['Plugin'] +
            " with comments: " + single_csv_vuln['Comments'] + 
            " on repos: " + str(transformed_repos)))
        #TODO: modify the printout of transformed_repos

        #log risk acceptance in all repos. 
        result = securityCenterAPI.acceptRiskSingleItem(
                pluginId = single_csv_vuln['Plugin'], #pluginId
                comments = single_csv_vuln['Comments'],
                expiration_date = vuln_acceptance_epoch,
                hostType = 'all',
                name = single_csv_vuln['PluginName'],
                repositories = transformed_repos
            );

        #log the Nessus API reply to risk acceptance
        logging.info(args.user, "Nessus Accept Risk API reply: " + str(result))

    else:
        logging.info(args.user, " did not accept Vulnerability with PlugIn ID: " + str(single_csv_vuln['Plugin']))
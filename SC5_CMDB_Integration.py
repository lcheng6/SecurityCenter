import SC5API
import sys
import json
import argparse
import pprint
import requests
import ConfigParser
import urllib2
import CMDBInventory
import csv
import getpass
import logging


# prompt user to update an asset: 
#   print out the new asset host ips
#   ask the user whether to update the asset
def prompt_user_to_update_asset(asset_id, asset_string, asset_hosts_ips):
    print "Update " + asset_string + " with ID of " + str(asset_id)
    print "with " + '. '.join(asset_hosts_ips);
    user_input = raw_input("Y/N? ");
    if (user_input == 'Y' or user_input == "y"):
        return True;
    else: 
        return False;


def get_host_ips_from_cmdb_inventory(cmdbAPIInitData): 
	inventoryAPI = CMDBInventory.CMDBInventoryAPI(cmdbAPIInitData)
	windowsIPs = inventoryAPI.get_windows_instance_private_IPs()
	linuxIPs = inventoryAPI.get_linux_instance_private_IPs()\

	return (windowsIPs, linuxIPs)

#create a SecurityCenterAPI object after signing into security center API
def signin_to_security_center(securityCenterHost, username, password):
	securityCenterURL = 'https://' + securityCenterHost
	securityCenterAPI = SC5API.SecurityCenterAPI()
	securityCenterAPI.set_url(securityCenterURL)
	securityCenterAPI.login(username, password)

	return securityCenterAPI;


#Save a copy of the asset specified the asset_id
def save_asset_by_id(securityCenterAPI, asset_id): 

	original_asset = securityCenterAPI.get_asset_by_id(asset_id);
	return original_asset;

#update the asset with host IPs 
def update_asset_by_id(securityCenterAPI, asset_id, host_ips): 

	
	return True;


#BEGIN MAIN

#read the input parameters
argParser = argparse.ArgumentParser(description='Enter your Nessus Security Center username and configuration')
pp = pprint.PrettyPrinter(indent=4);
configParser = ConfigParser.RawConfigParser()
elasticSearchWindowsSearch = "";
elasticSearchNonWindowsSearch = "";

argParser.add_argument('-u', dest = 'user', type=str, required=True, help='Nessus Security Center username')
argParser.add_argument('-p', dest = 'password', type=str, required=False, help='Nessus Security Center password')
argParser.add_argument('-c', dest = 'config', type =str, required=True, help='Configuration File')

args = argParser.parse_args()

#set up basic logging
logging.basicConfig(filename='./NessusCMDBAutomation.log', level=logging.DEBUG)

#this block of code gets all the program parameters 
cmdbAPIInitData = {}
securityCenterInitData = {}
securityCenterVulnInitData = {}

if args.config :
    configFilePath = r'{0}'.format(args.config)
    configParser.read(configFilePath)
    
    #read the Nessus Security Center parameter section
    securityCenterInitData["host"] = configParser.get('NessusSecurityCenterConfig','host')
    securityCenterInitData["linuxAssetId"] = configParser.get('NessusSecurityCenterConfig','linux_asset_id')
    securityCenterInitData["windowsAssetId"] = configParser.get('NessusSecurityCenterConfig','windows_asset_id')
    
    #read the CMDB Elastic Search parameter section
    cmdbAPIInitData["cmdbElasticSearchURL"] =configParser.get('CMDBElasticSearch','url')
    cmdbAPIInitData["cmdbElasticSearchIndex"] = configParser.get('CMDBElasticSearch', 'index')
    cmdbAPIInitData["elasticSearchWindowsSearch"] =configParser.get('CMDBElasticSearch','windows_search_string')
    cmdbAPIInitData["elasticSearchNonWindowsSearch"] =configParser.get('CMDBElasticSearch','non_windows_search_string')
    cmdbAPIInitData["elasticSearchSize"]=configParser.get('CMDBElasticSearch','search_size')
    cmdbAPIInitData["appliance_exclusion_file"]=configParser.get('CMDBElasticSearch', 'appliance_exclusion_file');

    #read the Security Center Vulnerability Acceptance section
    securityCenterVulnInitData["vulnAcceptanceListFile"] = configParser.get('NessusSecurityCenterVulnAcceptance', 
        'vuln_acceptance_list')

	#Block of code to access Security Center API
    if args.password is None :
        nessus_password = getpass.getpass(args.user + " password:")
    else : 
        nessus_password = args.password

#log attempted signin with username
logging.info(args.user + ',' + 'attempt logging to Nessus Scanner ' + securityCenterInitData["host"])

#Log into Nessus Security Center
securityCenterAPI = signin_to_security_center(securityCenterInitData["host"], args.user, nessus_password)

#log successful signin with username
logging.info(args.user + ',' + 'successfully logged to Nessus Scanner ' + securityCenterInitData["host"])

#save a back up of assets from the security center

#Get the linux asset from Security Center API
linux_asset = securityCenterAPI.get_asset_by_id(securityCenterInitData["linuxAssetId"])
logging.debug('linuxAssetId: ' + str(linux_asset))
#Get the linux asset from Security Center API
windows_asset = securityCenterAPI.get_asset_by_id(securityCenterInitData["windowsAssetId"])
logging.debug('windowsAssetId: ' + str(windows_asset))

#log successful read from an CMDB
logging.info('attempt to read windows and linux hosts from CMDB')
(windowsIPs, linuxIPs) = get_host_ips_from_cmdb_inventory(cmdbAPIInitData)
logging.info('read windows IPs from CMDB: [' + ','.join(windowsIPs) + ']')
logging.info('read linux IPs from CMDB: [' + ','.join(windowsIPs) + ']' )

#Prompt users to accept new changes 

update_asset = prompt_user_to_update_asset(securityCenterInitData["windowsAssetId"], windows_asset['name'], windowsIPs)
if(update_asset == True):
    #logging acceptance of windows update 
    logging.info(args.user + ' has accepted windows update')
    #logging the windows asset update attempt
    logging.info(args.user + ', ' + str(securityCenterInitData["windowsAssetId"]) + ', ' + 
        windows_asset['name'] + ', update with static IPs [' + str(windowsIPs) + ']');
    update_result= SecurityCenterAPI.update_hosts_by_asset_id(securityCenterInitData["windowsAssetId"], windowsIPs)
    
    #logging the Nessus SSC response to windows asset update
    logging.info(args.user + ', ' + str(securityCenterInitData["windowsAssetId"]) + ', ' + 
        windows_asset['name'] + 'Nessus Security Center Response: ' + str(update_result))
else:
    #log user did not choose to update
    logging.info(args.user + ' did not accepted windows update');

update_asset = prompt_user_to_update_asset(securityCenterInitData["linuxAssetId"], linux_asset['name'], linuxIPs)
if(update_asset == True):
    #logging acceptance of linux asset update 
    logging.info(args.user + ' has accepted windows update');
    #logging the linux asset update attempt
    logging.info(args.user + ', ' + str(securityCenterInitData["linuxAssetId"]) + ', ' + 
        linux_asset['name'] + ', [' + str(linuxIPs) + ']');
    update_result= SecurityCenterAPI.update_hosts_by_asset_id(securityCenterInitData["linuxAssetId"], linuxIPs)

    #logging the Nessus SSC response to linux asset update
    logging.info(args.user + ', ' + str(securityCenterInitData["linuxAssetId"]) + ', ' + 
        linux_asset['name'] + ' Nessus Security Center Response: ' + str(update_result))
else:
    #log user did not choose to update
    logging.info(args.user + ' did not accepted linux update');


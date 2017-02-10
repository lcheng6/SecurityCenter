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

	return SecurityCenterAPI;


#Save a copy of the asset specified the asset_id
def save_asset_by_id(securityCenterAPI, asset_id): 

	original_asset = securityCenterAPI.get_asset_by_id(asset_id);
	return original_asset;

#update the asset with host IPs 
def update_asset_by_id(securityCenterAPI, asset_id, host_ips): 

	
	return True;


#BEGIN MAIN
argParser = argparse.ArgumentParser(description='Enter your Nessus Security Center username and configuration')
pp = pprint.PrettyPrinter(indent=4);
configParser = ConfigParser.RawConfigParser()
elasticSearchWindowsSearch = "";
elasticSearchNonWindowsSearch = "";

argParser.add_argument('-u', dest = 'user', type=str, required=True, help='Nessus Security Center username')
argParser.add_argument('-p', dest = 'password', type=str, required=False, help='Nessus Security Center password')
argParser.add_argument('-c', dest = 'config', type =str, required=True, help='Configuration File')

args = argParser.parse_args()


#this block of code gets all the program parameters 
cmdbAPIInitData = {}

if args.config :
    configFilePath = r'{0}'.format(args.config)
    configParser.read(configFilePath)
    
    securityCenterHost = configParser.get('NessusSecurityCenterConfig','host')
    
    cmdbAPIInitData["cmdbElasticSearchURL"] =configParser.get('CMDBElasticSearch','url')
    cmdbAPIInitData["cmdbElasticSearchIndex"] = configParser.get('CMDBElasticSearch', 'index')
    cmdbAPIInitData["elasticSearchWindowsSearch"] =configParser.get('CMDBElasticSearch','windows_search_string')
    cmdbAPIInitData["elasticSearchNonWindowsSearch"] =configParser.get('CMDBElasticSearch','non_windows_search_string')
    cmdbAPIInitData["elasticSearchSize"]=configParser.get('CMDBElasticSearch','search_size')
    cmdbAPIInitData["appliance_exclusion_file"]=configParser.get('CMDBElasticSearch', 'appliance_exclusion_file');
    


	#Block of code to access Security Center API
	if args.password is None :
		nessus_password = getpass(arg.user + " password: ")

securityCenterAPI = signin_to_security_center(securityCenterURL, arg.user, nessus_password);
(windowsIPs, linuxIPs) = get_host_ips_from_cmdb_inventory(cmdbAPIInitData)



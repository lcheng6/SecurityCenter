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


def back_up_asset_by_id(securityCenterAPI, asset_id): 

	original_asset = securityCenterAPI.get_asset_by_id(asset_id);
	return original_asset;

def update_asset_by_id(securityCenterAPI, asset_id): 

	nessus
	return True;


#BEGIN MAIN
argParser = argparse.ArgumentParser(description='Enter your Nessus Security Center username and configuration')
pp = pprint.PrettyPrinter(indent=4);
configParser = ConfigParser.RawConfigParser()
elasticSearchWindowsSearch = "";
elasticSearchNonWindowsSearch = "";

argParser.add_argument('-u', dest = 'user', type=str, required=True, help='Nessus Security Center username')
argParser.add_argument('-c', dest = 'config', type =str, required=True, help='Configuration File')


args = argParser.parse_args()

securityCenterAPI = SC5API.SecurityCenterAPI()
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
    


#Block of code to test Security Center API Access
securityCenterURL = 'https://' + securityCenterHost
securityCenterAPI.set_url(securityCenterURL)
securityCenterAPI.login(args.user, args.password)

asset_219 = securityCenterAPI.get_asset_by_id(219);

pp.pprint(asset_219);



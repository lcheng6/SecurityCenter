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

argParser = argparse.ArgumentParser(description='Enter your Nessus Security Center host name, uname, and password')
pp = pprint.PrettyPrinter(indent=4);
configParser = ConfigParser.RawConfigParser()
elasticSearchWindowsSearch = "";
elasticSearchNonWindowsSearch = "";

#parser.add_argument('--schost', dest = 'hostname', type=str, required=True, help='hostname or IP Address of the Nessus Security Center')
argParser.add_argument('-u', dest = 'user', type=str, required=True, help='Nessus Security Center username')
argParser.add_argument('-p', dest = 'password', type=str, required=True, help='Password')
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

#asset_219 = securityCenterAPI.get_asset_by_id(219);

#pp.pprint(asset_219);


#analysis_list_332 = securityCenterAPI.get_analysis_by_id(333)
#pp.pprint(analysis_list_333);

#this code block runs the accpet risk tests 
#repos = securityCenterAPI.get_respository_fields();
#transformed_repos = securityCenterAPI.transformRepositoriesForAcceptRisk(repos);
#pp.pprint(transformed_repos);


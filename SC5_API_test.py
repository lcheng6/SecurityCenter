import SC5API
import sys
import json
import argparse
import pprint
import requests
import ConfigParser
import urllib2
import CMDBInventory

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


if args.config :
    configFilePath = r'{0}'.format(args.config)
    configParser.read(configFilePath)
    
    securityCenterHost = configParser.get('NessusSecurityCenterConfig','host')
    
    cmdbAPIInitData = {}
    cmdbAPIInitData.cmdbElasticSearchURL =configParser.get('CMDBElasticSearch','url')
    cmdbAPIInitData.cmdbElasticSearchIndex = configParser.get('CMDBElasticSearch', 'index')
    cmdbAPIInitData.elasticSearchWindowsSearch =configParser.get('CMDBElasticSearch','windows_search_string')
    cmdbAPIInitData.elasticSearchNonWindowsSearch =configParser.get('CMDBElasticSearch','non_windows_search_string')
    cmdbAPIInitData.elasticSearchSize=configParser.get('CMDBElasticSearch','search_size')
    
    


#Block of code to test Security Center API Access
#securityCenterURL = 'https://' + securityCenterHost
#securityCenterAPI.set_url(securityCenterURL)
#securityCenterAPI.login(args.user, args.password)

#securityCenterAPI.update_hosts_by_asset_id(219, '10.191.1.1, 10.191.1.2, 10.191.1.3, 10.191.1.4, 10.191.1.5, 10.191.1.10/32');

#asset_219 = securityCenterAPI.get_asset_by_id(219);

#pp.pprint(asset_219);


#Block of code to test CMDB ElasticSearch 

inventoryAPI = CMDBInventory.CMDBInventoryAPI(cmdbAPIInitData)

    
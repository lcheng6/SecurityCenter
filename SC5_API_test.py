import SC5API
import sys
import json
import argparse
import pprint
import requests
import ConfigParser
import urllib2
import json

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
    
    cmdbElasticSearchURL =configParser.get('CMDBElasticSearch','URL')
    cmdbElasticSearchIndex = configParser.get('CMDBElasticSearch', 'index')
    elasticSearchWindowsSearch =configParser.get('CMDBElasticSearch','windows_search_string')
    elasticSearchNonWindowsSearch =configParser.get('CMDBElasticSearch','non_windows_search_string')

#Block of code to test Security Center API Access
#securityCenterURL = 'https://' + securityCenterHost
#securityCenterAPI.set_url(securityCenterURL)
#securityCenterAPI.login(args.user, args.password)

#securityCenterAPI.update_hosts_by_asset_id(219, '10.191.1.1, 10.191.1.2, 10.191.1.3, 10.191.1.4, 10.191.1.5, 10.191.1.10/32');

#asset_219 = securityCenterAPI.get_asset_by_id(219);

#pp.pprint(asset_219);


#Block of code to test CMDB ElasticSearch 

cmdbElasticSearchGetURL = "https://" + cmdbElasticSearchHost + "/" + cmdbElasticSearchIndex + "/_search"
print "URL: " + cmdbElasticSearchGetURL

req = urllib2.Request(cmdbElasticSearchGetURL)
out = urllib2.urlopen(req)
data = out.read()

print data;

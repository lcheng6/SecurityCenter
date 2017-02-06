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

#this function transform a CSV vulnerability entry into a format for 
#accept risk api data query; and add the repository information
def transform_csv_entry_to_api_data (single_csv_vuln, repos, date):
	query_data = {
		"comments": single_csv_vuln["Comments"],
		"expires": date,
		"hostType": "all",
		"name": single_csv_vuln["PluginName"],
		"newSeverity": {
			"id": 3
		},
		"plugin": {
			"id": str(single_csv_vuln["Plugin"])
		},
		"port": "0",
		"protocol": 6,
		"repositories" : repos
	}

	return query_data;


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
    cmdbAPIInitData["acceptance_list_file"] = configParser.get('NessusSecurityCenterVulnAcceptance', 'vuln_acceptance_list')   


#Block of code to test Security Center API Access
securityCenterURL = 'https://' + securityCenterHost
securityCenterAPI.set_url(securityCenterURL)
securityCenterAPI.login(args.user, args.password)

#asset_219 = securityCenterAPI.get_asset_by_id(219);

#pp.pprint(asset_219);


#analysis_list_332 = securityCenterAPI.get_analysis_by_id(333)
#pp.pprint(analysis_list_333);

#this code block runs the accept risk tests 
repos = securityCenterAPI.get_respository_fields();
transformed_repos = securityCenterAPI.transformRepositoriesForAcceptRisk(repos);
print "Transfored Repositories:" 
pp.pprint(transformed_repos);


vulnList = VulnAcceptanceList.VulnAcceptanceList()
print "Sample Vulnerability from CSV: "
vulnList.read_csv_file(cmdbAPIInitData["acceptance_list_file"])
for index in [0, 1, 2, 3]: 
	single_csv_vuln = vulnList.get_row_by_index(index)
	pp.pprint(single_csv_vuln);

	#print "Sample Accept Vulnerability API Data: "
	#accept_vuln_post_data = transform_csv_entry_to_api_data(single_csv_vuln, transformed_repos, -1);
	#pp.pprint(accept_vuln_post_data);

	#print "Accept Vulnerability API Result Data: "
	#result = securityCenterAPI.postAcceptRiskSingleItem(accept_vuln_post_data);
	#pp.pprint(result);

	print "Accept Vulnerability API for PlugIn ID: " + str(single_csv_vuln['Plugin']);

	result = securityCenterAPI.acceptRiskSingleItem(
			pluginId = single_csv_vuln['Plugin'], #pluginId
			comments = single_csv_vuln['Comments'],
			expiration_date = -1,
			hostType = 'all',
			name = single_csv_vuln['PluginName'],
			repositories = transformed_repos
		);

	#pp.pprint(result);

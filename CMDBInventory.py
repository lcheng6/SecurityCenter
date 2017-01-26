import json
import requests
import urllib2

class CMDBInventoryAPI:
    cmdbElasticSearchURL = ""
    cmdbElasticSearchIndex = ""
    elasticSearchWindowsSearch = ""
    elasticSearchNonWindowsSearch = ""
    elasticSearchSize = ""
    applianceIPListFile = ""
    
    #the initData is the config block in SecurityCenterAutomation.config, which will include the following:
    # url of Elastic Search 
    # index to search
    # windows_search_string
    # non_windows_search_string
    # search_size
    # appliance_exlusion_file
    def __init__(self, initData):
        self.cmdbElasticSearchURL = initData["cmdbElasticSearchURL"]
        self.cmdbElasticSearchIndex = initData["cmdbElasticSearchIndex"]
        self.elasticSearchWindowsSearch = initData["elasticSearchWindowsSearch"]
        self.elasticSearchNonWindowsSearch = initData["elasticSearchNonWindowsSearch"]
        self.elasticSearchSize = initData["elasticSearchSize"]
        self.applianceIPListFile = initData["appliance_exclusion_file"]
        self.applianceIPDictionary = {}
        
        applianceIPFile = open(self.applianceIPListFile, "r");
        applianceIPList = applianceIPFile.readlines();
        for ipStr in applianceIPList:
            ipAddr = ipStr.strip();
            self.applianceIPDictionary[ipAddr] = True;
    
    def get_windows_instance_private_IPs(self):
        headers = {}
        results = [];
        from_index = 0
        totalHitCount = 1
        
        while(from_index < totalHitCount):
        
            cmdbElasticSearchGetURL = self.cmdbElasticSearchURL + "/" + self.cmdbElasticSearchIndex + "/_search?from=" + str(from_index) + "&size="+str(self.elasticSearchSize)
            req = urllib2.Request(cmdbElasticSearchGetURL, self.elasticSearchWindowsSearch, headers)
            out = urllib2.urlopen(req)
            data = out.read();
            data = json.loads(data)
            totalHitCount = data['hits']['total']
            allHits = data['hits']['hits']
        
            for hit in allHits:
                #print '_source/json_aws_data_ec2/platform: ' + hit['_source']['json_aws_data_ec2']['platform']
                #print '_id: ' + hit['_id']
                #print 'privateIP: ' + hit['_source']['json_aws_data_ec2']['private_ip_address']
                results.append(hit['_source']['json_aws_data_ec2']['private_ip_address']);
                from_index = from_index + 1
        
        return results
    
    def get_linux_instance_private_IPs(self):
        headers = {}
        results = []
        from_index = 0
        totalHitCount = 1;
        
        while(from_index < totalHitCount):
        
            cmdbElasticSearchGetURL = self.cmdbElasticSearchURL + "/" + self.cmdbElasticSearchIndex + "/_search?from=" + str(from_index) + "&size="+str(self.elasticSearchSize)
            
            req = urllib2.Request(cmdbElasticSearchGetURL, elasticSearchNonWindowsSearch, headers)
            out = urllib2.urlopen(req)
            data = out.read();
            data = json.loads(data)
            totalHitCount = data['hits']['total']
            allHits = data['hits']['hits']
            
            for hit in allHits:
                #print '_source/json_aws_data_ec2/platform: ' + hit['_source']['json_aws_data_ec2']['platform']
                print '_id: ' + hit['_id']
                print 'privateIP: ' + hit['_source']['json_aws_data_ec2']['private_ip_address']
                results.append(hit['_source']['json_aws_data_ec2']['private_ip_address']);
                from_index = from_index+1
                
                
        #TODO: filter out the appliance private IPs
        
        filteredResults = [];
        for unfiltereIP in results:
            if unfiltereIP in self.applianceIPDictionary.keys():
                #do nothing
                pass
            else:
                #add the IP into filteredResults set
                filteredResults.append(unfiltereIP);
        
        return filteredResults;
        
    def get_all_hosts_raw_info(self):
        
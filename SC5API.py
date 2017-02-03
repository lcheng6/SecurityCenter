import json
import sys
import requests
import pprint
import urllib

requests.packages.urllib3.disable_warnings()


class SecurityCenterAPI: 
    url = "https://10.14.226.13"
    username = ""
    password = ""
    token = ''
    cookie = ''

    def __init__(self): 
        self.data = {}
    
    def set_url(self, url):
        self.url = url
		
    def build_url(self, restCall):
        """ Formats the SC URL with the rest API call"""
        return '{0}{1}'.format(self.url, restCall)

    def connect(self, method, resource, data=None, headers=None, cookies=None):
        """ The connect method is used to connect to SC and pass our API calls."""
        if headers is None:
            headers = {'Content-type': 'application/json',
                    'X-SecurityCenter': str(self.token)}
        if data is not None:
            data = json.dumps(data)

        if method == "POST":
            r = requests.post(self.build_url(resource), data=data, headers=headers, cookies=self.cookie,
                            verify=False)
        elif method == "DELETE":
            r = requests.delete(self.build_url(resource), data=data, headers=headers, cookies=self.cookie,
                                verify=False)
        elif method == 'PATCH':
            r = requests.patch(self.build_url(resource), data=data, headers=headers, cookies=self.cookie,
                            verify=False)
        else:
            r = requests.get(self.build_url(resource), data=data, headers=headers, cookies=self.cookie,
                            verify=False)

        if r.status_code != 200:
            e = r.json()
            print(e['error_msg'])
            sys.exit()

        return r


    def login(self, uname, pword):
        """ Logs into SecurityCenter and retrieves our token and cookie.
        We create a seperate header here since we do not have a X-SecurityCenter token yet."""
        headers = {'Content-Type':'application/json'}
        login = {'username': uname, 'password':pword}
        self.username = uname;
        self.password = pword;

        # We use the connect function and pass it a POST method, /rest/token resource,
        # and our login credentials as data.  We also pass our headers from above for this function.
        data = self.connect('POST', '/rest/token', data=login, headers=headers)

        # We can pull the cookie out of our data object and store it as a variable.
        self.cookie = data.cookies

        # We can alo pull our token out from the returned data as well.
        self.token = data.json()['response']['token']
        return (self.cookie, self.token)

    # ------ UNCOMMENT THE CODE BELOW TO ENABLE THE FUNCTION.  THIS WAS LEFT IN FOR REFERENCE. ------ #
    # ------    LINES WITH '##' ARE COMMENTS, YOU DO NOT NEED TO UNCOMMENT THOSE LINES.        ------ #
    def get_assets(self):
        # Initiate an empty asset list.
        assets = []

        # Use the connect function with a GET method and /rest/asset resource.
        data = self.connect('GET', '/rest/asset')

        # Store the manageable assets in the results variable.
        results = data.json()['response']['manageable']

        # If results is empty, there are no manageable assets and the script exits.
        if not results:
            sys.exit("This user has no managed assets.")
        else:
            # For each asset in our results file, append the asset ID to our asset list.
            for i in results:
                assets.append(i['id'])
        return assets

    def get_asset_by_id(self, id):
        #Get the asset group by its id.  The ID should be a number
        data = self.connect('GET', '/rest/asset/{0}'.format(id))
        
        results = data.json()['response'];
        
        if not results:
            sys.exit("no managed assets")
        else: 
            return results;
    
    def update_hosts_by_asset_id(self, id, hosts_ips):
        #Post the hosts private IPs to the asset identified by ID
        #hosts_ips is an array of ips.  
        patch_records = {'definedIPs' : ', '.join(hosts_ips)};
        
        data = self.connect('PATCH', '/rest/asset/{0}'.format(id), patch_records)
        results = data.json()['response'];
        
        if not results:
            sys.exit("No response from patch operation");
        else:
            return results;
    
    def get_analysis_by_id(self, scanId): 
        #Post the hosts with a commmand to get analysis by scanID.  
        #scanID is an integer of the scan.  

        begin_offset = 0;
        end_offset = 50;
        totalRecords = 50;
        totalRecordsIsValid = False;
        allAnalysisRecords = [];
        scanIDStr = str(scanId)


        while (begin_offset < totalRecords):
            query_data = {
                "query": {
                    "createdTime":0,
                    "modifiedTime":0,
                    "groups":[],
                    "type":"vuln",
                    "tool":"sumid",
                    "sourceType":"individual",
                    "startOffset":begin_offset,
                    "endOffset":end_offset,
                    "filters":[],
                    "sortColumn":"severity",
                    "sortDirection":"desc",
                    "scanID": scanIDStr, 
                    "view": "all"
                },
                "sourceType": "individual",
                "scanID": scanIDStr,
                "sortField": "severity",
                "sortDir": "desc",
                "columns":[],
                "type":"vuln"
            };

            data = self.connect('POST', '/rest/analysis', query_data);
            results = data.json()['response'];

            if (totalRecordsIsValid == False): 
                #update totalRecords count once and only once
                totalRecords = results['totalRecords']
                totalRecords = int(totalRecords)
                totalRecordsIsValid = True; 
                #print 'totalRecords: ' + totalRecords

            returnedRecordsCount = results['returnedRecords']
            #print 'returnedRecordsCount: ' + str(returnedRecordsCount);

            returnedRecords = results['results'];
            #print 'first record: ' + str(returnedRecords[0])
            allAnalysisRecords.extend(returnedRecords);
            begin_offset += returnedRecordsCount; 
            #print 'begin_offset: ' + str(begin_offset)
            end_offset += returnedRecordsCount;
            #print 'end_offset: ' + str(end_offset)

            if not results: 
                sys.exit("No response from patch operation");
        
        return allAnalysisRecords

    def get_respository_fields(self): 
        # this function apparently pulls the repository data. 
        # this data will subsequently be used to construct a statement for acceptRiskRule API
        
        query_string = { 'fields' : 'name,description,type,dataFormat,modifiedTime,vulnCount,ipCount,typeFields'};
        encoded_query_string = urllib.urlencode(query_string)
        data = self.connect('GET', '/rest/repository'+ '?' + encoded_query_string);
        results = data.json()['response']

        return results;


    def acceptRiskSingleItem(self, pluginId, comments, expiration_date, hostType, name, respositories): 
        query_data = {
            "comments": comments,
            "expires": -1, #mockup
            "hostType": "all", #mockup
            #"name": "RHEL-06-000019 - There must be no .rhosts or hosts.equiv files on the system - ~/.rhosts.", #mockup 
            "name": name,
            "newSeverity": {
                "id": 3
            },
            "plugin": {
                "id": "1001387"
            },
            "port": "0",
            "protocol": 6,
            "repositories": respositories
        }

        return True;

    def transformRepositoriesForAcceptRisk(self, resposRawData):
        transformedReposArray = [];
        for repo in resposRawData : 
            transformedRepo = {
                "context": "",
                "correlation": [],
                "createdTime": null,
                "dataFormat": "IPv4",
                "description": repo["description"],
                "id": repo["id"],
                "ipRange": repo["typeFields"]["ipRange"],
                "modifiedTime": repo["modifiedTime"],
                "name": repo["name"],
                "organizations": [],
                "status": null,
                "trendWithRaw": repo["trendWithRaw"],
                "trendingDays": repo["trendingDays"],
                "type": repo["type"]
            }

            transformedReposArray.append(transformedRepo);

        return transformedReposArray

    

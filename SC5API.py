import json
import sys
import requests
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
    def get_assets():
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



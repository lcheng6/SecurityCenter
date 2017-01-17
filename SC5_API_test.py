import SC5API
import sys
import json
import argparse

parser = argparse.ArgumentParser(description='Enter your Nessus Security Center host name, uname, and password')

parser.add_argument('--hostname', dest = 'hostname', type=str, required=True, help='hostname of the Nessus Security Center')
parser.add_argument('-u', dest = 'user', type=str, required=True, help='Nessus Security Center username')
parser.add_argument('-p', dest = 'password', type=str, required=True, help='Password')


args = parser.parse_args()
if args.user
    print args.user;
#api = SC5API.SecurityCenterAPI()
#api.set_url('https://10.14.226.13')
#api.login(sys.argv[1], sys.argv[2])

#asset_219 = api.get_asset_by_id(219);

#json.dumps(asset_219);
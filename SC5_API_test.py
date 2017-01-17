import SC5API
import sys
import json
import argpase improt ArugmentParser

parser = argparse.ArgumentParser(description='Enter your Nessus Security Center host name, uname, and password')

parser.add_argument('-h', dest = 'hostname', type=str, required=True)
parser.add_argument('-u', dest = 'user', type=str, required=True)
parser.add_argument('-p', dest = 'password', type=str, required=True)


args = parser.parse_args()
if args.user
    print args.user;
#api = SC5API.SecurityCenterAPI()
#api.set_url('https://10.14.226.13')
#api.login(sys.argv[1], sys.argv[2])

#asset_219 = api.get_asset_by_id(219);

#json.dumps(asset_219);
import SC5API
import sys
import json
import argparse
import pprint

parser = argparse.ArgumentParser(description='Enter your Nessus Security Center host name, uname, and password')
pp = pprint.PrettyPrinter(indent=4);

parser.add_argument('--hostname', dest = 'hostname', type=str, required=True, help='hostname of the Nessus Security Center')
parser.add_argument('-u', dest = 'user', type=str, required=True, help='Nessus Security Center username')
parser.add_argument('-p', dest = 'password', type=str, required=True, help='Password')


args = parser.parse_args()

api = SC5API.SecurityCenterAPI()
url = 'https://' + args.hostname
api.set_url(url)
api.login(args.user, args.password)

api.update_hosts_by_asset_id(219, '10.191.1.1, 10.191.1.2, 10.191.1.3, 10.191.1.4, 10.191.1.5, 10.191.1.10');

asset_219 = api.get_asset_by_id(219);

pp.pprint(asset_219);
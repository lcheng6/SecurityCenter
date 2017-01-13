import SC5API
import sys
import json

api = SC5API.SecurityCenterAPI()
api.set_url('https://10.14.226.13')
api.login(sys.argv[1], sys.argv[2])


#assetList = api.get_assets()
#for id in assetList:
#    print("Asset ID: "+id)
    
asset_219 = api.get_asset_by_id(219);

json.dumps(asset_219);
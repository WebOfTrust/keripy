from blockfrost import BlockFrostApi, ApiUrls
import sys
import json
from  pprint import pp

blockfrostProjectId="previewapifaDDKsMZE7asmrcG8W3zbRE1pojXY"
api = BlockFrostApi(
    project_id=blockfrostProjectId,
    base_url=ApiUrls.preview.value
)

txs = api.address_transactions(sys.argv[1])
for tx in txs:
    tx_detail = api.transaction(tx.tx_hash)
    m = api.transaction_metadata(tx.tx_hash, return_type='json')
    if m:
        print("SeqNo: "+m[0]['label'] + " - Fees: "+ str(int(tx_detail.fees)/1000000) +" ADA")
        oneString = ''.join(m[0]['json_metadata']["KE"])
        pp(json.loads(oneString))
        print("----------------------------------------------------------------------------")
    
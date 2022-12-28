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
    meta = api.transaction_metadata(tx.tx_hash, return_type='json')
    if meta:
        print("Fees: ",str(int(tx_detail.fees)/1000000), "ADA")
        for n in meta:
            print("SeqNo: ",n['label'])
            oneString = ''.join(n['json_metadata'])
            pp(json.loads(oneString))
        print("----------------------------------------------------------------------------")
    
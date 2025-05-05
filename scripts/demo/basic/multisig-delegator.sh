#!/bin/bash
set -e

. "$(dirname "$0")/../demo-scripts.sh"
. "$(dirname "$0")/script-utils.sh"

delegator_1=$(random_name delegator_1)
delegator_2=$(random_name delegator_2)
delegate=$(random_name delegate)

background_start kli init --name "$delegator_1" --nopasscode
background_start kli init --name "$delegator_2" --nopasscode
background_start kli init --name "$delegate" --nopasscode
background_wait

delegator_witness_aid="BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM"
delegator_witness_url="http://127.0.0.1:5643/oobi/$delegator_witness_aid/controller"
delegate_witness_aid="BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha"
delegate_witness_url="http://127.0.0.1:5642/oobi/$delegate_witness_aid/controller"

background_start kli oobi resolve --name "$delegator_1" --oobi "$delegator_witness_url"
background_start kli oobi resolve --name "$delegator_2" --oobi "$delegator_witness_url"
background_start kli oobi resolve --name "$delegate" --oobi "$delegate_witness_url"
background_wait

kli incept --name "$delegator_1" --alias member --icount 1 --ncount 1 --isith 1 --nsith 1 --transferable --toad 1 --wit "$delegator_witness_aid"
kli incept --name "$delegator_2" --alias member --icount 1 --ncount 1 --isith 1 --nsith 1 --transferable --toad 1 --wit "$delegator_witness_aid"
kli ends add --name "$delegator_1" --alias member --eid "$delegator_witness_aid" --role mailbox
kli ends add --name "$delegator_2" --alias member --eid "$delegator_witness_aid" --role mailbox

delegator_1_aid=$(kli aid --name "$delegator_1" --alias member)
delegator_1_oobi=$(kli oobi generate --name "$delegator_1" --alias member --role witness | tail -n 1)
delegator_2_aid=$(kli aid --name "$delegator_2" --alias member)
delegator_2_oobi=$(kli oobi generate --name "$delegator_2" --alias member --role witness | tail -n 1)

background_start kli oobi resolve --name "$delegator_1" --oobi "$delegator_2_oobi"
background_start kli oobi resolve --name "$delegator_2" --oobi "$delegator_1_oobi"
background_wait

delegator_json=$(mktemp)
cat << EOF > "$delegator_json"
{
  "transferable": true,
  "wits": ["$delegator_witness_aid"],
  "aids": ["$delegator_1_aid", "$delegator_2_aid"],
  "toad": 1,
  "isith": "2",
  "nsith": "2"
}
EOF

background_start kli multisig incept --name "$delegator_1" --alias member --group delegator --file "$delegator_json"
background_start kli multisig incept --name "$delegator_2" --alias member --group delegator --file "$delegator_json"
background_wait

# timestamp=$(kli time)
# background_start kli ends add --name "$delegator_1" --alias delegator --eid "$delegator_witness_aid" --role mailbox --time "$timestamp"
# background_start kli ends add --name "$delegator_2" --alias delegator --eid "$delegator_witness_aid" --role mailbox --time "$timestamp"
# background_wait

# Create proxy and resolve OOBIs
kli incept --name "$delegate" --alias proxy --icount 1 --ncount 1 --isith 1 --nsith 1 --transferable --toad 1 --wit "$delegate_witness_aid"
kli ends add --name "$delegate" --alias proxy --eid "$delegate_witness_aid" --role mailbox
proxy_oobi=$(kli oobi generate --name "$delegate" --alias proxy --role witness | tail -n 1)
delegator_oobi=$(kli oobi generate --name "$delegator_1" --alias delegator --role witness | tail -n 1)
delegator_aid=$(kli aid --name "$delegator_1" --alias delegator)

background_start kli oobi resolve --name "$delegate" --oobi-alias delegator --oobi "${delegator_oobi}"
background_start kli oobi resolve --name "$delegate" --oobi-alias delegator_1 --oobi "${delegator_1_oobi}"
background_start kli oobi resolve --name "$delegate" --oobi-alias delegator_2 --oobi "${delegator_2_oobi}"
background_start kli oobi resolve --name "$delegator_1" --oobi-alias proxy --oobi "${proxy_oobi}"
background_start kli oobi resolve --name "$delegator_2" --oobi-alias proxy --oobi "${proxy_oobi}"
background_wait

delegate_json=$(mktemp)
cat << EOF > "$delegate_json"
{
    "transferable": true,
    "toad": 1,
    "wits": ["$delegate_witness_aid"],
    "icount": 1,
    "ncount": 1,
    "isith": "1",
    "nsith": "1",
    "delpre": "$delegator_aid"
}
EOF

# Create delegated identifier
background_start kli incept --name "$delegate" --alias delegate --proxy proxy --file "$delegate_json"
sleep 2
background_start kli delegate confirm --name "$delegator_1" --alias delegator --interact -Y
background_start kli delegate confirm --name "$delegator_2" --alias delegator --interact -Y
background_wait

kli status --name "$delegate" --alias delegate

#!/bin/bash
set -e

. "$(dirname "$0")/script-utils.sh"

delegator_1=$(random_name delegator_1)
delegator_2=$(random_name delegator_2)
delegate=$(random_name delegate)

kli init --name "$delegator_1" --nopasscode
kli init --name "$delegator_2" --nopasscode
kli init --name "$delegate" --nopasscode

delegator_witness_aid="BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM"
delegator_witness_url="http://127.0.0.1:5643/oobi/$delegator_witness_aid/controller"
delegate_witness_aid="BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha"
delegate_witness_url="http://127.0.0.1:5642/oobi/$delegate_witness_aid/controller"

kli oobi resolve --name "$delegator_1" --oobi "$delegator_witness_url"
kli oobi resolve --name "$delegator_2" --oobi "$delegator_witness_url"
kli oobi resolve --name "$delegate" --oobi "$delegate_witness_url"

kli incept --name "$delegator_1" --alias member --icount 1 --ncount 1 --isith 1 --nsith 1 --transferable --toad 1 --wit "$delegator_witness_aid"
kli incept --name "$delegator_2" --alias member --icount 1 --ncount 1 --isith 1 --nsith 1 --transferable --toad 1 --wit "$delegator_witness_aid"
kli ends add --name "$delegator_1" --alias member --eid "$delegator_witness_aid" --role mailbox
kli ends add --name "$delegator_2" --alias member --eid "$delegator_witness_aid" --role mailbox

delegator_1_aid=$(kli aid --name "$delegator_1" --alias member)
delegator_1_oobi=$(kli oobi generate --name "$delegator_1" --alias member --role witness | tail -n 1)
delegator_2_aid=$(kli aid --name "$delegator_2" --alias member)
delegator_2_oobi=$(kli oobi generate --name "$delegator_2" --alias member --role witness | tail -n 1)

kli oobi resolve --name "$delegator_1" --oobi "$delegator_2_oobi"
kli oobi resolve --name "$delegator_2" --oobi "$delegator_1_oobi"

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

kli multisig incept --name "$delegator_1" --alias member --group delegator --file "$delegator_json" &
pid=$!
kli multisig incept --name "$delegator_2" --alias member --group delegator --file "$delegator_json"
wait $pid

# Create proxy and resolve OOBIs
kli incept --name "$delegate" --alias proxy --icount 1 --ncount 1 --isith 1 --nsith 1 --transferable --toad 1 --wit "$delegate_witness_aid"
kli ends add --name "$delegate" --alias proxy --eid "$delegate_witness_aid" --role mailbox
proxy_oobi=$(kli oobi generate --name "$delegate" --alias proxy --role witness | tail -n 1)
delegator_oobi=$(kli oobi generate --name "$delegator_1" --alias delegator --role witness | tail -n 1)
delegator_aid=$(kli aid --name "$delegator_1" --alias delegator)

kli oobi resolve --name "$delegate" --oobi-alias delegator --oobi "${delegator_oobi}"
kli oobi resolve --name "$delegator_1" --oobi-alias proxy --oobi "${proxy_oobi}"
kli oobi resolve --name "$delegator_2" --oobi-alias proxy --oobi "${proxy_oobi}"

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
kli incept --name "$delegate" --alias delegate --proxy proxy --file "$delegate_json" &
PID_LIST="$!"
kli delegate confirm --name "$delegator_1" --alias delegator --interact -Y &
PID_LIST+=" $!"
kli delegate confirm --name "$delegator_2" --alias delegator --interact -Y &
PID_LIST+=" $!"
wait $PID_LIST

kli status --name "$delegate" --alias delegate

#!/bin/bash
set -e

source "$(dirname "$0")/script-utils.sh"

delegator=$(random_name delegator)
delegate_1=$(random_name delegate_1)
delegate_2=$(random_name delegate_2)

kli init --name "$delegator" --nopasscode
kli init --name "$delegate_1" --nopasscode
kli init --name "$delegate_2" --nopasscode

delegator_witness_aid="BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM"
delegator_witness_url="http://127.0.0.1:5643/oobi/$delegator_witness_aid/controller"
delegate_witness_aid="BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha"
delegate_witness_url="http://127.0.0.1:5642/oobi/$delegate_witness_aid/controller"

kli oobi resolve --name "$delegator" --oobi "$delegator_witness_url"
kli oobi resolve --name "$delegate_1" --oobi "$delegate_witness_url"
kli oobi resolve --name "$delegate_2" --oobi "$delegate_witness_url"

kli incept --name "$delegator" --alias delegator --icount 1 --ncount 1 --isith 1 --nsith 1 --transferable --toad 1 --wit "$delegator_witness_aid"
kli ends add --name "$delegator" --alias delegator --eid "$delegator_witness_aid" --role mailbox

delegator_aid=$(kli aid --name "$delegator" --alias delegator)
delegator_oobi=$(kli oobi generate --name "$delegator" --alias delegator --role witness | tail -n 1)

kli incept --name "$delegate_1" --alias member --icount 1 --ncount 1 --isith 1 --nsith 1 --transferable --toad 1 --wit "$delegate_witness_aid"
kli incept --name "$delegate_2" --alias member --icount 1 --ncount 1 --isith 1 --nsith 1 --transferable --toad 1 --wit "$delegate_witness_aid"
kli ends add --name "$delegate_1" --alias member --eid "$delegate_witness_aid" --role mailbox
kli ends add --name "$delegate_2" --alias member --eid "$delegate_witness_aid" --role mailbox

delegate_1_oobi=$(kli oobi generate --name "$delegate_1" --alias member --role witness | tail -n 1)
delegate_2_oobi=$(kli oobi generate --name "$delegate_2" --alias member --role witness | tail -n 1)
delegate_1_aid=$(kli aid --name "$delegate_1" --alias member)
delegate_2_aid=$(kli aid --name "$delegate_2" --alias member)
delegator_oobi=$(kli oobi generate --name "$delegator" --alias delegator --role witness | tail -n 1)
delegator_aid=$(kli aid --name "$delegator" --alias delegator)

kli oobi resolve --name "$delegate_1" --oobi-alias delegator --oobi "${delegator_oobi}"
kli oobi resolve --name "$delegate_1" --oobi-alias delegate_2 --oobi "${delegate_2_oobi}"
kli oobi resolve --name "$delegate_2" --oobi-alias delegate_1 --oobi "${delegate_1_oobi}"
kli oobi resolve --name "$delegator" --oobi-alias delegate_1 --oobi "${delegate_1_oobi}"

delegate_json=$(mktemp)
cat << EOF > "$delegate_json"
{
    "transferable": true,
    "toad": 1,
    "wits": ["$delegate_witness_aid"],
    "aids": ["$delegate_1_aid", "$delegate_2_aid"],
    "isith": "1",
    "nsith": "1",
    "delpre": "$delegator_aid"
}
EOF

# Delegate 1 initiates the delegated identifier
kli multisig incept --name "$delegate_1" --alias member --group delegate --file "$delegate_json" &
PID_LIST="$!"
kli delegate confirm --name "$delegator" --alias delegator --interact -Y &
PID_LIST+=" $!"
wait $PID_LIST

kli status --name "$delegate_1" --alias delegate
delegate_aid_from_1=$(kli aid --name "$delegate_1" --alias delegate)

# Delegate 2 now catches up by joining the inception event
kli oobi resolve --name "$delegate_2" --oobi-alias delegator --oobi "${delegator_oobi}"
kli multisig join --name "$delegate_2" --auto --group delegate
kli status --name "$delegate_2" --alias delegate
delegate_aid_from_2=$(kli aid --name "$delegate_2" --alias delegate)

if [[ "$delegate_aid_from_1" != "$delegate_aid_from_2" ]]; then
    echo "Delegate AIDs do not match"
    exit 1
fi

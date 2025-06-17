#!/bin/bash
set -e

source "$(dirname "$0")/script-utils.sh"

delegator=$(random_name delegator)
delegate=$(random_name delegate)
validator=$(random_name validator)

kli init --name "$delegator" --nopasscode
kli init --name "$delegate" --nopasscode
kli init --name "$validator" --nopasscode

kli oobi resolve --name "$delegator" --oobi http://127.0.0.1:5643/oobi/BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM/controller
kli oobi resolve --name "$delegate" --oobi http://127.0.0.1:5642/oobi/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha/controller
kli oobi resolve --name "$validator" --oobi http://127.0.0.1:5644/oobi/BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX/controller

kli incept --name "$delegator" --alias delegator \
    --wit BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM \
    --toad 1 \
    --icount 1 \
    --ncount 1 \
    --isith 1 \
    --nsith 1 \
    --transferable

kli incept --name "$delegate" --alias proxy \
    --wit BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha \
    --toad 1 \
    --icount 1 \
    --ncount 1 \
    --isith 1 \
    --nsith 1 \
    --transferable

kli incept --name "$validator" --alias validator \
    --wit BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX \
    --toad 1 \
    --icount 1 \
    --ncount 1 \
    --isith 1 \
    --nsith 1 \
    --transferable

kli ends add --name "$delegate" --alias proxy --eid "BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha" --role mailbox

delegator_oobi=$(kli oobi generate --name "$delegator" --alias delegator --role witness | tail -n 1)
delegator_aid=$(kli aid --name "$delegator" --alias delegator)
proxy_oobi=$(kli oobi generate --name "$delegate" --alias proxy --role witness | tail -n 1)

kli oobi resolve --name "$delegate" --oobi-alias delegator --oobi "${delegator_oobi}"
kli oobi resolve --name "$delegator" --oobi-alias proxy --oobi "${proxy_oobi}"

delegate_json=$(mktemp)
cat << EOF > "$delegate_json"
{
    "transferable": true,
    "toad": 1,
    "wits": ["BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha"],
    "icount": 1,
    "ncount": 1,
    "isith": "1",
    "nsith": "1",
    "delpre": "$delegator_aid"
}
EOF

# Create delegated identifier
kli incept --name "$delegate" --alias delegate --proxy proxy --file "$delegate_json" &
pid=$!
kli delegate confirm --name "$delegator" --alias delegator --interact -Y
wait $pid

kli status --name "$delegate" --alias delegate
delegate_oobi=$(kli oobi generate --name "$delegate" --alias delegate --role witness | tail -n 1)
delegate_aid=$(kli aid --name "$delegate" --alias delegate)

# Rotate delegated identifier
kli rotate --name "$delegate" --alias delegate --proxy proxy &
pid=$!
kli delegate confirm --name "$delegator" --alias delegator --interact -Y

kli status --name "$delegate" --alias delegate

# 3rd party validated delegated identifier
kli oobi resolve --name "$validator" --oobi-alias delegate --oobi "$delegate_oobi"
kli oobi resolve --name "$validator" --oobi-alias delegator --oobi "$delegator_oobi"
kli kevers --name "$validator" --prefix "$delegate_aid" --poll

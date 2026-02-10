#!/bin/bash
set -e

# Test script for replacing a multisig member
# The initial multisig group:
#   (member_1, member_2, member_3) with signature threshold 2
# The multisig group after rotation:
#   (member_2, member_3, member_4) with signature threshold 2

suffix=$(head /dev/urandom | tr -dc a-z0-9 | head -c4)
member_1="member_1_${suffix}"
member_2="member_2_${suffix}"
member_3="member_3_${suffix}"
member_4="member_4_${suffix}"

group_witness_aid="BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha"
group_witness_url="http://127.0.0.1:5642/oobi/$group_witness_aid/controller"

if ! curl -s "$group_witness_url" > /dev/null; then
    echo "Witness URL is not reachable, remember to run: kli witness demo"
    exit 1
fi

kli init --name "$member_1" --nopasscode
kli init --name "$member_2" --nopasscode
kli init --name "$member_3" --nopasscode
kli init --name "$member_4" --nopasscode

kli oobi resolve --name "$member_1" --oobi "$group_witness_url"
kli oobi resolve --name "$member_2" --oobi "$group_witness_url"
kli oobi resolve --name "$member_3" --oobi "$group_witness_url"
kli oobi resolve --name "$member_4" --oobi "$group_witness_url"

kli incept --name "$member_1" --alias member --icount 1 --ncount 1 --isith 1 --nsith 1 --transferable --toad 1 --wit "$group_witness_aid"
kli incept --name "$member_2" --alias member --icount 1 --ncount 1 --isith 1 --nsith 1 --transferable --toad 1 --wit "$group_witness_aid"
kli incept --name "$member_3" --alias member --icount 1 --ncount 1 --isith 1 --nsith 1 --transferable --toad 1 --wit "$group_witness_aid"
kli incept --name "$member_4" --alias member --icount 1 --ncount 1 --isith 1 --nsith 1 --transferable --toad 1 --wit "$group_witness_aid"
kli ends add --name "$member_1" --alias member --eid "$group_witness_aid" --role mailbox
kli ends add --name "$member_2" --alias member --eid "$group_witness_aid" --role mailbox
kli ends add --name "$member_3" --alias member --eid "$group_witness_aid" --role mailbox
kli ends add --name "$member_4" --alias member --eid "$group_witness_aid" --role mailbox

member_1_oobi=$(kli oobi generate --name "$member_1" --alias member --role witness | tail -n 1)
member_2_oobi=$(kli oobi generate --name "$member_2" --alias member --role witness | tail -n 1)
member_3_oobi=$(kli oobi generate --name "$member_3" --alias member --role witness | tail -n 1)
member_4_oobi=$(kli oobi generate --name "$member_4" --alias member --role witness | tail -n 1)
member_1_aid=$(kli aid --name "$member_1" --alias member)
member_2_aid=$(kli aid --name "$member_2" --alias member)
member_3_aid=$(kli aid --name "$member_3" --alias member)
member_4_aid=$(kli aid --name "$member_4" --alias member)

kli oobi resolve --name "$member_1" --oobi-alias member_2 --oobi "${member_2_oobi}"
kli oobi resolve --name "$member_1" --oobi-alias member_3 --oobi "${member_3_oobi}"
kli oobi resolve --name "$member_1" --oobi-alias member_4 --oobi "${member_4_oobi}"

kli oobi resolve --name "$member_2" --oobi-alias member_1 --oobi "${member_1_oobi}"
kli oobi resolve --name "$member_2" --oobi-alias member_3 --oobi "${member_3_oobi}"
kli oobi resolve --name "$member_2" --oobi-alias member_4 --oobi "${member_4_oobi}"

kli oobi resolve --name "$member_3" --oobi-alias member_1 --oobi "${member_1_oobi}"
kli oobi resolve --name "$member_3" --oobi-alias member_2 --oobi "${member_2_oobi}"
kli oobi resolve --name "$member_3" --oobi-alias member_4 --oobi "${member_4_oobi}"

group_json=$(mktemp)
cat << EOF > "$group_json"
{
    "transferable": true,
    "toad": 1,
    "wits": ["$group_witness_aid"],
    "aids": ["$member_1_aid", "$member_2_aid", "$member_3_aid"],
    "isith": "2",
    "nsith": "2"
}
EOF

kli multisig incept --name "$member_1" --alias member --group group --file "$group_json" &
PID_LIST="$!"
kli multisig incept --name "$member_2" --alias member --group group --file "$group_json" &
PID_LIST+=" $!"
wait $PID_LIST

kli multisig join --name "$member_3" --group group --auto

group_oobi=$(kli oobi generate --name "$member_1" --alias group --role witness | tail -n 1)

kli status --name "$member_1" --alias group
kli status --name "$member_2" --alias group
kli status --name "$member_3" --alias group

kli rotate --name "$member_2" --alias member
kli rotate --name "$member_3" --alias member

kli query --name "$member_2" --alias member --prefix "$member_1_aid"
kli query --name "$member_2" --alias member --prefix "$member_3_aid"
kli query --name "$member_3" --alias member --prefix "$member_1_aid"
kli query --name "$member_3" --alias member --prefix "$member_2_aid"

kli oobi resolve --name "$member_4" --oobi-alias member_1 --oobi "$member_1_oobi"
kli oobi resolve --name "$member_4" --oobi-alias member_2 --oobi "$member_2_oobi"
kli oobi resolve --name "$member_4" --oobi-alias member_3 --oobi "$member_3_oobi"

kli multisig rotate --name "$member_2" --alias group --smids "$member_2_aid" --smids "$member_3_aid" --smids "$member_4_aid" --isith "2" --nsith "2" --rmids "$member_2_aid" --rmids "$member_3_aid" --rmids "$member_4_aid" &
PID_LIST="$!"
kli multisig rotate --name "$member_3" --alias group --smids "$member_2_aid" --smids "$member_3_aid" --smids "$member_4_aid" --isith "2" --nsith "2" --rmids "$member_2_aid" --rmids "$member_3_aid" --rmids "$member_4_aid" &
PID_LIST+=" $!"
wait $PID_LIST

kli status --name "$member_1" --alias group
kli status --name "$member_2" --alias group

kli oobi resolve --name "$member_4" --oobi-alias group --oobi "$group_oobi"

kli multisig join --name "$member_4" --group group --auto

kli local watch --name "$member_1"

kli status --name "$member_1" --alias group
kli status --name "$member_2" --alias group
kli status --name "$member_3" --alias group
kli status --name "$member_4" --alias group

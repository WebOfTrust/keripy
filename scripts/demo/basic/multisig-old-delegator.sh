#!/bin/bash
set -e

. "$(dirname "$0")/../demo-scripts.sh"
. "$(dirname "$0")/script-utils.sh"

kli_1() {
  if [ ! -f .venv_1/bin/kli ]; then
    python3.12 -m venv .venv_1
    .venv_1/bin/pip install keri==1.1.32
  fi

  .venv_1/bin/kli "$@"
}

kli_2() {
  if [ ! -f .venv_2/bin/kli ]; then
    python3.13 -m venv .venv_2
    .venv_2/bin/pip install -r requirements.txt
  fi

  .venv_2/bin/kli "$@"
}

kli_1 version
kli_2 version

delegator_1=$(random_name delegator_1)
delegator_2=$(random_name delegator_2)

background_start kli_1 init --name "$delegator_1" --nopasscode
background_start kli_1 init --name "$delegator_2" --nopasscode
background_wait

delegator_witness_aid="BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM"
delegator_witness_url="http://127.0.0.1:5643/oobi/$delegator_witness_aid/controller"

background_start kli_1 oobi resolve --name "$delegator_1" --oobi "$delegator_witness_url"
background_start kli_1 oobi resolve --name "$delegator_2" --oobi "$delegator_witness_url"
background_wait

kli_1 incept --name "$delegator_1" --alias member --icount 1 --ncount 1 --isith 1 --nsith 1 --transferable --toad 1 --wit "$delegator_witness_aid"
kli_1 incept --name "$delegator_2" --alias member --icount 1 --ncount 1 --isith 1 --nsith 1 --transferable --toad 1 --wit "$delegator_witness_aid"

delegator_1_aid=$(kli_1 status --name "$delegator_1" --alias member | grep "Identifier: " | cut -d ' ' -f 2)
delegator_1_oobi=$(kli_1 oobi generate --name "$delegator_1" --alias member --role witness | tail -n 1)
delegator_2_aid=$(kli_1 status --name "$delegator_2" --alias member | grep "Identifier: " | cut -d ' ' -f 2)
delegator_2_oobi=$(kli_1 oobi generate --name "$delegator_2" --alias member --role witness | tail -n 1)

background_start kli_1 oobi resolve --name "$delegator_1" --oobi "$delegator_2_oobi"
background_start kli_1 oobi resolve --name "$delegator_2" --oobi "$delegator_1_oobi"
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

background_start kli_1 multisig incept --name "$delegator_1" --alias member --group delegator --file "$delegator_json"
background_start kli_1 multisig incept --name "$delegator_2" --alias member --group delegator --file "$delegator_json"
background_wait

delegator_oobi=$(kli_1 oobi generate --name "$delegator_1" --alias delegator --role witness | tail -n 1)
delegator_aid=$(kli_1 status --name "$delegator_1" --alias delegator | grep "Identifier: " | cut -d ' ' -f 2)

# Create delegatee
delegate_1=$(random_name delegate_1)
delegate_2=$(random_name delegate_2)
delegate_witness_aid="BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha"
delegate_witness_url="http://127.0.0.1:5642/oobi/$delegate_witness_aid/controller"

background_start kli_2 init --name "$delegate_1" --nopasscode
background_start kli_2 init --name "$delegate_2" --nopasscode
background_wait

background_start kli_2 oobi resolve --name "$delegate_1" --oobi "$delegate_witness_url"
background_start kli_2 oobi resolve --name "$delegate_2" --oobi "$delegate_witness_url"
background_wait

kli_2 incept --name "$delegate_1" --alias member --icount 1 --ncount 1 --isith 1 --nsith 1 --transferable --toad 1 --wit "$delegate_witness_aid"
kli_2 incept --name "$delegate_2" --alias member --icount 1 --ncount 1 --isith 1 --nsith 1 --transferable --toad 1 --wit "$delegate_witness_aid"

kli_2 ends add --name "$delegate_1" --alias member --role mailbox --eid "$delegate_witness_aid"
kli_2 ends add --name "$delegate_2" --alias member --role mailbox --eid "$delegate_witness_aid"

delegate_1_aid=$(kli_2 status --name "$delegate_1" --alias member | grep "Identifier: " | cut -d ' ' -f 2)
delegate_1_oobi=$(kli_2 oobi generate --name "$delegate_1" --alias member --role witness | tail -n 1)
delegate_2_aid=$(kli_2 status --name "$delegate_2" --alias member | grep "Identifier: " | cut -d ' ' -f 2)
delegate_2_oobi=$(kli_2 oobi generate --name "$delegate_2" --alias member --role witness | tail -n 1)

# background_start kli_1 oobi resolve --name "$delegator_1" --oobi "$delegate_1_oobi"
# background_start kli_1 oobi resolve --name "$delegator_2" --oobi "$delegate_2_oobi"
background_start kli_2 oobi resolve --name "$delegate_1" --oobi "$delegator_oobi"
background_start kli_2 oobi resolve --name "$delegate_2" --oobi "$delegator_oobi"
background_start kli_2 oobi resolve --name "$delegate_1" --oobi "$delegate_2_oobi"
background_start kli_2 oobi resolve --name "$delegate_2" --oobi "$delegate_1_oobi"
background_wait

delegate_json=$(mktemp)
cat << EOF > "$delegate_json"
{
  "transferable": true,
  "wits": ["$delegate_witness_aid"],
  "aids": ["$delegate_1_aid", "$delegate_2_aid"],
  "toad": 1,
  "isith": "2",
  "nsith": "2",
  "delpre": "$delegator_aid"
}
EOF

background_start kli_2 multisig incept --name "$delegate_1" --alias member --group delegate --file "$delegate_json"
background_start kli_2 multisig incept --name "$delegate_2" --alias member --group delegate --file "$delegate_json"
background_start kli_1 delegate confirm --name "$delegator_1" --alias delegator --interact -Y
background_start kli_1 delegate confirm --name "$delegator_2" --alias delegator --interact -Y
background_wait

kli_2 status --name "$delegate_1" --alias delegate

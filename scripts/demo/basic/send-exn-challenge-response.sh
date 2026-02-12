#!/bin/bash
set -e

source "$(dirname "$0")/script-utils.sh"

cha1=$(random_name cha1)
cha2=$(random_name cha2)

kli init --name "$cha1" --nopasscode
kli init --name "$cha2" --nopasscode

kli oobi resolve --name "$cha1" --oobi http://127.0.0.1:5643/oobi/BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM/controller
kli oobi resolve --name "$cha2" --oobi http://127.0.0.1:5643/oobi/BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM/controller
kli oobi resolve --name "$cha1" --oobi http://127.0.0.1:5642/oobi/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha/controller
kli oobi resolve --name "$cha2" --oobi http://127.0.0.1:5642/oobi/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha/controller

kli incept --name "$cha1" --alias cha1 \
    --wit BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM \
    --toad 1 \
    --icount 1 \
    --ncount 1 \
    --isith 1 \
    --nsith 1 \
    --transferable

kli incept --name "$cha2" --alias cha2 \
    --wit BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha \
    --toad 1 \
    --icount 1 \
    --ncount 1 \
    --isith 1 \
    --nsith 1 \
    --transferable

kli ends add --name "$cha1" --alias cha1 --eid BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM --role mailbox
kli ends add --name "$cha2" --alias cha2 --eid BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha --role mailbox

cha1_oobi="$(kli oobi generate --name "$cha1" --alias cha1 --role witness | tail -n 1)"
cha2_oobi="$(kli oobi generate --name "$cha2" --alias cha2 --role witness | tail -n 1)"

kli oobi resolve --name "$cha1" --oobi-alias cha2 --oobi "${cha2_oobi}"
kli oobi resolve --name "$cha2" --oobi-alias cha1 --oobi "${cha1_oobi}"
words1_json="$(kli challenge generate --out json)"
words1="$(echo $words1_json | jq -r '. | join(" ")')"

echo "Responding with exn message and inline words"
kli exn send --name "$cha1" --sender cha1 --recipient cha2 --route /challenge/response --data "words=${words1_json}"
kli challenge verify --name "$cha2" --signer cha1 --words "${words1}"

words2_json="$(kli challenge generate --out json)"
words2="$(echo $words2_json | jq -r '. | join(" ")')"

echo "Responding with exn message and file data"
words2_file=$(mktemp)
echo "${words2_json}" | jq '. | { words: . }' > "${words2_file}"
kli exn send --name "$cha2" --sender cha2 --recipient cha1 --route /challenge/response --data "@${words2_file}"
kli challenge verify --name "$cha1" --signer cha2 --words "${words2}"
rm "${words2_file}"

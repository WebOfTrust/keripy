#!/bin/bash

kli init --name cha1 --nopasscode --config-dir "${KERI_SCRIPT_DIR}" --config-file demo-witness-oobis
kli incept --name cha1 --alias cha1 --file ${KERI_DEMO_SCRIPT_DIR}/data/challenge-sample.json
kli ends add --name cha1 --alias cha1 --eid BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM --role mailbox

kli init --name cha2 --nopasscode --config-dir "${KERI_SCRIPT_DIR}" --config-file pool2-witness-oobis
kli incept --name cha2 --alias cha2 --file ${KERI_DEMO_SCRIPT_DIR}/data/challenge-sample-pool2.json
kli ends add --name cha2 --alias cha2 --eid BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM --role mailbox

cha1_oobi="$(kli oobi generate --name cha1 --alias cha1 --role witness | sed -n '2 p')"
cha2_oobi="$(kli oobi generate --name cha2 --alias cha2 --role witness | sed -n '2 p')"

kli oobi resolve --name cha1 --oobi-alias cha2 --oobi "${cha2_oobi}"
kli oobi resolve --name cha2 --oobi-alias cha1 --oobi "${cha1_oobi}"

cha1_pre="$(kli aid --name cha1 --alias cha1)"
cha2_pre="$(kli aid --name cha2 --alias cha2)"

kli contacts replace --name cha1 --prefix "${cha2_pre}" --alias cha2
kli contacts replace --name cha2 --prefix "${cha1_pre}" --alias cha1

words1="$(kli challenge generate --out string)"
words2="$(kli challenge generate --out string)"

echo "Challenging cha1 with ${words1}"
kli challenge respond --name cha1 --alias cha1 --recipient cha2 --words "${words1}"
kli challenge verify --name cha2 --alias cha2 --signer cha1 --words "${words1}"

echo "Challenging cha2 with ${words2}"
kli challenge respond --name cha2 --alias cha2 --recipient cha1 --words "${words2}"
kli challenge verify --name cha1 --alias cha1 --signer cha2 --words "${words2}"

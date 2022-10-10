#!/bin/bash

kli init --name rootgar1 --salt 0ACDEyMzQ1Njc4OWxtbm9aBc --nopasscode --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis
kli incept --name rootgar1 --alias rootgar1 --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-1-sample.json

kli init --name rootgar2 --salt 0ACDEyMzQ1Njc4OWdoaWpsaw --nopasscode --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis
kli incept --name rootgar2 --alias rootgar2 --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-2-sample.json

kli oobi resolve --name rootgar1 --oobi-alias rootgar2 --oobi http://127.0.0.1:5642/oobi/EPhpLSjZw61ZsCXfcvpMWj3ccQMYNjooRQYUE3T7ewWc/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name rootgar2 --oobi-alias rootgar1 --oobi http://127.0.0.1:5642/oobi/EHdjvi0ZroUp1XAsmLMiWG1Y2YcVbmMsB7_472CurNw4/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha

echo "rootgar1 OOBIs:"
kli oobi generate --name rootgar1 --alias rootgar1 --role witness
echo ""
echo "rootgar2 OOBIs"
kli oobi generate --name rootgar2 --alias rootgar2 --role witness

# Follow commands run in parallel
kli multisig incept --name rootgar1 --alias rootgar1 --group rootgar --file ${KERI_DEMO_SCRIPT_DIR}/data/rootgar-sample.json &
pid=$!
PID_LIST+=" $pid"
kli multisig incept --name rootgar2 --alias rootgar2 --group rootgar --file ${KERI_DEMO_SCRIPT_DIR}/data/rootgar-sample.json &
pid=$!
PID_LIST+=" $pid"

wait $PID_LIST

kli status --name rootgar1 --alias rootgar
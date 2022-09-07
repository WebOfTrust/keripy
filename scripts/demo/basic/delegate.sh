#!/bin/bash
kli init --name delegate --nopasscode --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis --salt 0AMDEyMzQ1Njc4OWxtbm9wcQ
kli init --name delegator --nopasscode --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis --salt 0AMDEyMzQ1Njc4OWdoaWpsaw
kli incept --name delegator --alias delegator --file ${KERI_DEMO_SCRIPT_DIR}/data/delegator.json
kli oobi resolve --name delegate --oobi-alias delegator --oobi http://127.0.0.1:5642/oobi/EOlr22tu3VurGT7T22kruLtDhhQd6I5F5OCaBE5_ZUIc/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha

kli incept --name delegate --alias delegate --file ${KERI_DEMO_SCRIPT_DIR}/data/delegatee.json &
pid=$!
PID_LIST+=" $pid"

# In other console run the following:
sleep 2
kli delegate confirm --name delegator --alias delegator -Y &
pid=$!
PID_LIST+=" $pid"

wait $PID_LIST

kli status --name delegate --alias delegate
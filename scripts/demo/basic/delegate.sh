#!/bin/bash
kli init --name delegate --nopasscode --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis --salt 0ACDEyMzQ1Njc4OWxtbm9aBc
kli init --name delegator --nopasscode --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis --salt 0ACDEyMzQ1Njc4OWdoaWpsaw
kli incept --name delegator --alias delegator --file ${KERI_DEMO_SCRIPT_DIR}/data/delegator.json
kli oobi resolve --name delegate --oobi-alias delegator --oobi http://127.0.0.1:5642/oobi/EHpD0-CDWOdu5RJ8jHBSUkOqBZ3cXeDVHWNb_Ul89VI7/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha

kli incept --name delegate --alias proxy --file ${KERI_DEMO_SCRIPT_DIR}/data/delegator.json
kli incept --name delegate --alias delegate --proxy proxy --file ${KERI_DEMO_SCRIPT_DIR}/data/delegatee.json &
pid=$!
PID_LIST+=" $pid"

kli delegate confirm --name delegator --alias delegator -Y &
pid=$!
PID_LIST+=" $pid"

wait $PID_LIST

kli status --name delegate --alias delegate

echo "Now rotating delegate..."
kli rotate --name delegate --alias delegate --proxy proxy &
pid=$!
PID_LIST="$pid"

echo "Checking for delegate rotate..."
kli delegate confirm --name delegator --alias delegator -Y &
pid=$!
PID_LIST+=" $pid"

wait $PID_LIST

kli status --name delegate --alias delegate

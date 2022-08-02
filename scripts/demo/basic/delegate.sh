#!/bin/bash
kli init --name delegate --nopasscode --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis --salt 0AMDEyMzQ1Njc4OWxtbm9wcQ
kli init --name delegator --nopasscode --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis --salt 0AMDEyMzQ1Njc4OWdoaWpsaw
kli incept --name delegator --alias delegator --file ${KERI_DEMO_SCRIPT_DIR}/data/delegator.json
kli oobi resolve --name delegate --oobi-alias delegator --oobi http://127.0.0.1:5642/oobi/E8AKUcbZyik8EdkOwXgnyAxO5mSIPJWGZ_o7zMhnNnjo/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo

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
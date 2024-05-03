#!/bin/bash
# three stooges

source ${KERI_SCRIPT_DIR}/demo/basic/script-utils.sh

# WITNESSES
# To run the following scripts, open another console window and run:
# $ kli witness demo

print_yellow "Multisig rotation with three AIDs"
echo

kli init --name larry --salt 0ACDEyMzQ1Njc4OWxtbm9aBc --nopasscode --config-dir "${KERI_SCRIPT_DIR}" --config-file demo-witness-oobis
kli incept --name larry --alias larry --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-1-sample.json

kli init --name moe --salt 0ACDEyMzQ1Njc4OWdoaWpsaw --nopasscode --config-dir "${KERI_SCRIPT_DIR}" --config-file demo-witness-oobis
kli incept --name moe --alias moe --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-2-sample.json

kli init --name curly --salt 0ACDEyMzQ1Njc4OWdoaWpsaw --nopasscode --config-dir "${KERI_SCRIPT_DIR}" --config-file demo-witness-oobis
kli incept --name curly --alias curly --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-3-sample.json

# OOBI resolution does the initial discovery of key state
echo
print_yellow "Resolve OOBIs"
kli oobi resolve --name larry --oobi-alias moe --oobi http://127.0.0.1:5642/oobi/EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name larry --oobi-alias curly --oobi http://127.0.0.1:5642/oobi/ENkjt7khEI5edCMw5qugagbJw1QvGnQEtcewxb0FnU9U/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha

kli oobi resolve --name moe --oobi-alias larry --oobi http://127.0.0.1:5642/oobi/EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name moe --oobi-alias curly --oobi http://127.0.0.1:5642/oobi/ENkjt7khEI5edCMw5qugagbJw1QvGnQEtcewxb0FnU9U/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha

kli oobi resolve --name curly --oobi-alias larry --oobi http://127.0.0.1:5642/oobi/EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name curly --oobi-alias moe --oobi http://127.0.0.1:5642/oobi/EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha

# Multisig Inception
echo
print_yellow "Multisig Inception"
# Follow commands run in parallel
kli multisig incept --name larry --alias larry --group multisig --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-three-aids.json &
pid=$!
PID_LIST+=" $pid"
kli multisig incept --name moe --alias moe --group multisig --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-three-aids.json &
pid=$!
PID_LIST+=" $pid"
kli multisig incept --name curly --alias curly --group multisig --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-three-aids.json &
pid=$!
PID_LIST+=" $pid"

echo
print_yellow "Multisig Inception - wait"
wait $PID_LIST

echo
print_green "Multisig Inception - status"
kli status --name larry --alias multisig

# Rotate keys for each multisig - required before rotating the multisig
echo
print_yellow "Rotate keys for each multisig"
kli rotate --name larry --alias larry
kli rotate --name moe --alias moe
kli rotate --name curly --alias curly

# Pull key state in from other multisig group participant identifiers so they have the next digest
echo
print_yellow "Pull key state in from other multisig group participant identifiers"
# 2 about 1
kli query --name moe --alias moe --prefix EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4
# 2 about 3
kli query --name moe --alias moe --prefix ENkjt7khEI5edCMw5qugagbJw1QvGnQEtcewxb0FnU9U
# 1 about 2
kli query --name larry --alias larry --prefix EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1
# 1 about 3
kli query --name larry --alias larry --prefix ENkjt7khEI5edCMw5qugagbJw1QvGnQEtcewxb0FnU9U
# 3 about 1
kli query --name curly --alias curly --prefix EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4
# 3 about 2
kli query --name curly --alias curly --prefix EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1


echo
print_yellow "Multisig rotation"

PID_LIST=""

kli multisig rotate --name larry --alias multisig --smids EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4 --smids EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1 --smids ENkjt7khEI5edCMw5qugagbJw1QvGnQEtcewxb0FnU9U --isith '["1/3", "1/3", "1/3"]' --nsith '["1/2", "1/2", "1/2"]' --rmids EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4 --rmids EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1 --rmids ENkjt7khEI5edCMw5qugagbJw1QvGnQEtcewxb0FnU9U &
pid=$!
PID_LIST+=" $pid"
kli multisig rotate --name moe --alias multisig --smids EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4 --smids EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1 --smids ENkjt7khEI5edCMw5qugagbJw1QvGnQEtcewxb0FnU9U --isith '["1/3", "1/3", "1/3"]' --nsith '["1/2", "1/2", "1/2"]' --rmids EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4 --rmids EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1 --rmids ENkjt7khEI5edCMw5qugagbJw1QvGnQEtcewxb0FnU9U &
pid=$!
PID_LIST+=" $pid"
kli multisig rotate --name curly --alias multisig --smids EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4 --smids EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1 --smids ENkjt7khEI5edCMw5qugagbJw1QvGnQEtcewxb0FnU9U --isith '["1/3", "1/3", "1/3"]' --nsith '["1/2", "1/2", "1/2"]' --rmids EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4 --rmids EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1 --rmids ENkjt7khEI5edCMw5qugagbJw1QvGnQEtcewxb0FnU9U &
pid=$!
PID_LIST+=" $pid"

echo
print_yellow "Multisig rotation - wait"
wait $PID_LIST

echo
print_green "Multisig rotation - status"
kli status --name larry --alias multisig

echo
print_yellow "Multisig interact"

PID_LIST=""

kli multisig interact --name larry --alias multisig --data "{'tagline': 'three lost souls'}" &
pid=$!
PID_LIST+=" $pid"
kli multisig interact --name moe --alias multisig --data "{'tagline': 'three lost souls'}" &
pid=$!
PID_LIST+=" $pid"
kli multisig interact --name curly --alias multisig --data "{'tagline': 'three lost souls'}" &
pid=$!
PID_LIST+=" $pid"

echo
print_yellow "Multisig interact - wait"
wait $PID_LIST

echo
print_green "Multisig interact - status"
kli status --name larry --alias multisig
print_lcyan "Multisig rotate three stooges - done."

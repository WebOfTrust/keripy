#!/bin/bash
# three stooges

source ${KERI_SCRIPT_DIR}/demo/basic/script-utils.sh

# WITNESSES
# To run the following scripts, open another console window and run:
# $ kli witness demo

print_yellow "Multisig rotation with three AIDs"
echo

kli init --name multisig1 --salt 0ACDEyMzQ1Njc4OWxtbm9aBc --nopasscode --config-dir "${KERI_SCRIPT_DIR}" --config-file demo-witness-oobis
kli incept --name multisig1 --alias multisig1 --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-1-sample.json

kli init --name multisig2 --salt 0ACDEyMzQ1Njc4OWdoaWpsaw --nopasscode --config-dir "${KERI_SCRIPT_DIR}" --config-file demo-witness-oobis
kli incept --name multisig2 --alias multisig2 --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-2-sample.json

kli init --name multisig3 --salt 0ACDEyMzQ1Njc4OWdoaWpsaw --nopasscode --config-dir "${KERI_SCRIPT_DIR}" --config-file demo-witness-oobis
kli incept --name multisig3 --alias multisig3 --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-3-sample.json

# OOBI resolution does the initial discovery of key state
echo
print_yellow "Resolve OOBIs"
kli oobi resolve --name multisig1 --oobi-alias multisig2 --oobi http://127.0.0.1:5642/oobi/EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name multisig1 --oobi-alias multisig3 --oobi http://127.0.0.1:5642/oobi/ENkjt7khEI5edCMw5qugagbJw1QvGnQEtcewxb0FnU9U/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha

kli oobi resolve --name multisig2 --oobi-alias multisig1 --oobi http://127.0.0.1:5642/oobi/EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name multisig2 --oobi-alias multisig3 --oobi http://127.0.0.1:5642/oobi/ENkjt7khEI5edCMw5qugagbJw1QvGnQEtcewxb0FnU9U/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha

kli oobi resolve --name multisig3 --oobi-alias multisig1 --oobi http://127.0.0.1:5642/oobi/EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name multisig3 --oobi-alias multisig2 --oobi http://127.0.0.1:5642/oobi/EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha

# Multisig Inception
echo
print_yellow "Multisig Inception"
# Follow commands run in parallel
kli multisig incept --name multisig1 --alias multisig1 --group multisig --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-three-aids.json &
pid=$!
PID_LIST+=" $pid"
kli multisig incept --name multisig2 --alias multisig2 --group multisig --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-three-aids.json &
pid=$!
PID_LIST+=" $pid"
kli multisig incept --name multisig3 --alias multisig3 --group multisig --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-three-aids.json &
pid=$!
PID_LIST+=" $pid"

echo
print_yellow "Multisig Inception - wait"
wait $PID_LIST

echo
print_green "Multisig Inception - status"
kli status --name multisig1 --alias multisig

# Rotate keys for each multisig - required before rotating the multisig
echo
print_yellow "Rotate keys for each multisig"
kli rotate --name multisig1 --alias multisig1
kli rotate --name multisig2 --alias multisig2
kli rotate --name multisig3 --alias multisig3

# Pull key state in from other multisig group participant identifiers so they have the next digest
echo
print_yellow "Pull key state in from other multisig group participant identifiers"
# 2 about 1
kli query --name multisig2 --alias multisig2 --prefix EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4
# 2 about 3
kli query --name multisig2 --alias multisig2 --prefix ENkjt7khEI5edCMw5qugagbJw1QvGnQEtcewxb0FnU9U
# 1 about 2
kli query --name multisig1 --alias multisig1 --prefix EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1
# 1 about 3
kli query --name multisig1 --alias multisig1 --prefix ENkjt7khEI5edCMw5qugagbJw1QvGnQEtcewxb0FnU9U
# 3 about 1
kli query --name multisig3 --alias multisig3 --prefix EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4
# 3 about 2
kli query --name multisig3 --alias multisig3 --prefix EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1


echo
print_yellow "Multisig rotation"

PID_LIST=""

kli multisig rotate --name multisig1 --alias multisig --smids EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4 --smids EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1 --smids ENkjt7khEI5edCMw5qugagbJw1QvGnQEtcewxb0FnU9U --isith '["1/3", "1/3", "1/3"]' --nsith '["1/2", "1/2", "1/2"]' --rmids EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4 --rmids EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1 --rmids ENkjt7khEI5edCMw5qugagbJw1QvGnQEtcewxb0FnU9U &
pid=$!
PID_LIST+=" $pid"
kli multisig rotate --name multisig2 --alias multisig --smids EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4 --smids EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1 --smids ENkjt7khEI5edCMw5qugagbJw1QvGnQEtcewxb0FnU9U --isith '["1/3", "1/3", "1/3"]' --nsith '["1/2", "1/2", "1/2"]' --rmids EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4 --rmids EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1 --rmids ENkjt7khEI5edCMw5qugagbJw1QvGnQEtcewxb0FnU9U &
pid=$!
PID_LIST+=" $pid"
kli multisig rotate --name multisig3 --alias multisig --smids EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4 --smids EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1 --smids ENkjt7khEI5edCMw5qugagbJw1QvGnQEtcewxb0FnU9U --isith '["1/3", "1/3", "1/3"]' --nsith '["1/2", "1/2", "1/2"]' --rmids EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4 --rmids EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1 --rmids ENkjt7khEI5edCMw5qugagbJw1QvGnQEtcewxb0FnU9U &
pid=$!
PID_LIST+=" $pid"

echo
print_yellow "Multisig rotation - wait"
wait $PID_LIST

echo
print_green "Multisig rotation - status"
kli status --name multisig1 --alias multisig

echo
print_yellow "Multisig interact"

PID_LIST=""

kli multisig interact --name multisig1 --alias multisig --data "{}" &
pid=$!
PID_LIST+=" $pid"
kli multisig interact --name multisig2 --alias multisig --data "{}" &
pid=$!
PID_LIST+=" $pid"
kli multisig interact --name multisig3 --alias multisig --data "{}" &
pid=$!
PID_LIST+=" $pid"

echo
print_yellow "Multisig interact - wait"
wait $PID_LIST

echo
print_green "Multisig interact - status"
kli status --name multisig1 --alias multisig
print_lcyan "Multisig rotate three stooges - done."

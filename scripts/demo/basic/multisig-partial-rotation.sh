#!/bin/bash

# WITNESSES
# To run the following scripts, open another console window and run:
# $ kli witness demo

kli init --name multisig1 --salt 0ACDEyMzQ1Njc4OWxtbm9aBc --nopasscode --config-dir "${KERI_SCRIPT_DIR}" --config-file demo-witness-oobis
kli incept --name multisig1 --alias multisig1 --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-1-sample.json

kli init --name multisig2 --salt 0ACDEyMzQ1Njc4OWdoaWpsaw --nopasscode --config-dir "${KERI_SCRIPT_DIR}" --config-file demo-witness-oobis
kli incept --name multisig2 --alias multisig2 --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-2-sample.json

kli init --name multisig3 --salt 0ACDEyMzQ1Njc4OWdoaWpsaw --nopasscode --config-dir "${KERI_SCRIPT_DIR}" --config-file demo-witness-oobis
kli incept --name multisig3 --alias multisig3 --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-3-sample.json

kli oobi resolve --name multisig1 --oobi-alias multisig2 --oobi http://127.0.0.1:5642/oobi/EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name multisig1 --oobi-alias multisig3 --oobi http://127.0.0.1:5642/oobi/ENkjt7khEI5edCMw5qugagbJw1QvGnQEtcewxb0FnU9U/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name multisig2 --oobi-alias multisig1 --oobi http://127.0.0.1:5642/oobi/EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name multisig2 --oobi-alias multisig3 --oobi http://127.0.0.1:5642/oobi/ENkjt7khEI5edCMw5qugagbJw1QvGnQEtcewxb0FnU9U/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name multisig3 --oobi-alias multisig1 --oobi http://127.0.0.1:5642/oobi/EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name multisig3 --oobi-alias multisig2 --oobi http://127.0.0.1:5642/oobi/EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha

# Follow commands run in parallel
kli multisig incept --name multisig1 --alias multisig1 --group multisig --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-triple-sample.json &
pid=$!
PID_LIST+=" $pid"
kli multisig incept --name multisig2 --alias multisig2 --group multisig --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-triple-sample.json &
pid=$!
PID_LIST+=" $pid"
kli multisig incept --name multisig3 --alias multisig3 --group multisig --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-triple-sample.json &
pid=$!
PID_LIST+=" $pid"

wait $PID_LIST

kli status --name multisig1 --alias multisig

PID_LIST=""

kli multisig rotate --name multisig1 --alias multisig --smids EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4 --smids EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1 --isith '["1/2", "1/2"]' --nsith '["1/2", "1/2", "1/2"]' --rmids EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4 --rmids EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1 --rmids ENkjt7khEI5edCMw5qugagbJw1QvGnQEtcewxb0FnU9U &
pid=$!
PID_LIST+=" $pid"
kli multisig rotate --name multisig2 --alias multisig --smids EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4 --smids EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1 --isith '["1/2", "1/2"]' --nsith '["1/2", "1/2", "1/2"]' --rmids EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4 --rmids EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1 --rmids ENkjt7khEI5edCMw5qugagbJw1QvGnQEtcewxb0FnU9U &
pid=$!
PID_LIST+=" $pid"

wait $PID_LIST

kli status --name multisig1 --alias multisig

PID_LIST=""

kli multisig interact --name multisig1 --alias multisig --data "{}" &
pid=$!
PID_LIST+=" $pid"
kli multisig interact --name multisig2 --alias multisig --data "{}" &
pid=$!
PID_LIST+=" $pid"

wait $PID_LIST

kli status --name multisig1 --alias multisig

# Run watch command for multisig3 to see that she is out of date with the group
echo
echo "Watching multisig AID for multisig3 (out of date member)"
kli local watch --name multisig3




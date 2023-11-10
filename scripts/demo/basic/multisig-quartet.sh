#!/bin/bash

# WITNESSES
# To run the following scripts, open another console window and run:
# $ kli witness demo

# Create 4 individual AIDS
kli init --name multisig1 --salt 0ACDEyMzQ1Njc4OWxtbm9aBc --nopasscode --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis
kli incept --name multisig1 --alias multisig1 --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-1-sample.json

kli init --name multisig2 --salt 0ACDEyMzQ1Njc4OWdoaWpsaw --nopasscode --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis
kli incept --name multisig2 --alias multisig2 --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-2-sample.json

kli init --name multisig3 --salt 0ACDEyMzQ1Njc4OWdoaWpsce --nopasscode --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis
kli incept --name multisig3 --alias multisig3 --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-3-sample.json

kli init --name multisig4 --salt 0ACDEyMzQ1Njc4OWdoaWps04 --nopasscode --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis
kli incept --name multisig4 --alias multisig4 --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-3-sample.json

# Connect them all with OOBIs
kli oobi resolve --name multisig1 --oobi-alias multisig2 --oobi http://127.0.0.1:5642/oobi/EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name multisig1 --oobi-alias multisig3 --oobi http://127.0.0.1:5642/oobi/EMkvHBDM2n9rvjnUiLvdAFJjNZ81Fp0QmEgto-2cG8CS/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name multisig1 --oobi-alias multisig4 --oobi http://127.0.0.1:5642/oobi/EAV9iv9aFLy2AULDisAfeHgLy1-NmKP6fEVddYAE7dyf/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name multisig2 --oobi-alias multisig1 --oobi http://127.0.0.1:5642/oobi/EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name multisig2 --oobi-alias multisig3 --oobi http://127.0.0.1:5642/oobi/EMkvHBDM2n9rvjnUiLvdAFJjNZ81Fp0QmEgto-2cG8CS/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name multisig2 --oobi-alias multisig4 --oobi http://127.0.0.1:5642/oobi/EAV9iv9aFLy2AULDisAfeHgLy1-NmKP6fEVddYAE7dyf/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name multisig3 --oobi-alias multisig1 --oobi http://127.0.0.1:5642/oobi/EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name multisig3 --oobi-alias multisig2 --oobi http://127.0.0.1:5642/oobi/EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name multisig3 --oobi-alias multisig4 --oobi http://127.0.0.1:5642/oobi/EAV9iv9aFLy2AULDisAfeHgLy1-NmKP6fEVddYAE7dyf/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name multisig4 --oobi-alias multisig1 --oobi http://127.0.0.1:5642/oobi/EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name multisig4 --oobi-alias multisig2 --oobi http://127.0.0.1:5642/oobi/EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name multisig4 --oobi-alias multisig3 --oobi http://127.0.0.1:5642/oobi/EMkvHBDM2n9rvjnUiLvdAFJjNZ81Fp0QmEgto-2cG8CS/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha

# Each single run the same command to create the multisig in parallel
kli multisig incept --name multisig1 --alias multisig1 --group multisig --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-quartet-sample.json &
pid=$!
PID_LIST+=" $pid"
kli multisig incept --name multisig2 --alias multisig2 --group multisig --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-quartet-sample.json &
pid=$!
PID_LIST+=" $pid"
kli multisig incept --name multisig3 --alias multisig3 --group multisig --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-quartet-sample.json &
pid=$!
PID_LIST+=" $pid"
kli multisig incept --name multisig4 --alias multisig4 --group multisig --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-quartet-sample.json &
pid=$!
PID_LIST+=" $pid"

wait $PID_LIST

kli status --name multisig4 --alias multisig

# Now perform a rotation and an interaction
kli multisig rotate --name multisig1 --alias multisig --smids EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4 --smids EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1 --smids EMkvHBDM2n9rvjnUiLvdAFJjNZ81Fp0QmEgto-2cG8CS --smids EAV9iv9aFLy2AULDisAfeHgLy1-NmKP6fEVddYAE7dyf --isith '["1/2", "1/2", "1/2", "1/2"]' --nsith '["1/2", "1/2", "1/2", "1/2"]' --rmids EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4 --rmids EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1 --rmids EMkvHBDM2n9rvjnUiLvdAFJjNZ81Fp0QmEgto-2cG8CS --rmids EAV9iv9aFLy2AULDisAfeHgLy1-NmKP6fEVddYAE7dyf &
pid=$!
PID_LIST="$pid"
kli multisig rotate --name multisig2 --alias multisig --smids EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4 --smids EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1 --smids EMkvHBDM2n9rvjnUiLvdAFJjNZ81Fp0QmEgto-2cG8CS --smids EAV9iv9aFLy2AULDisAfeHgLy1-NmKP6fEVddYAE7dyf --isith '["1/2", "1/2", "1/2", "1/2"]' --nsith '["1/2", "1/2", "1/2", "1/2"]' --rmids EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4 --rmids EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1 --rmids EMkvHBDM2n9rvjnUiLvdAFJjNZ81Fp0QmEgto-2cG8CS --rmids EAV9iv9aFLy2AULDisAfeHgLy1-NmKP6fEVddYAE7dyf &
pid=$!
PID_LIST+=" $pid"
kli multisig rotate --name multisig3 --alias multisig --smids EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4 --smids EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1 --smids EMkvHBDM2n9rvjnUiLvdAFJjNZ81Fp0QmEgto-2cG8CS --smids EAV9iv9aFLy2AULDisAfeHgLy1-NmKP6fEVddYAE7dyf --isith '["1/2", "1/2", "1/2", "1/2"]' --nsith '["1/2", "1/2", "1/2", "1/2"]' --rmids EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4 --rmids EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1 --rmids EMkvHBDM2n9rvjnUiLvdAFJjNZ81Fp0QmEgto-2cG8CS --rmids EAV9iv9aFLy2AULDisAfeHgLy1-NmKP6fEVddYAE7dyf &
pid=$!
PID_LIST+=" $pid"
kli multisig rotate --name multisig4 --alias multisig --smids EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4 --smids EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1 --smids EMkvHBDM2n9rvjnUiLvdAFJjNZ81Fp0QmEgto-2cG8CS --smids EAV9iv9aFLy2AULDisAfeHgLy1-NmKP6fEVddYAE7dyf --isith '["1/2", "1/2", "1/2", "1/2"]' --nsith '["1/2", "1/2", "1/2", "1/2"]' --rmids EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4 --rmids EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1 --rmids EMkvHBDM2n9rvjnUiLvdAFJjNZ81Fp0QmEgto-2cG8CS --rmids EAV9iv9aFLy2AULDisAfeHgLy1-NmKP6fEVddYAE7dyf &
pid=$!
PID_LIST+=" $pid"

wait $PID_LIST

kli status --name multisig1 --alias multisig

PID_LIST=""

kli multisig interact --name multisig1 --alias multisig --data "{}" &
pid=$!
PID_LIST="$pid"
kli multisig interact --name multisig2 --alias multisig --data "{}" &
pid=$!
PID_LIST+=" $pid"
kli multisig interact --name multisig3 --alias multisig --data "{}" &
pid=$!
PID_LIST+=" $pid"
kli multisig interact --name multisig4 --alias multisig --data "{}" &
pid=$!
PID_LIST+=" $pid"

wait $PID_LIST

kli status --name multisig3 --alias multisig

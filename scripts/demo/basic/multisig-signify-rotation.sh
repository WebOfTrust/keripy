#!/bin/bash

# WITNESSES
# To run the following scripts, open another console window and run:
# $ kli witness demo

kli init --name multisig1 --salt 0ACDEyMzQ1Njc4OWxtbm9aBc --nopasscode --config-dir "${KERI_SCRIPT_DIR}" --config-file demo-witness-oobis
kli incept --name multisig1 --alias multisig1 --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-1-sample.json

kli init --name multisig2 --salt 0ACDEyMzQ1Njc4OWdoaWpsaw --nopasscode --config-dir "${KERI_SCRIPT_DIR}" --config-file demo-witness-oobis
kli incept --name multisig2 --alias multisig2 --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-2-sample.json

kli oobi resolve --name multisig1 --oobi-alias multisig2 --oobi http://127.0.0.1:5642/oobi/EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name multisig1 --oobi-alias agent0 --oobi http://127.0.0.1:3902/oobi/ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK/agent/EFebpJik0emPaSuvoSPYuLVpSAsaWVDwf4WYVPOBva_p
kli oobi resolve --name multisig2 --oobi-alias multisig1 --oobi http://127.0.0.1:5642/oobi/EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name multisig2 --oobi-alias agent0 --oobi http://127.0.0.1:3902/oobi/ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK/agent/EFebpJik0emPaSuvoSPYuLVpSAsaWVDwf4WYVPOBva_p

# Follow commands run in parallel
kli multisig incept --name multisig1 --alias multisig1 --group multisig --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-signify-sample.json &
pid=$!
PID_LIST+=" $pid"
kli multisig incept --name multisig2 --alias multisig2 --group multisig --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-signify-sample.json &
pid=$!

wait $PID_LIST
PID_LIST=""

kli status --name multisig1 --alias multisig


kli multisig interact --name multisig1 --alias multisig --data '{"i": "EE77q3_zWb5ojgJr-R1vzsL5yiL4Nzm-bfSOQzQl02dy"}' &
pid=$!
PID_LIST+=" $pid"
kli multisig interact --name multisig2 --alias multisig --data '{"i": "EE77q3_zWb5ojgJr-R1vzsL5yiL4Nzm-bfSOQzQl02dy"}' &
pid=$!
PID_LIST+=" $pid"

wait $PID_LIST
PID_LIST=""

read  -n 1 -r -p "Press any key after agent0 has rotated:"

kli rotate --name multisig1 --alias multisig1
kli query --name multisig2 --alias multisig2 --prefix EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4
kli query --name multisig2 --alias multisig2 --prefix ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK
kli rotate --name multisig2 --alias multisig2
kli query --name multisig1 --alias multisig1 --prefix EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1
kli query --name multisig1 --alias multisig1 --prefix ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK

kli multisig rotate --name multisig1 --alias multisig --smids EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4:1 --smids EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1:1 --smids ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK:1 --isith '["1/3", "1/3", "1/3"]' --nsith '["1/3", "1/3", "1/3"]' --rmids EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4 --rmids EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1 --rmids ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK &
pid=$!
PID_LIST+=" $pid"
kli multisig rotate --name multisig2 --alias multisig --smids EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4:1 --smids EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1:1 --smids ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK:1 --isith '["1/3", "1/3", "1/3"]' --nsith '["1/3", "1/3", "1/3"]' --rmids EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4 --rmids EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1 --rmids ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK &
pid=$!
PID_LIST+=" $pid"

wait $PID_LIST

kli status --name multisig1 --alias multisig

PID_LIST=""





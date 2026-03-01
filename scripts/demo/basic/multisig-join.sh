#!/bin/bash

# WITNESSES
# To run the following scripts, open another console window and run:
# $ kli witness demo

kli init --name multisigj1 --salt 0ACDEyMzQ1Njc4OWxtbm9aBc --nopasscode --config-dir "${KERI_SCRIPT_DIR}" --config-file demo-witness-oobis
kli incept --name multisigj1 --alias multisigj1 --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-1-sample.json

kli init --name multisigj2 --salt 0ACDEyMzQ1Njc4OWdoaWpsaw --nopasscode --config-dir "${KERI_SCRIPT_DIR}" --config-file demo-witness-oobis
kli incept --name multisigj2 --alias multisigj2 --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-2-sample.json

kli oobi resolve --name multisigj1 --oobi-alias multisigj2 --oobi http://127.0.0.1:5642/oobi/EKJ6tNVUGbdaiwx2nWDCFXG-_PY_AzESOcoKlm0kRNP3/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name multisigj2 --oobi-alias multisigj1 --oobi http://127.0.0.1:5642/oobi/EFY7MixHb0so4WFFHw6btOPc5qeeWfPm7v5MJWcdcbyG/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha

PID_LIST=""

kli multisig incept --name multisigj1 --alias multisigj1 --group multisig --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-join-sample.json &
pid=$!
PID_LIST+=" $pid"

kli multisig join --name multisigj2 --auto --timeout 10 &
pid=$!
PID_LIST+=" $pid"

wait $PID_LIST
if [ $? -ne 0 ]; then
  echo "Multisig group inception/join failed"
  exit 1
fi

kli status --name multisigj1 --alias multisig

kli rotate --name multisigj1 --alias multisigj1
sleep 1 && kli query --name multisigj2 --alias multisigj2 --prefix EFY7MixHb0so4WFFHw6btOPc5qeeWfPm7v5MJWcdcbyG
kli rotate --name multisigj2 --alias multisigj2
sleep 1 && kli query --name multisigj1 --alias multisigj1 --prefix EKJ6tNVUGbdaiwx2nWDCFXG-_PY_AzESOcoKlm0kRNP3

PID_LIST=""

kli multisig rotate --name multisigj1 --alias multisig --smids EKJ6tNVUGbdaiwx2nWDCFXG-_PY_AzESOcoKlm0kRNP3 --smids EFY7MixHb0so4WFFHw6btOPc5qeeWfPm7v5MJWcdcbyG --isith '["1/2", "1/2"]' --nsith '["1/2", "1/2"]' --rmids EKJ6tNVUGbdaiwx2nWDCFXG-_PY_AzESOcoKlm0kRNP3 --rmids EFY7MixHb0so4WFFHw6btOPc5qeeWfPm7v5MJWcdcbyG &
pid=$!
PID_LIST+=" $pid"

kli multisig join --name multisigj2 --auto --timeout 10 &
pid=$!
PID_LIST+=" $pid"

wait $PID_LIST
if [ $? -ne 0 ]; then
  echo "Multisig group rotation/join failed"
  exit 1
fi

kli status --name multisigj1 --alias multisig

PID_LIST=""

kli multisig interact --name multisigj1 --alias multisig --data '{"d": "potato"}' &
pid=$!
PID_LIST+=" $pid"

kli multisig join --name multisigj2 --auto --timeout 10 &
pid=$!
PID_LIST+=" $pid"

wait $PID_LIST

kli status --name multisigj1 --alias multisig

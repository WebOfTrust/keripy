#!/bin/bash

# WITNESSES
# To run the following scripts, open another console window and run:
# $ kli witness demo

echo
echo Creating keystores and incepting
echo

kli init --name multisig1 \
  --config-dir ${KERI_SCRIPT_DIR} --base "" \
  --salt 0ACDEyMzQ1Njc4OWxtbm9aBc --nopasscode --config-file demo-witness-oobis
kli incept --name multisig1 \
  --config-dir ${KERI_SCRIPT_DIR} --base "" \
  --alias multisig1 --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-1-sample.json

kli init --name multisig2 \
  --base "" --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis \
  --salt 0ACDEyMzQ1Njc4OWdoaWpsaw --nopasscode
kli incept --name multisig2 \
  --config-dir ${KERI_SCRIPT_DIR} --base "" \
  --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-2-sample.json \
  --alias multisig2

echo
echo Resolving OOBIs
echo

kli oobi resolve --name multisig1 \
  --config-dir ${KERI_SCRIPT_DIR} --base "" \
  --oobi-alias multisig2 --oobi http://127.0.0.1:5642/oobi/EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name multisig2 \
  --config-dir ${KERI_SCRIPT_DIR} --base "" \
  --oobi-alias multisig1 --oobi http://127.0.0.1:5642/oobi/EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha

echo
echo Multisig inception with multisig group
echo
# Follow commands run in parallel
kli multisig incept --name multisig1 \
  --config-dir ${KERI_SCRIPT_DIR} --base "" \
  --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-sample.json \
  --alias multisig1 --group multisig &

pid=$!
PID_LIST+=" $pid"
kli multisig incept --name multisig2 \
  --config-dir ${KERI_SCRIPT_DIR} --base "" \
  --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-sample.json \
  --alias multisig2 --group multisig  &

pid=$!
PID_LIST+=" $pid"

wait $PID_LIST

echo
echo Checking multisig status
echo
kli status --name multisig1 --config-dir ${KERI_SCRIPT_DIR} --base "" --alias multisig

echo
echo "Multisig Test Complete"
echo
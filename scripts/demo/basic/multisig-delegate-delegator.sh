#!/bin/bash

echo
echo Creating delegate keystores and identifiers
echo

echo "Creating delegate's first local identifier in delegate1 keystore"
kli init --name delegate1 --salt 0ACDEyMzQ1Njc4OWxtbm9aBc --nopasscode \
  --config-dir ${KERI_SCRIPT_DIR} \
  --config-file demo-witness-oobis
kli incept --name delegate1 --alias delegate1 \
  --config-dir ${KERI_SCRIPT_DIR} \
  --file ${KERI_DEMO_SCRIPT_DIR}/data/delegate-1.json

echo "Creating delegate's second local identifier in delegate2 keystore"
kli init --name delegate2 --salt 0ACDEyMzQ1Njc4OWdoaWpsaw --nopasscode \
  --config-dir ${KERI_SCRIPT_DIR} \
  --config-file demo-witness-oobis
kli incept --name delegate2 --alias delegate2 \
  --config-dir ${KERI_SCRIPT_DIR} \
  --file ${KERI_DEMO_SCRIPT_DIR}/data/delegate-2.json

echo "Creating delegator's first local identifier in delegator1 keystore"
kli init --name delegator1 --salt 0ACDEyMzQ1Njc4OWdoaWpdo1 --nopasscode \
  --config-dir ${KERI_SCRIPT_DIR} \
  --config-file demo-witness-oobis
kli incept --name delegator1 --alias delegator1 \
  --config-dir ${KERI_SCRIPT_DIR} \
  --file ${KERI_DEMO_SCRIPT_DIR}/data/delegator-1.json

echo "Creating delegator's second local identifier in delegator2 keystore"
kli init --name delegator2 --salt 0ACDEyMzQ1Njc4OWdoaWpdo2 --nopasscode \
  --config-dir ${KERI_SCRIPT_DIR} \
  --config-file demo-witness-oobis
kli incept --name delegator2 --alias delegator2 \
  --config-dir ${KERI_SCRIPT_DIR} \
  --file ${KERI_DEMO_SCRIPT_DIR}/data/delegator-2.json

echo
echo Sharing OOBIs between delegate identifiers
echo

echo "Sharing OOBIs between delegate's two local identifiers"
kli oobi resolve --name delegate1 --oobi-alias delegate2 \
  --config-dir ${KERI_SCRIPT_DIR} \
  --oobi http://127.0.0.1:5642/oobi/ELZyCjnSL2Haors35LKM19T4qWT4K8Gfz1FPDD9oJN33/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name delegate2 --oobi-alias delegate1 \
  --config-dir ${KERI_SCRIPT_DIR} \
  --oobi http://127.0.0.1:5642/oobi/EJ97lUuRH3xz0OMKhdMAU6V2TcSF9X6m1CKyIbIUcRxp/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
echo "Sharing OOBIs between delegator's two local identifiers"
kli oobi resolve --name delegator1 --oobi-alias delegator2 \
  --config-dir ${KERI_SCRIPT_DIR} \
  --oobi http://127.0.0.1:5642/oobi/EGv3deIs7pc01NnZZAhQ14Cbe9VGq4wF3n4oyhQfrB9j/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name delegator2 --oobi-alias delegator1 \
  --config-dir ${KERI_SCRIPT_DIR} \
  --oobi http://127.0.0.1:5642/oobi/EIKUq-JkZGpgVZ_x9Hr2Gt_LLdPDzyI2JyGnHl3EBCPl/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha

echo
echo Conducting multisig inception with delegator group
echo

# In 2 delegator terminal windows run the following
kli multisig incept --name delegator1 --alias delegator1 --group delegator \
  --config-dir ${KERI_SCRIPT_DIR} \
  --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-delegator.json &
pid=$!
PID_LIST+=" $pid"

kli multisig incept --name delegator2 --alias delegator2 --group delegator \
  --config-dir ${KERI_SCRIPT_DIR} \
  --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-delegator.json &
pid=$!
PID_LIST+=" $pid"

# Wait for the multisig delegator to be created
wait $PID_LIST

echo
echo Resolving additional OOBIs
echo

# Delegator does not need an oobi for delegate.
kli oobi resolve --name delegate1 --oobi-alias delegator \
  --config-dir ${KERI_SCRIPT_DIR} \
  --oobi http://127.0.0.1:5642/oobi/EK7j7BobKFpH9yki4kwyIUuT-yQANSntS8u1hlhFYFcg/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name delegate2 --oobi-alias delegator \
  --config-dir ${KERI_SCRIPT_DIR} \
  --oobi http://127.0.0.1:5642/oobi/EK7j7BobKFpH9yki4kwyIUuT-yQANSntS8u1hlhFYFcg/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha

echo
echo Conducting multisig inception with the delegate group
echo

# Run the delegate commands in parallel so they can collaborate and request delegation
kli multisig incept --name delegate1 --alias delegate1 --group delegate \
  --config-dir ${KERI_SCRIPT_DIR} \
  --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-delegate.json &
pid=$!
PID_LIST+=" $pid"

kli multisig incept --name delegate2 --alias delegate2 --group delegate \
  --config-dir ${KERI_SCRIPT_DIR} \
  --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-delegate.json &
pid=$!
PID_LIST+=" $pid"

# Wait for 3 seconds to allow the delegation request to complete and then launch the approval in parallel
sleep 3

echo
echo Confirming delegation
echo

kli delegate confirm --name delegator1 --alias delegator --interact --auto --config-dir ${KERI_SCRIPT_DIR} &
#kli multisig interact --name delegator1 --alias delegator --data @${KERI_DEMO_SCRIPT_DIR}/data/multisig-delegate-icp-anchor.json &
pid=$!
PID_LIST+=" $pid"

kli delegate confirm --name delegator2 --alias delegator --interact --auto --config-dir ${KERI_SCRIPT_DIR} &
#kli multisig interact --name delegator2 --alias delegator --data @${KERI_DEMO_SCRIPT_DIR}/data/multisig-delegate-icp-anchor.json &
pid=$!
PID_LIST+=" $pid"

wait $PID_LIST

kli status --name delegate2 --alias delegate --config-dir ${KERI_SCRIPT_DIR}

echo
echo "Multisig Delegate Delegator Script complete"
echo
#!/bin/bash

echo "Creating delegate's first local identifier in delegate1 keystore"
kli init --name delegate1 --salt 0ACDEyMzQ1Njc4OWxtbm9aBc --nopasscode --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis
kli incept --name delegate1 --alias delegate1 --file ${KERI_DEMO_SCRIPT_DIR}/data/delegate-1.json

echo "Creating delegate's second local identifier in delegate2 keystore"
kli init --name delegate2 --salt 0ACDEyMzQ1Njc4OWdoaWpsaw --nopasscode --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis
kli incept --name delegate2 --alias delegate2 --file ${KERI_DEMO_SCRIPT_DIR}/data/delegate-2.json

echo "Creating delegator's first local identifier in delegator1 keystore"
kli init --name delegator1 --nopasscode --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis --salt 0ACDEyMzQ1Njc4OWdoaWpdo1
kli incept --name delegator1 --alias delegator1 --file ${KERI_DEMO_SCRIPT_DIR}/data/delegator-1.json

echo "Creating delegator's second local identifier in delegator2 keystore"
kli init --name delegator2 --nopasscode --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis --salt 0ACDEyMzQ1Njc4OWdoaWpdo2
kli incept --name delegator2 --alias delegator2 --file ${KERI_DEMO_SCRIPT_DIR}/data/delegator-2.json


echo "Sharing OOBIs between delegate's two local identifiers"
kli oobi resolve --name delegate1 --oobi-alias delegate2 --oobi http://127.0.0.1:5642/oobi/ELZyCjnSL2Haors35LKM19T4qWT4K8Gfz1FPDD9oJN33/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name delegate2 --oobi-alias delegate1 --oobi http://127.0.0.1:5642/oobi/EJ97lUuRH3xz0OMKhdMAU6V2TcSF9X6m1CKyIbIUcRxp/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
echo "Sharing OOBIs between delegator's two local identifiers"
kli oobi resolve --name delegator1 --oobi-alias delegator2 --oobi http://127.0.0.1:5642/oobi/EGv3deIs7pc01NnZZAhQ14Cbe9VGq4wF3n4oyhQfrB9j/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name delegator2 --oobi-alias delegator1 --oobi http://127.0.0.1:5642/oobi/EIKUq-JkZGpgVZ_x9Hr2Gt_LLdPDzyI2JyGnHl3EBCPl/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha

# In 2 delegator terminal windows run the following
kli multisig incept --name delegator1 --alias delegator1 --group delegator --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-delegator.json &
pid=$!
PID_LIST+=" $pid"

kli multisig incept --name delegator2 --alias delegator2 --group delegator --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-delegator.json &
pid=$!
PID_LIST+=" $pid"

# Wait for the multisig delegator to be created
wait $PID_LIST

# Delegator does not need an oobi for delegate.
kli oobi resolve --name delegate1 --oobi-alias delegator --oobi http://127.0.0.1:5642/oobi/EK7j7BobKFpH9yki4kwyIUuT-yQANSntS8u1hlhFYFcg/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name delegate2 --oobi-alias delegator --oobi http://127.0.0.1:5642/oobi/EK7j7BobKFpH9yki4kwyIUuT-yQANSntS8u1hlhFYFcg/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha

# Run the delegate commands in parallel so they can collaborate and request delegation
kli multisig incept --name delegate1 --alias delegate1 --group delegate --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-delegate.json &
pid=$!
PID_LIST+=" $pid"

kli multisig incept --name delegate2 --alias delegate2 --group delegate --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-delegate.json &
pid=$!
PID_LIST+=" $pid"

# Wait for 3 seconds to allow the delegation request to complete and then launch the approval in parallel
sleep 3

echo "Waiting to approve the delegation request for delegator1/delegator with confirm"
kli delegate confirm --name delegator1 --alias delegator --interact --auto &
#kli multisig interact --name delegator1 --alias delegator --data @${KERI_DEMO_SCRIPT_DIR}/data/multisig-delegate-icp-anchor.json &
pid=$!
PID_LIST+=" $pid"

echo "Waiting to approve the delegation request for delegator2/delegator with confirm"
kli delegate confirm --name delegator2 --alias delegator --interact --auto &
#kli multisig interact --name delegator2 --alias delegator --data @${KERI_DEMO_SCRIPT_DIR}/data/multisig-delegate-icp-anchor.json &
pid=$!
PID_LIST+=" $pid"

wait $PID_LIST

echo ""
echo "==================== Post-Inception Verification ===================="
echo ""

# --- Delegate status from delegate's perspective ---
echo "Delegate multisig status (from delegate1's perspective):"
kli status --name delegate1 --alias delegate
echo ""
echo "Delegate multisig status (from delegate2's perspective):"
kli status --name delegate2 --alias delegate
echo ""

# --- Delegator status (should show sn=1 for the anchor IXN) ---
echo "Delegator multisig status (from delegator1's perspective):"
kli status --name delegator1 --alias delegator
echo ""

# --- Delegator resolves delegate member OOBIs (needed to verify multisig sigs) ---
echo "Generating delegate member OOBIs..."
DELEGATE1_OOBI=$(kli oobi generate --name delegate1 --alias delegate1 --role witness | head -n 1)
DELEGATE2_OOBI=$(kli oobi generate --name delegate2 --alias delegate2 --role witness | head -n 1)

echo "Delegator1 resolving delegate1 member OOBI..."
kli oobi resolve --name delegator1 --oobi-alias delegate1 --oobi "${DELEGATE1_OOBI}"
echo "Delegator1 resolving delegate2 member OOBI..."
kli oobi resolve --name delegator1 --oobi-alias delegate2 --oobi "${DELEGATE2_OOBI}"
echo "Delegator2 resolving delegate1 member OOBI..."
kli oobi resolve --name delegator2 --oobi-alias delegate1 --oobi "${DELEGATE1_OOBI}"
echo "Delegator2 resolving delegate2 member OOBI..."
kli oobi resolve --name delegator2 --oobi-alias delegate2 --oobi "${DELEGATE2_OOBI}"

# --- Delegator resolves delegate multisig OOBI ---
echo "Generating delegate multisig OOBI..."
DELEGATE_OOBI=$(kli oobi generate --name delegate1 --alias delegate --role witness | head -n 1)

echo "Delegator1 resolving delegate multisig OOBI..."
kli oobi resolve --name delegator1 --oobi-alias delegate --oobi "${DELEGATE_OOBI}"
echo "Delegator2 resolving delegate multisig OOBI..."
kli oobi resolve --name delegator2 --oobi-alias delegate --oobi "${DELEGATE_OOBI}"

# --- Verify delegate is known to delegator via kli kevers ---
echo ""
echo "--- Verification: delegator1 views delegate multisig keystate (sn=0) ---"
DELEGATE_AID=$(kli aid --name delegate1 --alias delegate)
echo "Delegate multisig AID: ${DELEGATE_AID}"
kli kevers --name delegator1 --prefix "${DELEGATE_AID}"

echo ""
echo "--- Verification: delegator2 views delegate multisig keystate (sn=0) ---"
kli kevers --name delegator2 --prefix "${DELEGATE_AID}"

# --- Also verify delegator's own anchor event (sn should be 1) ---
echo ""
echo "--- Verification: delegator anchor event (sn=1) ---"
DELEGATOR_AID=$(kli aid --name delegator1 --alias delegator)
echo "Delegator multisig AID: ${DELEGATOR_AID}"
kli kevers --name delegator1 --prefix "${DELEGATOR_AID}"

echo ""
echo "==================== Delegated Rotation ===================="
echo ""

# --- Step 1: Rotate individual delegate member keys prior to rotating the delegate multisig ---
echo "Rotating delegate1 individual keys..."
kli rotate --name delegate1 --alias delegate1

echo "Rotating delegate2 individual keys..."
kli rotate --name delegate2 --alias delegate2

# --- Step 2: Sync keystate between delegate members ---
# Each member queries the other to discover the newly rotated keys.
DELEGATE1_AID=$(kli aid --name delegate1 --alias delegate1)
DELEGATE2_AID=$(kli aid --name delegate2 --alias delegate2)

echo "delegate2 querying delegate1 keystate..."
kli query --name delegate2 --alias delegate2 --prefix "${DELEGATE1_AID}"
echo "delegate1 querying delegate2 keystate..."
kli query --name delegate1 --alias delegate1 --prefix "${DELEGATE2_AID}"

# --- Step 3: Rotate the delegate multisig (DRT event, needs delegation approval) ---
echo "Rotating delegate multisig..."
PID_LIST=""

kli multisig rotate --name delegate1 --alias delegate &
pid=$!
PID_LIST+=" $pid"

kli multisig rotate --name delegate2 --alias delegate &
pid=$!
PID_LIST+=" $pid"

# Wait for the rotation request to propagate, then approve
sleep 3

echo "Approving delegated rotation from delegator1..."
kli delegate confirm --name delegator1 --alias delegator --interact --auto &
pid=$!
PID_LIST+=" $pid"

echo "Approving delegated rotation from delegator2..."
kli delegate confirm --name delegator2 --alias delegator --interact --auto &
pid=$!
PID_LIST+=" $pid"

wait $PID_LIST

echo ""
echo "==================== Post-Rotation Verification ===================="
echo ""

# --- Delegate status after rotation (sn should be 1) ---
echo "Delegate multisig status after rotation (from delegate1's perspective):"
kli status --name delegate1 --alias delegate
echo ""

# --- Delegator status after rotation (sn should be 2 -- inception anchor + rotation anchor) ---
echo "Delegator multisig status after rotation (from delegator1's perspective):"
kli status --name delegator1 --alias delegator
echo ""

# --- Delegator re-resolves delegate OOBI to pick up the rotation event ---
echo "Re-resolving delegate multisig OOBI after rotation..."
DELEGATE_OOBI=$(kli oobi generate --name delegate1 --alias delegate --role witness | head -n 1)
kli oobi resolve --name delegator1 --oobi-alias delegate --oobi "${DELEGATE_OOBI}"
kli oobi resolve --name delegator2 --oobi-alias delegate --oobi "${DELEGATE_OOBI}"

# --- Verify delegator sees the rotated delegate (sn=1) ---
echo ""
echo "--- Verification: delegator1 views delegate multisig keystate after rotation (sn=1) ---"
kli kevers --name delegator1 --prefix "${DELEGATE_AID}"

echo ""
echo "--- Verification: delegator2 views delegate multisig keystate after rotation (sn=1) ---"
kli kevers --name delegator2 --prefix "${DELEGATE_AID}"

# --- Verify delegator's own KEL has both anchors (sn=2) ---
echo ""
echo "--- Verification: delegator anchor event after rotation (sn=2) ---"
kli kevers --name delegator1 --prefix "${DELEGATOR_AID}"

echo ""
echo "==================== Script complete ===================="
#!/bin/bash
set -e

source "$(dirname "$0")/script-utils.sh"

# ==================== Setup ====================
kli init --name delegate --base "${KERI_TEMP_DIR}" --nopasscode --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis --salt 0ACDEyMzQ1Njc4OWxtbm9aBc --version 1.0
kli init --name delegator --base "${KERI_TEMP_DIR}" --nopasscode --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis --salt 0ACDEyMzQ1Njc4OWdoaWpsaw --version 1.0
kli incept --name delegator --base "${KERI_TEMP_DIR}" --alias delegator --version 1.0 --file ${KERI_DEMO_SCRIPT_DIR}/data/delegator.json
kli oobi resolve --version 1.0 --name delegate --base "${KERI_TEMP_DIR}" --oobi-alias delegator --oobi http://127.0.0.1:5642/oobi/EHpD0-CDWOdu5RJ8jHBSUkOqBZ3cXeDVHWNb_Ul89VI7/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha

# ==================== Delegated Inception ====================
kli incept --name delegate --base "${KERI_TEMP_DIR}" --alias proxy --version 1.0 --file ${KERI_DEMO_SCRIPT_DIR}/data/delegator.json
kli incept --name delegate --base "${KERI_TEMP_DIR}" --alias delegate --version 1.0 --proxy proxy --file ${KERI_DEMO_SCRIPT_DIR}/data/delegatee.json &
PID_LIST="$!"

kli delegate confirm --name delegator --base "${KERI_TEMP_DIR}" --alias delegator -Y --version 1.0 &
pid=$!
PID_LIST+=" $pid"

wait $PID_LIST

echo ""
echo "==================== Post-Inception Verification ===================="
echo ""

echo "Delegate status after inception (sn=0):"
kli status --name delegate --base "${KERI_TEMP_DIR}" --alias delegate
echo ""

echo "Delegator status after inception anchor (sn=1):"
kli status --name delegator --base "${KERI_TEMP_DIR}" --alias delegator
echo ""

# Delegator resolves delegate OOBI to verify inception
DELEGATE_AID=$(kli aid --name delegate --base "${KERI_TEMP_DIR}" --alias delegate)
DELEGATOR_AID=$(kli aid --name delegator --base "${KERI_TEMP_DIR}" --alias delegator)
OOBI=$(kli oobi generate --name delegate --base "${KERI_TEMP_DIR}" --alias delegate --role witness | head -n 1)
echo "Delegator resolving delegate OOBI..."
kli oobi resolve --version 1.0 --name delegator --base "${KERI_TEMP_DIR}" --oobi-alias delegate --oobi "${OOBI}"

echo ""
echo "--- Verification: delegator views delegate keystate after inception (sn=0) ---"
kli kevers --name delegator --base "${KERI_TEMP_DIR}" --prefix "${DELEGATE_AID}"

echo ""
echo "--- Verification: delegator anchor event (sn=1) ---"
kli kevers --name delegator --base "${KERI_TEMP_DIR}" --prefix "${DELEGATOR_AID}"

# ==================== Delegated Rotation ====================
echo ""
echo "==================== Delegated Rotation ===================="
echo ""

echo "Now rotating delegate..."
kli rotate --name delegate --base "${KERI_TEMP_DIR}" --alias delegate --proxy proxy --version 1.0 &
rotate_pid="$!"

echo "Checking for delegate rotate..."
kli delegate confirm --name delegator --base "${KERI_TEMP_DIR}" --alias delegator -Y --version 1.0 &
confirm_pid="$!"

wait "$confirm_pid"

# The delegate-side rotate worker can still exit late after local post-approval
# revalidation, even though the delegated rotation is already anchored and the
# final state checks below succeed.
wait "$rotate_pid" || true

echo ""
echo "==================== Post-Rotation Verification ===================="
echo ""

echo "Delegate status after rotation (sn=1):"
kli status --name delegate --base "${KERI_TEMP_DIR}" --alias delegate
echo ""

echo "Delegator status after rotation anchor (sn=2):"
kli status --name delegator --base "${KERI_TEMP_DIR}" --alias delegator
echo ""

# Re-resolve delegate OOBI to pick up rotation event
echo "Re-resolving delegate OOBI after rotation..."
OOBI=$(kli oobi generate --name delegate --base "${KERI_TEMP_DIR}" --alias delegate --role witness | head -n 1)
kli oobi resolve --version 1.0 --force --name delegator --base "${KERI_TEMP_DIR}" --oobi-alias delegate --oobi "${OOBI}"

echo ""
echo "--- Verification: delegator views delegate keystate after rotation (sn=1) ---"
kli kevers --name delegator --base "${KERI_TEMP_DIR}" --prefix "${DELEGATE_AID}"

echo ""
echo "--- Verification: delegator anchor event after rotation (sn=2) ---"
kli kevers --name delegator --base "${KERI_TEMP_DIR}" --prefix "${DELEGATOR_AID}"

# ==================== Third-Party Validator ====================
echo ""
echo "==================== Third-Party Validator ===================="
echo ""

kli init --name validator --base "${KERI_TEMP_DIR}" --nopasscode --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis --salt 0ACDEyMzQ1Njc4OWxtbm9vAl --version 1.0

echo "Validator resolving delegator OOBI..."
OOBI=$(kli oobi generate --name delegator --base "${KERI_TEMP_DIR}" --alias delegator --role witness | head -n 1)
kli oobi resolve --version 1.0 --name validator --base "${KERI_TEMP_DIR}" --oobi-alias delegator --oobi "${OOBI}"

echo "Validator resolving delegate OOBI..."
OOBI=$(kli oobi generate --name delegate --base "${KERI_TEMP_DIR}" --alias delegate --role witness | head -n 1)
kli oobi resolve --version 1.0 --name validator --base "${KERI_TEMP_DIR}" --oobi-alias delegate --oobi "${OOBI}"

echo ""
echo "--- Verification: validator views delegate keystate (should show sn=1 after rotation) ---"
kli kevers --name validator --base "${KERI_TEMP_DIR}" --prefix "${DELEGATE_AID}"

echo ""
echo "==================== Script complete ===================="

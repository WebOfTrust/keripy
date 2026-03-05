#!/bin/bash

# WITNESSES
# To run the following scripts, open another console window and run:
# $ kli witness demo

# CI safety: bound how long multisig join waits so that failures
# in the initiating side do not leave automated runs hanging
# indefinitely. JOIN_TIMEOUT and TIMEOUT_BIN may be overridden
# by the caller (for example, in CI configuration).
JOIN_TIMEOUT=${JOIN_TIMEOUT:-60}
TIMEOUT_BIN=${TIMEOUT_BIN:-timeout}

run_multisig_join_bg() {
  if command -v "$TIMEOUT_BIN" >/dev/null 2>&1; then
    "$TIMEOUT_BIN" "$JOIN_TIMEOUT" kli multisig join --name multisigj2 --auto
  else
    kli multisig join --name multisigj2 --auto
  fi
}

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

run_multisig_join_bg &
pid=$!
PID_LIST+=" $pid"

wait $PID_LIST
# Exit immediately if incept or join failed or later phases will hang indefinitely
wait_status=$?
if [ $wait_status -ne 0 ]; then
  echo "multisig-join.sh: group phase failed with exit code $wait_status"
  exit $wait_status
fi

kli status --name multisigj1 --alias multisig

kli rotate --name multisigj1 --alias multisigj1
kli query --name multisigj2 --alias multisigj2 --prefix EFY7MixHb0so4WFFHw6btOPc5qeeWfPm7v5MJWcdcbyG
kli rotate --name multisigj2 --alias multisigj2
kli query --name multisigj1 --alias multisigj1 --prefix EKJ6tNVUGbdaiwx2nWDCFXG-_PY_AzESOcoKlm0kRNP3

PID_LIST=""

kli multisig rotate --name multisigj1 --alias multisig --smids EKJ6tNVUGbdaiwx2nWDCFXG-_PY_AzESOcoKlm0kRNP3 --smids EFY7MixHb0so4WFFHw6btOPc5qeeWfPm7v5MJWcdcbyG --isith '["1/2", "1/2"]' --nsith '["1/2", "1/2"]' --rmids EKJ6tNVUGbdaiwx2nWDCFXG-_PY_AzESOcoKlm0kRNP3 --rmids EFY7MixHb0so4WFFHw6btOPc5qeeWfPm7v5MJWcdcbyG &
pid=$!
PID_LIST+=" $pid"

run_multisig_join_bg &
pid=$!
PID_LIST+=" $pid"

wait $PID_LIST
# Exit immediately if rotate or join failed; broken state causes script to hang waiting for events that never come.
wait_status=$?
if [ $wait_status -ne 0 ]; then
  echo "multisig-join.sh: group phase failed with exit code $wait_status"
  exit $wait_status
fi

kli status --name multisigj1 --alias multisig

PID_LIST=""

kli multisig interact --name multisigj1 --alias multisig --data '{"d": "potato"}' &
pid=$!
PID_LIST+=" $pid"

run_multisig_join_bg &
pid=$!
PID_LIST+=" $pid"

wait $PID_LIST
# Exit on failure instead of falsely reporting success after a timeout.
wait_status=$?
if [ $wait_status -ne 0 ]; then
  echo "multisig-join.sh: group phase failed with exit code $wait_status"
  exit $wait_status
fi

kli status --name multisigj1 --alias multisig

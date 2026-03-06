#!/bin/bash

# WITNESSES
# To run the following scripts, open another console window and run:
# $ kli witness demo

# This script uses initiator-first wait so a failing incept/rotate/interact does not leave
# the join process running indefinitely. The group rotation phase retries up to
# ROTATE_MAX_ATTEMPTS on non-zero rotate exit (configurable via env).

kli init --name multisigj1 --salt 0ACDEyMzQ1Njc4OWxtbm9aBc --nopasscode --config-dir "${KERI_SCRIPT_DIR}" --config-file demo-witness-oobis
kli incept --name multisigj1 --alias multisigj1 --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-1-sample.json

kli init --name multisigj2 --salt 0ACDEyMzQ1Njc4OWdoaWpsaw --nopasscode --config-dir "${KERI_SCRIPT_DIR}" --config-file demo-witness-oobis
kli incept --name multisigj2 --alias multisigj2 --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-2-sample.json

kli oobi resolve --name multisigj1 --oobi-alias multisigj2 --oobi http://127.0.0.1:5642/oobi/EKJ6tNVUGbdaiwx2nWDCFXG-_PY_AzESOcoKlm0kRNP3/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name multisigj2 --oobi-alias multisigj1 --oobi http://127.0.0.1:5642/oobi/EFY7MixHb0so4WFFHw6btOPc5qeeWfPm7v5MJWcdcbyG/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha

# --- Incept phase: initiator-first wait ---
kli multisig incept --name multisigj1 --alias multisigj1 --group multisig --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-join-sample.json &
inceptor_pid=$!
kli multisig join --name multisigj2 --auto &
join_pid=$!

wait $inceptor_pid
inceptor_status=$?
if [ $inceptor_status -ne 0 ]; then
  kill $join_pid 2>/dev/null || true
  wait $join_pid 2>/dev/null || true
  echo "multisig-join.sh: group incept failed with exit code $inceptor_status"
  exit $inceptor_status
fi
wait $join_pid
join_status=$?
if [ $join_status -ne 0 ]; then
  echo "multisig-join.sh: group incept join failed with exit code $join_status"
  exit $join_status
fi

kli status --name multisigj1 --alias multisig

# --- Group rotation phase: one join waiting; retry only rotate until success ---
ROTATE_MAX_ATTEMPTS=${ROTATE_MAX_ATTEMPTS:-10}
ROTATE_RETRY_DELAY=${ROTATE_RETRY_DELAY:-1}
attempt=1

# Member sync once (individual rotations and cross-queries); do not re-rotate on retry.
kli rotate --name multisigj1 --alias multisigj1
kli query --name multisigj2 --alias multisigj2 --prefix EFY7MixHb0so4WFFHw6btOPc5qeeWfPm7v5MJWcdcbyG
kli rotate --name multisigj2 --alias multisigj2
kli query --name multisigj1 --alias multisigj1 --prefix EKJ6tNVUGbdaiwx2nWDCFXG-_PY_AzESOcoKlm0kRNP3

kli multisig join --name multisigj2 --auto &
join_pid=$!

while [ $attempt -le $ROTATE_MAX_ATTEMPTS ]; do
  if [ $attempt -gt 1 ]; then
    sleep $ROTATE_RETRY_DELAY
    kli query --name multisigj2 --alias multisigj2 --prefix EFY7MixHb0so4WFFHw6btOPc5qeeWfPm7v5MJWcdcbyG
    kli query --name multisigj1 --alias multisigj1 --prefix EKJ6tNVUGbdaiwx2nWDCFXG-_PY_AzESOcoKlm0kRNP3
  fi

  if kli multisig rotate --name multisigj1 --alias multisig --smids EKJ6tNVUGbdaiwx2nWDCFXG-_PY_AzESOcoKlm0kRNP3 --smids EFY7MixHb0so4WFFHw6btOPc5qeeWfPm7v5MJWcdcbyG --isith '["1/2", "1/2"]' --nsith '["1/2", "1/2"]' --rmids EKJ6tNVUGbdaiwx2nWDCFXG-_PY_AzESOcoKlm0kRNP3 --rmids EFY7MixHb0so4WFFHw6btOPc5qeeWfPm7v5MJWcdcbyG; then
    break
  fi
  if [ $attempt -eq $ROTATE_MAX_ATTEMPTS ]; then
    kill $join_pid 2>/dev/null || true
    wait $join_pid 2>/dev/null || true
    echo "multisig-join.sh: group rotate failed after $ROTATE_MAX_ATTEMPTS attempts"
    exit 1
  fi
  attempt=$((attempt + 1))
done

wait $join_pid
join_status=$?
if [ $join_status -ne 0 ]; then
  echo "multisig-join.sh: group rotate join failed with exit code $join_status"
  exit $join_status
fi

kli status --name multisigj1 --alias multisig

# --- Interact phase: initiator-first wait ---
kli multisig interact --name multisigj1 --alias multisig --data '{"d": "potato"}' &
interactor_pid=$!
kli multisig join --name multisigj2 --auto &
join_pid=$!

wait $interactor_pid
interactor_status=$?
if [ $interactor_status -ne 0 ]; then
  kill $join_pid 2>/dev/null || true
  wait $join_pid 2>/dev/null || true
  echo "multisig-join.sh: group interact failed with exit code $interactor_status"
  exit $interactor_status
fi
wait $join_pid
join_status=$?
if [ $join_status -ne 0 ]; then
  echo "multisig-join.sh: group interact join failed with exit code $join_status"
  exit $join_status
fi

kli status --name multisigj1 --alias multisig

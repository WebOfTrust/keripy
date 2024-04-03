#!/bin/bash

echo "Testing clean"

function isSuccess() {
    ret=$?
    if [ $ret -ne 0 ]; then
       echo "Error $ret"
       exit $ret
    fi
}

# CREATE DATABASE AND KEYSTORE
kli init --name nat --base "${KERI_TEMP_DIR}" --nopasscode
isSuccess

# RESOLVE WITNESS OOBIs
kli oobi resolve --name nat --base "${KERI_TEMP_DIR}" --oobi-alias wan --oobi http://127.0.0.1:5643/oobi/BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM/controller
isSuccess
kli oobi resolve --name nat --base "${KERI_TEMP_DIR}"  --oobi-alias wil --oobi http://127.0.0.1:5642/oobi/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha/controller
isSuccess
kli oobi resolve --name nat --base "${KERI_TEMP_DIR}"  --oobi-alias wes --oobi http://127.0.0.1:5644/oobi/BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX/controller
isSuccess

## INCEPT AND PROPOGATE EVENTS AND RECEIPTS TO WITNESSES
kli incept --name nat --base "${KERI_TEMP_DIR}" --receipt-endpoint --alias nat --file "${KERI_DEMO_SCRIPT_DIR}/data/trans-wits-sample.json"
isSuccess
kli interact --name nat --base "${KERI_TEMP_DIR}" --alias nat
isSuccess
kli rotate --name nat --base "${KERI_TEMP_DIR}"  --receipt-endpoint --alias nat --witness-cut BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX
isSuccess
kli rotate --name nat --base "${KERI_TEMP_DIR}"  --receipt-endpoint --alias nat --witness-add BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX
isSuccess
kli interact --name nat --base "${KERI_TEMP_DIR}" --alias nat
isSuccess
kli interact --name nat --base "${KERI_TEMP_DIR}" --alias nat
isSuccess
kli interact --name nat --base "${KERI_TEMP_DIR}" --alias nat
isSuccess
kli interact --name nat --base "${KERI_TEMP_DIR}" --alias nat
isSuccess

kli clean --name nat  --base "${KERI_TEMP_DIR}"
isSuccess

kli status --name nat --alias nat

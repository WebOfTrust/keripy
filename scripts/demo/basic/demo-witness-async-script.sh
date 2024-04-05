#!/bin/bash

# WITNESSES
# To run the following scripts, open another console window and run:
# $ kli witness demo

function isSuccess() {
    ret=$?
    if [ $ret -ne 0 ]; then
       echo "Error $ret"
       exit $ret
    fi
}

# CREATE DATABASE AND KEYSTORE
kli init --name async-witness-test --base "${KERI_TEMP_DIR}" --nopasscode
isSuccess

# RESOLVE WITNESS OOBIs
kli oobi resolve --name async-witness-test --base "${KERI_TEMP_DIR}" --oobi-alias wan --oobi http://127.0.0.1:5643/oobi/BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM/controller
isSuccess
kli oobi resolve --name async-witness-test --base "${KERI_TEMP_DIR}"  --oobi-alias wil --oobi http://127.0.0.1:5642/oobi/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha/controller
isSuccess
kli oobi resolve --name async-witness-test --base "${KERI_TEMP_DIR}"  --oobi-alias wes --oobi http://127.0.0.1:5644/oobi/BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX/controller
isSuccess

## INCEPT AND PROPOGATE EVENTS AND RECEIPTS TO WITNESSES
kli incept --name async-witness-test --base "${KERI_TEMP_DIR}" --alias trans-wits --file "${KERI_DEMO_SCRIPT_DIR}/data/trans-wits-sample.json"
isSuccess

kli incept --name async-witness-test --base "${KERI_TEMP_DIR}"  --alias inquisitor --file "${KERI_DEMO_SCRIPT_DIR}/data/inquisitor-sample.json"
isSuccess

kli status --name async-witness-test --base "${KERI_TEMP_DIR}"  --alias trans-wits

kli rotate --name async-witness-test --base "${KERI_TEMP_DIR}"  --alias trans-wits --witness-cut BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX
isSuccess

kli status --name async-witness-test --base "${KERI_TEMP_DIR}"  --alias trans-wits

kli rotate --name async-witness-test --base "${KERI_TEMP_DIR}"  --alias trans-wits --witness-add BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX
isSuccess

kli status --name async-witness-test --base "${KERI_TEMP_DIR}"  --alias trans-wits

echo 'Test Complete'
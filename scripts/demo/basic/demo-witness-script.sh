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
kli init --name witness-test --nopasscode
isSuccess

# RESOLVE WITNESS OOBIs
kli oobi resolve --name witness-test --oobi-alias wan --oobi http://127.0.0.1:5643/oobi/BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw/controller
isSuccess
kli oobi resolve --name witness-test --oobi-alias wil --oobi http://127.0.0.1:5642/oobi/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo/controller
isSuccess
kli oobi resolve --name witness-test --oobi-alias wes --oobi http://127.0.0.1:5644/oobi/Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c/controller
isSuccess

# INCEPT AND PROPOGATE EVENTS AND RECEIPTS TO WITNESSES
kli incept --name witness-test --alias trans-wits --file ${KERI_DEMO_SCRIPT_DIR}/data/trans-wits-sample.json
isSuccess

kli incept --name witness-test --alias inquisitor --file ${KERI_DEMO_SCRIPT_DIR}/data/inquisitor-sample.json
isSuccess

kli status --name witness-test --alias trans-wits

kli rotate --name witness-test --alias trans-wits --witness-cut Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c
isSuccess

kli status --name witness-test --alias trans-wits

kli rotate --name witness-test --alias trans-wits --witness-add Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c
isSuccess

kli status --name witness-test --alias trans-wits

echo 'Test Complete'
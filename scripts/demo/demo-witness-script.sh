#!/bin/bash

# WITNESSES
# Start a witness with the following command in the background, test with curl
# kli witness start --name non-trans --http 5631 --tcp 5632
#
# To run the following scripts, open another console window and run:
# $ kli witness demo
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
echo $SCRIPT_DIR

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
kli incept --name witness-test --alias trans-wits --file ${SCRIPT_DIR}/trans-wits-sample.json
isSuccess

kli incept --name witness-test --alias inquisitor --file ${SCRIPT_DIR}/inquisitor-sample.json
isSuccess

kli status --name witness-test --alias trans-wits

# kli query --name witness-test --alias inquisitor --prefix Ezgv-1LmULy9ghlCP5Wt9mrQY-jJ-tQHcZZ9SteV7Hqo --witness BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw

kli rotate --name witness-test --alias trans-wits --witness-cut Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c
isSuccess

kli status --name witness-test --alias trans-wits

# TODO: Fix, this currently blocks because of a problem getting receipts from newly added witnesses.
kli rotate --name witness-test --alias trans-wits --witness-add Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c
isSuccess

kli status --name witness-test --alias trans-wits

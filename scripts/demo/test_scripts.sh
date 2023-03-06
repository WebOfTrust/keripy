#!/bin/bash

# Grap directory of this script
script_dir=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

source "${script_dir}"/demo-scripts.sh

# Launch witnesses in background
kli witness demo &
wits=$!
sleep 3

# Ensure we kill the witnesses on exit
trap 'kill -HUP $wits' EXIT

function isSuccess() {
    ret=$?
    if [ $ret -ne 0 ]; then
       echo "Error $ret"
       exit $ret
    fi
}

# Test scripts
"${script_dir}/basic/demo-script.sh"
isSuccess
"${script_dir}/basic/demo-witness-script.sh"
isSuccess
"${script_dir}/basic/demo-witness-async-script.sh"
isSuccess
"${script_dir}/basic/multisig.sh"
isSuccess
"${script_dir}/basic/multisig-delegate-delegator.sh"
isSuccess
"${script_dir}/basic/challenge.sh"
isSuccess

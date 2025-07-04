#!/bin/bash

# Grap directory of this script
script_dir=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

source "${script_dir}"/demo-scripts.sh
source "${script_dir}"/basic/script-utils.sh

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
printf "\n************************************\n"
printf "Running demo-script.sh"
printf "\n************************************\n"
"${script_dir}/basic/demo-script.sh"
isSuccess

printf "\n************************************\n"
printf "Running demo-witness-script.sh"
printf "\n************************************\n"
"${script_dir}/basic/demo-witness-script.sh"
isSuccess

printf "\n************************************\n"
printf "Running demo-witness-async-script.sh"
printf "\n************************************\n"
"${script_dir}/basic/demo-witness-async-script.sh"
isSuccess

printf "\n************************************\n"
printf "Running delegate.sh"
printf "\n************************************\n"
"${script_dir}/basic/delegate.sh"
isSuccess

printf "\n************************************\n"
printf "Running multisig-delegate-join.sh"
printf "\n************************************\n"
"${script_dir}/basic/multisig-delegate-join.sh"
isSuccess

printf "\n************************************\n"
printf "Running multisig.sh"
printf "\n************************************\n"
"${script_dir}/basic/multisig.sh"
isSuccess

printf "\n************************************\n"
printf "Running multisig-rotate-three-stooges.sh"
printf "\n************************************\n"
"${script_dir}/basic/multisig-rotate-three-stooges.sh"
isSuccess

printf "Running multisig-delegator.sh"
printf "\n************************************\n"
"${script_dir}/basic/multisig-delegator.sh"
isSuccess

printf "\n************************************\n"
printf "Running multisig-delegate-delegator.sh"
"${script_dir}/basic/multisig-delegate-delegator.sh"
isSuccess

printf "\n************************************\n"
printf "Running challenge.sh"
printf "\n************************************\n"
"${script_dir}/basic/challenge.sh"
isSuccess

printf "\n************************************\n"
printf "Running multisig-join.sh"
printf "\n************************************\n"
"${script_dir}/basic/multisig-join.sh"
isSuccess

printf "\n************************************\n"
printf "Running rename.sh"
printf "\n************************************\n"
"${script_dir}/basic/rename-alias.sh"
isSuccess


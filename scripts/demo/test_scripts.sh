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

# Test scripts
"${script_dir}/basic/demo-script.sh"
"${script_dir}/basic/demo-witness-script.sh"
"${script_dir}/basic/multisig.sh"

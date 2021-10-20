#!/bin/bash

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

kli status --name jane-smith > /dev/null 2>&1

if [ $? -eq 0 ]
then
  echo "Identifier prefix exists."
else
  echo "Identifier prefix does not exist, running incept"
  kli incept --name jane-smith --file ${SCRIPT_DIR}/jane-smith-incept.json
  kli vc registry incept --name jane-smith --registry-name jane-smith
fi

echo "Launching Jane Smith Agent"
kli agent start --name jane-smith --controller E4Zq5dxbnWKq5K-Bssn4g_qhBbSwNSI2MH4QYnkEUFDM --insecure --tcp 5821  --admin-http-port 5823  --path=../kiwi/dist-jane-smith

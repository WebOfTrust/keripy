#!/bin/bash

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

kli status --name john-doe > /dev/null 2>&1

if [ $? -eq 0 ]
then
  echo "Identifier prefix exists."
else
  echo "Identifier prefix does not exist, running incept"
  kli incept --name john-doe --file ${SCRIPT_DIR}/john-doe-incept.json
  kli vc registry incept --name john-doe --registry-name john-doe
fi

echo "Launching John Doe Agent"
kli agent start --name john-doe --controller E4Zq5dxbnWKq5K-Bssn4g_qhBbSwNSI2MH4QYnkEUFDM --insecure --tcp 5021  --admin-http-port 5023  --path=../kiwi/dist-john-doe

#!/bin/bash

kli status --name gleif > /dev/null 2>&1

if [ $? -eq 0 ]
then
  echo "Identifier prefix exists, launching GLEIF agent."
else
  echo "Identifier prefix does not exist, running incept"
  kli incept --name gleif --file scripts/pilot/gleif-incept.json
  kli vc registry incept --name gleif --registry-name gleif
fi

kli agent start --name gleif --controller E4Zq5dxbnWKq5K-Bssn4g_qhBbSwNSI2MH4QYnkEUFDM --insecure --tcp 5921 --admin-http-port 5923 --path=../kiwi/dist-gleif

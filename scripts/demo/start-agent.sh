#!/bin/bash

kli status --name gleif > /dev/null 2>&1

if [ $? -eq 0 ]
then
  echo "Identifier prefix exists, launching agent."
else
  echo "Identifier prefix does not exist, running incept"
  kli incept --name gleif --file tests/app/cli/gleif-sample.json
  kli vc registry incept --name gleif
fi

kli agent start --name gleif --pre E4Zq5dxbnWKq5K-Bssn4g_qhBbSwNSI2MH4QYnkEUFDM --insecure

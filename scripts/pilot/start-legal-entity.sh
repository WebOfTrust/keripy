#!/bin/bash

kli status --name legal-entity > /dev/null 2>&1

if [ $? -eq 0 ]
then
  echo "Identifier prefix exists, launching legal-entity agent."
else
  echo "Identifier prefix does not exist, running incept"
  kli incept --name legal-entity --file scripts/pilot/legal-entity-incept.json
  kli vc registry incept --name legal-entity --registry-name legal-entity
fi

kli agent start --name legal-entity --controller E4Zq5dxbnWKq5K-Bssn4g_qhBbSwNSI2MH4QYnkEUFDM --insecure --tcp 5221 \
  --admin-http-port 5223  --path=../kiwi/dist-legal-entity

#!/bin/bash

kli status --name qvi > /dev/null 2>&1

if [ $? -eq 0 ]
then
  echo "Identifier prefix exists."
else
  echo "Identifier prefix does not exist, running incept"
  kli delegate incept --name qvi --file scripts/pilot/qvi-incept.json
  kli vc registry incept --name qvi --registry-name qvi
fi

echo "Launching QVI agent"
kli agent start --name qvi --controller E4Zq5dxbnWKq5K-Bssn4g_qhBbSwNSI2MH4QYnkEUFDM --insecure --tcp 5621 \
  --admin-http-port 5623 --path=../kiwi/dist-qvi

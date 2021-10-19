#!/bin/bash

kli status --name data-user > /dev/null 2>&1

if [ $? -eq 0 ]
then
  echo "Identifier prefix exists, launching data-user agent."
else
  echo "Identifier prefix does not exist, running incept"
  kli incept --name data-user --file scripts/pilot/data-user-incept.json
fi

kli agent start --name data-user --controller E4Zq5dxbnWKq5K-Bssn4g_qhBbSwNSI2MH4QYnkEUFDM --insecure --tcp 5121 \
  --admin-http-port 5123  --path=../kiwi/dist-lei-data-user

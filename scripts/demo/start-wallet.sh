#!/bin/bash


kli status --name han > /dev/null 2>&1

if [ $? -eq 0 ]
then
  echo "Identifier prefix exists, launching wallet."
else
  echo "Identifier prefix does not exist, running incept"
  kli incept --name han --file tests/app/cli/holder-sample.json
  kli send --name han --target 5621
  kli query --name han --witness Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c --prefix Eu_se69BU6tYdF2o-YD411OzwbvImOfu1m023Bu8FM_I
  kli query --name han --witness Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c --prefix E5JuUB6iOaKV5-0EeADj0S3KCvvkUZDnuLw8VPK8Qang
  kli query --name han --witness Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c --prefix EEWuHgyO9iTgfz43mtY1IaRH-TrmV-YpcbpPoKKSpz8U
fi

kli wallet start --name han

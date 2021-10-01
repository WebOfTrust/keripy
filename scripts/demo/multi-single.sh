#!/bin/bash

kli incept --name multisig1 --file tests/app/cli/commands/multisig/multisig-1-sample.json
kli incept --name multisig2 --file tests/app/cli/commands/multisig/multisig-2-sample.json
kli incept --name multisig3 --file tests/app/cli/commands/multisig/multisig-3-sample.json

kli multisig demo --file tests/app/cli/commands/multisig/multisig-sample.json
kli vc registry demo

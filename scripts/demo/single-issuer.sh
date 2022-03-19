#!/bin/bash

kli init --name issuer --salt 0AMDEyMzQ1Njc4OWxtbm9wcQ --nopasscode --config-dir ./scripts --config-file demo-witness-oobis
kli incept --name issuer --alias issuer --file tests/app/cli/gleif-sample.json

kli vc registry incept --name issuer --alias issuer

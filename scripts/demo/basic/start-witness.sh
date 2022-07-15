#!/bin/bash

kli init --name witness --nopasscode
kli incept --name witness --alias=wil --file ${KERI_DEMO_SCRIPT_DIR}/data/wil-witness-sample.json
kli witness start --name witness --alias=wil

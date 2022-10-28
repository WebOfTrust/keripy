#!/bin/bash

kli init --name witness --nopasscode --config-dir ${KERI_SCRIPT_DIR} --config-file witness
kli incept --name witness --alias witness --config ${KERI_SCRIPT_DIR} --file ${KERI_DEMO_SCRIPT_DIR}/data/wil-witness-sample.json
kli witness start --name witness --alias witness

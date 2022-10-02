#!/bin/bash

kli init --name issuer --salt 0ACDEyMzQ1Njc4OWxtbm9aBc --nopasscode --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis
kli incept --name issuer --alias issuer --file ${KERI_DEMO_SCRIPT_DIR}/data/gleif-sample.json

kli init --name holder --salt 0ACDEyMzQ1Njc4OWxtbm9qWc --nopasscode --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis
kli incept --name holder --alias holder --file ${KERI_DEMO_SCRIPT_DIR}/data/gleif-sample.json

kli oobi resolve --name issuer --oobi-alias holder --oobi http://127.0.0.1:5642/oobi/ELjSFdrTdCebJlmvbFNX9-TLhR2PO0_60al1kQp5_e6k/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name holder --oobi-alias issuer --oobi http://127.0.0.1:5642/oobi/EKxICWTx5Ph4EKq5xie2znZf7amggUn4Sd-2-46MIQTg/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name issuer --oobi-alias issuer --oobi http://127.0.0.1:7723/oobi/ELqriXX1-lbV9zgXP4BXxqJlpZTgFchll3cyjaCyVKiz
kli oobi resolve --name holder --oobi-alias holder --oobi http://127.0.0.1:7723/oobi/ELqriXX1-lbV9zgXP4BXxqJlpZTgFchll3cyjaCyVKiz

kli vc registry incept --name issuer --alias issuer --registry-name vLEI

kli vc issue --name issuer --alias issuer --registry-name vLEI --schema ELqriXX1-lbV9zgXP4BXxqJlpZTgFchll3cyjaCyVKiz --recipient ELjSFdrTdCebJlmvbFNX9-TLhR2PO0_60al1kQp5_e6k --data @${KERI_DEMO_SCRIPT_DIR}/data/credential-data.json
sleep 2
kli vc list --name holder --alias holder --poll
SAID=`kli vc list --name holder --alias holder --said --schema ELqriXX1-lbV9zgXP4BXxqJlpZTgFchll3cyjaCyVKiz`

kli vc revoke --name issuer --alias issuer --registry-name vLEI --said ${SAID}
sleep 2
kli vc list --name holder --alias holder --poll

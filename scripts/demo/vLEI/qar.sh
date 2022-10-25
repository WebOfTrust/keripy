#!/bin/bash

kli init --name extgar1 --salt 0ACDEyMzQ1Njc4OWxtbm9aBc --nopasscode --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis
kli incept --name extgar1 --alias extgar1 --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-1-sample.json

kli init --name extgar2 --salt 0ACDEyMzQ1Njc4OWdoaWpsaw --nopasscode --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis
kli incept --name extgar2 --alias extgar2 --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-2-sample.json

kli oobi resolve --name extgar1 --oobi-alias extgar2 --oobi http://127.0.0.1:5642/oobi/Eyzi1Yme3BEbu2h8HUf7fqeXjBQ-yjE6YW7OFSH3WgyY/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name extgar2 --oobi-alias extgar1 --oobi http://127.0.0.1:5642/oobi/E2q4geQjWVAIScE08i_ey_2DgG32rEwz5UlwO_Gd7adA/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha

echo "ExtGAR1 OOBIs:"
kli oobi generate --name extgar1 --alias extgar1 --role witness
echo ""
echo "ExtGAR2 OOBIs"
kli oobi generate --name extgar2 --alias extgar2 --role witness

# Create GLEIF Internal Multisig Group
# kli multisig incept --name extgar1 --alias extgar1 --group "GLEIF External" --file scripts/demo/external-gar-nodel-incept.json
# kli multisig incept --name extgar2 --alias extgar2 --group "GLEIF External" --file scripts/demo/external-gar-nodel-incept.json

# also guard buffalo scatter useless bench into fortune cheese solid oblige neither

# Approve QVI Delegation
# kli multisig interact --name extgar1 --alias "GLEIF External" --data @scripts/demo/extgar-delegate-icp-anchor.json
# kli multisig interact --name extgar2 --alias "GLEIF External" --data @scripts/demo/extgar-delegate-icp-anchor.json

# Resolve UbiSecure OOBI
# kli oobi resolve --name extgar1 --oobi-alias "UbiSecure QVI" --oobi http://127.0.0.1:5642/oobi/EyruLi8ybgPKO-aULHrVAq_yw_QQGTDmmuvvmoPINe-U/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
# kli oobi resolve --name extgar2 --oobi-alias "UbiSecure QVI" --oobi http://127.0.0.1:5642/oobi/EyruLi8ybgPKO-aULHrVAq_yw_QQGTDmmuvvmoPINe-U/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha

# Create Revocation Registry
# kli vc registry incept --name extgar1 --alias "GLEIF External" --registry-name vLEI --nonce AHSNDV3ABI6U8OIgKaj3aky91ZpNL54I5_7-qwtC6q2s
# kli vc registry incept --name extgar2 --alias "GLEIF External" --registry-name vLEI --nonce AHSNDV3ABI6U8OIgKaj3aky91ZpNL54I5_7-qwtC6q2s

# Resolve Credential Schema
# kli oobi resolve --name extgar1 --oobi-alias vc --oobi http://127.0.0.1:7723/oobi/ELqriXX1-lbV9zgXP4BXxqJlpZTgFchll3cyjaCyVKiz
# kli oobi resolve --name extgar2 --oobi-alias vc --oobi http://127.0.0.1:7723/oobi/ELqriXX1-lbV9zgXP4BXxqJlpZTgFchll3cyjaCyVKiz

# Issue QVI Credential from GLEIF External
# kli vc issue --name extgar1 --alias "GLEIF External" --registry-name vLEI --schema ELqriXX1-lbV9zgXP4BXxqJlpZTgFchll3cyjaCyVKiz --recipient "UbiSecure QVI" --data @scripts/demo/qvi-data.json
# kli vc issue --name extgar2 --alias "GLEIF External" --credential @./credential.json

sleep 3
echo
echo "Creating GLEIF Internal"
kli init --name intgar1 --salt 0ACDEyMzQ1Njc4OWxtbm9AbC --nopasscode --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis
kli incept --name intgar1 --alias intgar1 --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-1-sample.json

kli init --name intgar2 --salt 0ACDEyMzQ1Njc4OWdoaWpEfG --nopasscode --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis
kli incept --name intgar2 --alias intgar2 --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-2-sample.json

kli oobi resolve --name intgar1 --oobi-alias intgar2 --oobi http://127.0.0.1:5642/oobi/ELS0QzVVwZiGAs_IzDaIjMmscsRfE34apLICJNgC55a8/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name intgar2 --oobi-alias intgar1 --oobi http://127.0.0.1:5642/oobi/EOVXzTuvdfVtDt6nXiOWFt97QM3jG1x-Mz_MfL8kyRQc/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha

echo "intgar1 OOBIs:"
kli oobi generate --name intgar1 --alias intgar1 --role witness
echo ""
echo "intgar2 OOBIs"
kli oobi generate --name intgar2 --alias intgar2 --role witness

# kli multisig incept --name intgar1 --alias intgar1 --group "GLEIF Internal" --file scripts/demo/internal-gar-nodel-incept.json
# kli multisig incept --name intgar2 --alias intgar2 --group "GLEIF Internal" --file scripts/demo/internal-gar-nodel-incept.json

# kli oobi generate --name intgar1 --alias "GLEIF Internal" --role witness
# kli oobi resolve --name intgar1 --oobi-alias "UbiSecure QVI" --oobi http://127.0.0.1:5642/oobi/EyruLi8ybgPKO-aULHrVAq_yw_QQGTDmmuvvmoPINe-U/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
# kli oobi resolve --name intgar2 --oobi-alias "UbiSecure QVI" --oobi http://127.0.0.1:5642/oobi/EyruLi8ybgPKO-aULHrVAq_yw_QQGTDmmuvvmoPINe-U/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
# kli challenge respond --name intgar1 --alias "GLEIF Internal" --recipient "UbiSecure QVI" --words ""
# kli challenge respond --name intgar2 --alias "GLEIF Internal" --recipient "UbiSecure QVI" --words ""

kli oobi resolve --name intgar1 --oobi-alias vc --oobi http://127.0.0.1:7723/oobi/ELqriXX1-lbV9zgXP4BXxqJlpZTgFchll3cyjaCyVKiz
kli oobi resolve --name intgar2 --oobi-alias vc --oobi http://127.0.0.1:7723/oobi/ELqriXX1-lbV9zgXP4BXxqJlpZTgFchll3cyjaCyVKiz
kli oobi resolve --name intgar1 --oobi-alias vc --oobi http://127.0.0.1:7723/oobi/EK0jwjJbtYLIynGtmXXLO5MGJ7BDuX2vr2_MhM9QjAxZ
kli oobi resolve --name intgar2 --oobi-alias vc --oobi http://127.0.0.1:7723/oobi/EK0jwjJbtYLIynGtmXXLO5MGJ7BDuX2vr2_MhM9QjAxZ

# kli vc list --name intgar1 --alias "GLEIF Internal" --poll
# kli vc list --name intgar2 --alias "GLEIF Internal" --poll
#!/bin/bash

kli init --name intgar1 --salt 0AMDEyMzQ1Njc4OWxtbm9AbC --nopasscode --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis
kli incept --name intgar1 --alias intgar1 --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-1-sample.json

kli init --name intgar2 --salt 0AMDEyMzQ1Njc4OWdoaWpEfG --nopasscode --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis
kli incept --name intgar2 --alias intgar2 --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-2-sample.json

kli oobi resolve --name intgar1 --oobi-alias "GLEIF Root" --oobi http://127.0.0.1:7723/.well-known/keri/oobi/gleif-root
kli oobi resolve --name intgar2 --oobi-alias "GLEIF Root" --oobi http://127.0.0.1:7723/.well-known/keri/oobi/gleif-root
kli oobi resolve --name intgar1 --oobi-alias intgar2 --oobi http://127.0.0.1:5642/oobi/ELS0QzVVwZiGAs_IzDaIjMmscsRfE34apLICJNgC55a8/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name intgar2 --oobi-alias intgar1 --oobi http://127.0.0.1:5642/oobi/EOVXzTuvdfVtDt6nXiOWFt97QM3jG1x-Mz_MfL8kyRQc/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha

echo "intgar1 OOBIs:"
kli oobi generate --name intgar1 --alias intgar1 --role witness
echo ""
echo "intgar2 OOBIs"
kli oobi generate --name intgar2 --alias intgar2 --role witness

# kli multisig incept --name intgar1 --alias intgar1 --group "External GAR" --file ${KERI_DEMO_SCRIPT_DIR}/data/internal-gar-incept.json
# kli multisig incept --name intgar2 --alias intgar2 --group "External GAR" --file ${KERI_DEMO_SCRIPT_DIR}/data/internal-gar-incept.json

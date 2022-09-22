#!/bin/bash

kli init --name extgar1 --salt 0ACDEyMzQ1Njc4OWxtbm9aBc --nopasscode --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis
kli incept --name extgar1 --alias extgar1 --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-1-sample.json

kli init --name extgar2 --salt 0ACDEyMzQ1Njc4OWdoaWpsaw --nopasscode --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis
kli incept --name extgar2 --alias extgar2 --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-2-sample.json

kli oobi resolve --name extgar1 --oobi-alias extgar2 --oobi http://127.0.0.1:5642/oobi/EIud2cHFGftkecizFIKrKb6WJwSpbt99_9p6Q8U5GsXV/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name extgar2 --oobi-alias extgar1 --oobi http://127.0.0.1:5642/oobi/ENbiqLBPHLbCz9c8F-KL8qGygi_T-bsYes1HYFxIe4HY/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha

echo "ExtGAR1 OOBIs:"
kli oobi generate --name extgar1 --alias extgar1 --role witness
echo ""
echo "ExtGAR2 OOBIs"
kli oobi generate --name extgar2 --alias extgar2 --role witness

# kli oobi resolve --name extgar1 --oobi-alias "GLEIF Root" --oobi http://127.0.0.1:5642/oobi/EHHL5ZodRcLYKx1R6XVufz_TnYp1UXsmfGYLhIYk-GjL/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
# kli oobi resolve --name extgar2 --oobi-alias "GLEIF Root" --oobi http://127.0.0.1:5642/oobi/EHHL5ZodRcLYKx1R6XVufz_TnYp1UXsmfGYLhIYk-GjL/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
# kli challenge respond --name extgar1 --alias extgar1 --recipient "GLEIF ROOT" --words "dynamic about obtain explain tragic gather outside genius crucial follow machine picnic"
# kli challenge respond --name extgar2 --alias extgar2 --recipient "GLEIF ROOT" --words "dynamic about obtain explain tragic gather outside genius crucial follow machine picnic"
# kli multisig incept --name extgar1 --alias extgar1 --group "External GAR" --file ${KERI_DEMO_SCRIPT_DIR}/data/external-gar-incept.json
# kli multisig incept --name extgar2 --alias extgar2 --group "External GAR" --file ${KERI_DEMO_SCRIPT_DIR}/data/external-gar-incept.json

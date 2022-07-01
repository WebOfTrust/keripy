#!/bin/bash

kli init --name extgar1 --salt 0AMDEyMzQ1Njc4OWxtbm9wcQ --nopasscode --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis
kli incept --name extgar1 --alias extgar1 --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-1-sample.json

kli init --name extgar2 --salt 0AMDEyMzQ1Njc4OWdoaWpsaw --nopasscode --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis
kli incept --name extgar2 --alias extgar2 --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-2-sample.json

kli oobi resolve --name extgar1 --alias extgar1 --oobi-alias "GLEIF Root" --oobi http://127.0.0.1:7723/.well-known/keri/oobi/gleif-root
kli oobi resolve --name extgar2 --alias extgar2 --oobi-alias "GLEIF Root" --oobi http://127.0.0.1:7723/.well-known/keri/oobi/gleif-root
kli oobi resolve --name extgar1 --alias extgar1 --oobi-alias extgar2 --oobi http://127.0.0.1:5642/oobi/Eyzi1Yme3BEbu2h8HUf7fqeXjBQ-yjE6YW7OFSH3WgyY/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo
kli oobi resolve --name extgar2 --alias extgar2 --oobi-alias extgar1 --oobi http://127.0.0.1:5642/oobi/E2q4geQjWVAIScE08i_ey_2DgG32rEwz5UlwO_Gd7adA/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo

echo "ExtGAR1 OOBIs:"
kli oobi generate --name extgar1 --alias extgar1 --role witness
echo ""
echo "ExtGAR2 OOBIs"
kli oobi generate --name extgar2 --alias extgar2 --role witness

# kli multisig incept --name extgar1 --alias extgar1 --group "External GAR" --file ${KERI_DEMO_SCRIPT_DIR}/data/external-gar-incept.json
# kli multisig incept --name extgar2 --alias extgar2 --group "External GAR" --file ${KERI_DEMO_SCRIPT_DIR}/data/external-gar-incept.json

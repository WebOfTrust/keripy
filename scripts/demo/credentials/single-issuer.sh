#!/bin/bash

kli init --name issuer --salt 0AMDEyMzQ1Njc4OWxtbm9wcQ --nopasscode --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis
kli incept --name issuer --alias issuer --file ${KERI_DEMO_SCRIPT_DIR}/data/gleif-sample.json

kli init --name holder --salt 0AMDEyMzQ1Njc4OWxtbm9qWc --nopasscode --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis
kli incept --name holder --alias holder --file ${KERI_DEMO_SCRIPT_DIR}/data/gleif-sample.json

kli oobi resolve --name issuer --oobi-alias holder --oobi http://127.0.0.1:5642/oobi/EeWTHzoGK_dNn71CmJh-4iILvqHGXcqEoKGF4VUc6ZXI/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo
kli oobi resolve --name holder --oobi-alias issuer --oobi http://127.0.0.1:5642/oobi/Ew-o5dU5WjDrxDBK4b4HrF82_rYb6MX6xsegjq4n0Y7M/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo
kli oobi resolve --name issuer --oobi-alias issuer --oobi http://127.0.0.1:7723/oobi/EWCeT9zTxaZkaC_3-amV2JtG6oUxNA36sCC0P5MI7Buw
kli oobi resolve --name holder --oobi-alias holder --oobi http://127.0.0.1:7723/oobi/EWCeT9zTxaZkaC_3-amV2JtG6oUxNA36sCC0P5MI7Buw

kli vc registry incept --name issuer --alias issuer --registry-name vLEI

kli vc issue --name issuer --alias issuer --registry-name vLEI --schema EWCeT9zTxaZkaC_3-amV2JtG6oUxNA36sCC0P5MI7Buw --recipient EeWTHzoGK_dNn71CmJh-4iILvqHGXcqEoKGF4VUc6ZXI --data @${KERI_DEMO_SCRIPT_DIR}/data/credential-data.json

sleep 2
kli vc list --name holder --alias holder --poll
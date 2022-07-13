#!/bin/bash

# To run this script you need to run the following command in a separate terminals:
#   > kli witness demo
# and from the vLEI repo run:
#   > vLEI-server -s ./schema/acdc -c ./samples/acdc/ -o ./samples/oobis/
#

# EWN6BzdXo6IByOsuh_fYanK300iEOrQKf6msmbIeC4Y0
kli init --name external --salt 0AMDEyMzQ1Njc4OWxtbm9GhI --nopasscode --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis
kli incept --name external --alias external --file ${KERI_DEMO_SCRIPT_DIR}/data/gleif-sample.json

# EY4ldIBDZP4Tpnm3RX320BO0yz8Uz2nUSN-C409GnCJM
kli init --name qvi --salt 0AMDEyMzQ1Njc4OWxtbm9wcQ --nopasscode --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis
kli incept --name qvi --alias qvi --file ${KERI_DEMO_SCRIPT_DIR}/data/gleif-sample.json

# EKXPX7hWw8KK5Y_Mxs2TOuCrGdN45vPIZ78NofRlVBws
kli init --name legal-entity --salt 0AMDEyMzQ1Njc4OWxtbm9AbC --nopasscode --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis
kli incept --name legal-entity --alias legal-entity --file ${KERI_DEMO_SCRIPT_DIR}/data/gleif-sample.json

# Esf8b_AngI1d0KbOFjPGIfpVani0HTagWeaYTLs14PlE
# Passcode: DoB2-6Fj4x-9Lbo-AFWJr-a17O
kli init --name person --salt 0AMDEyMzQ1Njc4OWxtbm9dEf --passcode DoB26Fj4x9LboAFWJra17O --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis
kli incept --name person --alias person --passcode DoB26Fj4x9LboAFWJra17O --file ${KERI_DEMO_SCRIPT_DIR}/data/gleif-sample.json

echo 'resolving external'
kli oobi resolve --name qvi --alias qvi --oobi-alias external --oobi http://127.0.0.1:5642/oobi/EWN6BzdXo6IByOsuh_fYanK300iEOrQKf6msmbIeC4Y0/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo
kli oobi resolve --name legal-entity --alias legal-entity --oobi-alias external --oobi http://127.0.0.1:5642/oobi/EWN6BzdXo6IByOsuh_fYanK300iEOrQKf6msmbIeC4Y0/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo
kli oobi resolve --name person --alias person --passcode DoB26Fj4x9LboAFWJra17O --oobi-alias external --oobi http://127.0.0.1:5642/oobi/EWN6BzdXo6IByOsuh_fYanK300iEOrQKf6msmbIeC4Y0/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo
echo 'resolving qvi'
kli oobi resolve --name external --alias external --oobi-alias qvi --oobi http://127.0.0.1:5642/oobi/EY4ldIBDZP4Tpnm3RX320BO0yz8Uz2nUSN-C409GnCJM/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo
kli oobi resolve --name legal-entity --alias legal-entity --oobi-alias qvi --oobi http://127.0.0.1:5642/oobi/EY4ldIBDZP4Tpnm3RX320BO0yz8Uz2nUSN-C409GnCJM/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo
kli oobi resolve --name person --alias person --passcode DoB26Fj4x9LboAFWJra17O --oobi-alias qvi --oobi http://127.0.0.1:5642/oobi/EY4ldIBDZP4Tpnm3RX320BO0yz8Uz2nUSN-C409GnCJM/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo
echo 'resolving legal-entity'
kli oobi resolve --name external --alias external --oobi-alias legal-entity --oobi http://127.0.0.1:5642/oobi/EKXPX7hWw8KK5Y_Mxs2TOuCrGdN45vPIZ78NofRlVBws/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo
kli oobi resolve --name qvi --alias qvi --oobi-alias legal-entity --oobi http://127.0.0.1:5642/oobi/EKXPX7hWw8KK5Y_Mxs2TOuCrGdN45vPIZ78NofRlVBws/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo
kli oobi resolve --name person --alias person --passcode DoB26Fj4x9LboAFWJra17O --oobi-alias legal-entity --oobi http://127.0.0.1:5642/oobi/EKXPX7hWw8KK5Y_Mxs2TOuCrGdN45vPIZ78NofRlVBws/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo
echo 'resolving person'
kli oobi resolve --name external --alias external --oobi-alias person --oobi http://127.0.0.1:5642/oobi/Esf8b_AngI1d0KbOFjPGIfpVani0HTagWeaYTLs14PlE/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo
kli oobi resolve --name qvi --alias qvi --oobi-alias person --oobi http://127.0.0.1:5642/oobi/Esf8b_AngI1d0KbOFjPGIfpVani0HTagWeaYTLs14PlE/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo
kli oobi resolve --name legal-entity --alias legal-entity --oobi-alias person --oobi http://127.0.0.1:5642/oobi/Esf8b_AngI1d0KbOFjPGIfpVani0HTagWeaYTLs14PlE/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo

echo 'resolving QVI vLEI Schema EWCeT9zTxaZkaC_3-amV2JtG6oUxNA36sCC0P5MI7Buw'
kli oobi resolve --name external --oobi-alias credential --oobi http://127.0.0.1:7723/oobi/EWCeT9zTxaZkaC_3-amV2JtG6oUxNA36sCC0P5MI7Buw
kli oobi resolve --name qvi --oobi-alias credential --oobi http://127.0.0.1:7723/oobi/EWCeT9zTxaZkaC_3-amV2JtG6oUxNA36sCC0P5MI7Buw
kli oobi resolve --name legal-entity --oobi-alias credential --oobi http://127.0.0.1:7723/oobi/EWCeT9zTxaZkaC_3-amV2JtG6oUxNA36sCC0P5MI7Buw
kli oobi resolve --name person --passcode DoB26Fj4x9LboAFWJra17O --oobi-alias credential --oobi http://127.0.0.1:7723/oobi/EWCeT9zTxaZkaC_3-amV2JtG6oUxNA36sCC0P5MI7Buw
echo 'resolving Legal Entity vLEI Schema EWJkQCFvKuyxZi582yJPb0wcwuW3VXmFNuvbQuBpgmIs'
kli oobi resolve --name external --oobi-alias credential --oobi http://127.0.0.1:7723/oobi/EWJkQCFvKuyxZi582yJPb0wcwuW3VXmFNuvbQuBpgmIs
kli oobi resolve --name qvi --oobi-alias credential --oobi http://127.0.0.1:7723/oobi/EWJkQCFvKuyxZi582yJPb0wcwuW3VXmFNuvbQuBpgmIs
kli oobi resolve --name legal-entity --oobi-alias credential --oobi http://127.0.0.1:7723/oobi/EWJkQCFvKuyxZi582yJPb0wcwuW3VXmFNuvbQuBpgmIs
kli oobi resolve --name person --passcode DoB26Fj4x9LboAFWJra17O --oobi-alias credential --oobi http://127.0.0.1:7723/oobi/EWJkQCFvKuyxZi582yJPb0wcwuW3VXmFNuvbQuBpgmIs
echo 'resolving OOR vLEI Schema E2RzmSCFmG2a5U2OqZF-yUobeSYkW-a3FsN82eZXMxY0'
kli oobi resolve --name external --oobi-alias credential --oobi http://127.0.0.1:7723/oobi/E2RzmSCFmG2a5U2OqZF-yUobeSYkW-a3FsN82eZXMxY0
kli oobi resolve --name qvi --oobi-alias credential --oobi http://127.0.0.1:7723/oobi/E2RzmSCFmG2a5U2OqZF-yUobeSYkW-a3FsN82eZXMxY0
kli oobi resolve --name legal-entity --oobi-alias credential --oobi http://127.0.0.1:7723/oobi/E2RzmSCFmG2a5U2OqZF-yUobeSYkW-a3FsN82eZXMxY0
kli oobi resolve --name person --passcode DoB26Fj4x9LboAFWJra17O --oobi-alias credential --oobi http://127.0.0.1:7723/oobi/E2RzmSCFmG2a5U2OqZF-yUobeSYkW-a3FsN82eZXMxY0
echo 'resolving iXBRL Data Attestation Schema Ehwr6tZh6XakKBKWQW07otQ9uCwg0g7CF-dPz9qb_fwQ'
kli oobi resolve --name external --oobi-alias credential --oobi http://127.0.0.1:7723/oobi/Ehwr6tZh6XakKBKWQW07otQ9uCwg0g7CF-dPz9qb_fwQ
kli oobi resolve --name qvi --oobi-alias credential --oobi http://127.0.0.1:7723/oobi/Ehwr6tZh6XakKBKWQW07otQ9uCwg0g7CF-dPz9qb_fwQ
kli oobi resolve --name legal-entity --oobi-alias credential --oobi http://127.0.0.1:7723/oobi/Ehwr6tZh6XakKBKWQW07otQ9uCwg0g7CF-dPz9qb_fwQ
kli oobi resolve --name person --passcode DoB26Fj4x9LboAFWJra17O --oobi-alias credential --oobi http://127.0.0.1:7723/oobi/Ehwr6tZh6XakKBKWQW07otQ9uCwg0g7CF-dPz9qb_fwQ

kli vc registry incept --name external --alias external --registry-name vLEI-external
kli vc registry incept --name qvi --alias qvi --registry-name vLEI-qvi
kli vc registry incept --name person  --passcode DoB26Fj4x9LboAFWJra17O --alias person --registry-name vLEI-person

# Issue QVI credential vLEI from GLEIF External to QVI
kli vc issue --name external --alias external --registry-name vLEI-external --schema EWCeT9zTxaZkaC_3-amV2JtG6oUxNA36sCC0P5MI7Buw --recipient EY4ldIBDZP4Tpnm3RX320BO0yz8Uz2nUSN-C409GnCJM --data @${KERI_DEMO_SCRIPT_DIR}/data/qvi-data.json
kli vc list --name qvi --alias qvi --poll

# Issue LE credential from QVI to Legal Entity - have to create the edges first
QVI_SAID=`kli vc list --name qvi --alias qvi --said`
echo \"$QVI_SAID\" | jq -f ${KERI_DEMO_SCRIPT_DIR}/data/legal-entity-edges-filter.jq  > /tmp/legal-entity-edges.json
kli saidify --file /tmp/legal-entity-edges.json
kli vc issue --name qvi --alias qvi --registry-name vLEI-qvi --schema EWJkQCFvKuyxZi582yJPb0wcwuW3VXmFNuvbQuBpgmIs --recipient EKXPX7hWw8KK5Y_Mxs2TOuCrGdN45vPIZ78NofRlVBws --data @${KERI_DEMO_SCRIPT_DIR}/data/legal-entity-data.json --edges @/tmp/legal-entity-edges.json --rules @${KERI_DEMO_SCRIPT_DIR}/data/rules.json
kli vc list --name legal-entity --alias legal-entity --poll

# Issue OOR credential from QVI to Person
LE_SAID=`kli vc list --name legal-entity --alias legal-entity --said`
echo "[\"$QVI_SAID\", \"$LE_SAID\"]" | jq -f ${KERI_DEMO_SCRIPT_DIR}/data/oor-edges-filter.jq > /tmp/oor-edges.json
kli saidify --file /tmp/oor-edges.json
kli vc issue --name qvi --alias qvi --registry-name vLEI-qvi --schema E2RzmSCFmG2a5U2OqZF-yUobeSYkW-a3FsN82eZXMxY0 --recipient Esf8b_AngI1d0KbOFjPGIfpVani0HTagWeaYTLs14PlE --data @${KERI_DEMO_SCRIPT_DIR}/data/oor-data.json --edges @/tmp/oor-edges.json --rules @${KERI_DEMO_SCRIPT_DIR}/data/rules.json
kli vc list --name person --alias person --passcode DoB26Fj4x9LboAFWJra17O --poll

# Issue iXBRL data attestation from Person
OOR_SAID=`kli vc list --name person --alias person --passcode DoB26Fj4x9LboAFWJra17O --said`
echo \"$OOR_SAID\" | jq -f ${KERI_DEMO_SCRIPT_DIR}/data/xbrl-edges-filter.jq > /tmp/xbrl-edges.json
kli saidify --file /tmp/xbrl-edges.json
kli vc issue --name person --alias person --passcode DoB26Fj4x9LboAFWJra17O --registry-name vLEI-person --schema Ehwr6tZh6XakKBKWQW07otQ9uCwg0g7CF-dPz9qb_fwQ --data @${KERI_DEMO_SCRIPT_DIR}/data/xbrl-data.json --edges @/tmp/xbrl-edges.json
kli vc list --name person --alias person --passcode DoB26Fj4x9LboAFWJra17O --issued
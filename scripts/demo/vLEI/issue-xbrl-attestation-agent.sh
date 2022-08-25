#!/bin/bash

# To run this script you need to run the following 2 commands in separate terminals:
#   > kli agent demo --config-file demo-witness-oobis-schema
#   > kli witness demo
# and from the vLEI repo run:
#   > vLEI-server -s ./schema/acdc -c ./samples/acdc/ -o ./samples/oobis/
#
echo "KERI_SCRIPT_DIR=" +${KERI_SCRIPT_DIR}
echo "KERI_DEMO_SCRIPT_DIR=" +${KERI_DEMO_SCRIPT_DIR}

echo "create/open external wallet; issue icp event"
# EWN6BzdXo6IByOsuh_fYanK300iEOrQKf6msmbIeC4Y0 - external
curl -s -X POST "http://localhost:5623/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"external\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\",\"salt\":\"0AMDEyMzQ1Njc4OWxtbm9GhI\"}" | jq
sleep 1
curl -s -X PUT "http://localhost:5623/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"external\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\"}" | jq
sleep 5
curl -s -X POST "http://localhost:5623/ids/external" -H "accept: */*" -H "Content-Type: application/json" -d "{\"transferable\":true,\"wits\":[\"BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\", \"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw\",\"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c\"],\"toad\":3, \"icount\":1,\"ncount\":1,\"isith\":1,\"nsith\":1}" | jq

echo "create/open qvi wallet; issue icp event"
## EY4ldIBDZP4Tpnm3RX320BO0yz8Uz2nUSN-C409GnCJM - qvi
curl -s -X POST "http://localhost:5626/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"qvi\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\",\"salt\":\"0AMDEyMzQ1Njc4OWxtbm9wcQ\"}" | jq
sleep 1
curl -s -X PUT "http://localhost:5626/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"qvi\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\"}" | jq
sleep 5
curl -s -X POST "http://localhost:5626/ids/qvi" -H "accept: */*" -H "Content-Type: application/json" -d "{\"transferable\":true,\"wits\":[\"BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\", \"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw\",\"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c\"],\"toad\":3, \"icount\":1,\"ncount\":1,\"isith\":1,\"nsith\":1}" | jq

echo "create/open LE wallet; issue icp event"
## EKXPX7hWw8KK5Y_Mxs2TOuCrGdN45vPIZ78NofRlVBws
curl -s -X POST "http://localhost:5628/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"legal-entity\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\",\"salt\":\"0AMDEyMzQ1Njc4OWxtbm9AbC\"}" | jq
sleep 1
curl -s -X PUT "http://localhost:5628/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"legal-entity\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\"}" | jq
sleep 5
curl -s -X POST "http://localhost:5628/ids/legal-entity" -H "accept: */*" -H "Content-Type: application/json" -d "{\"transferable\":true,\"wits\":[\"BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\", \"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw\",\"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c\"],\"toad\":3, \"icount\":1,\"ncount\":1,\"isith\":1,\"nsith\":1}" | jq

echo "create/open person wallet; issue icp event"
## Esf8b_AngI1d0KbOFjPGIfpVani0HTagWeaYTLs14PlE
## Passcode: DoB2-6Fj4x-9Lbo-AFWJr-a17O
curl -s -X POST "http://localhost:5630/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"person\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\",\"salt\":\"0AMDEyMzQ1Njc4OWxtbm9dEf\"}" | jq
sleep 1
curl -s -X PUT "http://localhost:5630/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"person\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\"}" | jq
sleep 5
curl -s -X POST "http://localhost:5630/ids/person" -H "accept: */*" -H "Content-Type: application/json" -d "{\"transferable\":true,\"wits\":[\"BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\", \"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw\",\"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c\"],\"toad\":3, \"icount\":1,\"ncount\":1,\"isith\":1,\"nsith\":1}" | jq

echo 'resolving external'
sleep 3
curl -s -X POST "http://localhost:5626/oobi" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"external\", \"url\":\"http://127.0.0.1:5642/oobi/EWN6BzdXo6IByOsuh_fYanK300iEOrQKf6msmbIeC4Y0/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\"}" | jq
curl -s -X POST "http://localhost:5628/oobi" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"external\", \"url\":\"http://127.0.0.1:5642/oobi/EWN6BzdXo6IByOsuh_fYanK300iEOrQKf6msmbIeC4Y0/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\"}" | jq
curl -s -X POST "http://localhost:5630/oobi" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"external\", \"url\":\"http://127.0.0.1:5642/oobi/EWN6BzdXo6IByOsuh_fYanK300iEOrQKf6msmbIeC4Y0/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\"}" | jq

echo 'resolving qvi'
curl -s -X POST "http://localhost:5623/oobi" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"qvi\", \"url\":\"http://127.0.0.1:5642/oobi/EY4ldIBDZP4Tpnm3RX320BO0yz8Uz2nUSN-C409GnCJM/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\"}" | jq
curl -s -X POST "http://localhost:5628/oobi" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"qvi\", \"url\":\"http://127.0.0.1:5642/oobi/EY4ldIBDZP4Tpnm3RX320BO0yz8Uz2nUSN-C409GnCJM/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\"}" | jq
curl -s -X POST "http://localhost:5630/oobi" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"qvi\", \"url\":\"http://127.0.0.1:5642/oobi/EY4ldIBDZP4Tpnm3RX320BO0yz8Uz2nUSN-C409GnCJM/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\"}" | jq

echo 'resolving legal-entity'
curl -s -X POST "http://localhost:5623/oobi" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"legal-entity\", \"url\":\"http://127.0.0.1:5642/oobi/EKXPX7hWw8KK5Y_Mxs2TOuCrGdN45vPIZ78NofRlVBws/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\"}" | jq
curl -s -X POST "http://localhost:5626/oobi" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"legal-entity\", \"url\":\"http://127.0.0.1:5642/oobi/EKXPX7hWw8KK5Y_Mxs2TOuCrGdN45vPIZ78NofRlVBws/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\"}" | jq
curl -s -X POST "http://localhost:5630/oobi" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"legal-entity\", \"url\":\"http://127.0.0.1:5642/oobi/EKXPX7hWw8KK5Y_Mxs2TOuCrGdN45vPIZ78NofRlVBws/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\"}" | jq

echo 'resolving person'
curl -s -X POST "http://localhost:5623/oobi" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"person\", \"url\":\"http://127.0.0.1:5642/oobi/Esf8b_AngI1d0KbOFjPGIfpVani0HTagWeaYTLs14PlE/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\"}" | jq
curl -s -X POST "http://localhost:5626/oobi" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"person\", \"url\":\"http://127.0.0.1:5642/oobi/Esf8b_AngI1d0KbOFjPGIfpVani0HTagWeaYTLs14PlE/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\"}" | jq
curl -s -X POST "http://localhost:5628/oobi" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"person\", \"url\":\"http://127.0.0.1:5642/oobi/Esf8b_AngI1d0KbOFjPGIfpVani0HTagWeaYTLs14PlE/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\"}" | jq

echo 'create registries'
sleep 3
curl -s -X POST "http://localhost:5623/registries" -H "accept: */*" -H "Content-Type: application/json" -d "{\"alias\":\"external\",\"baks\":[],\"estOnly\":false,\"name\":\"vLEI-external\",\"noBackers\":true,\"toad\":0}" | jq
curl -s -X POST "http://localhost:5626/registries" -H "accept: */*" -H "Content-Type: application/json" -d "{\"alias\":\"qvi\",\"baks\":[],\"estOnly\":false,\"name\":\"vLEI-qvi\",\"noBackers\":true,\"toad\":0}" | jq
curl -s -X POST "http://localhost:5628/registries" -H "accept: */*" -H "Content-Type: application/json" -d "{\"alias\":\"legal-entity\",\"baks\":[],\"estOnly\":false,\"name\":\"vLEI-legal-entity\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\",\"noBackers\":true,\"toad\":0}" | jq
curl -s -X POST "http://localhost:5630/registries" -H "accept: */*" -H "Content-Type: application/json" -d "{\"alias\":\"person\",\"baks\":[],\"estOnly\":false,\"name\":\"vLEI-person\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\",\"noBackers\":true,\"toad\":0}" | jq
sleep 5

# Issue QVI credential vLEI from GLEIF External to QVI
echo 'external issues qvi credential'
curl -s -X POST "http://localhost:5623/credentials/external" -H "accept: application/json" -H "Content-Type: application/json" -d "{\"credentialData\":{\"LEI\":\"6383001AJTYIGC8Y1X37\"},\"recipient\":\"EY4ldIBDZP4Tpnm3RX320BO0yz8Uz2nUSN-C409GnCJM\",\"registry\":\"vLEI-external\",\"schema\":\"EWCeT9zTxaZkaC_3-amV2JtG6oUxNA36sCC0P5MI7Buw\",\"source\":{}}" | jq
sleep 8
echo "qvi retrieves Credentials..."
curl -s -X GET "http://localhost:5626/credentials/qvi?type=received" -H "accept: application/json" | jq
sleep 3

# Issue LE credential from QVI to Legal Entity - have to create the edges first
echo 'Issue LE credential from QVI to Legal Entity - have to create the edges first'
QVI_SAID=$(curl -s -X GET "http://localhost:5626/credentials/qvi?type=received" -H "accept: application/json" -H "Content-Type: application/json" | jq '.[0] | .sad.d')
echo $QVI_SAID | jq -f ${KERI_DEMO_SCRIPT_DIR}/data/legal-entity-edges-filter.jq  > /tmp/legal-entity-edges.json
LE_EDGES=`cat /tmp/legal-entity-edges.json`
RULES=`cat ${KERI_DEMO_SCRIPT_DIR}/data/rules.json`
curl -s -X POST "http://localhost:5626/credentials/qvi" -H "accept: application/json" -H "Content-Type: application/json" -d "{\"credentialData\":{\"LEI\":\"5493001KJTIIGC8Y1R17\"},\"recipient\":\"EKXPX7hWw8KK5Y_Mxs2TOuCrGdN45vPIZ78NofRlVBws\",\"registry\":\"vLEI-qvi\",\"schema\":\"EWJkQCFvKuyxZi582yJPb0wcwuW3VXmFNuvbQuBpgmIs\",\"source\":$LE_EDGES,\"rules\":$RULES}" | jq

sleep 8
echo "LE retrieves Credentials..."
curl -s -X GET "http://localhost:5628/credentials/legal-entity?type=received" -H "accept: application/json" | jq
sleep 3

# Issue OOR Authorization credential from LE to QVI
echo 'LE issues OOR authorization credential to person'
LE_SAID=$(curl -s -X GET "http://localhost:5628/credentials/legal-entity?type=received" -H "accept: application/json" -H "Content-Type: application/json" | jq '.[0] | .sad.d')
echo $LE_SAID | jq -f ${KERI_DEMO_SCRIPT_DIR}/data/oor-auth-edges-filter.jq > /tmp/oor-auth-edges.json
OOR_AUTH_EDGES=`cat /tmp/oor-auth-edges.json`

curl -s -X POST "http://localhost:5628/credentials/legal-entity" -H "accept: application/json" -H "Content-Type: application/json" -d "{\"credentialData\":{\"AID\": \"Esf8b_AngI1d0KbOFjPGIfpVani0HTagWeaYTLs14PlE\", \"LEI\":\"6383001AJTYIGC8Y1X37\", \"personLegalName\": \"John Smith\", \"officialRole\": \"Chief Executive Officer\"},\"recipient\":\"EY4ldIBDZP4Tpnm3RX320BO0yz8Uz2nUSN-C409GnCJM\",\"registry\":\"vLEI-legal-entity\",\"schema\":\"EDpuiVPt4_sa1pShx6vOCnseru1edVPeNvRaQm6HrmMI\",\"source\":$OOR_AUTH_EDGES,\"rules\":$RULES}" | jq
sleep 8
echo "QVI retrieves Credentials..."
curl -s -X GET "http://localhost:5626/credentials/qvi?type=received" -H "accept: application/json" | jq
sleep 3

# Issue OOR credential from QVI to Person
echo 'qvi issues OOR credential to person'
AUTH_SAID=$(curl -s -X GET "http://localhost:5626/credentials/qvi?type=received&schema=EDpuiVPt4_sa1pShx6vOCnseru1edVPeNvRaQm6HrmMI" -H "accept: application/json" -H "Content-Type: application/json" | jq '.[0] | .sad.d')
echo "[$QVI_SAID, $AUTH_SAID]" | jq -f ${KERI_DEMO_SCRIPT_DIR}/data/oor-edges-filter.jq > /tmp/oor-edges.json
OOR_EDGES=`cat /tmp/oor-edges.json`

curl -s -X POST "http://localhost:5626/credentials/qvi" -H "accept: application/json" -H "Content-Type: application/json" -d "{\"credentialData\":{\"LEI\":\"6383001AJTYIGC8Y1X37\", \"personLegalName\": \"John Smith\", \"officialRole\": \"Chief Executive Officer\"},\"recipient\":\"Esf8b_AngI1d0KbOFjPGIfpVani0HTagWeaYTLs14PlE\",\"registry\":\"vLEI-qvi\",\"schema\":\"EzWz2j8AzVxFr3g1vy6NTERpy5GNZIOyjhkoniMMGUY4\",\"source\":$OOR_EDGES,\"rules\":$RULES}" | jq
sleep 8
echo "Person retrieves Credentials..."
curl -s -X GET "http://localhost:5630/credentials/person?type=received" -H "accept: application/json" | jq
sleep 3

echo "iXBRL data attestation from person"
OOR_SAID=$(curl -s -X GET "http://localhost:5630/credentials/person?type=received" -H "accept: application/json" -H "Content-Type: application/json" | jq '.[0] | .sad.d')
echo $OOR_SAID
echo $OOR_SAID | jq -f ${KERI_DEMO_SCRIPT_DIR}/data/xbrl-edges-filter.jq > /tmp/xbrl-edges.json
XBRL_EDGES=`cat /tmp/xbrl-edges.json`
NOW=`date -u +"%Y-%m-%dT%H:%M:%S+00:00"`
echo \"$NOW\" | jq -f ${KERI_DEMO_SCRIPT_DIR}/data/xbrl-data.jq > /tmp/xbrl-data.json
XBRL_DATA=`cat /tmp/xbrl-data.json`
curl -X POST "http://localhost:5630/credentials/person" -H "accept: application/json" -H "Content-Type: application/json" -d "{\"credentialData\":$XBRL_DATA,\"registry\":\"vLEI-person\",\"schema\":\"EH9jKc3FQ0O2hvp7YPG5sFBgM7wUFVy4OlssP038w6j0\",\"source\":$XBRL_EDGES}" | jq
sleep 4
echo "Person retrieves attestation..."
curl -s -X GET "http://localhost:5630/credentials/person?type=issued" -H "accept: application/json" -d "{\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\"}" | jq

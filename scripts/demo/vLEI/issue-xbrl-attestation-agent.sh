#!/bin/bash

# To run this script you need to run the following 2 commands in separate terminals:
#   > kli agent vlei
#   > kli witness demo
# and from the vLEI repo run:
#   > vLEI-server -s ./schema/acdc -c ./samples/acdc/ -o ./samples/oobis/
#
echo "KERI_SCRIPT_DIR=" +${KERI_SCRIPT_DIR}
echo "KERI_DEMO_SCRIPT_DIR=" +${KERI_DEMO_SCRIPT_DIR}

echo "create/open external wallet; issue icp event"
# EHOuGiHMxJShXHgSb6k_9pqxmRb8H-LT0R2hQouHp8pW - external
curl -s -X POST "http://localhost:5623/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"external\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\",\"salt\":\"0ACDEyMzQ1Njc4OWxtbm9GhI\"}" | jq
sleep 1
curl -s -X PUT "http://localhost:5623/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"external\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\"}" | jq
sleep 5
curl -s -X POST "http://localhost:5623/ids/external" -H "accept: */*" -H "Content-Type: application/json" -d "{\"transferable\":true,\"wits\":[\"BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha\", \"BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM\",\"BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX\"],\"toad\":3, \"icount\":1,\"ncount\":1,\"isith\":1,\"nsith\":1}" | jq

echo "create/open qvi wallet; issue icp event"
## EHMnCf8_nIemuPx-cUHaDQq8zSnQIFAurdEpwHpNbnvX - qvi
curl -s -X POST "http://localhost:5626/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"qvi\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\",\"salt\":\"0ACDEyMzQ1Njc4OWxtbm9aBc\"}" | jq
sleep 1
curl -s -X PUT "http://localhost:5626/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"qvi\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\"}" | jq
sleep 5
curl -s -X POST "http://localhost:5626/ids/qvi" -H "accept: */*" -H "Content-Type: application/json" -d "{\"transferable\":true,\"wits\":[\"BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha\", \"BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM\",\"BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX\"],\"toad\":3, \"icount\":1,\"ncount\":1,\"isith\":1,\"nsith\":1}" | jq

echo "create/open LE wallet; issue icp event"
## EIitNxxiNFXC1HDcPygyfyv3KUlBfS_Zf-ZYOvwjpTuz
curl -s -X POST "http://localhost:5628/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"legal-entity\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\",\"salt\":\"0ACDEyMzQ1Njc4OWxtbm9AbC\"}" | jq
sleep 1
curl -s -X PUT "http://localhost:5628/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"legal-entity\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\"}" | jq
sleep 5
curl -s -X POST "http://localhost:5628/ids/legal-entity" -H "accept: */*" -H "Content-Type: application/json" -d "{\"transferable\":true,\"wits\":[\"BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha\", \"BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM\",\"BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX\"],\"toad\":3, \"icount\":1,\"ncount\":1,\"isith\":1,\"nsith\":1}" | jq

echo "create/open person wallet; issue icp event"
## EKE7b7owCvObR6dBTrU7w38_oATL9Tcrp_-xjPn05zYe
## Passcode: DoB2-6Fj4x-9Lbo-AFWJr-a17O
curl -s -X POST "http://localhost:5630/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"person\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\",\"salt\":\"0ACDEyMzQ1Njc4OWxtbm9dEf\"}" | jq
sleep 1
curl -s -X PUT "http://localhost:5630/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"person\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\"}" | jq
sleep 5
curl -s -X POST "http://localhost:5630/ids/person" -H "accept: */*" -H "Content-Type: application/json" -d "{\"transferable\":true,\"wits\":[\"BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha\", \"BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM\",\"BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX\"],\"toad\":3, \"icount\":1,\"ncount\":1,\"isith\":1,\"nsith\":1}" | jq

echo 'resolving external'
sleep 3
curl -s -X POST "http://localhost:5626/oobi" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"external\", \"url\":\"http://127.0.0.1:5642/oobi/EHOuGiHMxJShXHgSb6k_9pqxmRb8H-LT0R2hQouHp8pW/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha\"}" | jq
curl -s -X POST "http://localhost:5628/oobi" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"external\", \"url\":\"http://127.0.0.1:5642/oobi/EHOuGiHMxJShXHgSb6k_9pqxmRb8H-LT0R2hQouHp8pW/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha\"}" | jq
curl -s -X POST "http://localhost:5630/oobi" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"external\", \"url\":\"http://127.0.0.1:5642/oobi/EHOuGiHMxJShXHgSb6k_9pqxmRb8H-LT0R2hQouHp8pW/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha\"}" | jq

echo 'resolving qvi'
curl -s -X POST "http://localhost:5623/oobi" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"qvi\", \"url\":\"http://127.0.0.1:5642/oobi/EHMnCf8_nIemuPx-cUHaDQq8zSnQIFAurdEpwHpNbnvX/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha\"}" | jq
curl -s -X POST "http://localhost:5628/oobi" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"qvi\", \"url\":\"http://127.0.0.1:5642/oobi/EHMnCf8_nIemuPx-cUHaDQq8zSnQIFAurdEpwHpNbnvX/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha\"}" | jq
curl -s -X POST "http://localhost:5630/oobi" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"qvi\", \"url\":\"http://127.0.0.1:5642/oobi/EHMnCf8_nIemuPx-cUHaDQq8zSnQIFAurdEpwHpNbnvX/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha\"}" | jq

echo 'resolving legal-entity'
curl -s -X POST "http://localhost:5623/oobi" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"legal-entity\", \"url\":\"http://127.0.0.1:5642/oobi/EIitNxxiNFXC1HDcPygyfyv3KUlBfS_Zf-ZYOvwjpTuz/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha\"}" | jq
curl -s -X POST "http://localhost:5626/oobi" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"legal-entity\", \"url\":\"http://127.0.0.1:5642/oobi/EIitNxxiNFXC1HDcPygyfyv3KUlBfS_Zf-ZYOvwjpTuz/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha\"}" | jq
curl -s -X POST "http://localhost:5630/oobi" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"legal-entity\", \"url\":\"http://127.0.0.1:5642/oobi/EIitNxxiNFXC1HDcPygyfyv3KUlBfS_Zf-ZYOvwjpTuz/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha\"}" | jq

echo 'resolving person'
curl -s -X POST "http://localhost:5623/oobi" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"person\", \"url\":\"http://127.0.0.1:5642/oobi/EKE7b7owCvObR6dBTrU7w38_oATL9Tcrp_-xjPn05zYe/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha\"}" | jq
curl -s -X POST "http://localhost:5626/oobi" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"person\", \"url\":\"http://127.0.0.1:5642/oobi/EKE7b7owCvObR6dBTrU7w38_oATL9Tcrp_-xjPn05zYe/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha\"}" | jq
curl -s -X POST "http://localhost:5628/oobi" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"person\", \"url\":\"http://127.0.0.1:5642/oobi/EKE7b7owCvObR6dBTrU7w38_oATL9Tcrp_-xjPn05zYe/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha\"}" | jq

echo 'create registries'
sleep 3
curl -s -X POST "http://localhost:5623/registries" -H "accept: */*" -H "Content-Type: application/json" -d "{\"alias\":\"external\",\"baks\":[],\"estOnly\":false,\"name\":\"vLEI-external\",\"noBackers\":true,\"toad\":0}" | jq
curl -s -X POST "http://localhost:5626/registries" -H "accept: */*" -H "Content-Type: application/json" -d "{\"alias\":\"qvi\",\"baks\":[],\"estOnly\":false,\"name\":\"vLEI-qvi\",\"noBackers\":true,\"toad\":0}" | jq
curl -s -X POST "http://localhost:5628/registries" -H "accept: */*" -H "Content-Type: application/json" -d "{\"alias\":\"legal-entity\",\"baks\":[],\"estOnly\":false,\"name\":\"vLEI-legal-entity\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\",\"noBackers\":true,\"toad\":0}" | jq
curl -s -X POST "http://localhost:5630/registries" -H "accept: */*" -H "Content-Type: application/json" -d "{\"alias\":\"person\",\"baks\":[],\"estOnly\":false,\"name\":\"vLEI-person\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\",\"noBackers\":true,\"toad\":0}" | jq
sleep 5

# Issue QVI credential vLEI from GLEIF External to QVI
echo 'external issues qvi credential'
curl -s -X POST "http://localhost:5623/credentials/external" -H "accept: application/json" -H "Content-Type: application/json" -d "{\"credentialData\":{\"LEI\":\"6383001AJTYIGC8Y1X37\"},\"recipient\":\"EHMnCf8_nIemuPx-cUHaDQq8zSnQIFAurdEpwHpNbnvX\",\"registry\":\"vLEI-external\",\"schema\":\"ELqriXX1-lbV9zgXP4BXxqJlpZTgFchll3cyjaCyVKiz\"}"
sleep 8
echo "qvi retrieves Credentials..."
curl -s -X GET "http://localhost:5626/credentials/qvi?type=received" -H "accept: application/json"
sleep 3

# Issue LE credential from QVI to Legal Entity - have to create the edges first
echo 'Issue LE credential from QVI to Legal Entity - have to create the edges first'
QVI_SAID=$(curl -s -X GET "http://localhost:5626/credentials/qvi?type=received" -H "accept: application/json" -H "Content-Type: application/json" | jq '.[0] | .sad.d')
echo $QVI_SAID | jq -f ${KERI_DEMO_SCRIPT_DIR}/data/legal-entity-edges-filter.jq  > /tmp/legal-entity-edges.json
LE_EDGES=`cat /tmp/legal-entity-edges.json`
RULES=`cat ${KERI_DEMO_SCRIPT_DIR}/data/rules.json`
curl -s -X POST "http://localhost:5626/credentials/qvi" -H "accept: application/json" -H "Content-Type: application/json" -d "{\"credentialData\":{\"LEI\":\"5493001KJTIIGC8Y1R17\"},\"recipient\":\"EIitNxxiNFXC1HDcPygyfyv3KUlBfS_Zf-ZYOvwjpTuz\",\"registry\":\"vLEI-qvi\",\"schema\":\"EK0jwjJbtYLIynGtmXXLO5MGJ7BDuX2vr2_MhM9QjAxZ\",\"source\":$LE_EDGES,\"rules\":$RULES}" | jq

sleep 8
echo "LE retrieves Credentials..."
curl -s -X GET "http://localhost:5628/credentials/legal-entity?type=received" -H "accept: application/json" | jq
sleep 3

# Issue OOR Authorization credential from LE to QVI
echo 'LE issues OOR authorization credential to person'
LE_SAID=$(curl -s -X GET "http://localhost:5628/credentials/legal-entity?type=received" -H "accept: application/json" -H "Content-Type: application/json" | jq '.[0] | .sad.d')
echo $LE_SAID | jq -f ${KERI_DEMO_SCRIPT_DIR}/data/oor-auth-edges-filter.jq > /tmp/oor-auth-edges.json
OOR_AUTH_EDGES=`cat /tmp/oor-auth-edges.json`

curl -s -X POST "http://localhost:5628/credentials/legal-entity" -H "accept: application/json" -H "Content-Type: application/json" -d "{\"credentialData\":{\"AID\": \"EKE7b7owCvObR6dBTrU7w38_oATL9Tcrp_-xjPn05zYe\", \"LEI\":\"6383001AJTYIGC8Y1X37\", \"personLegalName\": \"John Smith\", \"officialRole\": \"Chief Executive Officer\"},\"recipient\":\"EHMnCf8_nIemuPx-cUHaDQq8zSnQIFAurdEpwHpNbnvX\",\"registry\":\"vLEI-legal-entity\",\"schema\":\"EDqjl80uP0r_SNSp-yImpLGglTEbOwgO77wsOPjyRVKy\",\"source\":$OOR_AUTH_EDGES,\"rules\":$RULES}" | jq
sleep 8
echo "QVI retrieves Credentials..."
curl -s -X GET "http://localhost:5626/credentials/qvi?type=received" -H "accept: application/json" | jq
sleep 3

# Issue OOR credential from QVI to Person
echo 'qvi issues OOR credential to person'
AUTH_SAID=$(curl -s -X GET "http://localhost:5626/credentials/qvi?type=received&schema=EDqjl80uP0r_SNSp-yImpLGglTEbOwgO77wsOPjyRVKy" -H "accept: application/json" -H "Content-Type: application/json" | jq '.[0] | .sad.d')
echo "[$QVI_SAID, $AUTH_SAID]" | jq -f ${KERI_DEMO_SCRIPT_DIR}/data/oor-edges-filter.jq > /tmp/oor-edges.json
OOR_EDGES=`cat /tmp/oor-edges.json`

curl -s -X POST "http://localhost:5626/credentials/qvi" -H "accept: application/json" -H "Content-Type: application/json" -d "{\"credentialData\":{\"LEI\":\"6383001AJTYIGC8Y1X37\", \"personLegalName\": \"John Smith\", \"officialRole\": \"Chief Executive Officer\"},\"recipient\":\"EKE7b7owCvObR6dBTrU7w38_oATL9Tcrp_-xjPn05zYe\",\"registry\":\"vLEI-qvi\",\"schema\":\"EIL-RWno8cEnkGTi9cr7-PFg_IXTPx9fZ0r9snFFZ0nm\",\"source\":$OOR_EDGES,\"rules\":$RULES}" | jq
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
curl -X POST "http://localhost:5630/credentials/person" -H "accept: application/json" -H "Content-Type: application/json" -d "{\"credentialData\":$XBRL_DATA,\"registry\":\"vLEI-person\",\"schema\":\"EMhvwOlyEJ9kN4PrwCpr9Jsv7TxPhiYveZ0oP3lJzdEi\",\"source\":$XBRL_EDGES}" | jq
sleep 4
echo "Person retrieves attestation..."
curl -s -X GET "http://localhost:5630/credentials/person?type=issued" -H "accept: application/json" -d "{\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\"}" | jq

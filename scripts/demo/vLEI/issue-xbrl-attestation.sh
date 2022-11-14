#!/bin/bash

# To run this script you need to run the following command in a separate terminals:
#   > kli witness demo
# and from the vLEI repo run:
#   > vLEI-server -s ./schema/acdc -c ./samples/acdc/ -o ./samples/oobis/
#

# EHOuGiHMxJShXHgSb6k_9pqxmRb8H-LT0R2hQouHp8pW
kli init --name external --salt 0ACDEyMzQ1Njc4OWxtbm9GhI --nopasscode --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis-schema
kli incept --name external --alias external --file ${KERI_DEMO_SCRIPT_DIR}/data/gleif-sample.json

# EHMnCf8_nIemuPx-cUHaDQq8zSnQIFAurdEpwHpNbnvX
kli init --name qvi --salt 0ACDEyMzQ1Njc4OWxtbm9aBc --nopasscode --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis-schema
kli incept --name qvi --alias qvi --file ${KERI_DEMO_SCRIPT_DIR}/data/gleif-sample.json

# EIitNxxiNFXC1HDcPygyfyv3KUlBfS_Zf-ZYOvwjpTuz
kli init --name legal-entity --salt 0ACDEyMzQ1Njc4OWxtbm9AbC --nopasscode --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis-schema
kli incept --name legal-entity --alias legal-entity --file ${KERI_DEMO_SCRIPT_DIR}/data/gleif-sample.json

# EKE7b7owCvObR6dBTrU7w38_oATL9Tcrp_-xjPn05zYe
# Passcode: DoB2-6Fj4x-9Lbo-AFWJr-a17O
kli init --name person --salt 0ACDEyMzQ1Njc4OWxtbm9dEf --passcode DoB26Fj4x9LboAFWJra17O --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis-schema
kli incept --name person --alias person --passcode DoB26Fj4x9LboAFWJra17O --file ${KERI_DEMO_SCRIPT_DIR}/data/gleif-sample.json

echo 'resolving external'
kli oobi resolve --name qvi --oobi-alias external --oobi http://127.0.0.1:5642/oobi/EHOuGiHMxJShXHgSb6k_9pqxmRb8H-LT0R2hQouHp8pW/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name legal-entity --oobi-alias external --oobi http://127.0.0.1:5642/oobi/EHOuGiHMxJShXHgSb6k_9pqxmRb8H-LT0R2hQouHp8pW/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name person --passcode DoB26Fj4x9LboAFWJra17O --oobi-alias external --oobi http://127.0.0.1:5642/oobi/EHOuGiHMxJShXHgSb6k_9pqxmRb8H-LT0R2hQouHp8pW/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
echo 'resolving qvi'
kli oobi resolve --name external --oobi-alias qvi --oobi http://127.0.0.1:5642/oobi/EHMnCf8_nIemuPx-cUHaDQq8zSnQIFAurdEpwHpNbnvX/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name legal-entity --oobi-alias qvi --oobi http://127.0.0.1:5642/oobi/EHMnCf8_nIemuPx-cUHaDQq8zSnQIFAurdEpwHpNbnvX/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name person --passcode DoB26Fj4x9LboAFWJra17O --oobi-alias qvi --oobi http://127.0.0.1:5642/oobi/EHMnCf8_nIemuPx-cUHaDQq8zSnQIFAurdEpwHpNbnvX/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
echo 'resolving legal-entity'
kli oobi resolve --name external --oobi-alias legal-entity --oobi http://127.0.0.1:5642/oobi/EIitNxxiNFXC1HDcPygyfyv3KUlBfS_Zf-ZYOvwjpTuz/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name qvi --oobi-alias legal-entity --oobi http://127.0.0.1:5642/oobi/EIitNxxiNFXC1HDcPygyfyv3KUlBfS_Zf-ZYOvwjpTuz/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name person --passcode DoB26Fj4x9LboAFWJra17O --oobi-alias legal-entity --oobi http://127.0.0.1:5642/oobi/EIitNxxiNFXC1HDcPygyfyv3KUlBfS_Zf-ZYOvwjpTuz/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
echo 'resolving person'
kli oobi resolve --name external --oobi-alias person --oobi http://127.0.0.1:5642/oobi/EKE7b7owCvObR6dBTrU7w38_oATL9Tcrp_-xjPn05zYe/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name qvi --oobi-alias person --oobi http://127.0.0.1:5642/oobi/EKE7b7owCvObR6dBTrU7w38_oATL9Tcrp_-xjPn05zYe/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name legal-entity --oobi-alias person --oobi http://127.0.0.1:5642/oobi/EKE7b7owCvObR6dBTrU7w38_oATL9Tcrp_-xjPn05zYe/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha

echo 'resolving iXBRL Data Attestation Schema EMhvwOlyEJ9kN4PrwCpr9Jsv7TxPhiYveZ0oP3lJzdEi'
kli oobi resolve --name external --oobi-alias credential --oobi http://127.0.0.1:7723/oobi/EMhvwOlyEJ9kN4PrwCpr9Jsv7TxPhiYveZ0oP3lJzdEi
kli oobi resolve --name qvi --oobi-alias credential --oobi http://127.0.0.1:7723/oobi/EMhvwOlyEJ9kN4PrwCpr9Jsv7TxPhiYveZ0oP3lJzdEi
kli oobi resolve --name legal-entity --oobi-alias credential --oobi http://127.0.0.1:7723/oobi/EMhvwOlyEJ9kN4PrwCpr9Jsv7TxPhiYveZ0oP3lJzdEi
kli oobi resolve --name person --passcode DoB26Fj4x9LboAFWJra17O --oobi-alias credential --oobi http://127.0.0.1:7723/oobi/EMhvwOlyEJ9kN4PrwCpr9Jsv7TxPhiYveZ0oP3lJzdEi

kli vc registry incept --name external --alias external --registry-name vLEI-external
kli vc registry incept --name qvi --alias qvi --registry-name vLEI-qvi
kli vc registry incept --name legal-entity --alias legal-entity --registry-name vLEI-legal-entity
kli vc registry incept --name person  --passcode DoB26Fj4x9LboAFWJra17O --alias person --registry-name vLEI-person

# Issue QVI credential vLEI from GLEIF External to QVI
kli vc issue --name external --alias external --registry-name vLEI-external --schema ELqriXX1-lbV9zgXP4BXxqJlpZTgFchll3cyjaCyVKiz --recipient EHMnCf8_nIemuPx-cUHaDQq8zSnQIFAurdEpwHpNbnvX --data @${KERI_DEMO_SCRIPT_DIR}/data/qvi-data.json
kli vc list --name qvi --alias qvi --poll

# Issue LE credential from QVI to Legal Entity - have to create the edges first
QVI_SAID=`kli vc list --name qvi --alias qvi --said --schema ELqriXX1-lbV9zgXP4BXxqJlpZTgFchll3cyjaCyVKiz`
echo \"$QVI_SAID\" | jq -f ${KERI_DEMO_SCRIPT_DIR}/data/legal-entity-edges-filter.jq  > /tmp/legal-entity-edges.json
kli saidify --file /tmp/legal-entity-edges.json
kli vc issue --name qvi --alias qvi --registry-name vLEI-qvi --schema EK0jwjJbtYLIynGtmXXLO5MGJ7BDuX2vr2_MhM9QjAxZ --recipient EIitNxxiNFXC1HDcPygyfyv3KUlBfS_Zf-ZYOvwjpTuz --data @${KERI_DEMO_SCRIPT_DIR}/data/legal-entity-data.json --edges @/tmp/legal-entity-edges.json --rules @${KERI_DEMO_SCRIPT_DIR}/data/rules.json
kli vc list --name legal-entity --alias legal-entity --poll

# Issue ECR Authorization credential from Legal Entity to QVI - have to create the edges first
LE_SAID=`kli vc list --name legal-entity --alias legal-entity --said`
echo \"$LE_SAID\" | jq -f ${KERI_DEMO_SCRIPT_DIR}/data/ecr-auth-edges-filter.jq > /tmp/ecr-auth-edges.json
kli saidify --file /tmp/ecr-auth-edges.json
kli vc issue --name legal-entity --alias legal-entity --registry-name vLEI-legal-entity --schema ED_PcIn1wFDe0GB0W7Bk9I4Q_c9bQJZCM2w7Ex9Plsta --recipient EHMnCf8_nIemuPx-cUHaDQq8zSnQIFAurdEpwHpNbnvX --data @${KERI_DEMO_SCRIPT_DIR}/data/ecr-auth-data.json --edges @/tmp/ecr-auth-edges.json --rules @${KERI_DEMO_SCRIPT_DIR}/data/ecr-auth-rules.json
kli vc list --name qvi --alias qvi --poll

# Issue ECR credential from QVI to Person
AUTH_SAID=`kli vc list --name qvi --alias qvi --said --schema ED_PcIn1wFDe0GB0W7Bk9I4Q_c9bQJZCM2w7Ex9Plsta`
echo "[\"$QVI_SAID\", \"$AUTH_SAID\"]" | jq -f ${KERI_DEMO_SCRIPT_DIR}/data/ecr-edges-filter.jq > /tmp/ecr-edges.json
kli saidify --file /tmp/ecr-edges.json
kli vc issue --name qvi --alias qvi --private --registry-name vLEI-qvi --schema EOhcE9MV90LRygJuYN1N0c5XXNFkzwFxUBfQ24v7qeEY --recipient EKE7b7owCvObR6dBTrU7w38_oATL9Tcrp_-xjPn05zYe --data @${KERI_DEMO_SCRIPT_DIR}/data/ecr-data.json --edges @/tmp/ecr-edges.json --rules @${KERI_DEMO_SCRIPT_DIR}/data/ecr-rules.json
kli vc list --name person --alias person --passcode DoB26Fj4x9LboAFWJra17O --poll

# Issue OOR Authorization credential from Legal Entity to QVI - have to create the edges first
echo \"$LE_SAID\" | jq -f ${KERI_DEMO_SCRIPT_DIR}/data/oor-auth-edges-filter.jq > /tmp/oor-auth-edges.json
kli saidify --file /tmp/oor-auth-edges.json
kli vc issue --name legal-entity --alias legal-entity --registry-name vLEI-legal-entity --schema EDqjl80uP0r_SNSp-yImpLGglTEbOwgO77wsOPjyRVKy --recipient EHMnCf8_nIemuPx-cUHaDQq8zSnQIFAurdEpwHpNbnvX --data @${KERI_DEMO_SCRIPT_DIR}/data/oor-auth-data.json --edges @/tmp/oor-auth-edges.json --rules @${KERI_DEMO_SCRIPT_DIR}/data/rules.json
kli vc list --name qvi --alias qvi --poll

# Issue OOR credential from QVI to Person
AUTH_SAID=`kli vc list --name qvi --alias qvi --said --schema EDqjl80uP0r_SNSp-yImpLGglTEbOwgO77wsOPjyRVKy`
echo "[\"$QVI_SAID\", \"$AUTH_SAID\"]" | jq -f ${KERI_DEMO_SCRIPT_DIR}/data/oor-edges-filter.jq > /tmp/oor-edges.json
kli saidify --file /tmp/oor-edges.json
kli vc issue --name qvi --alias qvi --registry-name vLEI-qvi --schema EIL-RWno8cEnkGTi9cr7-PFg_IXTPx9fZ0r9snFFZ0nm --recipient EKE7b7owCvObR6dBTrU7w38_oATL9Tcrp_-xjPn05zYe --data @${KERI_DEMO_SCRIPT_DIR}/data/oor-data.json --edges @/tmp/oor-edges.json --rules @${KERI_DEMO_SCRIPT_DIR}/data/rules.json
kli vc list --name person --alias person --passcode DoB26Fj4x9LboAFWJra17O --poll

# Issue iXBRL data attestation from Person
OOR_SAID=`kli vc list --name person --alias person --passcode DoB26Fj4x9LboAFWJra17O --said --schema EIL-RWno8cEnkGTi9cr7-PFg_IXTPx9fZ0r9snFFZ0nm`
echo \"$OOR_SAID\" | jq -f ${KERI_DEMO_SCRIPT_DIR}/data/xbrl-edges-filter.jq > /tmp/xbrl-edges.json
kli saidify --file /tmp/xbrl-edges.json
NOW=`date -u +"%Y-%m-%dT%H:%M:%S+00:00"`
echo \"$NOW\" | jq -f ${KERI_DEMO_SCRIPT_DIR}/data/xbrl-data.jq > /tmp/xbrl-data.json
kli saidify --file /tmp/xbrl-data.json
kli vc issue --name person --alias person --passcode DoB26Fj4x9LboAFWJra17O --registry-name vLEI-person --schema EMhvwOlyEJ9kN4PrwCpr9Jsv7TxPhiYveZ0oP3lJzdEi --data @/tmp/xbrl-data.json --edges @/tmp/xbrl-edges.json
kli vc list --name person --alias person --passcode DoB26Fj4x9LboAFWJra17O --issued
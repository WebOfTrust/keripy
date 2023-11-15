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
kli vc create --name external --alias external --registry-name vLEI-external --schema EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao --recipient EHMnCf8_nIemuPx-cUHaDQq8zSnQIFAurdEpwHpNbnvX --data @${KERI_DEMO_SCRIPT_DIR}/data/qvi-data.json
SAID=$(kli vc list --name external --alias external --issued --said --schema EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao)
kli ipex grant --name external --alias external --said "${SAID}" --recipient EHMnCf8_nIemuPx-cUHaDQq8zSnQIFAurdEpwHpNbnvX
GRANT=$(kli ipex list --name qvi --alias qvi --poll --said)
kli ipex admit --name qvi --alias qvi --said "${GRANT}"
kli vc list --name qvi --alias qvi

# Issue LE credential from QVI to Legal Entity - have to create the edges first
QVI_SAID=`kli vc list --name qvi --alias qvi --said --schema EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao`
echo \"$QVI_SAID\" | jq -f ${KERI_DEMO_SCRIPT_DIR}/data/legal-entity-edges-filter.jq  > /tmp/legal-entity-edges.json
kli saidify --file /tmp/legal-entity-edges.json
kli vc create --name qvi --alias qvi --registry-name vLEI-qvi --schema ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY --recipient EIitNxxiNFXC1HDcPygyfyv3KUlBfS_Zf-ZYOvwjpTuz --data @${KERI_DEMO_SCRIPT_DIR}/data/legal-entity-data.json --edges @/tmp/legal-entity-edges.json --rules @${KERI_DEMO_SCRIPT_DIR}/data/rules.json
SAID=$(kli vc list --name qvi --alias qvi --issued --said --schema ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY)
kli ipex grant --name qvi --alias qvi --said "${SAID}" --recipient EIitNxxiNFXC1HDcPygyfyv3KUlBfS_Zf-ZYOvwjpTuz
GRANT=$(kli ipex list --name legal-entity --alias legal-entity --poll --said)
kli ipex admit --name legal-entity --alias legal-entity --said "${GRANT}"
kli vc list --name legal-entity --alias legal-entity

# Issue ECR Authorization credential from Legal Entity to QVI - have to create the edges first
LE_SAID=`kli vc list --name legal-entity --alias legal-entity --said`
echo \"$LE_SAID\" | jq -f ${KERI_DEMO_SCRIPT_DIR}/data/ecr-auth-edges-filter.jq > /tmp/ecr-auth-edges.json
kli saidify --file /tmp/ecr-auth-edges.json
kli vc create --name legal-entity --alias legal-entity --registry-name vLEI-legal-entity --schema EH6ekLjSr8V32WyFbGe1zXjTzFs9PkTYmupJ9H65O14g --recipient EHMnCf8_nIemuPx-cUHaDQq8zSnQIFAurdEpwHpNbnvX --data @${KERI_DEMO_SCRIPT_DIR}/data/ecr-auth-data.json --edges @/tmp/ecr-auth-edges.json --rules @${KERI_DEMO_SCRIPT_DIR}/data/ecr-auth-rules.json
SAID=$(kli vc list --name legal-entity --alias legal-entity --issued --said --schema EH6ekLjSr8V32WyFbGe1zXjTzFs9PkTYmupJ9H65O14g)
kli ipex grant --name legal-entity --alias legal-entity --said "${SAID}" --recipient EHMnCf8_nIemuPx-cUHaDQq8zSnQIFAurdEpwHpNbnvX
GRANT=$(kli ipex list --name qvi --alias qvi --poll --said | tail -1)
kli ipex admit --name qvi --alias qvi --said "${GRANT}"
kli vc list --name qvi --alias qvi

# Issue ECR credential from QVI to Person
AUTH_SAID=`kli vc list --name qvi --alias qvi --said --schema EH6ekLjSr8V32WyFbGe1zXjTzFs9PkTYmupJ9H65O14g`
echo "[\"$QVI_SAID\", \"$AUTH_SAID\"]" | jq -f ${KERI_DEMO_SCRIPT_DIR}/data/ecr-edges-filter.jq > /tmp/ecr-edges.json
kli saidify --file /tmp/ecr-edges.json
kli vc create --name qvi --alias qvi --private --registry-name vLEI-qvi --schema EEy9PkikFcANV1l7EHukCeXqrzT1hNZjGlUk7wuMO5jw --recipient EKE7b7owCvObR6dBTrU7w38_oATL9Tcrp_-xjPn05zYe --data @${KERI_DEMO_SCRIPT_DIR}/data/ecr-data.json --edges @/tmp/ecr-edges.json --rules @${KERI_DEMO_SCRIPT_DIR}/data/ecr-rules.json
SAID=$(kli vc list --name qvi --alias qvi --issued --said --schema EEy9PkikFcANV1l7EHukCeXqrzT1hNZjGlUk7wuMO5jw)
kli ipex grant --name qvi --alias qvi --said "${SAID}" --recipient EKE7b7owCvObR6dBTrU7w38_oATL9Tcrp_-xjPn05zYe
GRANT=$(kli ipex list --name person --alias person --passcode DoB26Fj4x9LboAFWJra17O --poll --said)
kli ipex admit --name person --alias person --passcode DoB26Fj4x9LboAFWJra17O --said "${GRANT}"
kli vc list --name person --alias person --passcode DoB26Fj4x9LboAFWJra17O

# Issue OOR Authorization credential from Legal Entity to QVI - have to create the edges first
echo \"$LE_SAID\" | jq -f ${KERI_DEMO_SCRIPT_DIR}/data/oor-auth-edges-filter.jq > /tmp/oor-auth-edges.json
kli saidify --file /tmp/oor-auth-edges.json
kli vc create --name legal-entity --alias legal-entity --registry-name vLEI-legal-entity --schema EKA57bKBKxr_kN7iN5i7lMUxpMG-s19dRcmov1iDxz-E --recipient EHMnCf8_nIemuPx-cUHaDQq8zSnQIFAurdEpwHpNbnvX --data @${KERI_DEMO_SCRIPT_DIR}/data/oor-auth-data.json --edges @/tmp/oor-auth-edges.json --rules @${KERI_DEMO_SCRIPT_DIR}/data/rules.json
SAID=$(kli vc list --name legal-entity --alias legal-entity --issued --said --schema EKA57bKBKxr_kN7iN5i7lMUxpMG-s19dRcmov1iDxz-E)
kli ipex grant --name legal-entity --alias legal-entity --said "${SAID}" --recipient EHMnCf8_nIemuPx-cUHaDQq8zSnQIFAurdEpwHpNbnvX
GRANT=$(kli ipex list --name qvi --alias qvi --poll --said | tail -1)
kli ipex admit --name qvi --alias qvi --said "${GRANT}"
kli vc list --name qvi --alias qvi

# Issue OOR credential from QVI to Person
AUTH_SAID=`kli vc list --name qvi --alias qvi --said --schema EKA57bKBKxr_kN7iN5i7lMUxpMG-s19dRcmov1iDxz-E`
echo "[\"$QVI_SAID\", \"$AUTH_SAID\"]" | jq -f ${KERI_DEMO_SCRIPT_DIR}/data/oor-edges-filter.jq > /tmp/oor-edges.json
kli saidify --file /tmp/oor-edges.json
kli vc create --name qvi --alias qvi --registry-name vLEI-qvi --schema EBNaNu-M9P5cgrnfl2Fvymy4E_jvxxyjb70PRtiANlJy --recipient EKE7b7owCvObR6dBTrU7w38_oATL9Tcrp_-xjPn05zYe --data @${KERI_DEMO_SCRIPT_DIR}/data/oor-data.json --edges @/tmp/oor-edges.json --rules @${KERI_DEMO_SCRIPT_DIR}/data/rules.json
SAID=$(kli vc list --name qvi --alias qvi --issued --said --schema EBNaNu-M9P5cgrnfl2Fvymy4E_jvxxyjb70PRtiANlJy)
kli ipex grant --name qvi --alias qvi --said "${SAID}" --recipient EKE7b7owCvObR6dBTrU7w38_oATL9Tcrp_-xjPn05zYe
GRANT=$(kli ipex list --name person --alias person --passcode DoB26Fj4x9LboAFWJra17O --poll --said | tail -1)
kli ipex admit --name person --alias person --passcode DoB26Fj4x9LboAFWJra17O --said "${GRANT}"
kli vc list --name person --alias person --passcode DoB26Fj4x9LboAFWJra17O

# Issue iXBRL data attestation from Person
OOR_SAID=`kli vc list --name person --alias person --passcode DoB26Fj4x9LboAFWJra17O --said --schema EBNaNu-M9P5cgrnfl2Fvymy4E_jvxxyjb70PRtiANlJy`
echo \"$OOR_SAID\" | jq -f ${KERI_DEMO_SCRIPT_DIR}/data/xbrl-edges-filter.jq > /tmp/xbrl-edges.json
kli saidify --file /tmp/xbrl-edges.json
NOW=`date -u +"%Y-%m-%dT%H:%M:%S+00:00"`
echo \"$NOW\" | jq -f ${KERI_DEMO_SCRIPT_DIR}/data/xbrl-data.jq > /tmp/xbrl-data.json
kli saidify --file /tmp/xbrl-data.json
kli vc create --name person --alias person --passcode DoB26Fj4x9LboAFWJra17O --registry-name vLEI-person --schema EMhvwOlyEJ9kN4PrwCpr9Jsv7TxPhiYveZ0oP3lJzdEi --data @/tmp/xbrl-data.json --edges @/tmp/xbrl-edges.json
kli vc list --name person --alias person --passcode DoB26Fj4x9LboAFWJra17O --issued
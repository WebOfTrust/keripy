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

# Issue ECR credential from LE to Person
LE_SAID=`kli vc list --name legal-entity --alias legal-entity --said --schema ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY`
echo "${LE_SAID}"
echo \"$LE_SAID\" | jq -f ${KERI_DEMO_SCRIPT_DIR}/data/direct-ecr-edges-filter.jq > /tmp/direct-ecr-edges.json
kli saidify --file /tmp/direct-ecr-edges.json

# # 0ADndbdzYEQc_T8KFOt9AYUm
# # 0ADtZouB4SQwwn67c8zYOD0M
kli vc create --name legal-entity --alias legal-entity --private --private-credential-nonce 0ADndbdzYEQc_T8KFOt9AYUm --private-subject-nonce 0ADtZouB4SQwwn67c8zYOD0M --registry-name vLEI-legal-entity --schema EEy9PkikFcANV1l7EHukCeXqrzT1hNZjGlUk7wuMO5jw --recipient EKE7b7owCvObR6dBTrU7w38_oATL9Tcrp_-xjPn05zYe --data @${KERI_DEMO_SCRIPT_DIR}/data/direct-ecr-data.json --edges @/tmp/direct-ecr-edges.json --rules @${KERI_DEMO_SCRIPT_DIR}/data/direct-ecr-rules.json
SAID=$(kli vc list --name legal-entity --alias legal-entity --issued --said --schema EEy9PkikFcANV1l7EHukCeXqrzT1hNZjGlUk7wuMO5jw)

kli ipex grant --name legal-entity --alias legal-entity --said "${SAID}" --recipient EKE7b7owCvObR6dBTrU7w38_oATL9Tcrp_-xjPn05zYe
GRANT=$(kli ipex list --name person --alias person --passcode DoB26Fj4x9LboAFWJra17O --poll --said)
kli ipex admit --name person --alias person --passcode DoB26Fj4x9LboAFWJra17O --said "${GRANT}"
kli vc list --name person --alias person --passcode DoB26Fj4x9LboAFWJra17O --verbose

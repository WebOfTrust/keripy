#!/bin/bash

# To run this script you need to run the following command in a separate terminals:
#   > kli witness demo
# and from the vLEI repo run:
#   > vLEI-server -s ./schema/acdc -c ./samples/acdc/ -o ./samples/oobis/
#

# EWN6BzdXo6IByOsuh_fYanK300iEOrQKf6msmbIeC4Y0
kli init --name external --salt 0ACDEyMzQ1Njc4OWxtbm9GhI --nopasscode --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis
kli incept --name external --alias external --file ${KERI_DEMO_SCRIPT_DIR}/data/gleif-sample.json

# EY4ldIBDZP4Tpnm3RX320BO0yz8Uz2nUSN-C409GnCJM
kli init --name qvi --salt 0ACDEyMzQ1Njc4OWxtbm9aBc --nopasscode --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis
kli incept --name qvi --alias qvi --file ${KERI_DEMO_SCRIPT_DIR}/data/gleif-sample.json

# EKXPX7hWw8KK5Y_Mxs2TOuCrGdN45vPIZ78NofRlVBws
kli init --name legal-entity --salt 0ACDEyMzQ1Njc4OWxtbm9AbC --nopasscode --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis
kli incept --name legal-entity --alias legal-entity --file ${KERI_DEMO_SCRIPT_DIR}/data/gleif-sample.json

# Esf8b_AngI1d0KbOFjPGIfpVani0HTagWeaYTLs14PlE
# Passcode: DoB2-6Fj4x-9Lbo-AFWJr-a17O
kli init --name person --salt 0ACDEyMzQ1Njc4OWxtbm9dEf --passcode DoB26Fj4x9LboAFWJra17O --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis
kli incept --name person --alias person --passcode DoB26Fj4x9LboAFWJra17O --file ${KERI_DEMO_SCRIPT_DIR}/data/gleif-sample.json

echo 'resolving external'
kli oobi resolve --name qvi --oobi-alias external --oobi http://127.0.0.1:5642/oobi/EWN6BzdXo6IByOsuh_fYanK300iEOrQKf6msmbIeC4Y0/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name legal-entity --oobi-alias external --oobi http://127.0.0.1:5642/oobi/EWN6BzdXo6IByOsuh_fYanK300iEOrQKf6msmbIeC4Y0/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name person --passcode DoB26Fj4x9LboAFWJra17O --oobi-alias external --oobi http://127.0.0.1:5642/oobi/EWN6BzdXo6IByOsuh_fYanK300iEOrQKf6msmbIeC4Y0/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
echo 'resolving qvi'
kli oobi resolve --name external --oobi-alias qvi --oobi http://127.0.0.1:5642/oobi/EY4ldIBDZP4Tpnm3RX320BO0yz8Uz2nUSN-C409GnCJM/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name legal-entity --oobi-alias qvi --oobi http://127.0.0.1:5642/oobi/EY4ldIBDZP4Tpnm3RX320BO0yz8Uz2nUSN-C409GnCJM/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name person --passcode DoB26Fj4x9LboAFWJra17O --oobi-alias qvi --oobi http://127.0.0.1:5642/oobi/EY4ldIBDZP4Tpnm3RX320BO0yz8Uz2nUSN-C409GnCJM/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
echo 'resolving legal-entity'
kli oobi resolve --name external --oobi-alias legal-entity --oobi http://127.0.0.1:5642/oobi/EKXPX7hWw8KK5Y_Mxs2TOuCrGdN45vPIZ78NofRlVBws/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name qvi --oobi-alias legal-entity --oobi http://127.0.0.1:5642/oobi/EKXPX7hWw8KK5Y_Mxs2TOuCrGdN45vPIZ78NofRlVBws/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name person --passcode DoB26Fj4x9LboAFWJra17O --oobi-alias legal-entity --oobi http://127.0.0.1:5642/oobi/EKXPX7hWw8KK5Y_Mxs2TOuCrGdN45vPIZ78NofRlVBws/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
echo 'resolving person'
kli oobi resolve --name external --oobi-alias person --oobi http://127.0.0.1:5642/oobi/Esf8b_AngI1d0KbOFjPGIfpVani0HTagWeaYTLs14PlE/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name qvi --oobi-alias person --oobi http://127.0.0.1:5642/oobi/Esf8b_AngI1d0KbOFjPGIfpVani0HTagWeaYTLs14PlE/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name legal-entity --oobi-alias person --oobi http://127.0.0.1:5642/oobi/Esf8b_AngI1d0KbOFjPGIfpVani0HTagWeaYTLs14PlE/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha

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
echo 'resolving OOR Authorization vLEI Schema EDpuiVPt4_sa1pShx6vOCnseru1edVPeNvRaQm6HrmMI'
kli oobi resolve --name external --oobi-alias credential --oobi http://127.0.0.1:7723/oobi/EDpuiVPt4_sa1pShx6vOCnseru1edVPeNvRaQm6HrmMI
kli oobi resolve --name qvi --oobi-alias credential --oobi http://127.0.0.1:7723/oobi/EDpuiVPt4_sa1pShx6vOCnseru1edVPeNvRaQm6HrmMI
kli oobi resolve --name legal-entity --oobi-alias credential --oobi http://127.0.0.1:7723/oobi/EDpuiVPt4_sa1pShx6vOCnseru1edVPeNvRaQm6HrmMI
kli oobi resolve --name person --passcode DoB26Fj4x9LboAFWJra17O --oobi-alias credential --oobi http://127.0.0.1:7723/oobi/EDpuiVPt4_sa1pShx6vOCnseru1edVPeNvRaQm6HrmMI
echo 'resolving OOR vLEI Schema EzWz2j8AzVxFr3g1vy6NTERpy5GNZIOyjhkoniMMGUY4'
kli oobi resolve --name external --oobi-alias credential --oobi http://127.0.0.1:7723/oobi/EzWz2j8AzVxFr3g1vy6NTERpy5GNZIOyjhkoniMMGUY4
kli oobi resolve --name qvi --oobi-alias credential --oobi http://127.0.0.1:7723/oobi/EzWz2j8AzVxFr3g1vy6NTERpy5GNZIOyjhkoniMMGUY4
kli oobi resolve --name legal-entity --oobi-alias credential --oobi http://127.0.0.1:7723/oobi/EzWz2j8AzVxFr3g1vy6NTERpy5GNZIOyjhkoniMMGUY4
kli oobi resolve --name person --passcode DoB26Fj4x9LboAFWJra17O --oobi-alias credential --oobi http://127.0.0.1:7723/oobi/EzWz2j8AzVxFr3g1vy6NTERpy5GNZIOyjhkoniMMGUY4
echo 'resolving ECR Authorization vLEI Schema ELG17Q0M-uLZcjidzVbF7KBkoUhZa1ie3Az3Q_8aYi8s'
kli oobi resolve --name external --oobi-alias credential --oobi http://127.0.0.1:7723/oobi/ELG17Q0M-uLZcjidzVbF7KBkoUhZa1ie3Az3Q_8aYi8s
kli oobi resolve --name qvi --oobi-alias credential --oobi http://127.0.0.1:7723/oobi/ELG17Q0M-uLZcjidzVbF7KBkoUhZa1ie3Az3Q_8aYi8s
kli oobi resolve --name legal-entity --oobi-alias credential --oobi http://127.0.0.1:7723/oobi/ELG17Q0M-uLZcjidzVbF7KBkoUhZa1ie3Az3Q_8aYi8s
kli oobi resolve --name person --passcode DoB26Fj4x9LboAFWJra17O --oobi-alias credential --oobi http://127.0.0.1:7723/oobi/ELG17Q0M-uLZcjidzVbF7KBkoUhZa1ie3Az3Q_8aYi8s
echo 'resolving ECR vLEI Schema EwG_7aZDN7OTBVwETjj7ZMs-xsfH4bX111iKdwE104Yg'
kli oobi resolve --name external --oobi-alias credential --oobi http://127.0.0.1:7723/oobi/EwG_7aZDN7OTBVwETjj7ZMs-xsfH4bX111iKdwE104Yg
kli oobi resolve --name qvi --oobi-alias credential --oobi http://127.0.0.1:7723/oobi/EwG_7aZDN7OTBVwETjj7ZMs-xsfH4bX111iKdwE104Yg
kli oobi resolve --name legal-entity --oobi-alias credential --oobi http://127.0.0.1:7723/oobi/EwG_7aZDN7OTBVwETjj7ZMs-xsfH4bX111iKdwE104Yg
kli oobi resolve --name person --passcode DoB26Fj4x9LboAFWJra17O --oobi-alias credential --oobi http://127.0.0.1:7723/oobi/EwG_7aZDN7OTBVwETjj7ZMs-xsfH4bX111iKdwE104Yg
echo 'resolving iXBRL Data Attestation Schema EH9jKc3FQ0O2hvp7YPG5sFBgM7wUFVy4OlssP038w6j0'
kli oobi resolve --name external --oobi-alias credential --oobi http://127.0.0.1:7723/oobi/EH9jKc3FQ0O2hvp7YPG5sFBgM7wUFVy4OlssP038w6j0
kli oobi resolve --name qvi --oobi-alias credential --oobi http://127.0.0.1:7723/oobi/EH9jKc3FQ0O2hvp7YPG5sFBgM7wUFVy4OlssP038w6j0
kli oobi resolve --name legal-entity --oobi-alias credential --oobi http://127.0.0.1:7723/oobi/EH9jKc3FQ0O2hvp7YPG5sFBgM7wUFVy4OlssP038w6j0
kli oobi resolve --name person --passcode DoB26Fj4x9LboAFWJra17O --oobi-alias credential --oobi http://127.0.0.1:7723/oobi/EH9jKc3FQ0O2hvp7YPG5sFBgM7wUFVy4OlssP038w6j0

kli vc registry incept --name external --alias external --registry-name vLEI-external
kli vc registry incept --name qvi --alias qvi --registry-name vLEI-qvi
kli vc registry incept --name legal-entity --alias legal-entity --registry-name vLEI-legal-entity
kli vc registry incept --name person  --passcode DoB26Fj4x9LboAFWJra17O --alias person --registry-name vLEI-person

# Issue QVI credential vLEI from GLEIF External to QVI
kli vc issue --name external --alias external --registry-name vLEI-external --schema EWCeT9zTxaZkaC_3-amV2JtG6oUxNA36sCC0P5MI7Buw --recipient EY4ldIBDZP4Tpnm3RX320BO0yz8Uz2nUSN-C409GnCJM --data @${KERI_DEMO_SCRIPT_DIR}/data/qvi-data.json
kli vc list --name qvi --alias qvi --poll

# Issue LE credential from QVI to Legal Entity - have to create the edges first
QVI_SAID=`kli vc list --name qvi --alias qvi --said --schema EWCeT9zTxaZkaC_3-amV2JtG6oUxNA36sCC0P5MI7Buw`
echo \"$QVI_SAID\" | jq -f ${KERI_DEMO_SCRIPT_DIR}/data/legal-entity-edges-filter.jq  > /tmp/legal-entity-edges.json
kli saidify --file /tmp/legal-entity-edges.json
kli vc issue --name qvi --alias qvi --registry-name vLEI-qvi --schema EWJkQCFvKuyxZi582yJPb0wcwuW3VXmFNuvbQuBpgmIs --recipient EKXPX7hWw8KK5Y_Mxs2TOuCrGdN45vPIZ78NofRlVBws --data @${KERI_DEMO_SCRIPT_DIR}/data/legal-entity-data.json --edges @/tmp/legal-entity-edges.json --rules @${KERI_DEMO_SCRIPT_DIR}/data/rules.json
kli vc list --name legal-entity --alias legal-entity --poll

# Issue ECR Authorization credential from Legal Entity to QVI - have to create the edges first
LE_SAID=`kli vc list --name legal-entity --alias legal-entity --said`
echo \"$LE_SAID\" | jq -f ${KERI_DEMO_SCRIPT_DIR}/data/ecr-auth-edges-filter.jq > /tmp/ecr-auth-edges.json
kli saidify --file /tmp/ecr-auth-edges.json
kli vc issue --name legal-entity --alias legal-entity --registry-name vLEI-legal-entity --schema ELG17Q0M-uLZcjidzVbF7KBkoUhZa1ie3Az3Q_8aYi8s --recipient EY4ldIBDZP4Tpnm3RX320BO0yz8Uz2nUSN-C409GnCJM --data @${KERI_DEMO_SCRIPT_DIR}/data/ecr-auth-data.json --edges @/tmp/ecr-auth-edges.json --rules @${KERI_DEMO_SCRIPT_DIR}/data/rules.json
kli vc list --name qvi --alias qvi --poll

# Issue ECR credential from QVI to Person
AUTH_SAID=`kli vc list --name qvi --alias qvi --said --schema ELG17Q0M-uLZcjidzVbF7KBkoUhZa1ie3Az3Q_8aYi8s`
echo "[\"$QVI_SAID\", \"$AUTH_SAID\"]" | jq -f ${KERI_DEMO_SCRIPT_DIR}/data/ecr-edges-filter.jq > /tmp/ecr-edges.json
kli saidify --file /tmp/ecr-edges.json
kli vc issue --name qvi --alias qvi --registry-name vLEI-qvi --schema EwG_7aZDN7OTBVwETjj7ZMs-xsfH4bX111iKdwE104Yg --recipient Esf8b_AngI1d0KbOFjPGIfpVani0HTagWeaYTLs14PlE --data @${KERI_DEMO_SCRIPT_DIR}/data/ecr-data.json --edges @/tmp/ecr-edges.json --rules @${KERI_DEMO_SCRIPT_DIR}/data/rules.json
kli vc list --name person --alias person --passcode DoB26Fj4x9LboAFWJra17O --poll

# Issue OOR Authorization credential from Legal Entity to QVI - have to create the edges first
echo \"$LE_SAID\" | jq -f ${KERI_DEMO_SCRIPT_DIR}/data/oor-auth-edges-filter.jq > /tmp/oor-auth-edges.json
kli saidify --file /tmp/oor-auth-edges.json
kli vc issue --name legal-entity --alias legal-entity --registry-name vLEI-legal-entity --schema EDpuiVPt4_sa1pShx6vOCnseru1edVPeNvRaQm6HrmMI --recipient EY4ldIBDZP4Tpnm3RX320BO0yz8Uz2nUSN-C409GnCJM --data @${KERI_DEMO_SCRIPT_DIR}/data/oor-auth-data.json --edges @/tmp/oor-auth-edges.json --rules @${KERI_DEMO_SCRIPT_DIR}/data/rules.json
kli vc list --name qvi --alias qvi --poll

# Issue OOR credential from QVI to Person
AUTH_SAID=`kli vc list --name qvi --alias qvi --said --schema EDpuiVPt4_sa1pShx6vOCnseru1edVPeNvRaQm6HrmMI`
echo "[\"$QVI_SAID\", \"$AUTH_SAID\"]" | jq -f ${KERI_DEMO_SCRIPT_DIR}/data/oor-edges-filter.jq > /tmp/oor-edges.json
kli saidify --file /tmp/oor-edges.json
kli vc issue --name qvi --alias qvi --registry-name vLEI-qvi --schema EzWz2j8AzVxFr3g1vy6NTERpy5GNZIOyjhkoniMMGUY4 --recipient Esf8b_AngI1d0KbOFjPGIfpVani0HTagWeaYTLs14PlE --data @${KERI_DEMO_SCRIPT_DIR}/data/oor-data.json --edges @/tmp/oor-edges.json --rules @${KERI_DEMO_SCRIPT_DIR}/data/rules.json
kli vc list --name person --alias person --passcode DoB26Fj4x9LboAFWJra17O --poll

# Issue iXBRL data attestation from Person
OOR_SAID=`kli vc list --name person --alias person --passcode DoB26Fj4x9LboAFWJra17O --said --schema EzWz2j8AzVxFr3g1vy6NTERpy5GNZIOyjhkoniMMGUY4`
echo \"$OOR_SAID\" | jq -f ${KERI_DEMO_SCRIPT_DIR}/data/xbrl-edges-filter.jq > /tmp/xbrl-edges.json
kli saidify --file /tmp/xbrl-edges.json
NOW=`date -u +"%Y-%m-%dT%H:%M:%S+00:00"`
echo \"$NOW\" | jq -f ${KERI_DEMO_SCRIPT_DIR}/data/xbrl-data.jq > /tmp/xbrl-data.json
kli saidify --file /tmp/xbrl-data.json
kli vc issue --name person --alias person --passcode DoB26Fj4x9LboAFWJra17O --registry-name vLEI-person --schema EH9jKc3FQ0O2hvp7YPG5sFBgM7wUFVy4OlssP038w6j0 --data @/tmp/xbrl-data.json --edges @/tmp/xbrl-edges.json
kli vc list --name person --alias person --passcode DoB26Fj4x9LboAFWJra17O --issued
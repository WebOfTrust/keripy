#!/bin/bash

#kli init --name sender --salt 0ACDEyMzQ1Njc4OWxtbm9aBc --nopasscode --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis
#kli incept --name sender --alias sender --file ${KERI_DEMO_SCRIPT_DIR}/data/gleif-sample.json
#
#kli init --name recipient --salt 0ACDEyMzQ1Njc4OWxtbm9qWc --nopasscode --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis
#kli incept --name recipient --alias recipient --file ${KERI_DEMO_SCRIPT_DIR}/data/gleif-sample.json
#
#kli oobi resolve --name sender --oobi-alias recipient --oobi http://127.0.0.1:5642/oobi/EFXJsTFSo10FAZGR-8_Uw1DlhU8nuRFOAN9Z8ajJ56ci/witness
#kli oobi resolve --name recipient --oobi-alias sender --oobi http://127.0.0.1:5642/oobi/EJf7MfzNmehwY5310MUWXPSxhAA_3ifPW2bdsjwqnvae/witness
#
#kli vc registry incept --name sender --alias sender --registry-name vLEI
#
#kli vc create --name sender --alias sender --registry-name vLEI --schema EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao --recipient ELjSFdrTdCebJlmvbFNX9-TLhR2PO0_60al1kQp5_e6k --data @${KERI_DEMO_SCRIPT_DIR}/data/credential-data.json
#SAID=$(kli vc list --name sender --alias sender --issued --said --schema EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao)
#
#kli ipex grant --name sender --alias sender --said "${SAID}" --recipient ELjSFdrTdCebJlmvbFNX9-TLhR2PO0_60al1kQp5_e6k

kli essr send --name sender --alias sender --recipient recipient
#!/bin/bash

# WITNESSES
# To run the following scripts, open another console window and run:
# $ kli witness demo

kli init --name multisig1 --salt 0ACDEyMzQ1Njc4OWxtbm9aBc --nopasscode --config-dir "${KERI_SCRIPT_DIR}" --config-file demo-witness-oobis
kli incept --name multisig1 --alias multisig1 --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-1-sample.json

kli init --name multisig2 --salt 0ACDEyMzQ1Njc4OWdoaWpsaw --nopasscode --config-dir "${KERI_SCRIPT_DIR}" --config-file demo-witness-oobis
kli incept --name multisig2 --alias multisig2 --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-2-sample.json

# Create the identifier to which the credential will be issued
kli init --name holder --salt 0ACDEyMzQ1Njc4OWxtbm9qWc --nopasscode --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis
kli incept --name holder --alias holder --file ${KERI_DEMO_SCRIPT_DIR}/data/gleif-sample.json

kli oobi resolve --name multisig1 --oobi-alias multisig2 --oobi http://127.0.0.1:5642/oobi/EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name multisig2 --oobi-alias multisig1 --oobi http://127.0.0.1:5642/oobi/EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name multisig1 --oobi-alias holder --oobi http://127.0.0.1:5642/oobi/ELjSFdrTdCebJlmvbFNX9-TLhR2PO0_60al1kQp5_e6k/witness
kli oobi resolve --name multisig2 --oobi-alias holder --oobi http://127.0.0.1:5642/oobi/ELjSFdrTdCebJlmvbFNX9-TLhR2PO0_60al1kQp5_e6k/witness


kli oobi resolve --name multisig1 --oobi-alias vc --oobi http://127.0.0.1:7723/oobi/EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao
kli oobi resolve --name multisig2 --oobi-alias vc --oobi http://127.0.0.1:7723/oobi/EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao
kli oobi resolve --name holder --oobi-alias vc --oobi http://127.0.0.1:7723/oobi/EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao

read  -n 1 -r -p "Press any key after agent0 has created their AID:"

kli oobi resolve --name multisig1 --oobi-alias agent0 --oobi http://127.0.0.1:3902/oobi/EOGvmhJDBbJP4zeXaRun5vSz0O3_1zB10DwNMyjXlJEv/agent/EEXekkGu9IAzav6pZVJhkLnjtjM5v3AcyA-pdKUcaGei
kli oobi resolve --name multisig2 --oobi-alias agent0 --oobi http://127.0.0.1:3902/oobi/EOGvmhJDBbJP4zeXaRun5vSz0O3_1zB10DwNMyjXlJEv/agent/EEXekkGu9IAzav6pZVJhkLnjtjM5v3AcyA-pdKUcaGei

# Follow commands run in parallel
kli multisig incept --name multisig1 --alias multisig1 --group multisig --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-signify-sample.json &
pid=$!
PID_LIST+=" $pid"
kli multisig incept --name multisig2 --alias multisig2 --group multisig --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-signify-sample.json &
pid=$!

wait $PID_LIST
PID_LIST=""

kli status --name multisig1 --alias multisig

PID_LIST=""

# Create a credential registry owned by the multisig issuer
kli vc registry incept --name multisig1 --alias multisig --registry-name vLEI --usage "Issue vLEIs" --nonce AHSNDV3ABI6U8OIgKaj3aky91ZpNL54I5_7-qwtC6q2s &
pid=$!
PID_LIST=" $pid"

kli vc registry incept --name multisig2 --alias multisig --registry-name vLEI --usage "Issue vLEIs" --nonce AHSNDV3ABI6U8OIgKaj3aky91ZpNL54I5_7-qwtC6q2s &
pid=$!
PID_LIST+=" $pid"

wait $PID_LIST

# Issue Credential
#TIME=$(date -Iseconds -u)

TIME="2023-09-25T16:01:37.000000+00:00"
kli vc create --name multisig1 --alias multisig --registry-name vLEI --schema EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao --recipient ELjSFdrTdCebJlmvbFNX9-TLhR2PO0_60al1kQp5_e6k --data @${KERI_DEMO_SCRIPT_DIR}/data/credential-data.json --time "${TIME}" &
pid=$!
PID_LIST="$pid"

kli vc create --name multisig2 --alias multisig --registry-name vLEI --schema EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao --recipient ELjSFdrTdCebJlmvbFNX9-TLhR2PO0_60al1kQp5_e6k --data @${KERI_DEMO_SCRIPT_DIR}/data/credential-data.json --time "${TIME}" &
pid=$!
PID_LIST+=" $pid"

wait $PID_LIST

SAID=$(kli vc list --name multisig1 --alias multisig --issued --said)

kli ipex grant --name multisig1 --alias multisig --said "${SAID}" --recipient ELjSFdrTdCebJlmvbFNX9-TLhR2PO0_60al1kQp5_e6k --time "${TIME}" &
pid=$!
PID_LIST="$pid"

kli ipex grant --name multisig2 --alias multisig --said "${SAID}" --recipient ELjSFdrTdCebJlmvbFNX9-TLhR2PO0_60al1kQp5_e6k --time "${TIME}" &
pid=$!
PID_LIST+=" $pid"

wait $PID_LIST

kli oobi resolve --name holder --oobi-alias multisig --oobi http://127.0.0.1:5642/oobi/ENaQNFvFDTCWkoE3O5qTX_JfWLT3HxA2TvmOE-LeSsix/witness
kli oobi resolve --name holder --oobi-alias vc --oobi http://127.0.0.1:7723/oobi/EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao

echo "Polling for holder's IPEX message..."
SAID=$(kli ipex list --name holder --alias holder --poll --said)

echo "Admitting GRANT ${SAID}"
kli ipex admit --name holder --alias holder --said "${SAID}"

echo "Admitted the GRANT"
kli ipex list --name holder --alias holder

echo "Now possess the credential"
kli vc list --name holder --alias holder --poll



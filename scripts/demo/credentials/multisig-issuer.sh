#!/bin/bash
# To run this script you need to run the following command in separate terminals:
#   > kli witness demo
# and from the vLEI repo run:
#   > vLEI-server -s ./schema/acdc -c ./samples/acdc/ -o ./samples/oobis/
#

# Create local environments for multisig group
kli init --name multisig1 --salt 0ACDEyMzQ1Njc4OWxtbm9aBc --nopasscode --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis
kli incept --name multisig1 --alias multisig1 --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-1-sample.json

# Incept both local identifiers for multisig group
kli init --name multisig2 --salt 0ACDEyMzQ1Njc4OWdoaWpsaw --nopasscode --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis
kli incept --name multisig2 --alias multisig2 --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-2-sample.json

# Exchange OOBIs between multisig group
kli oobi resolve --name multisig1 --oobi-alias multisig2 --oobi http://127.0.0.1:5642/oobi/EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1/witness
kli oobi resolve --name multisig2 --oobi-alias multisig1 --oobi http://127.0.0.1:5642/oobi/EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4/witness

# Create the identifier to which the credential will be issued
kli init --name holder --salt 0ACDEyMzQ1Njc4OWxtbm9qWc --nopasscode --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis
kli incept --name holder --alias holder --file ${KERI_DEMO_SCRIPT_DIR}/data/gleif-sample.json

# Introduce multisig to Holder
kli oobi resolve --name holder --oobi-alias multisig2 --oobi http://127.0.0.1:5642/oobi/EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1/witness
kli oobi resolve --name holder --oobi-alias multisig1 --oobi http://127.0.0.1:5642/oobi/EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4/witness

# Introduce the holder to all participants in the multisig group
kli oobi resolve --name multisig1 --oobi-alias holder --oobi http://127.0.0.1:5642/oobi/ELjSFdrTdCebJlmvbFNX9-TLhR2PO0_60al1kQp5_e6k/witness
kli oobi resolve --name multisig2 --oobi-alias holder --oobi http://127.0.0.1:5642/oobi/ELjSFdrTdCebJlmvbFNX9-TLhR2PO0_60al1kQp5_e6k/witness

# Load Data OOBI for schema of credential to issue
kli oobi resolve --name multisig1 --oobi-alias vc --oobi http://127.0.0.1:7723/oobi/EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao
kli oobi resolve --name multisig2 --oobi-alias vc --oobi http://127.0.0.1:7723/oobi/EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao
kli oobi resolve --name holder --oobi-alias vc --oobi http://127.0.0.1:7723/oobi/EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao

# Run the follow in parallel and wait for the group to be created:
kli multisig incept --name multisig1 --alias multisig1 --group multisig --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-sample.json &
pid=$!
PID_LIST+=" $pid"

kli multisig incept --name multisig2 --alias multisig2 --group multisig --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-sample.json &
pid=$!
PID_LIST+=" $pid"

wait $PID_LIST

# Create a credential registry owned by the multisig issuer
kli vc registry incept --name multisig1 --alias multisig --registry-name vLEI --usage "Issue vLEIs" --nonce AHSNDV3ABI6U8OIgKaj3aky91ZpNL54I5_7-qwtC6q2s &
pid=$!
PID_LIST=" $pid"

kli vc registry incept --name multisig2 --alias multisig --registry-name vLEI --usage "Issue vLEIs" --nonce AHSNDV3ABI6U8OIgKaj3aky91ZpNL54I5_7-qwtC6q2s &
pid=$!
PID_LIST+=" $pid"

wait $PID_LIST

## Rotate multisig keys:
kli rotate --name multisig1 --alias multisig1
kli query --name multisig2 --alias multisig2 --prefix EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4
kli rotate --name multisig2 --alias multisig2
kli query --name multisig1 --alias multisig1 --prefix EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1

kli multisig rotate --name multisig1 --alias multisig --smids EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1:1 --smids EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4:1 &
pid=$!
PID_LIST=" $pid"

kli multisig rotate --name multisig2 --alias multisig --smids EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1:1 --smids EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4:1 &
pid=$!
PID_LIST+=" $pid"

wait $PID_LIST

# Issue Credential
TIME=$(date -Iseconds -u)
kli vc create --name multisig1 --alias multisig --registry-name vLEI --schema EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao --recipient ELjSFdrTdCebJlmvbFNX9-TLhR2PO0_60al1kQp5_e6k --data @${KERI_DEMO_SCRIPT_DIR}/data/credential-data.json --time "${TIME}" &
pid=$!
PID_LIST+=" $pid"

kli vc create --name multisig2 --alias multisig --registry-name vLEI --schema EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao --recipient ELjSFdrTdCebJlmvbFNX9-TLhR2PO0_60al1kQp5_e6k --data @${KERI_DEMO_SCRIPT_DIR}/data/credential-data.json --time "${TIME}" &
pid=$!
PID_LIST+=" $pid"

wait $PID_LIST

SAID=$(kli vc list --name multisig1 --alias multisig --issued --said)

kli ipex grant --name multisig1 --alias multisig --said "${SAID}" --recipient ELjSFdrTdCebJlmvbFNX9-TLhR2PO0_60al1kQp5_e6k --time "${TIME}" &
pid=$!
PID_LIST+=" $pid"

kli ipex grant --name multisig2 --alias multisig --said "${SAID}" --recipient ELjSFdrTdCebJlmvbFNX9-TLhR2PO0_60al1kQp5_e6k --time "${TIME}" &
pid=$!
PID_LIST+=" $pid"

wait $PID_LIST

kli oobi resolve --name holder --oobi-alias multisig --oobi http://127.0.0.1:5642/oobi/EC61gZ9lCKmHAS7U5ehUfEbGId5rcY0D7MirFZHDQcE2/witness

echo "Polling for holder's IPEX message..."
SAID=$(kli ipex list --name holder --alias holder --poll --said)

echo "Admitting GRANT ${SAID}"
kli ipex admit --name holder --alias holder --said "${SAID}"

kli vc list --name holder --alias holder --poll

SAID=$(kli vc list --name holder --alias holder --said --schema EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao)

echo "Revoking ${SAID}..."
TIME=$(date -Iseconds -u)
kli vc revoke --name multisig1 --alias multisig --registry-name vLEI --said "${SAID}" --time "${TIME}" &
pid=$!
PID_LIST=" $pid"

kli vc revoke --name multisig2 --alias multisig --registry-name vLEI --said "${SAID}" --time "${TIME}" &
pid=$!
PID_LIST+=" $pid"


wait $PID_LIST
kli vc list --name holder --alias holder --poll

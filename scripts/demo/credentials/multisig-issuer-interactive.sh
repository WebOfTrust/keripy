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
kli contacts replace --name multisig1 --prefix EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1 --alias multisig2
kli oobi resolve --name multisig2 --oobi-alias multisig1 --oobi http://127.0.0.1:5642/oobi/EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4/witness
kli contacts replace --name multisig2 --prefix EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4 --alias multisig1

# Create the identifier to which the credential will be issued
kli init --name holder --salt 0ACDEyMzQ1Njc4OWxtbm9qWc --nopasscode --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis
kli incept --name holder --alias holder --file ${KERI_DEMO_SCRIPT_DIR}/data/gleif-sample.json

# Introduce multisig to Holder
kli oobi resolve --name holder --oobi-alias multisig2 --oobi http://127.0.0.1:5642/oobi/EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1/witness
kli contacts replace --name holder --prefix EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1 --alias multisig2
kli oobi resolve --name holder --oobi-alias multisig1 --oobi http://127.0.0.1:5642/oobi/EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4/witness
kli contacts replace --name holder --prefix EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4 --alias multisig1

# Introduce the holder to all participants in the multisig group
kli oobi resolve --name multisig1 --oobi-alias holder --oobi http://127.0.0.1:5642/oobi/ELjSFdrTdCebJlmvbFNX9-TLhR2PO0_60al1kQp5_e6k/witness
kli contacts replace --name multisig1 --prefix ELjSFdrTdCebJlmvbFNX9-TLhR2PO0_60al1kQp5_e6k --alias holder
kli oobi resolve --name multisig2 --oobi-alias holder --oobi http://127.0.0.1:5642/oobi/ELjSFdrTdCebJlmvbFNX9-TLhR2PO0_60al1kQp5_e6k/witness
kli contacts replace --name multisig2 --prefix ELjSFdrTdCebJlmvbFNX9-TLhR2PO0_60al1kQp5_e6k --alias holder

# Load Data OOBI for schema of credential to issue
kli oobi resolve --name multisig1 --oobi-alias vc --oobi http://127.0.0.1:7723/oobi/EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao
kli oobi resolve --name multisig2 --oobi-alias vc --oobi http://127.0.0.1:7723/oobi/EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao
kli oobi resolve --name holder --oobi-alias vc --oobi http://127.0.0.1:7723/oobi/EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao

# Run the follow in parallel and wait for the group to be created:
kli multisig incept --name multisig1 --alias multisig1 --group multisig --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-sample.json &
pid=$!
PID_LIST+=" $pid"

#kli multisig incept --name multisig2 --alias multisig2 --group multisig --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-sample.json &
#pid=$!
#PID_LIST+=" $pid"
#
echo "Multisig2 looking to join inception event"
kli multisig join --name multisig2

wait $PID_LIST
kli oobi resolve --name holder --oobi-alias multisig --oobi http://127.0.0.1:5642/oobi/EC61gZ9lCKmHAS7U5ehUfEbGId5rcY0D7MirFZHDQcE2/witness
kli contacts replace --name holder --prefix EC61gZ9lCKmHAS7U5ehUfEbGId5rcY0D7MirFZHDQcE2 --alias multisig

# Create a credential registry owned by the multisig issuer
kli vc registry incept --name multisig1 --alias multisig --registry-name vLEI --usage "Issue vLEIs" --nonce AHSNDV3ABI6U8OIgKaj3aky91ZpNL54I5_7-qwtC6q2s &
pid=$!
PID_LIST=" $pid"

#kli vc registry incept --name multisig2 --alias multisig --registry-name vLEI --usage "Issue vLEIs" --nonce AHSNDV3ABI6U8OIgKaj3aky91ZpNL54I5_7-qwtC6q2s &
#pid=$!
#PID_LIST+=" $pid"

echo "Multisig2 looking to join credential registry creation"
kli multisig join --name multisig2

wait $PID_LIST

# Issue Credential
kli vc create --name multisig1 --alias multisig --registry-name vLEI --schema EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao --recipient ELjSFdrTdCebJlmvbFNX9-TLhR2PO0_60al1kQp5_e6k --data @${KERI_DEMO_SCRIPT_DIR}/data/credential-data.json &
pid=$!
PID_LIST+=" $pid"

# Wait for 3 seconds to allow credential.json to be created, but still launch in parallel because they will wait for each other
echo "Multisig2 looking to join credential creation"
kli multisig join --name multisig2

wait $PID_LIST

SAID=$(kli vc list --name multisig1 --alias multisig --issued --said)

kli ipex grant --name multisig1 --alias multisig --said "${SAID}" --recipient ELjSFdrTdCebJlmvbFNX9-TLhR2PO0_60al1kQp5_e6k &
pid=$!
PID_LIST="$pid"

kli ipex join --name multisig2

wait ${PID_LIST}

echo "Polling for holder's IPEX message..."
SAID=$(kli ipex list --name holder --alias holder --poll --said)

echo "Admitting GRANT ${SAID}"
kli ipex admit --name holder --alias holder --said "${SAID}"

kli vc list --name holder --alias holder

SAID=$(kli vc list --name holder --alias holder --said --schema EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao)

echo "Revoking ${SAID}..."
kli vc revoke --name multisig1 --alias multisig --registry-name vLEI --said "${SAID}"&
pid=$!
PID_LIST="$pid"

kli multisig join --name multisig2

wait $PID_LIST
kli vc list --name holder --alias holder --poll

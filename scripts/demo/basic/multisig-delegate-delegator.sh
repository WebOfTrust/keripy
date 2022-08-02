#!/bin/bash

echo "Creating delegate's first local identifier in delegate1 keystore"
kli init --name delegate1 --salt 0AMDEyMzQ1Njc4OWxtbm9wcQ --nopasscode --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis
kli incept --name delegate1 --alias delegate1 --file ${KERI_DEMO_SCRIPT_DIR}/data/delegate-1.json

echo "Creating delegate's second local identifier in delegate2 keystore"
kli init --name delegate2 --salt 0AMDEyMzQ1Njc4OWdoaWpsaw --nopasscode --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis
kli incept --name delegate2 --alias delegate2 --file ${KERI_DEMO_SCRIPT_DIR}/data/delegate-2.json

echo "Creating delegator's first local identifier in delegator1 keystore"
kli init --name delegator1 --nopasscode --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis --salt 0AMDEyMzQ1Njc4OWdoaWpdo1
kli incept --name delegator1 --alias delegator1 --file ${KERI_DEMO_SCRIPT_DIR}/data/delegator-1.json

echo "Creating delegator's second local identifier in delegator2 keystore"
kli init --name delegator2 --nopasscode --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis --salt 0AMDEyMzQ1Njc4OWdoaWpdo2
kli incept --name delegator2 --alias delegator2 --file ${KERI_DEMO_SCRIPT_DIR}/data/delegator-2.json

echo "Sharing OOBIs between delegate's two local identifiers"
kli oobi resolve --name delegate1 --oobi-alias delegate2 --oobi http://127.0.0.1:5642/oobi/E64X4wS9Oaps6NtcsE_rgNoxxAT5QzdGfGyUKu1ecHgo/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo
kli oobi resolve --name delegate2 --oobi-alias delegate1 --oobi http://127.0.0.1:5642/oobi/Eo6MekLECO_ZprzHwfi7wG2ubOt2DWKZQcMZvTbenBNU/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo
echo "Sharing OOBIs between delegator's two local identifiers"
kli oobi resolve --name delegator1 --oobi-alias delegator2 --oobi http://127.0.0.1:5642/oobi/EC1DxuYp8GgIDVQ2c8EYBaY1CwxozvQuqGxwppNVrapY/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo
kli oobi resolve --name delegator2 --oobi-alias delegator1 --oobi http://127.0.0.1:5642/oobi/Ef9Bhn_LeAU3rq8Rf3XHi5C1XmNdIM5uxv2DwWQT6qd8/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo

# In 2 delegator terminal windows run the following
kli multisig incept --name delegator1 --alias delegator1 --group delegator --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-delegator.json &
pid=$!
PID_LIST+=" $pid"

kli multisig incept --name delegator2 --alias delegator2 --group delegator --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-delegator.json &
pid=$!
PID_LIST+=" $pid"

# Wait for the multisig delegator to be created
wait $PID_LIST

# Delegator does not need an oobi for delegate.
kli oobi resolve --name delegate1 --oobi-alias delegator --oobi http://127.0.0.1:5642/oobi/EZbh5QuW1HI4dmYZrKYIjXE_34E5c2np8HjKggen7bu8/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo
kli oobi resolve --name delegate2 --oobi-alias delegator --oobi http://127.0.0.1:5642/oobi/EZbh5QuW1HI4dmYZrKYIjXE_34E5c2np8HjKggen7bu8/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo

# Run the delegate commands in parallel so they can collaborate and request delegation
kli multisig incept --name delegate1 --alias delegate1 --group delegate --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-delegate.json &
pid=$!
PID_LIST+=" $pid"

kli multisig incept --name delegate2 --alias delegate2 --group delegate --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-delegate.json &
pid=$!
PID_LIST+=" $pid"

# Wait for 3 seconds to allow the delegation request to complete and then launch the approval in parallel
sleep 3

kli multisig interact --name delegator1 --alias delegator --data @${KERI_DEMO_SCRIPT_DIR}/data/multisig-delegate-icp-anchor.json &
pid=$!
PID_LIST+=" $pid"

kli multisig interact --name delegator2 --alias delegator --data @${KERI_DEMO_SCRIPT_DIR}/data/multisig-delegate-icp-anchor.json &
pid=$!
PID_LIST+=" $pid"

wait $PID_LIST

kli status --name delegate2 --alias delegate

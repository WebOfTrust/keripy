#!/bin/bash

# WITNESSES
# To run the following scripts, open another console window and run:
# $ kli witness demo

kli init --name multisig1 --base "${KERI_TEMP_DIR}"  --salt 0ACDEyMzQ1Njc4OWxtbm9aBc --nopasscode --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis
kli incept --name multisig1 --base "${KERI_TEMP_DIR}"  --alias multisig1 --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-1-sample.json
#kli ends add --name multisig1 --base "${KERI_TEMP_DIR}" --alias multisig1 --eid BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM --role mailbox

kli init --name multisig2 --base "${KERI_TEMP_DIR}"  --salt 0ACDEyMzQ1Njc4OWdoaWpsaw --nopasscode --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis
kli incept --name multisig2 --base "${KERI_TEMP_DIR}"  --alias multisig2 --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-2-sample.json
#kli ends add --name multisig2 --base "${KERI_TEMP_DIR}" --alias multisig2 --eid BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX --role mailbox

kli oobi resolve --name multisig1 --base "${KERI_TEMP_DIR}"  --oobi-alias multisig2 --oobi http://127.0.0.1:5642/oobi/EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1
kli oobi resolve --name multisig2 --base "${KERI_TEMP_DIR}"  --oobi-alias multisig1 --oobi http://127.0.0.1:5642/oobi/EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4

# Follow commands run in parallel
kli multisig incept --name multisig1 --base "${KERI_TEMP_DIR}"  --alias multisig1 --group multisig --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-sample.json &
pid=$!
PID_LIST+=" $pid"
kli multisig incept --name multisig2 --base "${KERI_TEMP_DIR}"  --alias multisig2 --group multisig --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-sample.json &
pid=$!
PID_LIST+=" $pid"

wait $PID_LIST

kli status --name multisig1 --base "${KERI_TEMP_DIR}"  --alias multisig

TIME=$(date -Iseconds -u | sed 's/+00:00//').000000+00:00
kli ends add --base "${KERI_TEMP_DIR}" --name multisig1 --alias multisig --eid BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM --role mailbox --time "${TIME}" &
pid=$!
PID_LIST="$pid"

kli ends add --base "${KERI_TEMP_DIR}" --name multisig2 --alias multisig --eid BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM --role mailbox --time "${TIME}" &
pid=$!
PID_LIST+=" $pid"

wait $PID_LIST

echo "Test Complete"
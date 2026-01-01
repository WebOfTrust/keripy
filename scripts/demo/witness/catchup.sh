#!/bin/bash

# WITNESS CATCHUP TEST
#
# This script tests the scenario where a witness (wyz) loses data after
# receiving events. The catchup command is used to resync it.
#
# SETUP:
# 1. Start the witness demo (all witnesses):
#    $ kli witness demo
#
# 2. Run this script - it will:
#    - Create a multisig (all witnesses receive events including wyz)
#    - Prompt to delete wyz's database (simulating data loss)
#    - Restart witness demo
#    - Verify wyz no longer has the KEL
#    - Use catchup to resync wyz
#    - Verify wyz now has the KEL

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "========================================="
echo "WITNESS CATCHUP TEST"
echo ""
echo "Make sure 'kli witness demo' is running."
echo ""
echo "Press ENTER to continue..."
echo "========================================="
read

# Initialize keystores
kli init --name multisig1 --base "${KERI_TEMP_DIR}" --salt 0ACDEyMzQ1Njc4OWxtbm9aBc --nopasscode --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis
kli incept --name multisig1 --base "${KERI_TEMP_DIR}" --alias multisig1 --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-1-sample.json
kli ends add --name multisig1 --base "${KERI_TEMP_DIR}" --alias multisig1 --eid BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM --role mailbox

kli init --name multisig2 --base "${KERI_TEMP_DIR}" --salt 0ACDEyMzQ1Njc4OWdoaWpsaw --nopasscode --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis
kli incept --name multisig2 --base "${KERI_TEMP_DIR}" --alias multisig2 --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-2-sample.json
kli ends add --name multisig2 --base "${KERI_TEMP_DIR}" --alias multisig2 --eid BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX --role mailbox

# Resolve member OOBIs
kli oobi resolve --name multisig1 --base "${KERI_TEMP_DIR}" --oobi-alias multisig2 --oobi http://127.0.0.1:5642/oobi/EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1
kli oobi resolve --name multisig2 --base "${KERI_TEMP_DIR}" --oobi-alias multisig1 --oobi http://127.0.0.1:5642/oobi/EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4

# Resolve wyz witness OOBI so clients know its endpoint
kli oobi resolve --name multisig1 --base "${KERI_TEMP_DIR}" --oobi-alias wyz --oobi http://127.0.0.1:5647/oobi/BF2rZTW79z4IXocYRQnjjsOuvFUQv-ptCf8Yltd7PfsM/controller
kli oobi resolve --name multisig2 --base "${KERI_TEMP_DIR}" --oobi-alias wyz --oobi http://127.0.0.1:5647/oobi/BF2rZTW79z4IXocYRQnjjsOuvFUQv-ptCf8Yltd7PfsM/controller

echo ""
echo "===================================================="
echo "Creating multisig with wyz in witness list (toad=2)"
echo "All witnesses (including wyz) will receive events"
echo "===================================================="
echo ""

# Create multisig - all witnesses receive events
kli multisig incept --name multisig1 --base "${KERI_TEMP_DIR}" --alias multisig1 --group multisig --file ${SCRIPT_DIR}/multisig-catchup-sample.json &
pid=$!
PID_LIST="$pid"
kli multisig incept --name multisig2 --base "${KERI_TEMP_DIR}" --alias multisig2 --group multisig --file ${SCRIPT_DIR}/multisig-catchup-sample.json &
pid=$!
PID_LIST+=" $pid"

wait $PID_LIST
PID_LIST=""

echo ""
echo "Multisig created. Status:"
kli status --name multisig1 --base "${KERI_TEMP_DIR}" --alias multisig

# Do an interaction to add more events
TIME=$(date -Iseconds -u | sed 's/+00:00//').000000+00:00
kli ends add --base "${KERI_TEMP_DIR}" --name multisig1 --alias multisig --eid BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM --role mailbox --time "${TIME}" &
pid=$!
PID_LIST="$pid"
kli ends add --base "${KERI_TEMP_DIR}" --name multisig2 --alias multisig --eid BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM --role mailbox --time "${TIME}" &
pid=$!
PID_LIST+=" $pid"

wait $PID_LIST
PID_LIST=""

kli multisig interact --name multisig1 --base "${KERI_TEMP_DIR}" --alias multisig --data @${KERI_DEMO_SCRIPT_DIR}/data/anchor.json &
pid=$!
PID_LIST="$pid"
kli multisig interact --name multisig2 --base "${KERI_TEMP_DIR}" --alias multisig --data @${KERI_DEMO_SCRIPT_DIR}/data/anchor.json &
pid=$!
PID_LIST+=" $pid"

wait $PID_LIST
PID_LIST=""

echo ""
echo "Added interaction event. Current status:"
kli status --name multisig1 --base "${KERI_TEMP_DIR}" --alias multisig

# Get the multisig prefix for later use
MULTISIG_PRE=$(kli status --name multisig1 --base "${KERI_TEMP_DIR}" --alias multisig 2>&1 | grep "Identifier:" | awk '{print $2}')
echo ""
echo "Multisig prefix: ${MULTISIG_PRE}"

echo ""
echo "======================================================"
echo "Verifying wyz HAS the multisig KEL (before data loss)"
echo "======================================================"
WYZ_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:5647/oobi/${MULTISIG_PRE}")
if [ "$WYZ_STATUS" = "200" ]; then
    echo "PASS: wyz returns 200 - it has the multisig KEL"
else
    echo "FAIL: wyz returns ${WYZ_STATUS} - expected 200"
    exit 1
fi

echo ""
echo "======================================================================"
echo "SIMULATE DATA LOSS ON WYZ"
echo ""
echo "1. Stop the witness demo (Ctrl+C in that terminal)"
echo "2. Delete wyz's database:"
echo "   rm -rf ~/.keri/ks/wyz ~/.keri/db/wyz ~/.keri/cf/wyz ~/.keri/reg/wyz"
echo "3. Restart witness demo: kli witness demo"
echo ""
echo "Press ENTER when done..."
echo "======================================================================"
read

echo ""
echo "==========================================================================="
echo "ASSERTION: Verifying wyz does NOT have the multisig KEL (after data loss)"
echo "==========================================================================="
WYZ_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:5647/oobi/${MULTISIG_PRE}")
if [ "$WYZ_STATUS" = "404" ]; then
    echo "PASS: wyz returns 404 - it lost the multisig KEL (as expected)"
else
    echo "FAIL: wyz returns ${WYZ_STATUS} - expected 404 (data loss not simulated correctly)"
    exit 1
fi

# Create a temp keystore to verify OOBI from working witnesses
echo ""
echo "=================================================="
echo "Verifying OOBI works from wan (witness with data)"
echo "=================================================="
kli init --name temp --base "${KERI_TEMP_DIR}" --nopasscode
kli incept --name temp --base "${KERI_TEMP_DIR}" --alias temp --transferable --isith 1 --icount 1 --nsith 1 --ncount 1 --toad 0

kli oobi resolve --name temp --base "${KERI_TEMP_DIR}" --oobi-alias multisig --oobi http://127.0.0.1:5642/oobi/${MULTISIG_PRE}/witness
echo "OOBI from wan - kevers check:"
kli kevers --name temp --base "${KERI_TEMP_DIR}" --pre ${MULTISIG_PRE}

echo ""
echo "==================================================="
echo "Confirming OOBI from wyz fails (wyz lost its data)"
echo "==================================================="
echo "Skipping kli oobi resolve (would hang on 404) - curl assertion above confirms wyz has no data"

echo ""
echo "=============================="
echo "Using catchup to sync wyz..."
echo "=============================="
kli witness catchup --name multisig1 --base "${KERI_TEMP_DIR}" --alias multisig --witness BF2rZTW79z4IXocYRQnjjsOuvFUQv-ptCf8Yltd7PfsM

echo ""
echo "==================================================================="
echo "ASSERTION: Verifying wyz now HAS the multisig KEL (after catchup)"
echo "==================================================================="
WYZ_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:5647/oobi/${MULTISIG_PRE}")
if [ "$WYZ_STATUS" = "200" ]; then
    echo "PASS: wyz returns 200 - catchup restored the KEL"
else
    echo "FAIL: wyz returns ${WYZ_STATUS} - catchup did not work"
    exit 1
fi

echo ""
echo "Catchup complete. Testing OOBI from wyz..."

# Create temp keystore to verify OOBI now works from wyz
kli init --name temp2 --base "${KERI_TEMP_DIR}" --nopasscode
kli incept --name temp2 --base "${KERI_TEMP_DIR}" --alias temp2 --transferable --isith 1 --icount 1 --nsith 1 --ncount 1 --toad 0

kli oobi resolve --name temp2 --base "${KERI_TEMP_DIR}" --oobi-alias multisig --oobi http://127.0.0.1:5647/oobi/${MULTISIG_PRE}/witness

echo ""
echo "SUCCESS - Kevers from wyz after catchup:"
kli kevers --name temp2 --base "${KERI_TEMP_DIR}" --pre ${MULTISIG_PRE}

echo ""
echo "=============="
echo "Test Complete!"
echo "=============="

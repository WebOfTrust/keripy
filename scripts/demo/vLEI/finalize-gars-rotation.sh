#!/bin/bash
# Finalize a delegated rotation of the GARs multisig AID after external
# software has anchored the drt seal in Root's KEL.
#
# This script runs `kli multisig continue` on both GAR members in parallel.
# That command queries the delegator (Root) for the anchoring interaction
# event, pulls it via the witness mailbox, and commits the pending drt so
# GARs advances to sn=1.
#
# Prerequisites:
#   source scripts/demo/demo-scripts.sh
#   kli witness demo                       # in another terminal
#   ./scripts/demo/vLEI/setup-root-gars.sh  # Phase A, already run
#   ./scripts/demo/vLEI/rotate-gars.sh      # Phase C, drt dispatched, GARs pending
#   citadel (Root) has approved the GARs rotation and anchored it in Root's KEL.

# 22-character passcode shared by all keystores. Must match what was used by
# multisig-root-gars.sh.
PASSCODE="${PASSCODE:-DoB26Fj4x9LboAFWJra17O}"

# ---- Finalize GARs rotation on both members ----------------------------
kli multisig continue --name gar1 --passcode ${PASSCODE} --alias GARs &
PID_LIST+=" $!"
kli multisig continue --name gar2 --passcode ${PASSCODE} --alias GARs &
PID_LIST+=" $!"

wait $PID_LIST

kli status --name gar1 --passcode ${PASSCODE} --alias GARs

echo
echo "GARs rotation finalized."

#!/bin/bash
# Phase C of the Root/GARs reproducer.
#
# Rotates the GARs delegated multisig (keys only — same members, witnesses,
# 2-of-2 threshold). Each GAR local rotates first, then kli multisig rotate
# sends the drt delegation request exn. The script exits once the exn is
# on the wire; the drt anchoring is done by external software (citadel) on
# the Root side. Run finalize-gars-rotation.sh afterwards to commit.
#
# Must be run AFTER setup-root-gars.sh AND AFTER citadel has migrated the
# Root keystores. Running before migration leaves a 1.1.41-formatted entry
# in Root's pdes escrow that citadel's migration cannot read.
#cl
# Prerequisites:
#   source scripts/demo/demo-scripts.sh
#   kli witness demo                # in another terminal
#   ./setup-root-gars.sh            # already run
#   citadel/1.2.x                   # already pointed at root1/root2 and migrated

PASSCODE="${PASSCODE:-DoB26Fj4x9LboAFWJra17O}"

# KLI entrypoint. Defaults to the stock `kli` (logs at CRITICAL). For verbose
# tracing of the multisig rotate / drt exchange, point KLI at a debug wrapper
# that raises the ogler level before importing the cli, e.g.
#   KLI="python my-kli-debug.py"
KLI="${KLI:-kli}"

GAR1_PRE="EM0Di_wQZhUA0uKsR0gC0bSnOxcroCX-JbUuX9TBcvA1"
GAR2_PRE="EA7cQdIZoCoQGWbjdVQYBVo4aNURsQml-vnEV8RMaSIG"

# Refuse to run if a previous invocation's rotates are still alive — they
# survive script exit (nohup) and concurrent rotates on the same group jam
# the multisig sig exchange.
if pgrep -f "kli multisig rotate.*--alias GARs" > /dev/null; then
    echo "Stale 'kli multisig rotate --alias GARs' processes are still running." >&2
    echo "Kill them first: pkill -f 'kli multisig rotate.*--alias GARs'" >&2
    exit 1
fi

# ---- Rotate each GAR local ---------------------------------------------
kli rotate --name gar1 --passcode ${PASSCODE} --alias gar1
kli rotate --name gar2 --passcode ${PASSCODE} --alias gar2

# ---- Cross-query so each GAR local sees the other's new state ----------
kli query --name gar1 --passcode ${PASSCODE} --alias gar1 --prefix ${GAR2_PRE}
kli query --name gar2 --passcode ${PASSCODE} --alias gar2 --prefix ${GAR1_PRE}

# ---- Multisig rotate "GARs" (delegated rotation, drt) ------------------
# nohup + & so the rotates survive this script's exit. They need to keep
# running long enough to:
#   1. exchange sigs between gar1/gar2 via witness mailbox (multiple round-trips)
#   2. stage the drt in `dune`
#   3. have Anchorer.process send the /delegate/request exn to Root
# That whole sequence regularly takes 15-30s in practice.
nohup ${KLI} multisig rotate --name gar1 --passcode ${PASSCODE} --alias GARs \
    --smids ${GAR1_PRE}:1 --smids ${GAR2_PRE}:1 \
    --rmids ${GAR1_PRE}   --rmids ${GAR2_PRE} \
    > /tmp/rotate-gar1.log 2>&1 &
GAR1_PID=$!
nohup ${KLI} multisig rotate --name gar2 --passcode ${PASSCODE} --alias GARs \
    --smids ${GAR1_PRE}:1 --smids ${GAR2_PRE}:1 \
    --rmids ${GAR1_PRE}   --rmids ${GAR2_PRE} \
    > /tmp/rotate-gar2.log 2>&1 &
GAR2_PID=$!

# Hold long enough for the two members to exchange signatures, stage the drt
# in each member's `dune` (delegated-unanchored) escrow, and have the Anchorer
# dispatch the /delegate/request exn to Root.
sleep 30

# Stop the rotates now that the exn is on the wire. This leaves GARs genuinely
# pending at sn=0 (drt staged, awaiting the delegator's anchor) so Phase E
# (finalize-gars-rotation.sh) deterministically performs the delegate-side
# commit, rather than these lingering processes silently doing it.
kill ${GAR1_PID} ${GAR2_PID} 2>/dev/null
pkill -f "multisig rotate.*--alias GARs" 2>/dev/null  # sweep any re-parented stragglers

cat <<EOF
GARs drt request dispatched; rotate processes stopped.
  gar1 log=/tmp/rotate-gar1.log
  gar2 log=/tmp/rotate-gar2.log

GARs is now pending at sn=0 (drt staged, awaiting Root's anchor).

Next:
  1. In citadel (Root), approve the Delegated Rotation Approval.
  2. Run finalize-gars-rotation.sh to commit GARs to sn=1.

Verify the notice landed on Root:
  kli notifications list -n root1 -p ${PASSCODE}
should now include a /delegate/request entry.
EOF

#!/bin/bash

PID_LIST=""
kli init --name witness --nopasscode &
pid=$!
PID_LIST+=" $pid"

kli init --name witness2 --nopasscode &
pid=$!
PID_LIST+=" $pid"

wait $PID_LIST

PID_LIST=""
kli witness start --name witness --alias witness -T 5632 -H 5642 --config-dir "${KERI_SCRIPT_DIR}" --config-file witness &
pid=$!
PID_LIST+=" $pid"
kli witness start --name witness2 --alias witness2 -T 5652 -H 5662 --config-dir "${KERI_SCRIPT_DIR}" --config-file witness2 &
pid=$!
PID_LIST+=" $pid"
wait $PID_LIST

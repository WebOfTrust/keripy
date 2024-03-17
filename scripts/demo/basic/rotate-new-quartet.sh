#!/usr/bin/env bash

kli rotate --name multisig1 --alias multisig1
kli query --name multisig2 --alias multisig2 --prefix EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4
kli rotate --name multisig2 --alias multisig2
kli query --name multisig1 --alias multisig1 --prefix EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1

# Perform rotation of mulisig AID from local kli AIDs that roll themselves out and the new AIDs in
kli multisig rotate --name multisig1 --alias multisig \
         --smids EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4:1 \
         --smids EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1:1 \
         --smids EBFg-5SGDCv5YfwpkArWRBdTxNRUXU8uVcDKNzizOQZc:0 \
         --smids EBmW2bXbgsP3HITwW3FmITzAb3wVmHlxCusZ46vgGgP5:0 \
         --smids EL4RpdS2Atb2Syu5xLdpz9CcNNYoFUUDlLHxHD09vcgh:0 \
         --smids EAiBVuuhCZrgckeHc9KzROVGJpmGbk2-e1B25GaeRrJs:0 \
         --isith '["0", "0", "1/2", "1/2", "1/2", "1/2"]' \
         --rmids EBFg-5SGDCv5YfwpkArWRBdTxNRUXU8uVcDKNzizOQZc:0 \
         --rmids EBmW2bXbgsP3HITwW3FmITzAb3wVmHlxCusZ46vgGgP5:0 \
         --rmids EL4RpdS2Atb2Syu5xLdpz9CcNNYoFUUDlLHxHD09vcgh:0 \
         --rmids EAiBVuuhCZrgckeHc9KzROVGJpmGbk2-e1B25GaeRrJs:0 \
         --nsith '["1/2", "1/2", "1/2", "1/2"]' &
pid=$!
PID_LIST="$pid"
kli multisig rotate --name multisig2 --alias multisig \
         --smids EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4:1 \
         --smids EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1:1 \
         --smids EBFg-5SGDCv5YfwpkArWRBdTxNRUXU8uVcDKNzizOQZc:0 \
         --smids EBmW2bXbgsP3HITwW3FmITzAb3wVmHlxCusZ46vgGgP5:0 \
         --smids EL4RpdS2Atb2Syu5xLdpz9CcNNYoFUUDlLHxHD09vcgh:0 \
         --smids EAiBVuuhCZrgckeHc9KzROVGJpmGbk2-e1B25GaeRrJs:0 \
         --isith '["0", "0", "1/2", "1/2", "1/2", "1/2"]' \
         --rmids EBFg-5SGDCv5YfwpkArWRBdTxNRUXU8uVcDKNzizOQZc:0 \
         --rmids EBmW2bXbgsP3HITwW3FmITzAb3wVmHlxCusZ46vgGgP5:0 \
         --rmids EL4RpdS2Atb2Syu5xLdpz9CcNNYoFUUDlLHxHD09vcgh:0 \
         --rmids EAiBVuuhCZrgckeHc9KzROVGJpmGbk2-e1B25GaeRrJs:0 \
         --nsith '["1/2", "1/2", "1/2", "1/2"]' &
pid=$!
PID_LIST+=" $pid"

wait $PID_LIST

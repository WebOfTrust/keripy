#!/bin/bash

kli oobi resolve --name multisig1 --oobi-alias new-multisig1 --oobi http://127.0.0.1:3902/oobi/EBFg-5SGDCv5YfwpkArWRBdTxNRUXU8uVcDKNzizOQZc --force
kli oobi resolve --name multisig1 --oobi-alias new-multisig2 --oobi http://127.0.0.1:3902/oobi/EBmW2bXbgsP3HITwW3FmITzAb3wVmHlxCusZ46vgGgP5 --force
kli oobi resolve --name multisig1 --oobi-alias new-multisig3 --oobi http://127.0.0.1:3902/oobi/EL4RpdS2Atb2Syu5xLdpz9CcNNYoFUUDlLHxHD09vcgh --force
kli oobi resolve --name multisig1 --oobi-alias new-multisig4 --oobi http://127.0.0.1:3902/oobi/EAiBVuuhCZrgckeHc9KzROVGJpmGbk2-e1B25GaeRrJs --force

kli oobi resolve --name multisig2 --oobi-alias new-multisig1 --oobi http://127.0.0.1:3902/oobi/EBFg-5SGDCv5YfwpkArWRBdTxNRUXU8uVcDKNzizOQZc --force
kli oobi resolve --name multisig2 --oobi-alias new-multisig2 --oobi http://127.0.0.1:3902/oobi/EBmW2bXbgsP3HITwW3FmITzAb3wVmHlxCusZ46vgGgP5 --force
kli oobi resolve --name multisig2 --oobi-alias new-multisig3 --oobi http://127.0.0.1:3902/oobi/EL4RpdS2Atb2Syu5xLdpz9CcNNYoFUUDlLHxHD09vcgh --force
kli oobi resolve --name multisig2 --oobi-alias new-multisig4 --oobi http://127.0.0.1:3902/oobi/EAiBVuuhCZrgckeHc9KzROVGJpmGbk2-e1B25GaeRrJs --force


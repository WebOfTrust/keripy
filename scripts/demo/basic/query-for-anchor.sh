#!/bin/bash

kli init --name searcher --salt 0ACDEyMzQ1Njc4OWxtbm9aBc --nopasscode --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis
kli incept --name searcher --alias searcher --file ${KERI_DEMO_SCRIPT_DIR}/data/searcher-sample.json
kli ends add --name searcher --alias searcher --eid BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM --role mailbox

kli init --name anchorer --salt 0ACDEyMzQ1Njc4OWdoaWpsaw --nopasscode --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis
kli incept --name anchorer --alias anchorer --file ${KERI_DEMO_SCRIPT_DIR}/data/anchorer-sample.json
kli ends add --name anchorer --alias anchorer --eid BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX --role mailbox

kli oobi resolve --name searcher --oobi-alias anchorer --oobi http://127.0.0.1:5644/oobi/EK5bvqO2RP8MRTJnE_PHzAsESDj2dHU5avT5I8tuuIzK/witness
kli oobi resolve --name anchorer --oobi-alias searcher --oobi http://127.0.0.1:5643/oobi/EDbnNfFc1DqFLAOdGg_FGFDo5lo6EnYLyV7X9ZsAytT8/witness

kli query --name searcher --alias searcher --prefix EK5bvqO2RP8MRTJnE_PHzAsESDj2dHU5avT5I8tuuIzK --anchor ./scripts/demo/data/anchor.json &
pid=$!
PID_LIST+=" $pid"

kli interact --name anchorer --alias anchorer --data @./scripts/demo/data/anchor.json

wait $PID_LIST




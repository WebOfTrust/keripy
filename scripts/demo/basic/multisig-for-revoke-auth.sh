#!/bin/bash

# This script models revokable authority

# Initialize and incept the 3 parties
kli init -n multisig1 --salt 0ACDEyMzQ1Njc4OWdoaWpsaw --nopasscode --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis
kli incept -n multisig1 --alias multisig1 --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-1-sample.json

kli init -n multisig2 --salt 0ACDEyMzQ1Njc4OWdoaWphea --nopasscode --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis
kli incept -n multisig2 --alias multisig2 --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-2-sample.json

kli init -n multisig3 --salt 0ACDEyMzQ1Njc4OWdoaWpomw --nopasscode --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis
kli incept -n multisig3 --alias multisig3 --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-3-sample.json

# Resolve OOBIs to establish connections
kli oobi resolve -n multisig1 --oobi-alias multisig2 --oobi http://127.0.0.1:5642/oobi/EDC4X7ia6uAGGLQ20UgUdcIix_YgWlkNK_wC8e3ShTAC/witness
kli oobi resolve -n multisig2 --oobi-alias multisig1 --oobi http://127.0.0.1:5642/oobi/EI0jXuw_V_zjj_mFgJLJWgFtbpVRNdUmv01WoM4na1ek/witness

kli oobi resolve -n multisig1 --oobi-alias multisig3 --oobi http://127.0.0.1:5642/oobi/EIwtBwakOchYfReVjZnou_ZR9pA9Sjd877Y4pegfOGSC/witness
kli oobi resolve -n multisig3 --oobi-alias multisig1 --oobi http://127.0.0.1:5642/oobi/EI0jXuw_V_zjj_mFgJLJWgFtbpVRNdUmv01WoM4na1ek/witness

kli oobi resolve -n multisig2 --oobi-alias multisig3 --oobi http://127.0.0.1:5642/oobi/EIwtBwakOchYfReVjZnou_ZR9pA9Sjd877Y4pegfOGSC/witness
kli oobi resolve -n multisig3 --oobi-alias multisig2 --oobi http://127.0.0.1:5642/oobi/EDC4X7ia6uAGGLQ20UgUdcIix_YgWlkNK_wC8e3ShTAC/witness

# Incept a multisig group for multisig1 and multisig2 using a shared configuration file
kli multisig incept -n multisig1 --alias multisig1 --group multisig --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-sign-auth.json &
pid=$!
PID_LIST+=" $pid"

kli multisig incept -n multisig2 --alias multisig2 --group multisig --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-sign-auth.json &
pid=$!
PID_LIST+=" $pid"

wait $PID_LIST

# Rotate the keys for multisig2
# This models the ability of the second party to rotate keys and potentially exclude the first party's key
kli rotate -n multisig2 --alias multisig2

# Query the state of multisig3 to check the current configuration
kli query --name multisig3 --alias multisig3 --prefix EDC4X7ia6uAGGLQ20UgUdcIix_YgWlkNK_wC8e3ShTAC

# Resolve OOBIs for multisig3 to update its state with the latest information
kli oobi resolve -n multisig3 --oobi-alias multisig --oobi http://127.0.0.1:5642/oobi/EPKgQWXeBFsE9DjyqvspoPX1JVmRbRlNkCCaqvEeppM6/witness

# Perform a multisig rotate operation for multisig2
# The smids (signing member identifiers) and rmids (rotation member identifiers) are used to configure the new state
# The new state excludes the first party's key, effectively revoking its signing privileges
kli multisig rotate -n multisig2 --alias multisig \
    --smids EDC4X7ia6uAGGLQ20UgUdcIix_YgWlkNK_wC8e3ShTAC:1 \
    --smids EIwtBwakOchYfReVjZnou_ZR9pA9Sjd877Y4pegfOGSC:0 \
    --isith '["0","1"]' \
    --rmids EDC4X7ia6uAGGLQ20UgUdcIix_YgWlkNK_wC8e3ShTAC:1 \
    --rmids EIwtBwakOchYfReVjZnou_ZR9pA9Sjd877Y4pegfOGSC:0 \
    --nsith '["1","0"]' &
pid=$!
PID_LIST="$pid"

# Join the multisig group for multisig3 to synchronize its state
kli multisig join --name multisig3 --auto &
pid=$!
PID_LIST+=" $pid"

# Wait for all background processes to complete
wait $PID_LIST
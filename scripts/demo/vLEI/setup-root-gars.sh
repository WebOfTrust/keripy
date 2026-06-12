#!/bin/bash
# Creates a 2-of-2 EstablishmentOnly multisig "Root" AID and a 2-of-2 multisig "GARs" AID
# delegated from Root, anchors the GARs inception in Root's KEL via
# kli delegate confirm.

WITNESS_HOST="http://127.0.0.1:5642"
WIT="BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha"

PASSCODE="${PASSCODE:-DoB26Fj4x9LboAFWJra17O}"

ROOT1_PRE="EF11YNn4i0r0dX1KNrWs_ATQH878L3blwCMOSgwQVi57"
ROOT2_PRE="ENBdaRLJH7JOBAZo6aZbXelFP_I9yMd-RFrJ6pJ7V3CY"
GAR1_PRE="EM0Di_wQZhUA0uKsR0gC0bSnOxcroCX-JbUuX9TBcvA1"
GAR2_PRE="EA7cQdIZoCoQGWbjdVQYBVo4aNURsQml-vnEV8RMaSIG"
ROOT_PRE="ECbVd-kmWq0J8DHxLN6bKz3WbHtSl8RgeTD3VtnF9tQ4"
GARS_PRE="EAbWX_-KFnE51AB7pi9UJNDCQwjmPXvmzkB7RJJWv4pG"

# Root
kli init --name root1 --passcode ${PASSCODE} --salt 0ACDEyMzQ1Njc4OWdoaWpdo1 --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis
kli incept --name root1 --passcode ${PASSCODE} --alias root1 --file ${KERI_DEMO_SCRIPT_DIR}/data/delegator-1.json

kli init --name root2 --passcode ${PASSCODE} --salt 0ACDEyMzQ1Njc4OWdoaWpdo2 --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis
kli incept --name root2 --passcode ${PASSCODE} --alias root2 --file ${KERI_DEMO_SCRIPT_DIR}/data/delegator-2.json

# GARs
kli init --name gar1 --passcode ${PASSCODE} --salt 0ACDEyMzQ1Njc4OWdoaWpdo3 --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis
kli incept --name gar1 --passcode ${PASSCODE} --alias gar1 --file ${KERI_DEMO_SCRIPT_DIR}/data/gars-1.json

kli init --name gar2 --passcode ${PASSCODE} --salt 0ACDEyMzQ1Njc4OWdoaWpdo4 --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis
kli incept --name gar2 --passcode ${PASSCODE} --alias gar2 --file ${KERI_DEMO_SCRIPT_DIR}/data/gars-2.json

kli oobi resolve --name root1 --passcode ${PASSCODE} --oobi-alias root2 --oobi ${WITNESS_HOST}/oobi/${ROOT2_PRE}/witness/${WIT}
kli oobi resolve --name root2 --passcode ${PASSCODE} --oobi-alias root1 --oobi ${WITNESS_HOST}/oobi/${ROOT1_PRE}/witness/${WIT}

# Multisig incept for Root
kli multisig incept --name root1 --passcode ${PASSCODE} --alias root1 --group Root --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-root.json &
PID_LIST+=" $!"
kli multisig incept --name root2 --passcode ${PASSCODE} --alias root2 --group Root --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-root.json &
PID_LIST+=" $!"
wait $PID_LIST
unset PID_LIST

kli oobi resolve --name gar1 --passcode ${PASSCODE} --oobi-alias gar2 --oobi ${WITNESS_HOST}/oobi/${GAR2_PRE}/witness/${WIT}
kli oobi resolve --name gar2 --passcode ${PASSCODE} --oobi-alias gar1 --oobi ${WITNESS_HOST}/oobi/${GAR1_PRE}/witness/${WIT}
kli oobi resolve --name gar1 --passcode ${PASSCODE} --oobi-alias Root --oobi ${WITNESS_HOST}/oobi/${ROOT_PRE}/witness/${WIT}
kli oobi resolve --name gar2 --passcode ${PASSCODE} --oobi-alias Root --oobi ${WITNESS_HOST}/oobi/${ROOT_PRE}/witness/${WIT}

kli oobi resolve --name root1 --passcode ${PASSCODE} --oobi-alias gar1 --oobi ${WITNESS_HOST}/oobi/${GAR1_PRE}/witness/${WIT}
kli oobi resolve --name root1 --passcode ${PASSCODE} --oobi-alias gar2 --oobi ${WITNESS_HOST}/oobi/${GAR2_PRE}/witness/${WIT}
kli oobi resolve --name root2 --passcode ${PASSCODE} --oobi-alias gar1 --oobi ${WITNESS_HOST}/oobi/${GAR1_PRE}/witness/${WIT}
kli oobi resolve --name root2 --passcode ${PASSCODE} --oobi-alias gar2 --oobi ${WITNESS_HOST}/oobi/${GAR2_PRE}/witness/${WIT}

# Pre-rotate Root members so the group can rotate to approve
kli rotate --name root1 --passcode ${PASSCODE} --alias root1
kli rotate --name root2 --passcode ${PASSCODE} --alias root2
kli query --name root1 --passcode ${PASSCODE} --alias root1 --prefix ${ROOT2_PRE}
kli query --name root2 --passcode ${PASSCODE} --alias root2 --prefix ${ROOT1_PRE}

# Multisig incept GARs
kli multisig incept --name gar1 --passcode ${PASSCODE} --alias gar1 --group GARs --wait 90 --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-gars.json &
PID_LIST+=" $!"
kli multisig incept --name gar2 --passcode ${PASSCODE} --alias gar2 --group GARs --wait 90 --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-gars.json &
PID_LIST+=" $!"

# give the delegation request time to reach the Root members
sleep 3

# Root approves the GARs inception with anchor in a rotation
kli delegate confirm --name root1 --passcode ${PASSCODE} --alias Root --auto &
PID_LIST+=" $!"
kli delegate confirm --name root2 --passcode ${PASSCODE} --alias Root --auto &
PID_LIST+=" $!"

wait $PID_LIST
unset PID_LIST

sleep 2  # let GARs gather witness receipts on its now-anchored dip
kli oobi resolve --name root1 --passcode ${PASSCODE} --oobi-alias GARs --oobi ${WITNESS_HOST}/oobi/${GARS_PRE}/witness/${WIT}
kli oobi resolve --name root2 --passcode ${PASSCODE} --oobi-alias GARs --oobi ${WITNESS_HOST}/oobi/${GARS_PRE}/witness/${WIT}

# Verify the delegated GARs multisig incepted and anchored by Root
kli status --name root1 --passcode ${PASSCODE} --alias Root

kli status --name gar1 --passcode ${PASSCODE} --alias GARs
kli status --name gar2 --passcode ${PASSCODE} --alias GARs

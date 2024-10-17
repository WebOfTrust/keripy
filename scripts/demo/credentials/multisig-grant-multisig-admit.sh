#!/bin/bash
# To run this script you need to run the following command in separate terminals:
#   > kli witness demo
# and from the vLEI repo run:
#   > vLEI-server -s ./schema/acdc -c ./samples/acdc/ -o ./samples/oobis/
#

# issuer 1
# EEVlFHcMWAQNwezHjyKK5cKKzF6zgLlnrLyi_CcAEXCs
# issuer 2
# EFJtDtSoE6XOOqLoLvYoB7ctCzMtJDiAJltnXiK_EdlM
# issuee 1
# EI0IoYyHxXc7_uQyaN2WocSC3lRZsvrDAPbREOw7fM0_
# issuee 2
# EPw5WQAFcNXXSbg_pTKgh8-K_rfXnD1uDKS13OeNHkKE
# issuer group
# ELrnb8aI_wy2q_sSbCAwkgy2kOdMpRI1urFrhQiMJGLW
# issuee group
# ELkmm28zQEyxkryJZQ4WVT4fjukklM4dR91l2DQfQHZK

# Create local environments for issuer group
kli init --name issuer1 --salt 0ACDEyMzQ1Njc4OWxtbm9aBc --nopasscode --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis
kli incept --name issuer1 --alias issuer1 --file ${KERI_DEMO_SCRIPT_DIR}/data/issuer-1-sample.json

# Incept both local identifiers for issuer group
kli init --name issuer2 --salt 0ACDEyMzQ1Njc4OWdoaWpsaw --nopasscode --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis
kli incept --name issuer2 --alias issuer2 --file ${KERI_DEMO_SCRIPT_DIR}/data/issuer-2-sample.json

# Exchange OOBIs between issuer group
kli oobi resolve --name issuer1 --oobi-alias issuer2 --oobi http://127.0.0.1:5642/oobi/EFJtDtSoE6XOOqLoLvYoB7ctCzMtJDiAJltnXiK_EdlM/witness
kli contacts replace --name issuer1 --prefix EFJtDtSoE6XOOqLoLvYoB7ctCzMtJDiAJltnXiK_EdlM --alias issuer2
kli oobi resolve --name issuer2 --oobi-alias issuer1 --oobi http://127.0.0.1:5642/oobi/EEVlFHcMWAQNwezHjyKK5cKKzF6zgLlnrLyi_CcAEXCs/witness
kli contacts replace --name issuer2 --prefix EEVlFHcMWAQNwezHjyKK5cKKzF6zgLlnrLyi_CcAEXCs --alias issuer1

# Create the identifier to which the credential will be issued
kli init --name issuee1 --salt 0ACDEyMzQ1Njc4OWxtbm9qWc --nopasscode --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis
kli incept --name issuee1 --alias issuee1 --file ${KERI_DEMO_SCRIPT_DIR}/data/issuee-1-sample.json

# Create the identifier to which the credential will be issued
kli init --name issuee2 --salt 0ACDEyMzQ1Njc4OWxtbm9qWc --nopasscode --config-dir ${KERI_SCRIPT_DIR} --config-file demo-witness-oobis
kli incept --name issuee2 --alias issuee2 --file ${KERI_DEMO_SCRIPT_DIR}/data/issuee-2-sample.json

# Exchange OOBIs between issuee group
kli oobi resolve --name issuee1 --oobi-alias issuee2 --oobi http://127.0.0.1:5642/oobi/EPw5WQAFcNXXSbg_pTKgh8-K_rfXnD1uDKS13OeNHkKE/witness
kli contacts replace --name issuee1 --prefix EPw5WQAFcNXXSbg_pTKgh8-K_rfXnD1uDKS13OeNHkKE --alias issuee2
kli oobi resolve --name issuee2 --oobi-alias issuee1 --oobi http://127.0.0.1:5642/oobi/EI0IoYyHxXc7_uQyaN2WocSC3lRZsvrDAPbREOw7fM0_/witness
kli contacts replace --name issuee2 --prefix EI0IoYyHxXc7_uQyaN2WocSC3lRZsvrDAPbREOw7fM0_ --alias issuee1

# Introduce issuer to issuee
kli oobi resolve --name issuee1 --oobi-alias issuer1 --oobi http://127.0.0.1:5642/oobi/EEVlFHcMWAQNwezHjyKK5cKKzF6zgLlnrLyi_CcAEXCs/witness
kli contacts replace --name issuee1 --prefix EEVlFHcMWAQNwezHjyKK5cKKzF6zgLlnrLyi_CcAEXCs --alias issuer1
kli oobi resolve --name issuee2 --oobi-alias issuer1 --oobi http://127.0.0.1:5642/oobi/EEVlFHcMWAQNwezHjyKK5cKKzF6zgLlnrLyi_CcAEXCs/witness
kli contacts replace --name issuee2 --prefix EEVlFHcMWAQNwezHjyKK5cKKzF6zgLlnrLyi_CcAEXCs --alias issuer1
kli oobi resolve --name issuee1 --oobi-alias issuer2 --oobi http://127.0.0.1:5642/oobi/EFJtDtSoE6XOOqLoLvYoB7ctCzMtJDiAJltnXiK_EdlM/witness
kli contacts replace --name issuee1 --prefix EFJtDtSoE6XOOqLoLvYoB7ctCzMtJDiAJltnXiK_EdlM --alias issuer2
kli oobi resolve --name issuee2 --oobi-alias issuer2 --oobi http://127.0.0.1:5642/oobi/EFJtDtSoE6XOOqLoLvYoB7ctCzMtJDiAJltnXiK_EdlM/witness
kli contacts replace --name issuee2 --prefix EFJtDtSoE6XOOqLoLvYoB7ctCzMtJDiAJltnXiK_EdlM --alias issuer2

# Introduce the issuee to issuer
kli oobi resolve --name issuer1 --oobi-alias issuee1 --oobi http://127.0.0.1:5642/oobi/EI0IoYyHxXc7_uQyaN2WocSC3lRZsvrDAPbREOw7fM0_/witness
kli contacts replace --name issuer1 --prefix EI0IoYyHxXc7_uQyaN2WocSC3lRZsvrDAPbREOw7fM0_ --alias issuee1
kli oobi resolve --name issuer2 --oobi-alias issuee1 --oobi http://127.0.0.1:5642/oobi/EI0IoYyHxXc7_uQyaN2WocSC3lRZsvrDAPbREOw7fM0_/witness
kli contacts replace --name issuer2 --prefix EI0IoYyHxXc7_uQyaN2WocSC3lRZsvrDAPbREOw7fM0_ --alias issuee1
kli oobi resolve --name issuer1 --oobi-alias issuee2 --oobi http://127.0.0.1:5642/oobi/EPw5WQAFcNXXSbg_pTKgh8-K_rfXnD1uDKS13OeNHkKE/witness
kli contacts replace --name issuer1 --prefix EPw5WQAFcNXXSbg_pTKgh8-K_rfXnD1uDKS13OeNHkKE --alias issuee2
kli oobi resolve --name issuer2 --oobi-alias issuee2 --oobi http://127.0.0.1:5642/oobi/EPw5WQAFcNXXSbg_pTKgh8-K_rfXnD1uDKS13OeNHkKE/witness
kli contacts replace --name issuer2 --prefix EPw5WQAFcNXXSbg_pTKgh8-K_rfXnD1uDKS13OeNHkKE --alias issuee2

## Load Data OOBI for schema of credential to issue
kli oobi resolve --name issuer1 --oobi-alias vc --oobi http://127.0.0.1:7723/oobi/EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao
kli oobi resolve --name issuer2 --oobi-alias vc --oobi http://127.0.0.1:7723/oobi/EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao
kli oobi resolve --name issuee1 --oobi-alias vc --oobi http://127.0.0.1:7723/oobi/EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao
kli oobi resolve --name issuee2 --oobi-alias vc --oobi http://127.0.0.1:7723/oobi/EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao

# Run the follow in parallel and wait for the issuer group to be created:
kli multisig incept --name issuer1 --alias issuer1 --group issuer --file ${KERI_DEMO_SCRIPT_DIR}/data/issuer-multisig-sample.json &
pid=$!
PID_LIST+=" $pid"

kli multisig join --name issuer2
pid=$!
PID_LIST+=" $pid"

wait $PID_LIST

# Run the follow in parallel and wait for the issuee group to be created:
kli multisig incept --name issuee1 --alias issuee1 --group issuee --file ${KERI_DEMO_SCRIPT_DIR}/data/issuee-multisig-sample.json &
pid=$!
PID_LIST+=" $pid"

kli multisig join --name issuee2
pid=$!
PID_LIST+=" $pid"

wait $PID_LIST

# Introduce issuer issuer issuer to issuees
kli oobi resolve --name issuer1 --oobi-alias issuee --oobi http://127.0.0.1:5642/oobi/ELkmm28zQEyxkryJZQ4WVT4fjukklM4dR91l2DQfQHZK/witness
kli contacts replace --name issuer1 --prefix ELkmm28zQEyxkryJZQ4WVT4fjukklM4dR91l2DQfQHZK --alias issuee
kli oobi resolve --name issuer2 --oobi-alias issuee --oobi http://127.0.0.1:5642/oobi/ELkmm28zQEyxkryJZQ4WVT4fjukklM4dR91l2DQfQHZK/witness
kli contacts replace --name issuer2 --prefix ELkmm28zQEyxkryJZQ4WVT4fjukklM4dR91l2DQfQHZK --alias issuee

kli oobi resolve --name issuee1 --oobi-alias issuer --oobi http://127.0.0.1:5642/oobi/ELrnb8aI_wy2q_sSbCAwkgy2kOdMpRI1urFrhQiMJGLW/witness
kli contacts replace --name issuee1 --prefix ELrnb8aI_wy2q_sSbCAwkgy2kOdMpRI1urFrhQiMJGLW --alias issuer
kli oobi resolve --name issuee2 --oobi-alias issuer --oobi http://127.0.0.1:5642/oobi/ELrnb8aI_wy2q_sSbCAwkgy2kOdMpRI1urFrhQiMJGLW/witness
kli contacts replace --name issuee2 --prefix ELrnb8aI_wy2q_sSbCAwkgy2kOdMpRI1urFrhQiMJGLW --alias issuer

# Create a credential registry owned by the issuer issuer
kli vc registry incept --name issuer1 --alias issuer --registry-name vLEI --usage "Issue vLEIs" --nonce AHSNDV3ABI6U8OIgKaj3aky91ZpNL54I5_7-qwtC6q2s &
pid=$!
PID_LIST=" $pid"

echo "issuer2 looking to join credential registry creation"
kli multisig join --name issuer2

wait $PID_LIST

# Issue Credential
kli vc create --name issuer1 --alias issuer --registry-name vLEI --schema EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao --recipient ELkmm28zQEyxkryJZQ4WVT4fjukklM4dR91l2DQfQHZK --data @${KERI_DEMO_SCRIPT_DIR}/data/credential-data.json &
pid=$!
PID_LIST+=" $pid"

echo "issuer2 looking to join credential creation"
kli multisig join --name issuer2

wait $PID_LIST

SAID=$(kli vc list --name issuer1 --alias issuer --issued --said)

kli ipex grant --name issuer1 --alias issuer --said "${SAID}" --recipient ELkmm28zQEyxkryJZQ4WVT4fjukklM4dR91l2DQfQHZK &
pid=$!
PID_LIST="$pid"

kli ipex join --name issuer2

wait ${PID_LIST}

echo "Polling for issuee1's IPEX message..."
SAID=$(kli ipex list --name issuee1 --alias issuee1 --poll --said | sed -n '1 p')

echo "Polling for issuee2's IPEX message..."
kli ipex list --name issuee2 --alias issuee2 --poll --said

echo "Issuee1 Admitting GRANT ${SAID}"
kli ipex admit --name issuee1 --alias issuee --said "${SAID}" &
pid=$!
PID_LIST="$pid"

echo "Issuee2 Admitting GRANT ${SAID}"
kli ipex join --name issuee2

wait ${PID_LIST}

kli vc list --name issuee1 --alias issuee

echo "Issuer1 checking for ADMIT"
kli ipex list --name issuer1 --alias issuer --poll

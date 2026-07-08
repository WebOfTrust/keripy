#!/bin/bash
set -e

# three stooges

source "${KERI_SCRIPT_DIR}/demo/basic/script-utils.sh"

# WITNESSES
# To run the following scripts, open another console window and run:
# $ kli witness demo

print_yellow "Multisig rotation with three AIDs"
echo

kli init --name larry --base "${KERI_TEMP_DIR}" --salt 0ACDEyMzQ1Njc4OWxtbm9aBc --nopasscode --config-dir "${KERI_SCRIPT_DIR}" --config-file demo-witness-oobis --version 1.0
# Prefix EA5g3RMwkjcr_M4fI3k2ShCYlQMpgk3HD9mHhx7ZJs4U
kli incept --name larry --base "${KERI_TEMP_DIR}" --alias larry --version 1.0 --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-1-sample.json

kli init --name moe --base "${KERI_TEMP_DIR}" --salt 0ACDEyMzQ1Njc4OWdoaWpsaw --nopasscode --config-dir "${KERI_SCRIPT_DIR}" --config-file demo-witness-oobis --version 1.0
# Prefix ED7yk9oUIe5qRh8ILfTuT_sNHidrxwJ9Bl-tLPoAXbqW
kli incept --name moe --base "${KERI_TEMP_DIR}" --alias moe --version 1.0 --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-2-sample.json

kli init --name curly --base "${KERI_TEMP_DIR}" --salt 0ACDEyMzQ1Njc4OWdoaWpsaw --nopasscode --config-dir "${KERI_SCRIPT_DIR}" --config-file demo-witness-oobis --version 1.0
# Prefix EEHyoLseuHa0nuhDj9tBv6N6nU1PILwv4jTt5x8A8uLu
kli incept --name curly --base "${KERI_TEMP_DIR}" --alias curly --version 1.0 --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-3-sample.json

# OOBI resolution does the initial discovery of key state
echo
print_yellow "Resolve OOBIs"
kli oobi resolve --version 1.0 --name larry --base "${KERI_TEMP_DIR}" --oobi-alias moe --oobi http://127.0.0.1:5642/oobi/ED7yk9oUIe5qRh8ILfTuT_sNHidrxwJ9Bl-tLPoAXbqW/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --version 1.0 --name larry --base "${KERI_TEMP_DIR}" --oobi-alias curly --oobi http://127.0.0.1:5642/oobi/EEHyoLseuHa0nuhDj9tBv6N6nU1PILwv4jTt5x8A8uLu/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha

kli oobi resolve --version 1.0 --name moe --base "${KERI_TEMP_DIR}" --oobi-alias larry --oobi http://127.0.0.1:5642/oobi/EA5g3RMwkjcr_M4fI3k2ShCYlQMpgk3HD9mHhx7ZJs4U/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --version 1.0 --name moe --base "${KERI_TEMP_DIR}" --oobi-alias curly --oobi http://127.0.0.1:5642/oobi/EEHyoLseuHa0nuhDj9tBv6N6nU1PILwv4jTt5x8A8uLu/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha

kli oobi resolve --version 1.0 --name curly --base "${KERI_TEMP_DIR}" --oobi-alias larry --oobi http://127.0.0.1:5642/oobi/EA5g3RMwkjcr_M4fI3k2ShCYlQMpgk3HD9mHhx7ZJs4U/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --version 1.0 --name curly --base "${KERI_TEMP_DIR}" --oobi-alias moe --oobi http://127.0.0.1:5642/oobi/ED7yk9oUIe5qRh8ILfTuT_sNHidrxwJ9Bl-tLPoAXbqW/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha

# Multisig Inception
echo
print_yellow "Multisig Inception"
# Follow commands run in parallel
PID_LIST=""
kli multisig incept --name larry --base "${KERI_TEMP_DIR}" --alias larry --group multisig --version 1.0 --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-three-aids.json &
pid=$!
PID_LIST+=" $pid"
kli multisig incept --name moe --base "${KERI_TEMP_DIR}" --alias moe --group multisig --version 1.0 --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-three-aids.json &
pid=$!
PID_LIST+=" $pid"
kli multisig incept --name curly --base "${KERI_TEMP_DIR}" --alias curly --group multisig --version 1.0 --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-three-aids.json &
pid=$!
PID_LIST+=" $pid"

echo
print_yellow "Multisig Inception - wait"
wait $PID_LIST

echo
print_green "Multisig Inception - status"
kli status --name larry --base "${KERI_TEMP_DIR}" --alias multisig

# Rotate keys for each multisig - required before rotating the multisig
echo
print_yellow "Rotate keys for each multisig"
kli rotate --name larry --base "${KERI_TEMP_DIR}" --alias larry --version 1.0
kli rotate --name moe --base "${KERI_TEMP_DIR}" --alias moe --version 1.0
kli rotate --name curly --base "${KERI_TEMP_DIR}" --alias curly --version 1.0

# Pull key state in from other multisig group participant identifiers so they have the next digest
echo
print_yellow "Pull key state in from other multisig group participant identifiers"
# 2 about 1
kli query --name moe --base "${KERI_TEMP_DIR}" --alias moe --prefix EA5g3RMwkjcr_M4fI3k2ShCYlQMpgk3HD9mHhx7ZJs4U --version 1.0
# 2 about 3
kli query --name moe --base "${KERI_TEMP_DIR}" --alias moe --prefix EEHyoLseuHa0nuhDj9tBv6N6nU1PILwv4jTt5x8A8uLu --version 1.0
# 1 about 2
kli query --name larry --base "${KERI_TEMP_DIR}" --alias larry --prefix ED7yk9oUIe5qRh8ILfTuT_sNHidrxwJ9Bl-tLPoAXbqW --version 1.0
# 1 about 3
kli query --name larry --base "${KERI_TEMP_DIR}" --alias larry --prefix EEHyoLseuHa0nuhDj9tBv6N6nU1PILwv4jTt5x8A8uLu --version 1.0
# 3 about 1
kli query --name curly --base "${KERI_TEMP_DIR}" --alias curly --prefix EA5g3RMwkjcr_M4fI3k2ShCYlQMpgk3HD9mHhx7ZJs4U --version 1.0
# 3 about 2
kli query --name curly --base "${KERI_TEMP_DIR}" --alias curly --prefix ED7yk9oUIe5qRh8ILfTuT_sNHidrxwJ9Bl-tLPoAXbqW --version 1.0


echo
print_yellow "Multisig rotation"

PID_LIST=""

kli multisig rotate --name larry --base "${KERI_TEMP_DIR}" --alias multisig --smids EA5g3RMwkjcr_M4fI3k2ShCYlQMpgk3HD9mHhx7ZJs4U --smids ED7yk9oUIe5qRh8ILfTuT_sNHidrxwJ9Bl-tLPoAXbqW --smids EEHyoLseuHa0nuhDj9tBv6N6nU1PILwv4jTt5x8A8uLu --isith '["1/3", "1/3", "1/3"]' --nsith '["1/2", "1/2", "1/2"]' --rmids EA5g3RMwkjcr_M4fI3k2ShCYlQMpgk3HD9mHhx7ZJs4U --rmids ED7yk9oUIe5qRh8ILfTuT_sNHidrxwJ9Bl-tLPoAXbqW --rmids EEHyoLseuHa0nuhDj9tBv6N6nU1PILwv4jTt5x8A8uLu --version 1.0 &
pid=$!
PID_LIST+=" $pid"
kli multisig rotate --name moe --base "${KERI_TEMP_DIR}" --alias multisig --smids EA5g3RMwkjcr_M4fI3k2ShCYlQMpgk3HD9mHhx7ZJs4U --smids ED7yk9oUIe5qRh8ILfTuT_sNHidrxwJ9Bl-tLPoAXbqW --smids EEHyoLseuHa0nuhDj9tBv6N6nU1PILwv4jTt5x8A8uLu --isith '["1/3", "1/3", "1/3"]' --nsith '["1/2", "1/2", "1/2"]' --rmids EA5g3RMwkjcr_M4fI3k2ShCYlQMpgk3HD9mHhx7ZJs4U --rmids ED7yk9oUIe5qRh8ILfTuT_sNHidrxwJ9Bl-tLPoAXbqW --rmids EEHyoLseuHa0nuhDj9tBv6N6nU1PILwv4jTt5x8A8uLu --version 1.0 &
pid=$!
PID_LIST+=" $pid"
kli multisig rotate --name curly --base "${KERI_TEMP_DIR}" --alias multisig --smids EA5g3RMwkjcr_M4fI3k2ShCYlQMpgk3HD9mHhx7ZJs4U --smids ED7yk9oUIe5qRh8ILfTuT_sNHidrxwJ9Bl-tLPoAXbqW --smids EEHyoLseuHa0nuhDj9tBv6N6nU1PILwv4jTt5x8A8uLu --isith '["1/3", "1/3", "1/3"]' --nsith '["1/2", "1/2", "1/2"]' --rmids EA5g3RMwkjcr_M4fI3k2ShCYlQMpgk3HD9mHhx7ZJs4U --rmids ED7yk9oUIe5qRh8ILfTuT_sNHidrxwJ9Bl-tLPoAXbqW --rmids EEHyoLseuHa0nuhDj9tBv6N6nU1PILwv4jTt5x8A8uLu --version 1.0 &
pid=$!
PID_LIST+=" $pid"

echo
print_yellow "Multisig rotation - wait"
wait $PID_LIST

echo
print_green "Multisig rotation - status"
kli status --name larry --base "${KERI_TEMP_DIR}" --alias multisig

echo
print_yellow "Multisig interact"

PID_LIST=""

kli multisig interact --name larry --base "${KERI_TEMP_DIR}" --alias multisig --data "{\"tagline\":\"three lost souls\"}" --version 1.0 &
pid=$!
PID_LIST+=" $pid"
kli multisig interact --name moe --base "${KERI_TEMP_DIR}" --alias multisig --data "{\"tagline\":\"three lost souls\"}" --version 1.0 &
pid=$!
PID_LIST+=" $pid"
kli multisig interact --name curly --base "${KERI_TEMP_DIR}" --alias multisig --data "{\"tagline\":\"three lost souls\"}" --version 1.0 &
pid=$!
PID_LIST+=" $pid"

echo
print_yellow "Multisig interact - wait"
wait $PID_LIST

echo
print_green "Multisig interact - status"
kli status --name larry --base "${KERI_TEMP_DIR}" --alias multisig
print_lcyan "Multisig rotate three stooges - done."

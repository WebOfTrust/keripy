#!/bin/bash
#
# Minimal multisig export/import workflow with initial members M1, M2, and late-joiner M3.
#
# Prerequisites in separate terminals:
#   kli witness demo
#
# Script shows M3 as initially not seeing prior registry or issuance and then after export/import
# M3 sees registry and issuance

set -e

workflow_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
source "${workflow_dir}/../demo/demo-scripts.sh"

BASE="export-import-$$"
WORKFLOW_SCHEMA_DIR="${workflow_dir}/schema"
WORKFLOW_DATA_DIR="${workflow_dir}/data"
# .cesr files bundle dir name
BUNDLE="${KERI_SCRIPT_DIR}/${KERI_TEMP_DIR}/export-import-bundle-$$"
mkdir -p "${BUNDLE}"

WITNESS="BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha"
M1="EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4"
M2="EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1"
M3="ENkjt7khEI5edCMw5qugagbJw1QvGnQEtcewxb0FnU9U"
HOLDER="ELjSFdrTdCebJlmvbFNX9-TLhR2PO0_60al1kQp5_e6k"
GROUP="EC61gZ9lCKmHAS7U5ehUfEbGId5rcY0D7MirFZHDQcE2"
GLEIF_SCHEMA="EMQWEcCnVRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC"
GLEIF_SCHEMA_FILE="${WORKFLOW_SCHEMA_DIR}/gleif-vlei-credential-schema.json"
GLEIF_CREDENTIAL_DATA="${WORKFLOW_DATA_DIR}/credential-data.json"

echo "Using KLI base: ${BASE}"
echo "Using CESR bundle dir: ${BUNDLE}"

# Three Multisig participants, though multisig starts only with 2 up front.
kli init --name multisig1 --base "${BASE}" --salt 0ACDEyMzQ1Njc4OWxtbm9aBc --nopasscode --config-dir "${KERI_SCRIPT_DIR}" --config-file demo-witness-oobis
kli incept --name multisig1 --base "${BASE}" --alias multisig1 --file "${KERI_DEMO_SCRIPT_DIR}/data/multisig-1-sample.json"

kli init --name multisig2 --base "${BASE}" --salt 0ACDEyMzQ1Njc4OWdoaWpsaw --nopasscode --config-dir "${KERI_SCRIPT_DIR}" --config-file demo-witness-oobis
kli incept --name multisig2 --base "${BASE}" --alias multisig2 --file "${KERI_DEMO_SCRIPT_DIR}/data/multisig-2-sample.json"

kli init --name multisig3 --base "${BASE}" --salt 0ACDEyMzQ1Njc4OWdoaWpsaw --nopasscode --config-dir "${KERI_SCRIPT_DIR}" --config-file demo-witness-oobis
kli incept --name multisig3 --base "${BASE}" --alias multisig3 --file "${KERI_DEMO_SCRIPT_DIR}/data/multisig-3-sample.json"

# Credential holder the multisig issues ACDCs to.
kli init --name holder --base "${BASE}" --salt 0ACDEyMzQ1Njc4OWxtbm9qWc --nopasscode --config-dir "${KERI_SCRIPT_DIR}" --config-file demo-witness-oobis
kli incept --name holder --base "${BASE}" --alias holder --file "${KERI_DEMO_SCRIPT_DIR}/data/gleif-sample.json"

# import ACDC schema
for KLI_NAME in multisig1 multisig2 multisig3 holder; do
  kli vc schema import --name "${KLI_NAME}" --base "${BASE}" --schema "${GLEIF_SCHEMA_FILE}"
done

kli oobi resolve --name multisig1 --base "${BASE}" --oobi-alias multisig2 --oobi "http://127.0.0.1:5642/oobi/${M2}/witness/${WITNESS}"
kli oobi resolve --name multisig1 --base "${BASE}" --oobi-alias multisig3 --oobi "http://127.0.0.1:5642/oobi/${M3}/witness/${WITNESS}"
kli oobi resolve --name multisig1 --base "${BASE}" --oobi-alias holder --oobi "http://127.0.0.1:5642/oobi/${HOLDER}/witness/${WITNESS}"

kli oobi resolve --name multisig2 --base "${BASE}" --oobi-alias multisig1 --oobi "http://127.0.0.1:5642/oobi/${M1}/witness/${WITNESS}"
kli oobi resolve --name multisig2 --base "${BASE}" --oobi-alias multisig3 --oobi "http://127.0.0.1:5642/oobi/${M3}/witness/${WITNESS}"
kli oobi resolve --name multisig2 --base "${BASE}" --oobi-alias holder --oobi "http://127.0.0.1:5642/oobi/${HOLDER}/witness/${WITNESS}"

kli oobi resolve --name multisig3 --base "${BASE}" --oobi-alias multisig1 --oobi "http://127.0.0.1:5642/oobi/${M1}/witness/${WITNESS}"
kli oobi resolve --name multisig3 --base "${BASE}" --oobi-alias multisig2 --oobi "http://127.0.0.1:5642/oobi/${M2}/witness/${WITNESS}"

# create multisig with just M1 and M2, then registry, and then credential issuance.
PID_LIST=""
kli multisig incept --name multisig1 --base "${BASE}" --alias multisig1 --group multisig --file "${KERI_DEMO_SCRIPT_DIR}/data/multisig-sample.json" &
PID_LIST+=" $!"
kli multisig incept --name multisig2 --base "${BASE}" --alias multisig2 --group multisig --file "${KERI_DEMO_SCRIPT_DIR}/data/multisig-sample.json" &
PID_LIST+=" $!"
wait ${PID_LIST}

PID_LIST=""
kli vc registry incept --name multisig1 --base "${BASE}" --alias multisig --registry-name vLEI --usage "Issue vLEIs" --nonce AHSNDV3ABI6U8OIgKaj3aky91ZpNL54I5_7-qwtC6q2s &
PID_LIST+=" $!"
kli vc registry incept --name multisig2 --base "${BASE}" --alias multisig --registry-name vLEI --usage "Issue vLEIs" --nonce AHSNDV3ABI6U8OIgKaj3aky91ZpNL54I5_7-qwtC6q2s &
PID_LIST+=" $!"
wait ${PID_LIST}

TIME=$(date -Iseconds -u)
PID_LIST=""
kli vc create --name multisig1 --base "${BASE}" --alias multisig --registry-name vLEI --schema "${GLEIF_SCHEMA}" --recipient "${HOLDER}" --data @"${GLEIF_CREDENTIAL_DATA}" --time "${TIME}" &
PID_LIST+=" $!"
kli vc create --name multisig2 --base "${BASE}" --alias multisig --registry-name vLEI --schema "${GLEIF_SCHEMA}" --recipient "${HOLDER}" --data @"${GLEIF_CREDENTIAL_DATA}" --time "${TIME}" &
PID_LIST+=" $!"
wait ${PID_LIST}

# Gather expected registry and ACDC SAIDs from multisig1 so we can assert later that multisig3 sees them
EXPECTED_REGISTRY=$(kli vc registry list --name multisig1 --base "${BASE}" | awk '$1 == "vLEI" { print $3; exit }')
if [[ -z "${EXPECTED_REGISTRY}" ]]; then
  echo "Expected registry SAID was not found for multisig1" >&2
  exit 1
fi

EXPECTED_CREDENTIAL=$(kli vc list --name multisig1 --base "${BASE}" --alias multisig --issued --said --schema "${GLEIF_SCHEMA}" | awk 'NF { print; exit }')
if [[ -z "${EXPECTED_CREDENTIAL}" ]]; then
  echo "Expected credential SAID was not found for multisig1" >&2
  exit 1
fi

# prep M1 and M2 for rotating in M3, then rotate in M3
kli rotate --name multisig1 --base "${BASE}" --alias multisig1
kli query --name multisig2 --base "${BASE}" --alias multisig2 --prefix "${M1}"
kli rotate --name multisig2 --base "${BASE}" --alias multisig2
kli query --name multisig1 --base "${BASE}" --alias multisig1 --prefix "${M2}"

kli oobi resolve --name multisig3 --base "${BASE}" --oobi-alias multisig1 --oobi "http://127.0.0.1:5642/oobi/${M1}/witness/${WITNESS}"
kli oobi resolve --name multisig3 --base "${BASE}" --oobi-alias multisig2 --oobi "http://127.0.0.1:5642/oobi/${M2}/witness/${WITNESS}"
kli oobi resolve --name multisig3 --base "${BASE}" --oobi-alias multisig --oobi "http://127.0.0.1:5642/oobi/${GROUP}/witness/${WITNESS}"

PID_LIST=""
kli multisig rotate --name multisig1 --base "${BASE}" --alias multisig --smids "${M1}" --smids "${M2}" --smids "${M3}" --isith '["1/3", "1/3", "1/3"]' --nsith '["1/2", "1/2", "1/2"]' --rmids "${M1}" --rmids "${M2}" --rmids "${M3}" &
PID_LIST+=" $!"
kli multisig rotate --name multisig2 --base "${BASE}" --alias multisig --smids "${M1}" --smids "${M2}" --smids "${M3}" --isith '["1/3", "1/3", "1/3"]' --nsith '["1/2", "1/2", "1/2"]' --rmids "${M1}" --rmids "${M2}" --rmids "${M3}" &
PID_LIST+=" $!"
kli multisig join --name multisig3 --base "${BASE}" --group multisig --auto &
PID_LIST+=" $!"
wait ${PID_LIST}

# Export all .cesr files to the bundle directory.
(
  cd "${BUNDLE}"
  kli vc export --name multisig1 --base "${BASE}" --alias multisig --all-registries --all-credentials --full --files
)

# Import all .cesr files from bundle directory.
kli import --name multisig3 --base "${BASE}" --cesr-in "${BUNDLE}"

kli vc registry rename --name multisig3 --base "${BASE}" --registry-said "${EXPECTED_REGISTRY}" --new-name vLEI

echo
echo "Registries visible to multisig3 after import:"
M3_REGISTRIES=$(kli vc registry list --name multisig3 --base "${BASE}")
echo "${M3_REGISTRIES}"
# <<< feeds M3_REGISTRIES to grep as stdin, which then checks for the expected registry
if ! grep -Fq "${EXPECTED_REGISTRY}" <<< "${M3_REGISTRIES}"; then
  echo "Expected registry ${EXPECTED_REGISTRY} was not visible to multisig3" >&2
  exit 1
fi

echo
echo "Issued credentials visible to multisig3 after import:"
M3_CREDENTIALS=$(kli vc list --name multisig3 --base "${BASE}" --alias multisig --issued --said)
echo "${M3_CREDENTIALS}"
if ! grep -Fq "${EXPECTED_CREDENTIAL}" <<< "${M3_CREDENTIALS}"; then
  echo "Expected credential ${EXPECTED_CREDENTIAL} was not visible to multisig3" >&2
  exit 1
fi



echo
echo "Verified multisig3 sees registry ${EXPECTED_REGISTRY} and credential ${EXPECTED_CREDENTIAL}"

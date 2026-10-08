#!/bin/bash
set -euo pipefail


BASE="${BASE:-${KERI_SCRIPT_DIR}}"
MAILBOX_URL="${MAILBOX_URL:-http://127.0.0.1:9000/}"
MAILBOX_LOG="${MAILBOX_LOG:-${BASE}/mailbox.log}"

if [[ -f "${KERI_SCRIPT_DIR}/keri/cf/main/mailbox.json" ]]; then
  MAILBOX_CONFIG_DIR="${KERI_SCRIPT_DIR}"
  MAILBOX_CONFIG_FILE="main/mailbox.json"
elif [[ -f "${KERI_SCRIPT_DIR}/keri/cf/mailbox.json" ]]; then
  MAILBOX_CONFIG_DIR="${KERI_SCRIPT_DIR}"
  MAILBOX_CONFIG_FILE="mailbox.json"
else
  echo "Could not find a mailbox config file under scripts/keri/cf." >&2
  exit 1
fi

ALICE_NAME="${ALICE_NAME:-alice-demo}"
BOB_NAME="${BOB_NAME:-bob-demo}"
ALICE_ALIAS="${ALICE_ALIAS:-alice}"
BOB_ALIAS="${BOB_ALIAS:-bob}"
MAILBOX_NAME="${MAILBOX_NAME:-mailbox}"
MAILBOX_ALIAS="${MAILBOX_ALIAS:-mailbox}"

ALICE_SALT="${ALICE_SALT:-0ACDEyMzQ1Njc4OWxtbm9aBc}"
BOB_SALT="${BOB_SALT:-0ACDEyMzQ1Njc4OWdoaWpsaw}"

wait_for_mailbox() {
  local url="${1}"
  for _ in $(seq 1 40); do
    if curl -fsS "${url}/health" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
  done

  echo "Mailbox host did not become healthy at ${url}/health" >&2
  return 1
}

cleanup() {
  if [[ -n "${MAILBOX_PID:-}" ]]; then
    kill "${MAILBOX_PID}" >/dev/null 2>&1 || true
    wait "${MAILBOX_PID}" >/dev/null 2>&1 || true
  fi
}

trap cleanup EXIT

mkdir -p "$(dirname "${MAILBOX_LOG}")"

echo "Using mailbox config: ${MAILBOX_CONFIG_DIR}/keri/cf/${MAILBOX_CONFIG_FILE}"
echo "Mailbox log: ${MAILBOX_LOG}"

# Start mailbox host
kli mailbox start \
  --name "${MAILBOX_NAME}" \
  --alias "${MAILBOX_ALIAS}" \
  --config-dir "${MAILBOX_CONFIG_DIR}" \
  --config-file "${MAILBOX_CONFIG_FILE}" \
  --loglevel INFO \
  >"${MAILBOX_LOG}" 2>&1 &
MAILBOX_PID=$!

wait_for_mailbox "${MAILBOX_URL%/}"

# Create Alice
kli init --name "${ALICE_NAME}" --salt "${ALICE_SALT}" --nopasscode
kli incept \
  --name "${ALICE_NAME}" \
  --alias "${ALICE_ALIAS}" \
  --file "${KERI_SCRIPT_DIR}"/demo/data/transferable-sample.json

# Create Bob
kli init --name "${BOB_NAME}" --salt "${BOB_SALT}" --nopasscode
kli incept \
  --name "${BOB_NAME}" \
  --alias "${BOB_ALIAS}" \
  --file "${KERI_SCRIPT_DIR}"/demo/data/transferable-sample.json

MAILBOX_CTRL_OOBI="$(kli oobi generate --name "${MAILBOX_NAME}" --alias "${MAILBOX_ALIAS}" --role controller | tail -n 1)"
MAILBOX_AID="$(echo "${MAILBOX_CTRL_OOBI}" | awk -F/ '{print $(NF-1)}')"

echo
echo "Mailbox controller OOBI: ${MAILBOX_CTRL_OOBI}"
echo "Mailbox AID: ${MAILBOX_AID}"

# Resolve mailbox controller OOBI into both local stores
kli oobi resolve \
  --name "${ALICE_NAME}" \
  --oobi-alias "${MAILBOX_ALIAS}" \
  --oobi "${MAILBOX_CTRL_OOBI}"

kli oobi resolve \
  --name "${BOB_NAME}" \
  --oobi-alias "${MAILBOX_ALIAS}" \
  --oobi "${MAILBOX_CTRL_OOBI}"

# Add the mailbox to both AIDs
kli mailbox add \
  --name "${ALICE_NAME}" \
  --alias "${ALICE_ALIAS}" \
  --mailbox "${MAILBOX_ALIAS}"

kli mailbox add \
  --name "${BOB_NAME}" \
  --alias "${BOB_ALIAS}" \
  --mailbox "${MAILBOX_ALIAS}"

echo
echo "Mailbox lists after authorization:"
echo "  alice mailbox: "
echo "    $(kli mailbox list --name ${ALICE_NAME} --alias ${ALICE_ALIAS})"
echo "  bob mailbox: "
echo "    $(kli mailbox list --name ${BOB_NAME} --alias ${BOB_ALIAS})"

ALICE_MBX_OOBI="$(kli oobi generate --name "${ALICE_NAME}" --alias "${ALICE_ALIAS}" --role mailbox | tail -n 1)"
BOB_MBX_OOBI="$(kli oobi generate --name "${BOB_NAME}" --alias "${BOB_ALIAS}" --role mailbox | tail -n 1)"

echo
echo "Alice mailbox OOBI: ${ALICE_MBX_OOBI}"
echo "Bob mailbox OOBI:   ${BOB_MBX_OOBI}"

# Exchange mailbox OOBIs so each side can contact the other through the mailbox
kli oobi resolve \
  --name "${ALICE_NAME}" \
  --oobi-alias "${BOB_ALIAS}" \
  --oobi "${BOB_MBX_OOBI}"

kli oobi resolve \
  --name "${BOB_NAME}" \
  --oobi-alias "${ALICE_ALIAS}" \
  --oobi "${ALICE_MBX_OOBI}"

WORDS_ALICE="$(kli challenge generate --out string)"
WORDS_BOB="$(kli challenge generate --out string)"

echo
echo "Alice challenges Bob with: ${WORDS_ALICE}"
# Alice -> Bob challenge over mailbox delivery
kli challenge respond \
  --name "${ALICE_NAME}" \
  --alias "${ALICE_ALIAS}" \
  --recipient "${BOB_ALIAS}" \
  --words "${WORDS_ALICE}"
kli challenge verify \
  --name "${BOB_NAME}" \
  --signer "${ALICE_ALIAS}" \
  --words "${WORDS_ALICE}"

echo
echo "Bob challenges Alice with: ${WORDS_BOB}"
# Bob -> Alice challenge over mailbox delivery
kli challenge respond \
  --name "${BOB_NAME}" \
  --alias "${BOB_ALIAS}" \
  --recipient "${ALICE_ALIAS}" \
  --words "${WORDS_BOB}"
kli challenge verify \
  --name "${ALICE_NAME}" \
  --signer "${BOB_ALIAS}" \
  --words "${WORDS_BOB}"

echo
echo "Mailbox debug snapshots:"
# Inspect mailbox state from each side
kli mailbox debug \
  --name "${ALICE_NAME}" \
  --alias "${ALICE_ALIAS}" \
  --witness "${MAILBOX_AID}" \
  --verbose

kli mailbox debug \
  --name "${BOB_NAME}" \
  --alias "${BOB_ALIAS}" \
  --witness "${MAILBOX_AID}" \
  --verbose

echo
echo "Mailbox host log: ${MAILBOX_LOG}"
echo "Done."

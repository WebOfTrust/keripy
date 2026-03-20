#!/bin/bash

# Directory of this script
script_dir=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

source "${script_dir}"/demo-scripts.sh
source "${script_dir}"/basic/script-utils.sh

# Per-script timeout in seconds (5 minutes). Override with KERI_SCRIPT_TIMEOUT env var.
SCRIPT_TIMEOUT="${KERI_SCRIPT_TIMEOUT:-300}"
# Max retry attempts per script. Override with KERI_SCRIPT_RETRIES env var.
MAX_RETRIES="${KERI_SCRIPT_RETRIES:-3}"

clean_temp_state() {
    local base="${KERI_TEMP_DIR}"

    rm -rf \
        "/usr/local/var/keri/db/${base}" \
        "/usr/local/var/keri/ks/${base}" \
        "/usr/local/var/keri/reg/${base}" \
        "/usr/local/var/keri/cf/${base}" \
        "/usr/local/var/keri/cf/${base}.json" \
        "$HOME/.keri/db/${base}" \
        "$HOME/.keri/ks/${base}" \
        "$HOME/.keri/reg/${base}" \
        "$HOME/.keri/cf/${base}" \
        "$HOME/.keri/cf/${base}.json"
}

# Launch witnesses in background using the same isolated base as the demo scripts.
kli witness demo --base "${KERI_TEMP_DIR}" &
wits=$!
sleep 3

# Ensure we kill the witnesses on exit
trap 'kill -HUP $wits' EXIT

# Run a script with a timeout and retry on failure.
# Usage: run_with_retry <script_path> [timeout_seconds]
# Retries up to MAX_RETRIES times with exponential backoff (2s, 4s, 8s).
run_with_retry() {
    local script="$1"
    local t="${2:-$SCRIPT_TIMEOUT}"
    local name
    name=$(basename "$script")

    for attempt in $(seq 1 "$MAX_RETRIES"); do
        printf "\n************************************\n"
        if [ "$attempt" -gt 1 ]; then
            printf "RETRY %d/%d: %s\n" "$attempt" "$MAX_RETRIES" "$name"
        else
            printf "Running %s\n" "$name"
        fi
        printf "************************************\n"

        clean_temp_state

        if timeout "$t" "$script"; then
            return 0
        fi

        local exit_code=$?
        if [ "$attempt" -lt "$MAX_RETRIES" ]; then
            local delay=$(( 2 ** attempt ))
            printf "\e[33m%s failed (exit %d). Retrying in %ds...\e[0m\n" "$name" "$exit_code" "$delay"
            sleep "$delay"
        else
            printf "\e[31m%s failed after %d attempts (exit %d).\e[0m\n" "$name" "$MAX_RETRIES" "$exit_code"
            return "$exit_code"
        fi
    done
}

# Test scripts
run_with_retry "${script_dir}/basic/demo-script.sh"
run_with_retry "${script_dir}/basic/demo-witness-script.sh"
run_with_retry "${script_dir}/basic/demo-witness-async-script.sh"
run_with_retry "${script_dir}/basic/delegate.sh"
run_with_retry "${script_dir}/basic/multisig-delegate-join.sh"
run_with_retry "${script_dir}/basic/multisig.sh"
run_with_retry "${script_dir}/basic/multisig-rotate-three-stooges.sh"
run_with_retry "${script_dir}/basic/multisig-delegator.sh"
run_with_retry "${script_dir}/basic/multisig-delegate-delegator.sh"
run_with_retry "${script_dir}/basic/challenge.sh"
run_with_retry "${script_dir}/basic/multisig-join.sh"
run_with_retry "${script_dir}/basic/rename-alias.sh"


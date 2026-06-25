#!/bin/bash

# Directory of this script
script_dir=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

source "${script_dir}"/demo-scripts.sh
source "${script_dir}"/basic/script-utils.sh

# Per-script timeout in seconds (5 minutes). Override with KERI_SCRIPT_TIMEOUT env var.
SCRIPT_TIMEOUT="${KERI_SCRIPT_TIMEOUT:-300}"
# Max retry attempts per script. Override with KERI_SCRIPT_RETRIES env var.
MAX_RETRIES="${KERI_SCRIPT_RETRIES:-3}"
FAILURES=0

clean_all_temp_state() {
    local base="${KERI_TEMP_DIR}"

    rm -rf \
        "/usr/local/var/keri/db/${base}" \
        "/usr/local/var/keri/ks/${base}" \
        "/usr/local/var/keri/mbx/${base}" \
        "/usr/local/var/keri/reg/${base}" \
        "/usr/local/var/keri/cf/${base}" \
        "/usr/local/var/keri/cf/${base}.json" \
        "$HOME/.keri/db/${base}" \
        "$HOME/.keri/ks/${base}" \
        "$HOME/.keri/mbx/${base}" \
        "$HOME/.keri/reg/${base}" \
        "$HOME/.keri/cf/${base}" \
        "$HOME/.keri/cf/${base}.json"
}

wits=""
witness_oobis=(
    "http://127.0.0.1:5642/oobi/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha/controller"
    "http://127.0.0.1:5643/oobi/BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM/controller"
    "http://127.0.0.1:5644/oobi/BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX/controller"
)

witnesses_ready() {
    local url

    if ! command -v curl > /dev/null 2>&1; then
        sleep 5
        return 0
    fi

    for url in "${witness_oobis[@]}"; do
        curl -fsS --max-time 2 "$url" > /dev/null 2>&1 || return 1
    done
}

start_witnesses() {
    # Launch witnesses using the same isolated base and v1 protocol version as the scripts.
    command kli witness demo --base "${KERI_TEMP_DIR}" --version 1.0 &
    wits=$!

    for _ in {1..30}; do
        if ! kill -0 "$wits" > /dev/null 2>&1; then
            wait "$wits" > /dev/null 2>&1 || true
            wits=""
            return 1
        fi

        if witnesses_ready; then
            return 0
        fi

        sleep 1
    done

    return 1
}

stop_witnesses() {
    if [ -n "${wits:-}" ]; then
        kill -HUP "$wits" > /dev/null 2>&1 || true
        wait "$wits" > /dev/null 2>&1 || true
        wits=""
        sleep 1
    fi
}

# Ensure we kill the witnesses on exit
trap 'stop_witnesses' EXIT

# Run a script with a timeout and retry on failure.
# Usage: run_with_retry <script_path> [timeout_seconds]
# Retries up to MAX_RETRIES times with exponential backoff (2s, 4s, 8s).
run_with_retry() {
    local script="$1"
    local t="${2:-$SCRIPT_TIMEOUT}"
    local name
    local exit_code
    name=$(basename "$script")

    for attempt in $(seq 1 "$MAX_RETRIES"); do
        printf "\n************************************\n"
        if [ "$attempt" -gt 1 ]; then
            printf "RETRY %d/%d: %s\n" "$attempt" "$MAX_RETRIES" "$name"
        else
            printf "Running %s\n" "$name"
        fi
        printf "************************************\n"

        stop_witnesses
        clean_all_temp_state
        if ! start_witnesses; then
            exit_code=1
            stop_witnesses
            if [ "$attempt" -lt "$MAX_RETRIES" ]; then
                local delay=$(( 2 ** attempt ))
                printf "\e[33m%s could not start witnesses. Retrying in %ds...\e[0m\n" "$name" "$delay"
                sleep "$delay"
                continue
            else
                printf "\e[31m%s failed after %d attempts: witnesses did not start.\e[0m\n" "$name" "$MAX_RETRIES"
                return "$exit_code"
            fi
        fi

        if timeout "$t" "$script"; then
            stop_witnesses
            return 0
        else
            exit_code=$?
            stop_witnesses
        fi
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
run_with_retry "${script_dir}/basic/demo-script.sh" || FAILURES=1
run_with_retry "${script_dir}/basic/demo-witness-script.sh" || FAILURES=1
run_with_retry "${script_dir}/basic/demo-witness-async-script.sh" || FAILURES=1
run_with_retry "${script_dir}/basic/delegate.sh" || FAILURES=1
run_with_retry "${script_dir}/basic/multisig-delegate-join.sh" || FAILURES=1
run_with_retry "${script_dir}/basic/multisig.sh" || FAILURES=1
run_with_retry "${script_dir}/basic/multisig-rotate-three-stooges.sh" || FAILURES=1
run_with_retry "${script_dir}/basic/multisig-delegator.sh" || FAILURES=1
run_with_retry "${script_dir}/basic/multisig-delegate-delegator.sh" || FAILURES=1
run_with_retry "${script_dir}/basic/challenge.sh" || FAILURES=1
run_with_retry "${script_dir}/basic/multisig-join.sh" || FAILURES=1
run_with_retry "${script_dir}/basic/rename-alias.sh" || FAILURES=1

exit "$FAILURES"

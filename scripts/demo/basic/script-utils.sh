#!/bin/bash

# Utility functions
print_green() {
  text=$1
  printf "\e[32m${text}\e[0m\n"
}

print_yellow(){
  text=$1
  printf "\e[33m${text}\e[0m\n"
}

print_red() {
  text=$1
  printf "\e[31m${text}\e[0m\n"
}

print_lcyan() {
  text=$1
  printf "\e[96m${text}\e[0m\n"
}

random_name () {
   suffix=$(head /dev/urandom | tr -dc a-z0-9 | head -c4)
   prefix="${1:-test}"
   echo "${prefix}_${suffix}"
}

teardown () {
    echo "Teardown"
    trap - SIGTERM && kill -- -$$
}

background_pids=()
background_waiting=0
background_start () {
    if [[ $background_waiting -ne 0 ]]; then
        echo "Currently waiting for background processes, cannot start new process" 1>&2
        return 1
    fi

    "$@" &
    background_pids+=("$!")
}

background_wait() {
    if [[ $background_waiting -ne 0 ]]; then
        echo "Already waiting for background processes, cannot wait again" 1>&2
        return 1
    fi

    background_waiting=1
    for p in "${background_pids[@]}"; do
        if  [[ -n "$p" ]]; then
            wait "$p"
            background_pids=("${background_pids[@]/$p}")
        fi
    done
    background_pids=()
    background_waiting=0
}


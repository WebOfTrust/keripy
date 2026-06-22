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

kli () {
  if [[ -n "${KERI_TEMP_DIR:-}" ]]; then
    local arg
    for arg in "$@"; do
      case "$arg" in
        --base|-b|--base=*)
          command kli "$@"
          return
          ;;
      esac
    done

    # Challenge generation is stateless and does not accept keystore options.
    if [[ "${1:-}" == "challenge" && "${2:-}" == "generate" ]]; then
      command kli "$@"
      return
    fi

    command kli "$@" --base "$KERI_TEMP_DIR"
    return
  fi

  command kli "$@"
}

export -f kli

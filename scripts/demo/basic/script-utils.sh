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

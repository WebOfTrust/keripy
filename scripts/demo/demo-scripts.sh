#!/bin/bash

demo=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
export KERI_DEMO_SCRIPT_DIR="${demo}"
script=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && cd .. &> /dev/null && pwd )
export KERI_SCRIPT_DIR="${script}"
export KERI_TEMP_DIR="scripts_tmp"
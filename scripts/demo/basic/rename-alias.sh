#!/bin/bash

# CREATE DATABASE AND KEYSTORE
kli init --name rename-test --base "${KERI_TEMP_DIR}" --nopasscode

# Incept with the initial alias "sabbir"
kli incept --name rename-test --base "${KERI_TEMP_DIR}" --alias sabbir --file ${KERI_DEMO_SCRIPT_DIR}/data/transferable-sample.json

# Rename the alias from "sabbir" to "irfan"
kli rename --name rename-test --base "${KERI_TEMP_DIR}" --alias sabbir irfan

# Extract alias from status 
irfan_alias=$(kli status --name rename-test --base "${KERI_TEMP_DIR}" --alias irfan  | grep -Eo 'Alias:\s+(.+)' | awk '{print $2}')



# Check if the extracted alias is "irfan"
if [ "$irfan_alias" = "irfan" ]; then
    echo "Alias successfully changed to 'irfan'."
else
    echo "Alias did not change !"
   
fi

echo 'Test Complete'
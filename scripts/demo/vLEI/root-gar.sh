# Create local Root GAR keystores
# DoB26Fj4x9LboAFWJra17O
curl -s -X POST "http://localhost:5620/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"rootgar1\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\", \"salt\":\"0AMDEyMzQ1Njc4OWdoaWpd00\"}" | jq
curl -s -X POST "http://localhost:5621/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"rootgar2\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\", \"salt\":\"0AMDEyMzQ1Njc4OWdoaWpd01\"}" | jq
sleep 2

# Unlock local Root GAR agents
curl -s -X PUT "http://localhost:5620/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"rootgar1\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\"}" | jq
curl -s -X PUT "http://localhost:5621/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"rootgar2\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\"}" | jq
sleep 2

# Create local Root GAR AIDs
# rootgar1:
curl -s -X POST "http://localhost:5620/ids/rootgar1" -H "accept: */*" -H "Content-Type: application/json" -d "{\"transferable\":true,\"wits\":[\"BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha\",\"BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM\",\"BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX\"],\"toad\":2,\"icount\":1,\"ncount\":1,\"isith\":1,\"nsith\":1}" | jq

# rootgar2:
curl -s -X POST "http://localhost:5621/ids/rootgar2" -H "accept: */*" -H "Content-Type: application/json" -d "{\"transferable\":true,\"wits\":[\"BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha\",\"BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM\",\"BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX\"],\"toad\":2,\"icount\":1,\"ncount\":1,\"isith\":1,\"nsith\":1}" | jq
sleep 3

# OOBI between local Root GARs
curl -s -X POST "http://localhost:5620/oobi" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"rootgar2\", \"url\":\"http://127.0.0.1:5642/oobi/EUwocCDxDjqV0gT1ah6dA1FWDyR4EQyHEayQzeS0h-PA/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha\"}" | jq
curl -s -X POST "http://localhost:5621/oobi" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"rootgar1\", \"url\":\"http://127.0.0.1:5642/oobi/EC_y9UOQlOD8LEQDx3rnrJdwo3LVOzA6VdCK67qT2C-g/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha\"}" | jq
sleep 3
#
# # Initiate and join GLEIF Root multisig identifier
curl -s -X POST "http://localhost:5620/groups/RootGAR/icp" -H "accept: */*" -H "Content-Type: application/json" -d "{\"aids\":[\"EC_y9UOQlOD8LEQDx3rnrJdwo3LVOzA6VdCK67qT2C-g\",\"EUwocCDxDjqV0gT1ah6dA1FWDyR4EQyHEayQzeS0h-PA\"], \"transferable\":true,\"wits\":[\"BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha\", \"BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM\",\"BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX\"],\"toad\":3, \"isith\":2,\"nsith\":2}" | jq
curl -s -X POST "http://localhost:5621/groups/RootGAR/icp" -H "accept: */*" -H "Content-Type: application/json" -d "{\"aids\":[\"EC_y9UOQlOD8LEQDx3rnrJdwo3LVOzA6VdCK67qT2C-g\",\"EUwocCDxDjqV0gT1ah6dA1FWDyR4EQyHEayQzeS0h-PA\"], \"transferable\":true,\"wits\":[\"BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha\", \"BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM\",\"BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX\"],\"toad\":3, \"isith\":2,\"nsith\":2}" | jq

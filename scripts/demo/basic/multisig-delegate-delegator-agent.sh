#!/bin/bash

# To run the following scripts, open 2 other console windows and run:
# $ kli witness demo
# $ kli agent demo --config-file demo-witness-oobis

# Create and initialize agents with passcode DoB26Fj4x9LboAFWJra17O
curl -s -X POST "http://localhost:5623/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"delegate1\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\",\"salt\":\"0ACDEyMzQ1Njc4OWxtbm9aBc\"}" | jq
curl -s -X POST "http://localhost:5723/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"delegate2\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\", \"salt\":\"0ACDEyMzQ1Njc4OWdoaWpsaw\"}" | jq
curl -s -X POST "http://localhost:5823/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"delegator1\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\", \"salt\":\"0ACDEyMzQ1Njc4OWdoaWpdo1\"}" | jq
curl -s -X POST "http://localhost:5923/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"delegator2\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\", \"salt\":\"0ACDEyMzQ1Njc4OWdoaWpdo2\"}" | jq
sleep 2
curl -s -X PUT "http://localhost:5623/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"delegate1\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\"}" | jq
curl -s -X PUT "http://localhost:5723/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"delegate2\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\"}" | jq
curl -s -X PUT "http://localhost:5823/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"delegator1\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\"}" | jq
curl -s -X PUT "http://localhost:5923/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"delegator2\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\"}" | jq
sleep 2
curl -s -X POST "http://localhost:5623/ids/delegate1" -H "accept: */*" -H "Content-Type: application/json" -d "{\"transferable\":true,\"wits\":[\"BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha\"],\"toad\":1,\"icount\":1,\"ncount\":1,\"isith\":1,\"nsith\":1}" | jq
curl -s -X POST "http://localhost:5723/ids/delegate2" -H "accept: */*" -H "Content-Type: application/json" -d "{\"transferable\":true,\"wits\":[\"BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha\"],\"toad\":1,\"icount\":1,\"ncount\":1,\"isith\":1,\"nsith\":1}" | jq
curl -s -X POST "http://localhost:5823/ids/delegator1" -H "accept: */*" -H "Content-Type: application/json" -d "{\"transferable\":true,\"wits\":[\"BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha\",\"BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM\",\"BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX\"],\"toad\":2,\"icount\":1,\"ncount\":1,\"isith\":1,\"nsith\":1}" | jq
curl -s -X POST "http://localhost:5923/ids/delegator2" -H "accept: */*" -H "Content-Type: application/json" -d "{\"transferable\":true,\"wits\":[\"BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha\",\"BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM\",\"BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX\"],\"toad\":2,\"icount\":1,\"ncount\":1,\"isith\":1,\"nsith\":1}" | jq
sleep 3

curl -s -X POST "http://localhost:5623/oobi" -H "accept: */*" -H "Content-Type: application/json"  -d "{\"oobialias\": \"delegate2\", \"url\":\"http://127.0.0.1:5642/oobi/ELZyCjnSL2Haors35LKM19T4qWT4K8Gfz1FPDD9oJN33/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha\"}" | jq
curl -s -X POST "http://localhost:5723/oobi" -H "accept: */*" -H "Content-Type: application/json"  -d "{\"oobialias\": \"delegate1\", \"url\":\"http://127.0.0.1:5642/oobi/EJ97lUuRH3xz0OMKhdMAU6V2TcSF9X6m1CKyIbIUcRxp/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha\"}" | jq
curl -s -X POST "http://localhost:5823/oobi" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"delegator2\", \"url\":\"http://127.0.0.1:5642/oobi/EGv3deIs7pc01NnZZAhQ14Cbe9VGq4wF3n4oyhQfrB9j/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha\"}" | jq
curl -s -X POST "http://localhost:5923/oobi" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"delegator1\", \"url\":\"http://127.0.0.1:5642/oobi/EIKUq-JkZGpgVZ_x9Hr2Gt_LLdPDzyI2JyGnHl3EBCPl/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha\"}" | jq
sleep 3
curl -s -X POST "http://localhost:5823/groups/delegator/icp" -H "accept: */*" -H "Content-Type: application/json" -d "{\"aids\":[\"EIKUq-JkZGpgVZ_x9Hr2Gt_LLdPDzyI2JyGnHl3EBCPl\",\"EGv3deIs7pc01NnZZAhQ14Cbe9VGq4wF3n4oyhQfrB9j\"], \"transferable\":true,\"wits\":[\"BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha\", \"BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM\",\"BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX\"],\"toad\":3, \"isith\":2,\"nsith\":2}" | jq
curl -s -X PUT "http://localhost:5923/groups/delegator/icp" -H "accept: */*" -H "Content-Type: application/json" -d "{\"aids\":[\"EIKUq-JkZGpgVZ_x9Hr2Gt_LLdPDzyI2JyGnHl3EBCPl\",\"EGv3deIs7pc01NnZZAhQ14Cbe9VGq4wF3n4oyhQfrB9j\"], \"transferable\":true,\"wits\":[\"BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha\", \"BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM\",\"BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX\"],\"toad\":3, \"isith\":2,\"nsith\":2}" | jq

sleep 2
curl -s -X POST "http://localhost:5623/oobi" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"delegator\", \"url\":\"http://127.0.0.1:5642/oobi/EK7j7BobKFpH9yki4kwyIUuT-yQANSntS8u1hlhFYFcg/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha\"}"
curl -s -X POST "http://localhost:5723/oobi" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"delegator\", \"url\":\"http://127.0.0.1:5642/oobi/EK7j7BobKFpH9yki4kwyIUuT-yQANSntS8u1hlhFYFcg/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha\"}"

sleep 2
curl -s -X POST "http://localhost:5623/groups/delegate/icp" -H "accept: */*" -H "Content-Type: application/json" -d "{\"delpre\":\"EK7j7BobKFpH9yki4kwyIUuT-yQANSntS8u1hlhFYFcg\", \"aids\":[\"EJ97lUuRH3xz0OMKhdMAU6V2TcSF9X6m1CKyIbIUcRxp\",\"ELZyCjnSL2Haors35LKM19T4qWT4K8Gfz1FPDD9oJN33\"], \"transferable\":true,\"wits\":[\"BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha\", \"BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM\",\"BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX\"],\"toad\":3, \"isith\":2,\"nsith\":2}" | jq
curl -s -X PUT "http://localhost:5723/groups/delegate/icp" -H "accept: */*" -H "Content-Type: application/json" -d "{\"delpre\":\"EK7j7BobKFpH9yki4kwyIUuT-yQANSntS8u1hlhFYFcg\", \"aids\":[\"EJ97lUuRH3xz0OMKhdMAU6V2TcSF9X6m1CKyIbIUcRxp\",\"ELZyCjnSL2Haors35LKM19T4qWT4K8Gfz1FPDD9oJN33\"], \"transferable\":true,\"wits\":[\"BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha\", \"BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM\",\"BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX\"],\"toad\":3, \"isith\":2,\"nsith\":2}" | jq

sleep 3
curl -s -X POST "http://localhost:5923/groups/delegator/ixn" -H "accept: */*" -H "Content-Type: application/json" -d "{\"aids\":[\"EIKUq-JkZGpgVZ_x9Hr2Gt_LLdPDzyI2JyGnHl3EBCPl\",\"EGv3deIs7pc01NnZZAhQ14Cbe9VGq4wF3n4oyhQfrB9j\"], \"data\":[{\"i\":\"EOL2umo-DHgO9t22LR_iwmiR_cfsF531hcCh-zZ0p0gL\",\"s\":\"0\", \"d\":\"EOL2umo-DHgO9t22LR_iwmiR_cfsF531hcCh-zZ0p0gL\"}]}" | jq
curl -s -X PUT "http://localhost:5823/groups/delegator/ixn" -H "accept: */*" -H "Content-Type: application/json" -d "{\"aids\":[\"EIKUq-JkZGpgVZ_x9Hr2Gt_LLdPDzyI2JyGnHl3EBCPl\",\"EGv3deIs7pc01NnZZAhQ14Cbe9VGq4wF3n4oyhQfrB9j\"], \"data\":[{\"i\":\"EOL2umo-DHgO9t22LR_iwmiR_cfsF531hcCh-zZ0p0gL\",\"s\":\"0\", \"d\":\"EOL2umo-DHgO9t22LR_iwmiR_cfsF531hcCh-zZ0p0gL\"}]}" | jq

#!/bin/bash
# To run this script you need to run the following 2 commands in separate terminals:
#   > kli agent demo --config-file demo-witness-oobis-schema
#   > kli witness demo
# and from the vLEI repo run:
#   > vLEI-server -s ./schema/acdc -c ./samples/acdc/ -o ./samples/oobis/
#

curl -s -X POST "http://localhost:5623/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"multisig1\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\",\"salt\":\"0ACDEyMzQ1Njc4OWxtbm9aBc\"}" | jq
curl -s -X POST "http://localhost:5723/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"multisig2\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\", \"salt\":\"0ACDEyMzQ1Njc4OWdoaWpsaw\"}" | jq
curl -s -X POST "http://localhost:5823/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"holder\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\",\"salt\":\"0ACDEyMzQ1Njc4OWxtbm9abc\"}" | jq

sleep 3
curl -s -X PUT "http://localhost:5623/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"multisig1\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\"}" | jq
curl -s -X PUT "http://localhost:5723/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"multisig2\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\"}" | jq
curl -s -X PUT "http://localhost:5823/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"holder\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\"}" | jq

sleep 4
curl -s -X POST "http://localhost:5623/ids/multisig1" -H "accept: */*" -H "Content-Type: application/json" -d "{\"transferable\":true,\"wits\":[\"BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha\",\"BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM\",\"BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX\"],\"toad\":2,\"icount\":1,\"ncount\":1,\"isith\":1,\"nsith\":1}" | jq
curl -s -X POST "http://localhost:5723/ids/multisig2" -H "accept: */*" -H "Content-Type: application/json" -d "{\"transferable\":true,\"wits\":[\"BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha\",\"BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM\",\"BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX\"],\"toad\":2,\"icount\":1,\"ncount\":1,\"isith\":1,\"nsith\":1}" | jq
curl -s -X POST "http://localhost:5823/ids/holder" -H "accept: */*" -H "Content-Type: application/json" -d "{\"transferable\":true,\"wits\":[\"BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha\", \"BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM\",\"BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX\"],\"toad\":3, \"icount\":1,\"ncount\":1,\"isith\":1,\"nsith\":1}" | jq

sleep 4
curl -s -X POST "http://localhost:5623/oobi/multisig1" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"multisig2\", \"url\":\"http://127.0.0.1:5642/oobi/EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha\"}" | jq
curl -s -X POST "http://localhost:5723/oobi/multisig2" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"multisig1\", \"url\":\"http://127.0.0.1:5642/oobi/EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha\"}" | jq
curl -s -X POST "http://localhost:5623/oobi/multisig1" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"holder\", \"url\":\"http://127.0.0.1:5643/oobi/Ew9ae1KDP6apL8N7WeyaUBCXOEbEmCcO6uzgCo3WU72A/witness/BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM\"}" | jq
curl -s -X POST "http://localhost:5723/oobi/multisig2" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"holder\", \"url\":\"http://127.0.0.1:5643/oobi/Ew9ae1KDP6apL8N7WeyaUBCXOEbEmCcO6uzgCo3WU72A/witness/BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM\"}" | jq

sleep 3
curl -s -X POST "http://localhost:5623/groups/issuer/icp" -H "accept: */*" -H "Content-Type: application/json" -d "{\"aids\":[\"EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1\",\"EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4\"], \"transferable\":true,\"wits\":[\"BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha\", \"BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM\",\"BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX\"],\"toad\":3, \"isith\":2,\"nsith\":2}" | jq
curl -s -X PUT "http://localhost:5723/groups/issuer/icp" -H "accept: */*" -H "Content-Type: application/json" -d "{\"aids\":[\"EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1\",\"EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4\"], \"transferable\":true,\"wits\":[\"BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha\", \"BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM\",\"BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX\"],\"toad\":3, \"isith\":2,\"nsith\":2}" | jq

sleep 3
curl -s -X POST "http://localhost:5623/registries" -H "accept: */*" -H "Content-Type: application/json" -d "{\"alias\":\"issuer\",\"nonce\":\"AHSNDV3ABI6U8OIgKaj3aky91ZpNL54I5_7-qwtC6q2s\",\"baks\":[],\"estOnly\":false,\"name\":\"vLEI\",\"noBackers\":true,\"toad\":0}" | jq
curl -s -X POST "http://localhost:5723/registries" -H "accept: */*" -H "Content-Type: application/json" -d "{\"alias\":\"issuer\",\"nonce\":\"AHSNDV3ABI6U8OIgKaj3aky91ZpNL54I5_7-qwtC6q2s\",\"baks\":[],\"estOnly\":false,\"name\":\"vLEI\",\"noBackers\":true,\"toad\":0}" | jq

# sleep 3
# curl -s -X POST "http://localhost:5623/groups/issuer/rot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"adds\":[],\"aids\":[\"EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1\", \"EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4\"],\"count\":2,\"cuts\":[],\"data\":[],\"isith\":\"2\",\"toad\":2, \"wits\":[]}" | jq
# curl -s -X PUT "http://localhost:5723/groups/issuer/rot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"adds\":[],\"aids\":[\"EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1\", \"EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4\"],\"count\":2,\"cuts\":[],\"data\":[],\"isith\":\"2\",\"toad\":2, \"wits\":[]}" | jq

sleep 3
CRED=`curl -s -X POST "http://localhost:5623/groups/issuer/credentials" -H "accept: application/json" -H "Content-Type: application/json" -d "{\"credentialData\":{\"LEI\":\"5493001KJTIIGC8Y1R17\"},\"recipient\":\"Ew9ae1KDP6apL8N7WeyaUBCXOEbEmCcO6uzgCo3WU72A\",\"registry\":\"vLEI\",\"schema\":\"EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao\",\"source\":{}}"`
ESCAPED=`echo -n $CRED  | jq '{credential: . }'`
curl -s -X PUT "http://localhost:5723/groups/issuer/credentials" -H "accept: application/json" -H "Content-Type: application/json" -d "${ESCAPED}" | jq

sleep 3
echo "Holders Received Credentials..."
curl -s -X GET "http://localhost:5823/credentials/holder?type=received" -H "accept: application/json" | jq
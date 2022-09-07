#!/bin/bash
# To run the following scripts, open 2 other console windows and run:
# $ kli witness demo
# $ kli agent demo --config-file demo-witness-oobis

# Create and initialize agents with passcode DoB26Fj4x9LboAFWJra17O
curl -s -X POST "http://localhost:5623/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"multisig1\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\",\"salt\":\"0AMDEyMzQ1Njc4OWxtbm9wcQ\"}" | jq
curl -s -X POST "http://localhost:5723/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"multisig2\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\", \"salt\":\"0AMDEyMzQ1Njc4OWdoaWpsaw\"}" | jq
sleep 3
curl -s -X PUT "http://localhost:5623/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"multisig1\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\"}" | jq
curl -s -X PUT "http://localhost:5723/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"multisig2\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\"}" | jq

# Create 2 single sig AIDs
sleep 3
curl -s -X POST "http://localhost:5623/ids/multisig1" -H "accept: */*" -H "Content-Type: application/json" -d "{\"transferable\":true,\"wits\":[\"BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha\",\"BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM\",\"BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX\"],\"toad\":2,\"icount\":1,\"ncount\":1,\"isith\":1,\"nsith\":1}" | jq
curl -s -X POST "http://localhost:5723/ids/multisig2" -H "accept: */*" -H "Content-Type: application/json" -d "{\"transferable\":true,\"wits\":[\"BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha\",\"BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM\",\"BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX\"],\"toad\":2,\"icount\":1,\"ncount\":1,\"isith\":1,\"nsith\":1}" | jq

# Exchange OOBIs between participants
sleep 3
curl -s -X POST "http://localhost:5623/oobi/multisig1" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"multisig2\", \"url\":\"http://127.0.0.1:5642/oobi/EozYHef4je02EkMOA1IKM65WkIdSjfrL7XWDk_JzJL9o/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha\"}" | jq
curl -s -X POST "http://localhost:5723/oobi/multisig2" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"multisig1\", \"url\":\"http://127.0.0.1:5642/oobi/E-4-PsMBN0YEKyTl3zL0zulWcBehdaaG6Go5cMc0BzQ8/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha\"}" | jq

# Create distributed multisig AID
sleep 3
curl -s -X POST "http://localhost:5623/groups/issuer/icp" -H "accept: */*" -H "Content-Type: application/json" -d "{\"aids\":[\"EozYHef4je02EkMOA1IKM65WkIdSjfrL7XWDk_JzJL9o\",\"E-4-PsMBN0YEKyTl3zL0zulWcBehdaaG6Go5cMc0BzQ8\"], \"transferable\":true,\"wits\":[\"BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha\", \"BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM\",\"BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX\"],\"toad\":3, \"isith\":2,\"nsith\":2}" | jq
curl -s -X PUT "http://localhost:5723/groups/issuer/icp" -H "accept: */*" -H "Content-Type: application/json" -d "{\"aids\":[\"EozYHef4je02EkMOA1IKM65WkIdSjfrL7XWDk_JzJL9o\",\"E-4-PsMBN0YEKyTl3zL0zulWcBehdaaG6Go5cMc0BzQ8\"], \"transferable\":true,\"wits\":[\"BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha\", \"BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM\",\"BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX\"],\"toad\":3, \"isith\":2,\"nsith\":2}" | jq

# Rotate distributed multisig AID
sleep 3
curl -s -X POST "http://localhost:5623/groups/issuer/rot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"adds\":[],\"aids\":[\"EozYHef4je02EkMOA1IKM65WkIdSjfrL7XWDk_JzJL9o\", \"E-4-PsMBN0YEKyTl3zL0zulWcBehdaaG6Go5cMc0BzQ8\"],\"count\":2,\"cuts\":[],\"data\":[],\"isith\":\"2\",\"toad\":2, \"wits\":[]}" | jq
curl -s -X PUT "http://localhost:5723/groups/issuer/rot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"adds\":[],\"aids\":[\"EozYHef4je02EkMOA1IKM65WkIdSjfrL7XWDk_JzJL9o\", \"E-4-PsMBN0YEKyTl3zL0zulWcBehdaaG6Go5cMc0BzQ8\"],\"count\":2,\"cuts\":[],\"data\":[],\"isith\":\"2\",\"toad\":2, \"wits\":[]}" | jq

# Create interaction event for distributed multisig AID
sleep 3
curl -s -X PUT "http://localhost:5723/groups/issuer/ixn" -H "accept: */*" -H "Content-Type: application/json" -d "{\"aids\":[\"EozYHef4je02EkMOA1IKM65WkIdSjfrL7XWDk_JzJL9o\",\"E-4-PsMBN0YEKyTl3zL0zulWcBehdaaG6Go5cMc0BzQ8\"], \"data\":[{\"i\":\"EAXJtG-Ek349v43ztpFdRXozyP7YnALdB0DdCEanlHmg\",\"s\":\"0\", \"d\":\"EAR75fE1ZmuCSfDwKPfbLowUWLqqi0ZX4502DLIo857Q\"}]}" | jq
curl -s -X POST "http://localhost:5623/groups/issuer/ixn" -H "accept: */*" -H "Content-Type: application/json" -d "{\"aids\":[\"EozYHef4je02EkMOA1IKM65WkIdSjfrL7XWDk_JzJL9o\",\"E-4-PsMBN0YEKyTl3zL0zulWcBehdaaG6Go5cMc0BzQ8\"], \"data\":[{\"i\":\"EAXJtG-Ek349v43ztpFdRXozyP7YnALdB0DdCEanlHmg\",\"s\":\"0\", \"d\":\"EAR75fE1ZmuCSfDwKPfbLowUWLqqi0ZX4502DLIo857Q\"}]}" | jq

#!/bin/bash

# To run the following scripts, open 2 other console windows and run:
# $ kli witness demo
# $ kli agent demo --config-file demo-witness-oobis

# Initialize and Unlock 2 agents
curl -s -X POST "http://localhost:5623/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"delegate\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\",\"salt\":\"0AMDEyMzQ1Njc4OWxtbm9wcQ\"}" | jq
curl -s -X POST "http://localhost:5723/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"delegator\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\", \"salt\":\"0AMDEyMzQ1Njc4OWdoaWpsaw\"}" | jq
sleep 2
curl -s -X PUT "http://localhost:5623/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"delegate\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\"}" | jq
curl -s -X PUT "http://localhost:5723/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"delegator\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\"}" | jq
sleep 3

# Create Delegator ID
curl -s -X POST "http://localhost:5723/ids/delegator" -H "accept: */*" -H "Content-Type: application/json" -d "{\"transferable\":true,\"wits\":[\"BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha\",\"BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM\",\"BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX\"],\"toad\":2,\"icount\":1,\"ncount\":1,\"isith\":1,\"nsith\":1}" | jq
sleep 3
curl -s -X POST "http://localhost:5623/oobi" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"\", \"url\":\"http://127.0.0.1:5642/oobi/EOlr22tu3VurGT7T22kruLtDhhQd6I5F5OCaBE5_ZUIc/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha\"}" | jq

# Create Delegate ID and Approve with Rotation of Delegator
sleep 2
curl -s -X POST "http://localhost:5623/ids/delegate" -H "accept: */*" -H "Content-Type: application/json" -d "{\"delpre\":\"EOlr22tu3VurGT7T22kruLtDhhQd6I5F5OCaBE5_ZUIc\", \"transferable\":true,\"wits\":[\"BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha\",\"BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM\",\"BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX\"],\"toad\":2,\"icount\":1,\"ncount\":1,\"isith\":1,\"nsith\":1}" | jq
sleep 3
curl -s -X PUT "http://localhost:5723/ids/delegator/rot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"adds\":[],\"count\":1,\"cuts\":[],\"data\":[{\"i\":\"ENXX5omYUZwM4Dg7WOOHuNmjSeKE2nfNuQbEQBNo4c3c\",\"s\":\"0\", \"d\":\"ENXX5omYUZwM4Dg7WOOHuNmjSeKE2nfNuQbEQBNo4c3c\"}],\"isith\":\"1\",\"toad\":2,\"wits\":[]}" | jq

# Rotate Delegate ID and Approve with Rotation of Delegator
sleep 3
curl -s -X PUT "http://localhost:5623/ids/delegate/rot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"adds\":[],\"count\":1,\"cuts\":[],\"data\":[],\"isith\":\"1\",\"toad\":3,\"wits\":[]}" | jq
sleep 3
curl -s -X PUT "http://localhost:5723/ids/delegator/rot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"adds\":[],\"count\":1,\"cuts\":[],\"data\":[{\"i\":\"ENXX5omYUZwM4Dg7WOOHuNmjSeKE2nfNuQbEQBNo4c3c\",\"s\":\"1\", \"d\":\"EKwpwCeuV-78blh1JPa8pdhpeqYN_VhuIzYUPD3SFFBN\"}],\"isith\":\"1\",\"toad\":3,\"wits\":[]}" | jq

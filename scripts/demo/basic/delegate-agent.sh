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
curl -s -X POST "http://localhost:5723/ids/delegator" -H "accept: */*" -H "Content-Type: application/json" -d "{\"transferable\":true,\"wits\":[\"BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\",\"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw\",\"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c\"],\"toad\":2,\"icount\":1,\"ncount\":1,\"isith\":1,\"nsith\":1}" | jq
sleep 3
curl -s -X POST "http://localhost:5623/oobi" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"\", \"url\":\"http://127.0.0.1:5642/oobi/E8AKUcbZyik8EdkOwXgnyAxO5mSIPJWGZ_o7zMhnNnjo/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\"}" | jq

# Create Delegate ID and Approve with Rotation of Delegator
sleep 2
curl -s -X POST "http://localhost:5623/ids/delegate" -H "accept: */*" -H "Content-Type: application/json" -d "{\"delpre\":\"E8AKUcbZyik8EdkOwXgnyAxO5mSIPJWGZ_o7zMhnNnjo\", \"transferable\":true,\"wits\":[\"BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\",\"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw\",\"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c\"],\"toad\":2,\"icount\":1,\"ncount\":1,\"isith\":1,\"nsith\":1}" | jq
sleep 3
curl -s -X PUT "http://localhost:5723/ids/delegator/rot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"adds\":[],\"count\":1,\"cuts\":[],\"data\":[{\"i\":\"EKSajEj5IsHhXaTDKx1PIcQ4-gcFQt9usFA5lYl82DCE\",\"s\":\"0\", \"d\":\"EKSajEj5IsHhXaTDKx1PIcQ4-gcFQt9usFA5lYl82DCE\"}],\"isith\":\"1\",\"toad\":2,\"wits\":[]}" | jq

# Rotate Delegate ID and Approve with Rotation of Delegator
sleep 3
curl -s -X PUT "http://localhost:5623/ids/delegate/rot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"adds\":[],\"count\":1,\"cuts\":[],\"data\":[],\"isith\":\"1\",\"toad\":3,\"wits\":[]}" | jq
sleep 3
curl -s -X PUT "http://localhost:5723/ids/delegator/rot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"adds\":[],\"count\":1,\"cuts\":[],\"data\":[{\"i\":\"EKSajEj5IsHhXaTDKx1PIcQ4-gcFQt9usFA5lYl82DCE\",\"s\":\"1\", \"d\":\"ERHWqC7f5k-U0vYM8u_8qFnb2ggn0HN5qHgaHS4MB_ho\"}],\"isith\":\"1\",\"toad\":3,\"wits\":[]}" | jq

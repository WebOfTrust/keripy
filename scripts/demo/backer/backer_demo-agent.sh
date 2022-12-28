#!/bin/bash
# Steps to run this demos:
# 1. Run start_backer.sh in a terminal and wait for "Baker ready"
# 2. Run start_agent.sh  in a second terminal
# 3. Run this script in a third terminal passing two parameters: backer's prefix and backer's cardano address

curl -s -X POST "http://localhost:5972/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"rootsagent\",\"passcode\":\"6jiSnnltcxQbxqiaQuLor\"}" | jq

sleep 3

curl -s -X PUT "http://localhost:5972/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"rootsagent\",\"passcode\":\"6jiSnnltcxQbxqiaQuLor\"}"  | jq

sleep 3

curl -s -X POST "http://localhost:5972/oobi" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"witroot\", \"url\":\"http://127.0.0.1:5666/oobi/${1}/controller\"}" | jq

sleep 3

curl -s -X POST "http://localhost:5972/ids/Rooth" -H "accept: */*" -H "Content-Type: application/json" -d "{\"transferable\":true,\"wits\":[\"${1}\"],\"toad\":1,\"icount\":1,\"ncount\":1,\"isith\":1,\"nsith\":1,\"data\":[{\"ca\":\"${2}\"}]}" | jq

sleep 60

curl -s -X PUT "http://localhost:5972/ids/Rooth/rot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"data\":[{\"ca\":\"${2}\"},{\"blah\":\"blah0\"}]}" | jq

sleep 60

curl -s -X PUT "http://localhost:5972/ids/Rooth/ixn" -H "accept: */*" -H "Content-Type: application/json" -d "{\"data\":[{\"ca\":\"${2}\"},{\"blah\":\"blah1\"}]}" | jq

sleep 60

curl -s -X PUT "http://localhost:5972/ids/Rooth/rot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"data\":[{\"ca\":\"${2}\"},{\"blah\":\"blah2\"}]}" | jq

sleep 60

curl -s -X PUT "http://localhost:5972/ids/Rooth/rot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"data\":[{\"ca\":\"${2}\"},{\"blah\":\"blah3\"}]}" | jq


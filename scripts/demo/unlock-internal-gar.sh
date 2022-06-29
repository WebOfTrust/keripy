#!/bin/bash

# Unlock local QAR agents
curl -s -X PUT "http://localhost:5626/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"keep-qar-5626\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\"}" | jq
curl -s -X PUT "http://localhost:5627/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"keep-qar-5627\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\"}" | jq

# Unlock local IntGAR agents
curl -s -X PUT "http://localhost:5624/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"keep-internal-gar-5624\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\"}" | jq
curl -s -X PUT "http://localhost:5625/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"keep-internal-gar-5625\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\"}" | jq
sleep 2

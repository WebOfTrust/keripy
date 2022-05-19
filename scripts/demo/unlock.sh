#!/bin/bash

curl -s -X POST "http://localhost:5623/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"agent5623\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\",\"salt\":\"0AMDEyMzQ1Njc4OWxtbm9wcQ\"}" | jq

sleep 3
curl -s -X PUT "http://localhost:5623/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"agent5623\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\"}" | jq

sleep 3
curl -s -X GET "http://localhost:5623/lock" -H "accept: */*" | jq
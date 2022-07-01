#!/bin/bash
# To run this script you need to run the following 2 commands in separate terminals:
#   > kli agent demo --config-file demo-witness-oobis
#   > kli witness demo
# DoB26Fj4x9LboAFWJra17O
curl -s -X POST "http://localhost:5623/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"agent5623\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\",\"salt\":\"0AMDEyMzQ1Njc4OWxtbm9wcQ\"}" | jq
curl -s -X POST "http://localhost:5723/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"agent5723\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\",\"salt\":\"0AMDEyMzQ1Njc4OWxtbm9abc\"}" | jq
# curl -s -X POST "http://localhost:5823/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"agent5823\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\",\"salt\":\"0AMDEyMzQ1Njc4OWxtbm9def\"}" | jq
# curl -s -X POST "http://localhost:5923/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"agent5923\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\",\"salt\":\"0AMDEyMzQ1Njc4OWxtbm9ghi\"}" | jq
sleep 3

curl -s -X PUT "http://localhost:5623/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"agent5623\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\"}" | jq
curl -s -X PUT "http://localhost:5723/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"agent5723\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\"}" | jq
# curl -s -X PUT "http://localhost:5823/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"agent5823\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\"}" | jq
# curl -s -X PUT "http://localhost:5923/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"agent5923\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\"}" | jq
sleep 6

curl -s -X POST "http://localhost:5623/ids/Alice" -H "accept: */*" -H "Content-Type: application/json" -d "{\"transferable\":true,\"wits\":[\"BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\", \"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw\",\"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c\"],\"toad\":3, \"icount\":1,\"ncount\":1,\"isith\":1,\"nsith\":1}" | jq
curl -s -X POST "http://localhost:5723/ids/Bob" -H "accept: */*" -H "Content-Type: application/json" -d "{\"transferable\":true,\"wits\":[\"BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\", \"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw\",\"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c\"],\"toad\":3, \"icount\":1,\"ncount\":1,\"isith\":1,\"nsith\":1}" | jq
# curl -s -X POST "http://localhost:5823/ids/Vic" -H "accept: */*" -H "Content-Type: application/json" -d "{\"transferable\":true,\"wits\":[\"BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\", \"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw\",\"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c\"],\"toad\":3, \"icount\":1,\"ncount\":1,\"isith\":1,\"nsith\":1}" | jq
# curl -s -X POST "http://localhost:5923/ids/Han" -H "accept: */*" -H "Content-Type: application/json" -d "{\"transferable\":true,\"wits\":[\"BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\", \"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw\",\"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c\"],\"toad\":3, \"icount\":1,\"ncount\":1,\"isith\":1,\"nsith\":1}" | jq
sleep 3

curl -s -X POST "http://localhost:5623/oobi/Alice" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"Bob\", \"url\":\"http://127.0.0.1:5643/oobi/EHvJernk0fXfDpWRt93NeuTzZUOrvfnPaH7__63PJdqw/witness/BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw\"}" | jq
curl -s -X POST "http://localhost:5723/oobi/Bob" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"Alice\", \"url\":\"http://127.0.0.1:5644/oobi/ERFmtKcQCd8xW7Rzl-PqyJ1QAfJYlfdMxYRVncPBMDkk/witness/Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c\"}" | jq

sleep 2
echo "Alice's Contacts:"
curl -s -X GET "http://localhost:5623/contacts" -H "accept: */*" | jq
echo "Bob's Contacts:"
curl -s -X GET "http://localhost:5723/contacts" -H "accept: */*" | jq

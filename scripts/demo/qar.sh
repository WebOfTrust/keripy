# Create local External GAR keystores
curl -s -X POST "http://localhost:5622/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"extgar1\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\", \"salt\":\"0AMDEyMzQ1Njc4OWdoaWpdo1\"}" | jq
curl -s -X POST "http://localhost:5623/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"extgar2\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\", \"salt\":\"0AMDEyMzQ1Njc4OWdoaWpdo2\"}" | jq
sleep 2

# Unlock local External GAR agents
curl -s -X PUT "http://localhost:5622/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"extgar1\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\"}" | jq
curl -s -X PUT "http://localhost:5623/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"extgar2\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\"}" | jq
sleep 2

# Create local External GAR AIDs
# extgar1: EkLy1sV9JCenmRmjdQtdU2rOesZgh2GZ9F4QeGyc0eg8
curl -s -X POST "http://localhost:5622/ids/extgar1" -H "accept: */*" -H "Content-Type: application/json" -d "{\"transferable\":true,\"wits\":[\"BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\",\"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw\",\"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c\"],\"toad\":2,\"icount\":1,\"ncount\":1,\"isith\":1,\"nsith\":1}" | jq

# extgar2: EkgsP2eVSRoP6DVpBqJDzNAiBpHG6LMcZgA_EPzkRfzA
curl -s -X POST "http://localhost:5623/ids/extgar2" -H "accept: */*" -H "Content-Type: application/json" -d "{\"transferable\":true,\"wits\":[\"BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\",\"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw\",\"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c\"],\"toad\":2,\"icount\":1,\"ncount\":1,\"isith\":1,\"nsith\":1}" | jq
sleep 3

# OOBI between local External GARs
curl -s -X POST "http://localhost:5622/oobi/extgar1" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"extgar2\", \"url\":\"http://127.0.0.1:5642/oobi/EkgsP2eVSRoP6DVpBqJDzNAiBpHG6LMcZgA_EPzkRfzA/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\"}" | jq
curl -s -X POST "http://localhost:5623/oobi/extgar2" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"extgar1\", \"url\":\"http://127.0.0.1:5642/oobi/EkLy1sV9JCenmRmjdQtdU2rOesZgh2GZ9F4QeGyc0eg8/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\"}" | jq
sleep 3

# Initiate and join GLEIF External multisig identifier
# curl -s -X POST "http://localhost:5622/groups/ExtGAR/icp" -H "accept: */*" -H "Content-Type: application/json" -d "{\"aids\":[\"EkLy1sV9JCenmRmjdQtdU2rOesZgh2GZ9F4QeGyc0eg8\",\"EkgsP2eVSRoP6DVpBqJDzNAiBpHG6LMcZgA_EPzkRfzA\"], \"transferable\":true,\"wits\":[\"BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\", \"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw\",\"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c\"],\"toad\":3, \"isith\":2,\"nsith\":2}" | jq
# curl -s -X POST "http://localhost:5623/groups/ExtGAR/icp" -H "accept: */*" -H "Content-Type: application/json" -d "{\"aids\":[\"EkLy1sV9JCenmRmjdQtdU2rOesZgh2GZ9F4QeGyc0eg8\",\"EkgsP2eVSRoP6DVpBqJDzNAiBpHG6LMcZgA_EPzkRfzA\"], \"transferable\":true,\"wits\":[\"BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\", \"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw\",\"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c\"],\"toad\":3, \"isith\":2,\"nsith\":2}" | jq

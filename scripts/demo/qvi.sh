# Create local External GAR keystores
curl -s -X POST "http://localhost:5823/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"extgar1\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\", \"salt\":\"0AMDEyMzQ1Njc4OWdoaWpdo1\"}" | jq
curl -s -X POST "http://localhost:5923/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"extgar2\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\", \"salt\":\"0AMDEyMzQ1Njc4OWdoaWpdo2\"}" | jq
sleep 2

# Unlock local External GAR agents
curl -s -X PUT "http://localhost:5823/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"extgar1\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\"}" | jq
curl -s -X PUT "http://localhost:5923/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"extgar2\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\"}" | jq
sleep 2

# Create local External GAR AIDs
curl -s -X POST "http://localhost:5823/ids/extgar1" -H "accept: */*" -H "Content-Type: application/json" -d "{\"transferable\":true,\"wits\":[\"BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\",\"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw\",\"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c\"],\"toad\":2,\"icount\":1,\"ncount\":1,\"isith\":1,\"nsith\":1}" | jq
curl -s -X POST "http://localhost:5923/ids/extgar2" -H "accept: */*" -H "Content-Type: application/json" -d "{\"transferable\":true,\"wits\":[\"BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\",\"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw\",\"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c\"],\"toad\":2,\"icount\":1,\"ncount\":1,\"isith\":1,\"nsith\":1}" | jq
sleep 3

# OOBI between local External GARs
curl -s -X POST "http://localhost:5823/oobi/extgar2" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"extgar1\", \"url\":\"http://127.0.0.1:5642/oobi/EC1DxuYp8GgIDVQ2c8EYBaY1CwxozvQuqGxwppNVrapY/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\"}" | jq
curl -s -X POST "http://localhost:5923/oobi/extgar1" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"extgar2\", \"url\":\"http://127.0.0.1:5642/oobi/Ef9Bhn_LeAU3rq8Rf3XHi5C1XmNdIM5uxv2DwWQT6qd8/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\"}" | jq
sleep 3

# Initiate and join GLEIF External multisig identifier
curl -s -X POST "http://localhost:5823/groups/delegator/icp" -H "accept: */*" -H "Content-Type: application/json" -d "{\"aids\":[\"Ef9Bhn_LeAU3rq8Rf3XHi5C1XmNdIM5uxv2DwWQT6qd8\",\"EC1DxuYp8GgIDVQ2c8EYBaY1CwxozvQuqGxwppNVrapY\"], \"transferable\":true,\"wits\":[\"BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\", \"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw\",\"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c\"],\"toad\":3, \"isith\":2,\"nsith\":2}" | jq
curl -s -X POST "http://localhost:5923/groups/delegator/icp" -H "accept: */*" -H "Content-Type: application/json" -d "{\"aids\":[\"Ef9Bhn_LeAU3rq8Rf3XHi5C1XmNdIM5uxv2DwWQT6qd8\",\"EC1DxuYp8GgIDVQ2c8EYBaY1CwxozvQuqGxwppNVrapY\"], \"transferable\":true,\"wits\":[\"BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\", \"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw\",\"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c\"],\"toad\":3, \"isith\":2,\"nsith\":2}" | jq

#!/bin/bash
# DoB2-6Fj4x-9Lbo-AFWJr-a17O
# Create local QAR keystores
curl -s -X POST "http://localhost:5626/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"keep-qar-5626\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\", \"salt\":\"0AMDEyMzQ1Njc4OWdoaWpdo1\"}" | jq
curl -s -X POST "http://localhost:5627/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"keep-qar-5627\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\", \"salt\":\"0AMDEyMzQ1Njc4OWdoaWpdo2\"}" | jq

# Create local LAR keystore
curl -s -X POST "http://localhost:5628/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"keep-lar-5628\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\", \"salt\":\"0AMDEyMzQ1Njc4OWdoaWpdo3\"}" | jq
curl -s -X POST "http://localhost:5629/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"keep-lar-5629\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\", \"salt\":\"0AMDEyMzQ1Njc4OWdoaWpdo4\"}" | jq
sleep 2

# Unlock local QAR agents
curl -s -X PUT "http://localhost:5626/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"keep-qar-5626\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\"}" | jq
curl -s -X PUT "http://localhost:5627/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"keep-qar-5627\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\"}" | jq

# Unlock local LAR agents
curl -s -X PUT "http://localhost:5628/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"keep-lar-5628\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\"}" | jq
curl -s -X PUT "http://localhost:5629/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"keep-lar-5629\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\"}" | jq
sleep 2

# Create local QAR AIDs
# qar1: EKyS_K3auADxLDhKN2JiT0k6neX_LwfGJQxGg4f7Gp3g
# qar2: EUS3cZM8f55JyMpIAMAirr91369PbEkY2WqI28Uo4uys
curl -s -X POST "http://localhost:5626/ids/qar1" -H "accept: */*" -H "Content-Type: application/json" -d "{\"transferable\":true,\"wits\":[\"BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\",\"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw\",\"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c\"],\"toad\":2,\"icount\":1,\"ncount\":1,\"isith\":1,\"nsith\":1}" | jq
curl -s -X POST "http://localhost:5627/ids/qar2" -H "accept: */*" -H "Content-Type: application/json" -d "{\"transferable\":true,\"wits\":[\"BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\",\"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw\",\"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c\"],\"toad\":2,\"icount\":1,\"ncount\":1,\"isith\":1,\"nsith\":1}" | jq

# Create local LAR AIDs
# lar1: EunqQ85SnNhpJdEpakejQ3pDMBeYEuMaPCyH0gpZnppQ
# lar2: EMRvWr--WHsEjzcb4TST50HhAGy0NnBeHJ6ZMWMZ4zBY
curl -s -X POST "http://localhost:5628/ids/lar1" -H "accept: */*" -H "Content-Type: application/json" -d "{\"transferable\":true,\"wits\":[\"BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\",\"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw\",\"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c\"],\"toad\":2,\"icount\":1,\"ncount\":1,\"isith\":1,\"nsith\":1}" | jq
curl -s -X POST "http://localhost:5629/ids/lar2" -H "accept: */*" -H "Content-Type: application/json" -d "{\"transferable\":true,\"wits\":[\"BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\",\"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw\",\"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c\"],\"toad\":2,\"icount\":1,\"ncount\":1,\"isith\":1,\"nsith\":1}" | jq
sleep 3

# OOBI between local QARs
curl -s -X POST "http://localhost:5626/oobi/qar1" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"qar2\", \"url\":\"http://127.0.0.1:5642/oobi/EUS3cZM8f55JyMpIAMAirr91369PbEkY2WqI28Uo4uys/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\"}" | jq
curl -s -X POST "http://localhost:5627/oobi/qar2" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"qar1\", \"url\":\"http://127.0.0.1:5642/oobi/EKyS_K3auADxLDhKN2JiT0k6neX_LwfGJQxGg4f7Gp3g/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\"}" | jq

# OOBI between local LARs
curl -s -X POST "http://localhost:5628/oobi/lar1" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"lar2\", \"url\":\"http://127.0.0.1:5642/oobi/EMRvWr--WHsEjzcb4TST50HhAGy0NnBeHJ6ZMWMZ4zBY/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\"}" | jq
curl -s -X POST "http://localhost:5629/oobi/lar2" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"lar1\", \"url\":\"http://127.0.0.1:5642/oobi/EunqQ85SnNhpJdEpakejQ3pDMBeYEuMaPCyH0gpZnppQ/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\"}" | jq
sleep 3

# Initiate and join QVI multisig AID
curl -s -X POST "http://localhost:5626/groups/QAR/icp" -H "accept: */*" -H "Content-Type: application/json" -d "{\"aids\":[\"EKyS_K3auADxLDhKN2JiT0k6neX_LwfGJQxGg4f7Gp3g\",\"EUS3cZM8f55JyMpIAMAirr91369PbEkY2WqI28Uo4uys\"], \"transferable\":true,\"wits\":[\"BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\", \"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw\",\"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c\"],\"toad\":3, \"isith\":2,\"nsith\":2}" | jq
curl -s -X PUT "http://localhost:5627/groups/QAR/icp" -H "accept: */*" -H "Content-Type: application/json" -d "{\"aids\":[\"EKyS_K3auADxLDhKN2JiT0k6neX_LwfGJQxGg4f7Gp3g\",\"EUS3cZM8f55JyMpIAMAirr91369PbEkY2WqI28Uo4uys\"], \"transferable\":true,\"wits\":[\"BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\", \"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw\",\"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c\"],\"toad\":3, \"isith\":2,\"nsith\":2}" | jq

# Initiate and join LegalEntity multisig AID
curl -s -X POST "http://localhost:5628/groups/LAR/icp" -H "accept: */*" -H "Content-Type: application/json" -d "{\"aids\":[\"EunqQ85SnNhpJdEpakejQ3pDMBeYEuMaPCyH0gpZnppQ\",\"EMRvWr--WHsEjzcb4TST50HhAGy0NnBeHJ6ZMWMZ4zBY\"], \"transferable\":true,\"wits\":[\"BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\", \"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw\",\"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c\"],\"toad\":3, \"isith\":2,\"nsith\":2}" | jq
curl -s -X PUT "http://localhost:5629/groups/LAR/icp" -H "accept: */*" -H "Content-Type: application/json" -d "{\"aids\":[\"EunqQ85SnNhpJdEpakejQ3pDMBeYEuMaPCyH0gpZnppQ\",\"EMRvWr--WHsEjzcb4TST50HhAGy0NnBeHJ6ZMWMZ4zBY\"], \"transferable\":true,\"wits\":[\"BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\", \"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw\",\"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c\"],\"toad\":3, \"isith\":2,\"nsith\":2}" | jq

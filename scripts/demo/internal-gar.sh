#!/bin/bash
# DoB2-6Fj4x-9Lbo-AFWJr-a17O
# Create local QAR keystores
curl -s -X POST "http://localhost:5626/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"keep-qar-5626\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\", \"salt\":\"0AMDEyMzQ1Njc4OWdoaWpdo1\"}" | jq
curl -s -X POST "http://localhost:5627/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"keep-qar-5627\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\", \"salt\":\"0AMDEyMzQ1Njc4OWdoaWpdo2\"}" | jq

# Create local IntGAR keystore
curl -s -X POST "http://localhost:5624/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"keep-internal-gar-5624\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\", \"salt\":\"0AMDEyMzQ1Njc4OWdoaWpdo3\"}" | jq
curl -s -X POST "http://localhost:5625/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"keep-internal-gar-5625\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\", \"salt\":\"0AMDEyMzQ1Njc4OWdoaWpdo4\"}" | jq
sleep 2

# Unlock local QAR agents
curl -s -X PUT "http://localhost:5626/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"keep-qar-5626\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\"}" | jq
curl -s -X PUT "http://localhost:5627/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"keep-qar-5627\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\"}" | jq

# Unlock local IntGAR agents
curl -s -X PUT "http://localhost:5624/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"keep-internal-gar-5624\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\"}" | jq
curl -s -X PUT "http://localhost:5625/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"keep-internal-gar-5625\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\"}" | jq
sleep 2

# Create local QAR AIDs
# qar1: EKyS_K3auADxLDhKN2JiT0k6neX_LwfGJQxGg4f7Gp3g
# qar2: EUS3cZM8f55JyMpIAMAirr91369PbEkY2WqI28Uo4uys
curl -s -X POST "http://localhost:5626/ids/qar1" -H "accept: */*" -H "Content-Type: application/json" -d "{\"transferable\":true,\"wits\":[\"BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\",\"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw\",\"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c\"],\"toad\":2,\"icount\":1,\"ncount\":1,\"isith\":1,\"nsith\":1}" | jq
curl -s -X POST "http://localhost:5627/ids/qar2" -H "accept: */*" -H "Content-Type: application/json" -d "{\"transferable\":true,\"wits\":[\"BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\",\"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw\",\"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c\"],\"toad\":2,\"icount\":1,\"ncount\":1,\"isith\":1,\"nsith\":1}" | jq

# Create local IntGAR AIDs
# intgar1: EeoS9aaqWggd6hTBDbvM7aKTSxDrM1R4tZp-Vg2IVkMA
# intgar2: ECV586ydtrGHiVSeU_wJQCxGm3HQCMaSiD-vzSKm-AqI
curl -s -X POST "http://localhost:5624/ids/intgar1" -H "accept: */*" -H "Content-Type: application/json" -d "{\"transferable\":true,\"wits\":[\"BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\",\"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw\",\"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c\"],\"toad\":2,\"icount\":1,\"ncount\":1,\"isith\":1,\"nsith\":1}" | jq
curl -s -X POST "http://localhost:5625/ids/intgar2" -H "accept: */*" -H "Content-Type: application/json" -d "{\"transferable\":true,\"wits\":[\"BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\",\"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw\",\"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c\"],\"toad\":2,\"icount\":1,\"ncount\":1,\"isith\":1,\"nsith\":1}" | jq
sleep 3

# OOBI between local QARs
curl -s -X POST "http://localhost:5626/oobi/qar1" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"qar2\", \"url\":\"http://127.0.0.1:5642/oobi/EUS3cZM8f55JyMpIAMAirr91369PbEkY2WqI28Uo4uys/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\"}" | jq
curl -s -X POST "http://localhost:5627/oobi/qar2" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"qar1\", \"url\":\"http://127.0.0.1:5642/oobi/EKyS_K3auADxLDhKN2JiT0k6neX_LwfGJQxGg4f7Gp3g/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\"}" | jq

# OOBI between local IntGARs
curl -s -X POST "http://localhost:5624/oobi/intgar1" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"intgar2\", \"url\":\"http://127.0.0.1:5642/oobi/ECV586ydtrGHiVSeU_wJQCxGm3HQCMaSiD-vzSKm-AqI/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\"}" | jq
curl -s -X POST "http://localhost:5625/oobi/intgar2" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"intgar1\", \"url\":\"http://127.0.0.1:5642/oobi/EeoS9aaqWggd6hTBDbvM7aKTSxDrM1R4tZp-Vg2IVkMA/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\"}" | jq
sleep 3

# Initiate and join QVI multisig AID
# QVI: ESrWiCbP5K0Q7-m1e3GPaY8HJCvqioEIIJhqpz16zk6w
curl -s -X POST "http://localhost:5626/groups/QAR/icp" -H "accept: */*" -H "Content-Type: application/json" -d "{\"aids\":[\"EKyS_K3auADxLDhKN2JiT0k6neX_LwfGJQxGg4f7Gp3g\",\"EUS3cZM8f55JyMpIAMAirr91369PbEkY2WqI28Uo4uys\"], \"transferable\":true,\"wits\":[\"BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\", \"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw\",\"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c\"],\"toad\":3, \"isith\":2,\"nsith\":2}" | jq
curl -s -X PUT "http://localhost:5627/groups/QAR/icp" -H "accept: */*" -H "Content-Type: application/json" -d "{\"aids\":[\"EKyS_K3auADxLDhKN2JiT0k6neX_LwfGJQxGg4f7Gp3g\",\"EUS3cZM8f55JyMpIAMAirr91369PbEkY2WqI28Uo4uys\"], \"transferable\":true,\"wits\":[\"BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\", \"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw\",\"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c\"],\"toad\":3, \"isith\":2,\"nsith\":2}" | jq

# Initiate and join Internal GAR multisig AID
# IntGAR: ESQjNQnVk1N8nTdS7g6m17IWD0iuliABV-RMA-drjgIs
curl -s -X POST "http://localhost:5624/groups/IntGAR/icp" -H "accept: */*" -H "Content-Type: application/json" -d "{\"aids\":[\"EeoS9aaqWggd6hTBDbvM7aKTSxDrM1R4tZp-Vg2IVkMA\",\"ECV586ydtrGHiVSeU_wJQCxGm3HQCMaSiD-vzSKm-AqI\"], \"transferable\":true,\"wits\":[\"BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\", \"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw\",\"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c\"],\"toad\":3, \"isith\":2,\"nsith\":2}" | jq
curl -s -X PUT "http://localhost:5625/groups/IntGAR/icp" -H "accept: */*" -H "Content-Type: application/json" -d "{\"aids\":[\"EeoS9aaqWggd6hTBDbvM7aKTSxDrM1R4tZp-Vg2IVkMA\",\"ECV586ydtrGHiVSeU_wJQCxGm3HQCMaSiD-vzSKm-AqI\"], \"transferable\":true,\"wits\":[\"BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\", \"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw\",\"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c\"],\"toad\":3, \"isith\":2,\"nsith\":2}" | jq

#!/bin/bash
# DoB26Fj4x9LboAFWJra17O
curl -s -X POST "http://localhost:5623/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"multisig1\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\",\"salt\":\"0AMDEyMzQ1Njc4OWxtbm9wcQ\"}" | jq
curl -s -X POST "http://localhost:5723/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"multisig2\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\", \"salt\":\"0AMDEyMzQ1Njc4OWdoaWpsaw\"}" | jq
curl -s -X POST "http://localhost:5823/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"issuer\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\",\"salt\":\"0AMDEyMzQ1Njc4OWxtbm9abc\"}" | jq

sleep 3
curl -s -X PUT "http://localhost:5623/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"multisig1\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\"}" | jq
curl -s -X PUT "http://localhost:5723/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"multisig2\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\"}" | jq
curl -s -X PUT "http://localhost:5823/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"issuer\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\"}" | jq

sleep 4
curl -s -X POST "http://localhost:5623/ids/multisig1" -H "accept: */*" -H "Content-Type: application/json" -d "{\"transferable\":true,\"wits\":[\"BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\",\"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw\",\"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c\"],\"toad\":2,\"icount\":1,\"ncount\":1,\"isith\":1,\"nsith\":1}" | jq
curl -s -X POST "http://localhost:5723/ids/multisig2" -H "accept: */*" -H "Content-Type: application/json" -d "{\"transferable\":true,\"wits\":[\"BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\",\"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw\",\"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c\"],\"toad\":2,\"icount\":1,\"ncount\":1,\"isith\":1,\"nsith\":1}" | jq
curl -s -X POST "http://localhost:5823/ids/issuer" -H "accept: */*" -H "Content-Type: application/json" -d "{\"transferable\":true,\"wits\":[\"BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\", \"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw\",\"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c\"],\"toad\":3, \"icount\":1,\"ncount\":1,\"isith\":1,\"nsith\":1}" | jq

sleep 4
curl -s -X POST "http://localhost:5623/oobi/multisig1" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"multisig2\", \"url\":\"http://127.0.0.1:5642/oobi/EozYHef4je02EkMOA1IKM65WkIdSjfrL7XWDk_JzJL9o/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\"}" | jq
curl -s -X POST "http://localhost:5723/oobi/multisig2" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"multisig1\", \"url\":\"http://127.0.0.1:5642/oobi/E-4-PsMBN0YEKyTl3zL0zulWcBehdaaG6Go5cMc0BzQ8/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\"}" | jq
curl -s -X POST "http://localhost:5623/oobi/multisig1" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"issuer\", \"url\":\"http://127.0.0.1:5643/oobi/EIRdVAl2ItmJf8K82h1cwd5QNF5iVAT37uf8gyIS38QE/witness/BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw\"}" | jq
curl -s -X POST "http://localhost:5723/oobi/multisig2" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"issuer\", \"url\":\"http://127.0.0.1:5643/oobi/EIRdVAl2ItmJf8K82h1cwd5QNF5iVAT37uf8gyIS38QE/witness/BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw\"}" | jq

echo "Adding oobis"
echo "--issuer resolving oobis from multisig1 & multisig2"
curl -s -X POST "http://localhost:5823/oobi/issuer" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"multisig2\", \"url\":\"http://127.0.0.1:5642/oobi/EozYHef4je02EkMOA1IKM65WkIdSjfrL7XWDk_JzJL9o/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\"}" | jq
curl -s -X POST "http://localhost:5823/oobi/issuer" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"multisig1\", \"url\":\"http://127.0.0.1:5642/oobi/E-4-PsMBN0YEKyTl3zL0zulWcBehdaaG6Go5cMc0BzQ8/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\"}" | jq

echo "--schema oobis"
curl -s -X POST "http://localhost:5623/oobi/multisig1" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"multisig1\", \"url\":\"http://127.0.0.1:7723/oobi/EWCeT9zTxaZkaC_3-amV2JtG6oUxNA36sCC0P5MI7Buw\"}" | jq
curl -s -X POST "http://localhost:5723/oobi/multisig2" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"multisig2\", \"url\":\"http://127.0.0.1:7723/oobi/EWCeT9zTxaZkaC_3-amV2JtG6oUxNA36sCC0P5MI7Buw\"}" | jq
curl -s -X POST "http://localhost:5823/oobi/issuer" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"issuer\", \"url\":\"http://127.0.0.1:7723/oobi/EWCeT9zTxaZkaC_3-amV2JtG6oUxNA36sCC0P5MI7Buw\"}" | jq
echo "finished adding oobis"

echo "inception event for multisig holder"
sleep 3
curl -s -X POST "http://localhost:5623/groups/holder/icp" -H "accept: */*" -H "Content-Type: application/json" -d "{\"aids\":[\"EozYHef4je02EkMOA1IKM65WkIdSjfrL7XWDk_JzJL9o\",\"E-4-PsMBN0YEKyTl3zL0zulWcBehdaaG6Go5cMc0BzQ8\"], \"transferable\":true,\"wits\":[\"BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\", \"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw\",\"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c\"],\"toad\":3, \"isith\":2,\"nsith\":2}" | jq
curl -s -X PUT "http://localhost:5723/groups/holder/icp" -H "accept: */*" -H "Content-Type: application/json" -d "{\"aids\":[\"EozYHef4je02EkMOA1IKM65WkIdSjfrL7XWDk_JzJL9o\",\"E-4-PsMBN0YEKyTl3zL0zulWcBehdaaG6Go5cMc0BzQ8\"], \"transferable\":true,\"wits\":[\"BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\", \"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw\",\"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c\"],\"toad\":3, \"isith\":2,\"nsith\":2}" | jq

sleep 3
echo oobi holder to issuer
curl -s -X POST "http://localhost:5823/oobi/issuer" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"holder\", \"url\":\"http://127.0.0.1:5642/oobi/EOWwyMU3XA7RtWdelFt-6waurOTH_aW_Z9VTaU-CshGk/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\"}" | jq

echo "post registries"
curl -s -X POST "http://localhost:5823/registries" -H "accept: */*" -H "Content-Type: application/json" -d "{\"alias\":\"issuer\",\"baks\":[],\"estOnly\":false,\"name\":\"vLEI\",\"noBackers\":true,\"toad\":0}" | jq

#curl -s -X POST "http://localhost:5823/registries" -H "accept: */*" -H "Content-Type: application/json" -d "{\"alias\":\"issuer\",\"nonce\":\"AHSNDV3ABI6U8OIgKaj3aky91ZpNL54I5_7-qwtC6q2s\",\"baks\":[],\"estOnly\":false,\"name\":\"vLEI\",\"noBackers\":true,\"toad\":0}" | jq

# sleep 3
# curl -s -X POST "http://localhost:5623/groups/issuer/rot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"adds\":[],\"aids\":[\"EozYHef4je02EkMOA1IKM65WkIdSjfrL7XWDk_JzJL9o\", \"E-4-PsMBN0YEKyTl3zL0zulWcBehdaaG6Go5cMc0BzQ8\"],\"count\":2,\"cuts\":[],\"data\":[],\"isith\":\"2\",\"toad\":2, \"wits\":[]}" | jq
# curl -s -X PUT "http://localhost:5723/groups/issuer/rot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"adds\":[],\"aids\":[\"EozYHef4je02EkMOA1IKM65WkIdSjfrL7XWDk_JzJL9o\", \"E-4-PsMBN0YEKyTl3zL0zulWcBehdaaG6Go5cMc0BzQ8\"],\"count\":2,\"cuts\":[],\"data\":[],\"isith\":\"2\",\"toad\":2, \"wits\":[]}" | jq

sleep 3
echo "Issue Credential"
curl -X POST "http://localhost:5823/credentials/issuer" -H "accept: application/json" -H "Content-Type: application/json" -d "{\"credentialData\":{\"LEI\":\"5493001KJTIIGC8Y1R17\"},\"recipient\":\"EOWwyMU3XA7RtWdelFt-6waurOTH_aW_Z9VTaU-CshGk\",\"registry\":\"vLEI\",\"schema\":\"EWCeT9zTxaZkaC_3-amV2JtG6oUxNA36sCC0P5MI7Buw\",\"source\":{}}"
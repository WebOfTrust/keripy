#!/bin/bash

echo "Create keystores"
curl -s -X POST "http://localhost:5620/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"rootgar1\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\", \"salt\":\"0AMDEyMzQ1Njc4OWdoaWpsaw\"}" | jq
curl -s -X POST "http://localhost:5621/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"rootgar2\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\", \"salt\":\"0AMDEyMzQ1Njc4OWdoaWpsaw\"}" | jq
curl -s -X POST "http://localhost:5622/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"extgar1\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\",\"salt\":\"0AMDEyMzQ1Njc4OWxtbm9wcQ\"}" | jq
curl -s -X POST "http://localhost:5623/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"extgar2\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\", \"salt\":\"0AMDEyMzQ1Njc4OWdoaWpsaw\"}" | jq
sleep 2
echo "Unlock agents"
curl -s -X PUT "http://localhost:5620/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"rootgar1\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\"}" | jq
curl -s -X PUT "http://localhost:5621/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"rootgar2\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\"}" | jq
curl -s -X PUT "http://localhost:5622/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"extgar1\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\"}" | jq
curl -s -X PUT "http://localhost:5623/boot" -H "accept: */*" -H "Content-Type: application/json" -d "{\"name\":\"extgar2\",\"passcode\":\"DoB2-6Fj4x-9Lbo-AFWJr-a17O\"}" | jq
sleep 2
echo "Create identifiers"
curl -s -X POST "http://localhost:5620/ids/rootgar1" -H "accept: */*" -H "Content-Type: application/json" -d "{\"wits\":[\"BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\",\"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw\",\"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c\"]}" | jq
curl -s -X POST "http://localhost:5621/ids/rootgar2" -H "accept: */*" -H "Content-Type: application/json" -d "{\"wits\":[\"BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\",\"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw\",\"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c\"]}" | jq

# rootgar1
# EH3L9seOV-2X1zomF3NZ_U4RTj-M6mQI0Ffav3mAz4Ng

# rootgar2
# Eoap8SUfoW5oFw6QnSkNHZPRaNChJ5xy3SuR2r0dLgFs

# extgar1
# EjKsEuRs4GMSdpP5rNuNzw-fUDuyKpqDu-V2KdmfEiGY

# extgar2
# ETdcy4NvU6RMhH8KtFNYFtNGwvyIu83mGZHSsZvrHu9s

sleep 2
echo "Root GAR OOBIs"
curl -s -X POST "http://localhost:5620/oobi/rootgar1" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"rootgar2\", \"url\":\"http://127.0.0.1:5642/oobi/Eoap8SUfoW5oFw6QnSkNHZPRaNChJ5xy3SuR2r0dLgFs/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\"}" | jq
curl -s -X POST "http://localhost:5621/oobi/rootgar2" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"rootgar1\", \"url\":\"http://127.0.0.1:5642/oobi/EH3L9seOV-2X1zomF3NZ_U4RTj-M6mQI0Ffav3mAz4Ng/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\"}" | jq
sleep 2
echo "Root GAR Challenges"
curl -s -X POST "http://localhost:5620/challenge/rootgar1" -H "accept: */*" -H "Content-Type: application/json" -d "{\"recipient\":\"Eoap8SUfoW5oFw6QnSkNHZPRaNChJ5xy3SuR2r0dLgFs\",\"words\":[\"great\",\"enact\",\"capital\",\"pulse\",\"normal\",\"woman\",\"satisfy\",\"fashion\",\"mesh\",\"bicycle\",\"curve\",\"traffic\"]}" | jq
curl -s -X POST "http://localhost:5621/challenge/rootgar2" -H "accept: */*" -H "Content-Type: application/json" -d "{\"recipient\":\"EH3L9seOV-2X1zomF3NZ_U4RTj-M6mQI0Ffav3mAz4Ng\",\"words\":[\"robust\",\"soup\",\"strategy\",\"write\",\"knife\",\"valley\",\"ritual\",\"similar\",\"flush\",\"indoor\",\"home\",\"ride\"]}" | jq
sleep 2
echo "Mark new contacts as verified"
curl -s -X PUT 'http://localhost:5620/contacts/Eoap8SUfoW5oFw6QnSkNHZPRaNChJ5xy3SuR2r0dLgFs/rootgar1' -H 'Accept: */*' -H 'Content-Type: application/json' -d '{"verified":"true"}' | jq
curl -s -X PUT 'http://localhost:5621/contacts/EH3L9seOV-2X1zomF3NZ_U4RTj-M6mQI0Ffav3mAz4Ng/rootgar2' -H 'Accept: */*' -H 'Content-Type: application/json' -d '{"verified":"true"}' | jq
sleep 2
echo "Root GAR Multisig group inception"
curl -s -X PUT 'http://localhost:5620/groups/rootgars/icp' -H 'Accept: */*' -H 'Content-Type: application/json' -d '{"aids":["EH3L9seOV-2X1zomF3NZ_U4RTj-M6mQI0Ffav3mAz4Ng","Eoap8SUfoW5oFw6QnSkNHZPRaNChJ5xy3SuR2r0dLgFs"],"isith":"1/2,1/2","nsith":"1/2,1/2","toad":3,"wits":["BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo","BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c"]}' | jq
curl -s -X PUT 'http://localhost:5621/groups/rootgars/icp' -H 'Accept: */*' -H 'Content-Type: application/json' -d '{"aids":["EH3L9seOV-2X1zomF3NZ_U4RTj-M6mQI0Ffav3mAz4Ng","Eoap8SUfoW5oFw6QnSkNHZPRaNChJ5xy3SuR2r0dLgFs"],"isith":["1/2","1/2"],"nsith":["1/2","1/2"],"toad":3,"wits":["BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo","BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c"]}' | jq
#
sleep 2
curl -s -X POST "http://localhost:5622/ids/extgar1" -H "accept: */*" -H "Content-Type: application/json" -d "{\"wits\":[\"BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\",\"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw\",\"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c\"]}" | jq
curl -s -X POST "http://localhost:5623/ids/extgar2" -H "accept: */*" -H "Content-Type: application/json" -d "{\"wits\":[\"BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\",\"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw\",\"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c\"]}" | jq
sleep 2
echo "Ext GAR OOBIs"
curl -s -X POST "http://localhost:5622/oobi/extgar1" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"extgar2\", \"url\":\"http://127.0.0.1:5642/oobi/ETdcy4NvU6RMhH8KtFNYFtNGwvyIu83mGZHSsZvrHu9s/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\"}" | jq
curl -s -X POST "http://localhost:5623/oobi/extgar2" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"extgar1\", \"url\":\"http://127.0.0.1:5642/oobi/EjKsEuRs4GMSdpP5rNuNzw-fUDuyKpqDu-V2KdmfEiGY/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\"}" | jq
sleep 2
echo "Ext GAR Challenges"
curl -s -X POST "http://localhost:5622/challenge/extgar1" -H "accept: */*" -H "Content-Type: application/json" -d "{\"recipient\":\"ETdcy4NvU6RMhH8KtFNYFtNGwvyIu83mGZHSsZvrHu9s\",\"words\":[\"great\",\"enact\",\"capital\",\"pulse\",\"normal\",\"woman\",\"satisfy\",\"fashion\",\"mesh\",\"bicycle\",\"curve\",\"traffic\"]}" | jq
curl -s -X POST "http://localhost:5623/challenge/extgar2" -H "accept: */*" -H "Content-Type: application/json" -d "{\"recipient\":\"EjKsEuRs4GMSdpP5rNuNzw-fUDuyKpqDu-V2KdmfEiGY\",\"words\":[\"robust\",\"soup\",\"strategy\",\"write\",\"knife\",\"valley\",\"ritual\",\"similar\",\"flush\",\"indoor\",\"home\",\"ride\"]}" | jq
sleep 2
echo "Mark new contacts as verified"
curl -s -X PUT 'http://localhost:5622/contacts/ETdcy4NvU6RMhH8KtFNYFtNGwvyIu83mGZHSsZvrHu9s/extgar1' -H 'Accept: */*' -H 'Content-Type: application/json' -d '{"verified":"true"}' | jq
curl -s -X PUT 'http://localhost:5623/contacts/EjKsEuRs4GMSdpP5rNuNzw-fUDuyKpqDu-V2KdmfEiGY/extgar2' -H 'Accept: */*' -H 'Content-Type: application/json' -d '{"verified":"true"}' | jq

#sleep 2
#echo "Lead OOBIs"
#curl -s -X POST "http://localhost:5620/oobi/rootgar1" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"extgar1\", \"url\":\"http://127.0.0.1:5642/oobi/EjKsEuRs4GMSdpP5rNuNzw-fUDuyKpqDu-V2KdmfEiGY/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\"}" | jq
#curl -s -X POST "http://localhost:5622/oobi/extgar1" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"rootgar1\", \"url\":\"http://127.0.0.1:5642/oobi/EH3L9seOV-2X1zomF3NZ_U4RTj-M6mQI0Ffav3mAz4Ng/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\"}" | jq
#sleep 2
#echo "Lead Challenges"
#curl -s -X POST "http://localhost:5620/challenge/rootgar1" -H "accept: */*" -H "Content-Type: application/json" -d "{\"recipient\":\"EjKsEuRs4GMSdpP5rNuNzw-fUDuyKpqDu-V2KdmfEiGY\",\"words\":[\"great\",\"enact\",\"capital\",\"pulse\",\"normal\",\"woman\",\"satisfy\",\"fashion\",\"mesh\",\"bicycle\",\"curve\",\"traffic\"]}" | jq
#curl -s -X POST "http://localhost:5622/challenge/extgar1" -H "accept: */*" -H "Content-Type: application/json" -d "{\"recipient\":\"EH3L9seOV-2X1zomF3NZ_U4RTj-M6mQI0Ffav3mAz4Ng\",\"words\":[\"robust\",\"soup\",\"strategy\",\"write\",\"knife\",\"valley\",\"ritual\",\"similar\",\"flush\",\"indoor\",\"home\",\"ride\"]}" | jq
#sleep 2
#echo "Mark new contacts as verified"
#curl -s -X PUT 'http://localhost:5620/contacts/EjKsEuRs4GMSdpP5rNuNzw-fUDuyKpqDu-V2KdmfEiGY/rootgar1' -H 'Accept: */*' -H 'Content-Type: application/json' -d '{"verified":"true"}' | jq
#curl -s -X PUT 'http://localhost:5622/contacts/EH3L9seOV-2X1zomF3NZ_U4RTj-M6mQI0Ffav3mAz4Ng/extgar1' -H 'Accept: */*' -H 'Content-Type: application/json' -d '{"verified":"true"}' | jq

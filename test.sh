#!/bin/bash

curl -s 'http://127.0.0.1:5620/boot' \
  -H 'Accept: application/json, text/*' \
  -H 'Accept-Language: en-US,en;q=0.9' \
  -H 'Connection: keep-alive' \
  -H 'Content-Type: application/json; charset=UTF-8' \
  -H 'DNT: 1' \
  -H 'Origin: http://localhost:5520' \
  -H 'Referer: http://localhost:5520/' \
  -H 'Sec-Fetch-Dest: empty' \
  -H 'Sec-Fetch-Mode: cors' \
  -H 'Sec-Fetch-Site: cross-site' \
  -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36' \
  -H 'sec-ch-ua: "Chromium";v="104", " Not A;Brand";v="99", "Google Chrome";v="104"' \
  -H 'sec-ch-ua-mobile: ?0' \
  -H 'sec-ch-ua-platform: "macOS"' \
  --data-raw '{"name":"keep-root-gar-5620","passcode":"CSz6-mZqWf-KaSq-FFreH-nmdI"}' \
  --compressed | jq
sleep 3
curl -s 'http://127.0.0.1:5621/boot' \
  -H 'Accept: application/json, text/*' \
  -H 'Accept-Language: en-US,en;q=0.9' \
  -H 'Connection: keep-alive' \
  -H 'Content-Type: application/json; charset=UTF-8' \
  -H 'DNT: 1' \
  -H 'Origin: http://localhost:5521' \
  -H 'Referer: http://localhost:5521/' \
  -H 'Sec-Fetch-Dest: empty' \
  -H 'Sec-Fetch-Mode: cors' \
  -H 'Sec-Fetch-Site: cross-site' \
  -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36' \
  -H 'sec-ch-ua: "Chromium";v="104", " Not A;Brand";v="99", "Google Chrome";v="104"' \
  -H 'sec-ch-ua-mobile: ?0' \
  -H 'sec-ch-ua-platform: "macOS"' \
  --data-raw '{"name":"keep-root-gar-5621","passcode":"Olpm-VtcL1-41Va-p5D7P-zRSK"}' \
  --compressed | jq

sleep 6

curl -s 'http://127.0.0.1:5620/boot' \
  -X 'PUT' \
  -H 'Accept: application/json, text/*' \
  -H 'Accept-Language: en-US,en;q=0.9' \
  -H 'Connection: keep-alive' \
  -H 'Content-Type: application/json; charset=UTF-8' \
  -H 'DNT: 1' \
  -H 'Origin: http://localhost:5520' \
  -H 'Referer: http://localhost:5520/' \
  -H 'Sec-Fetch-Dest: empty' \
  -H 'Sec-Fetch-Mode: cors' \
  -H 'Sec-Fetch-Site: cross-site' \
  -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36' \
  -H 'sec-ch-ua: ".Not/A)Brand";v="99", "Google Chrome";v="103", "Chromium";v="103"' \
  -H 'sec-ch-ua-mobile: ?0' \
  -H 'sec-ch-ua-platform: "macOS"' \
  --data-raw '{"name":"keep-root-gar-5620","passcode":"CSz6-mZqWf-KaSq-FFreH-nmdI"}' \
  --compressed | jq

sleep 2
curl -s 'http://127.0.0.1:5621/boot' \
  -X 'PUT' \
  -H 'Accept: application/json, text/*' \
  -H 'Accept-Language: en-US,en;q=0.9' \
  -H 'Connection: keep-alive' \
  -H 'Content-Type: application/json; charset=UTF-8' \
  -H 'DNT: 1' \
  -H 'Origin: http://localhost:5521' \
  -H 'Referer: http://localhost:5521/' \
  -H 'Sec-Fetch-Dest: empty' \
  -H 'Sec-Fetch-Mode: cors' \
  -H 'Sec-Fetch-Site: cross-site' \
  -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36' \
  -H 'sec-ch-ua: ".Not/A)Brand";v="99", "Google Chrome";v="103", "Chromium";v="103"' \
  -H 'sec-ch-ua-mobile: ?0' \
  -H 'sec-ch-ua-platform: "macOS"' \
  --data-raw '{"name":"keep-root-gar-5621","passcode":"Olpm-VtcL1-41Va-p5D7P-zRSK"}' \
  --compressed | jq

sleep 2

curl -s 'http://127.0.0.1:5620/ids/Karla' \
  -H 'Accept: application/json, text/*' \
  -H 'Accept-Language: en-US,en;q=0.9' \
  -H 'Connection: keep-alive' \
  -H 'Content-Type: application/json; charset=UTF-8' \
  -H 'DNT: 1' \
  -H 'Origin: http://localhost:5520' \
  -H 'Referer: http://localhost:5520/' \
  -H 'Sec-Fetch-Dest: empty' \
  -H 'Sec-Fetch-Mode: cors' \
  -H 'Sec-Fetch-Site: cross-site' \
  -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36' \
  -H 'sec-ch-ua: "Chromium";v="104", " Not A;Brand";v="99", "Google Chrome";v="104"' \
  -H 'sec-ch-ua-mobile: ?0' \
  -H 'sec-ch-ua-platform: "macOS"' \
  --data-raw '{"wits":["BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo","BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c"]}' \
  --compressed | jq

curl -s 'http://127.0.0.1:5621/ids/Christoph' \
  -H 'Accept: application/json, text/*' \
  -H 'Accept-Language: en-US,en;q=0.9' \
  -H 'Connection: keep-alive' \
  -H 'Content-Type: application/json; charset=UTF-8' \
  -H 'DNT: 1' \
  -H 'Origin: http://localhost:5521' \
  -H 'Referer: http://localhost:5521/' \
  -H 'Sec-Fetch-Dest: empty' \
  -H 'Sec-Fetch-Mode: cors' \
  -H 'Sec-Fetch-Site: cross-site' \
  -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36' \
  -H 'sec-ch-ua: "Chromium";v="104", " Not A;Brand";v="99", "Google Chrome";v="104"' \
  -H 'sec-ch-ua-mobile: ?0' \
  -H 'sec-ch-ua-platform: "macOS"' \
  --data-raw '{"wits":["BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo","BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c"]}' \
  --compressed | jq

sleep 3
curl -s 'http://127.0.0.1:5621/oobi/Christoph' \
  -H 'Accept: application/json, text/*' \
  -H 'Accept-Language: en-US,en;q=0.9' \
  -H 'Connection: keep-alive' \
  -H 'Content-Type: application/json; charset=UTF-8' \
  -H 'DNT: 1' \
  -H 'Origin: http://localhost:5521' \
  -H 'Referer: http://localhost:5521/' \
  -H 'Sec-Fetch-Dest: empty' \
  -H 'Sec-Fetch-Mode: cors' \
  -H 'Sec-Fetch-Site: cross-site' \
  -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36' \
  -H 'sec-ch-ua: "Chromium";v="104", " Not A;Brand";v="99", "Google Chrome";v="104"' \
  -H 'sec-ch-ua-mobile: ?0' \
  -H 'sec-ch-ua-platform: "macOS"' \
  --data-raw '{"oobialias":"Karla","url":"http://127.0.0.1:5642/oobi/E1kvW2hxdYXW-tD0c4ljnSfaOKrTjnJhIuzx-XVjlz1M/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo"}' \
  --compressed | jq

curl -s 'http://127.0.0.1:5620/oobi/Karla' \
  -H 'Accept: application/json, text/*' \
  -H 'Accept-Language: en-US,en;q=0.9' \
  -H 'Connection: keep-alive' \
  -H 'Content-Type: application/json; charset=UTF-8' \
  -H 'DNT: 1' \
  -H 'Origin: http://localhost:5520' \
  -H 'Referer: http://localhost:5520/' \
  -H 'Sec-Fetch-Dest: empty' \
  -H 'Sec-Fetch-Mode: cors' \
  -H 'Sec-Fetch-Site: cross-site' \
  -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36' \
  -H 'sec-ch-ua: "Chromium";v="104", " Not A;Brand";v="99", "Google Chrome";v="104"' \
  -H 'sec-ch-ua-mobile: ?0' \
  -H 'sec-ch-ua-platform: "macOS"' \
  --data-raw '{"oobialias":"Christoph","url":"http://127.0.0.1:5642/oobi/ETz3oW9PnO3jbvWVy_TsZfqXfEVx9aY750tFhBxjHr80/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo"}' \
  --compressed | jq

sleep 2
curl -s 'http://127.0.0.1:5620/contacts/ETz3oW9PnO3jbvWVy_TsZfqXfEVx9aY750tFhBxjHr80' \
  -X 'PUT' \
  -H 'sec-ch-ua: "Chromium";v="104", " Not A;Brand";v="99", "Google Chrome";v="104"' \
  -H 'DNT: 1' \
  -H 'sec-ch-ua-mobile: ?0' \
  -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36' \
  -H 'Content-Type: application/json; charset=UTF-8' \
  -H 'Accept: application/json, text/*' \
  -H 'Referer: http://localhost:5520/' \
  -H 'sec-ch-ua-platform: "macOS"' \
  --data-raw '{"verified":"true"}' \
  --compressed | jq

curl -s 'http://127.0.0.1:5621/contacts/E1kvW2hxdYXW-tD0c4ljnSfaOKrTjnJhIuzx-XVjlz1M' \
  -X 'PUT' \
  -H 'sec-ch-ua: "Chromium";v="104", " Not A;Brand";v="99", "Google Chrome";v="104"' \
  -H 'DNT: 1' \
  -H 'sec-ch-ua-mobile: ?0' \
  -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36' \
  -H 'Content-Type: application/json; charset=UTF-8' \
  -H 'Accept: application/json, text/*' \
  -H 'Referer: http://localhost:5521/' \
  -H 'sec-ch-ua-platform: "macOS"' \
  --data-raw '{"verified":"true"}' \
  --compressed | jq

# sleep 3
# curl -s 'http://127.0.0.1:5620/groups/GLEIF%20Root%20AID/icp' \
#   -H 'Accept: application/json, text/*' \
#   -H 'Accept-Language: en-US,en;q=0.9' \
#   -H 'Connection: keep-alive' \
#   -H 'Content-Type: application/json; charset=UTF-8' \
#   -H 'DNT: 1' \
#   -H 'Origin: http://localhost:5520' \
#   -H 'Referer: http://localhost:5520/' \
#   -H 'Sec-Fetch-Dest: empty' \
#   -H 'Sec-Fetch-Mode: cors' \
#   -H 'Sec-Fetch-Site: cross-site' \
#   -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36' \
#   -H 'sec-ch-ua: "Chromium";v="104", " Not A;Brand";v="99", "Google Chrome";v="104"' \
#   -H 'sec-ch-ua-mobile: ?0' \
#   -H 'sec-ch-ua-platform: "macOS"' \
#   --data-raw '{"aids":["E1kvW2hxdYXW-tD0c4ljnSfaOKrTjnJhIuzx-XVjlz1M","ETz3oW9PnO3jbvWVy_TsZfqXfEVx9aY750tFhBxjHr80"],"isith":"2","nsith":"2","toad":3,"wits":["BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo","BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c"]}' \
#   --compressed | jq

# curl 'http://127.0.0.1:5620/challenge/Karla'   -H 'Accept: application/json, text/*'   -H 'Accept-Language: en-US,en;q=0.9'   -H 'Connection: keep-alive'   -H 'Content-Type: application/json; charset=UTF-8'   -H 'DNT: 1'   -H 'Origin: http://localhost:5520'   -H 'Referer: http://localhost:5520/'   -H 'Sec-Fetch-Dest: empty'   -H 'Sec-Fetch-Mode: cors'   -H 'Sec-Fetch-Site: cross-site'   -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36'   -H 'sec-ch-ua: ".Not/A)Brand";v="99", "Google Chrome";v="103", "Chromium";v="103"'   -H 'sec-ch-ua-mobile: ?0'   -H 'sec-ch-ua-platform: "macOS"'   --data-raw '{"recipient":"ETz3oW9PnO3jbvWVy_TsZfqXfEVx9aY750tFhBxjHr80","words":["spider","blue","dad","coconut","street","bulk","oblige","expire","express","mass","purpose","wrestle"]}'   --compressed
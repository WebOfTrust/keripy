#!/bin/bash

curl 'http://127.0.0.1:5621/boot' \
  -X 'PUT' \
  -H 'Accept: application/json, text/*' \
  -H 'Accept-Language: en-US,en;q=0.9' \
  -H 'Connection: keep-alive' \
  -H 'Content-Type: application/json; charset=UTF-8' \
  -H 'DNT: 1' \
  -H 'Origin: http://127.0.0.1:5521' \
  -H 'Referer: http://127.0.0.1:5521/' \
  -H 'Sec-Fetch-Dest: empty' \
  -H 'Sec-Fetch-Mode: cors' \
  -H 'Sec-Fetch-Site: same-site' \
  -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36' \
  -H 'sec-ch-ua: "Chromium";v="106", "Google Chrome";v="106", "Not;A=Brand";v="99"' \
  -H 'sec-ch-ua-mobile: ?0' \
  -H 'sec-ch-ua-platform: "macOS"' \
  --data-raw '{"name":"keep-root-gar-5621","passcode":"qvHRJgqQQwMy4dCP4nU9s"}' \
  --compressed
echo ''

curl 'http://127.0.0.1:5620/boot' \
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
  -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36' \
  -H 'sec-ch-ua: "Chromium";v="106", "Google Chrome";v="106", "Not;A=Brand";v="99"' \
  -H 'sec-ch-ua-mobile: ?0' \
  -H 'sec-ch-ua-platform: "macOS"' \
  --data-raw '{"name":"keep-root-gar-5620","passcode":"j9wibXLa44faiEnuFKULf"}' \
  --compressed
echo ''

sleep 3

echo 'oobiing'
curl 'http://127.0.0.1:5621/oobi' \
  -H 'Accept: application/json, text/*' \
  -H 'Accept-Language: en-US,en;q=0.9' \
  -H 'Connection: keep-alive' \
  -H 'Content-Type: application/json; charset=UTF-8' \
  -H 'DNT: 1' \
  -H 'Origin: http://127.0.0.1:5521' \
  -H 'Referer: http://127.0.0.1:5521/' \
  -H 'Sec-Fetch-Dest: empty' \
  -H 'Sec-Fetch-Mode: cors' \
  -H 'Sec-Fetch-Site: same-site' \
  -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36' \
  -H 'sec-ch-ua: "Chromium";v="106", "Google Chrome";v="106", "Not;A=Brand";v="99"' \
  -H 'sec-ch-ua-mobile: ?0' \
  -H 'sec-ch-ua-platform: "macOS"' \
  --data-raw '{"oobialias":"Christoph Schneider","url":"http://127.0.0.1:5642/oobi/EKC2rE5CcDVXrRgq00yfm0-GAw6M1U660XTLre6AOaDq/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha"}' \
  --compressed

curl 'http://127.0.0.1:5620/oobi' \
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
  -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36' \
  -H 'sec-ch-ua: "Chromium";v="106", "Google Chrome";v="106", "Not;A=Brand";v="99"' \
  -H 'sec-ch-ua-mobile: ?0' \
  -H 'sec-ch-ua-platform: "macOS"' \
  --data-raw '{"oobialias":"Karla McKenna","url":"http://127.0.0.1:5642/oobi/ECYoPhXvdOkSmWQLqX18IGtxZ74yeQzIXgEKvVcVCLO3/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha"}' \
  --compressed

sleep 3
echo 'Sending challenges'
curl -vs 'http://127.0.0.1:5620/challenge/Christoph%20Schneider' \
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
  -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36' \
  -H 'sec-ch-ua: "Chromium";v="106", "Google Chrome";v="106", "Not;A=Brand";v="99"' \
  -H 'sec-ch-ua-mobile: ?0' \
  -H 'sec-ch-ua-platform: "macOS"' \
  --data-raw '{"recipient":"ECYoPhXvdOkSmWQLqX18IGtxZ74yeQzIXgEKvVcVCLO3","words":["artist","beach","sphere","radar","damp","spatial","august","today","timber","core","art","practice"]}' \
  --compressed

curl -vs 'http://127.0.0.1:5621/challenge/Karla%20McKenna' \
  -H 'Accept: application/json, text/*' \
  -H 'Accept-Language: en-US,en;q=0.9' \
  -H 'Connection: keep-alive' \
  -H 'Content-Type: application/json; charset=UTF-8' \
  -H 'DNT: 1' \
  -H 'Origin: http://127.0.0.1:5521' \
  -H 'Referer: http://127.0.0.1:5521/' \
  -H 'Sec-Fetch-Dest: empty' \
  -H 'Sec-Fetch-Mode: cors' \
  -H 'Sec-Fetch-Site: same-site' \
  -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36' \
  -H 'sec-ch-ua: "Chromium";v="106", "Google Chrome";v="106", "Not;A=Brand";v="99"' \
  -H 'sec-ch-ua-mobile: ?0' \
  -H 'sec-ch-ua-platform: "macOS"' \
  --data-raw '{"recipient":"EKC2rE5CcDVXrRgq00yfm0-GAw6M1U660XTLre6AOaDq","words":["core","gather","essay","pave","file","slab","leave","stable","cereal","cotton","alcohol","shield"]}' \
  --compressed

curl 'http://127.0.0.1:5620/challenge/accept/Christoph%20Schneider' \
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
  -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36' \
  -H 'sec-ch-ua: "Chromium";v="106", "Google Chrome";v="106", "Not;A=Brand";v="99"' \
  -H 'sec-ch-ua-mobile: ?0' \
  -H 'sec-ch-ua-platform: "macOS"' \
  --data-raw '{"aid":"ECYoPhXvdOkSmWQLqX18IGtxZ74yeQzIXgEKvVcVCLO3","said":"EMoHYFPthfydeH-Y5HXr73bz7ZL08WqfwQZObEqHMTNR"}' \
  --compressed
# Steps to run this demos:
# 1. Run start_backer.sh in a terminal and wait for "Baker ready"
# 2. Run this script in a second terminal passing two parameters: backer's prefix and backer's cardano address

function isSuccess() {
    ret=$?
    if [ $ret -ne 0 ]; then
       echo "Error $ret"
       exit $ret
    fi
}
echo '{
    "transferable": true,
    "wits": ["'${1}'"],
    "toad": 1,
    "icount": 1,
    "ncount": 1,
    "isith": "1",
    "nsith": "1",
    "data": [{"ca":"'${2}'"}]
  }' > agent_config.json


kli init --name test  --nopasscode --salt 0ACDEyMzQ1Njc4OWxtbm9aBc
isSuccess

kli oobi resolve --name test  --oobi-alias backer --oobi http://127.0.0.1:5666/oobi/${1}/controller
isSuccess

kli incept --name test  --alias trans --file ./agent_config.json
isSuccess
sleep 80

kli rotate --name test  --alias trans
isSuccess
sleep 80

kli rotate --name test  --alias trans --data @event1.json
isSuccess
sleep 80

kli interact --name test  --alias trans --data @event1.json
isSuccess

kli status --name test  --alias trans --verbose



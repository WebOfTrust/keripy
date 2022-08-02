#!/bin/bash

kli init --name witness-test --nopasscode

kli oobi resolve --name witness-test --oobi-alias wes --oobi http://127.0.0.1:5644/oobi/Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c/controller

kli oobi resolve --name witness-test --oobi-alias wil --oobi http://127.0.0.1:5642/oobi/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo/controller

kli oobi resolve --name witness-test --oobi-alias wan --oobi http://127.0.0.1:5643/oobi/BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw/controller

kli incept --name witness-test --alias trans-wits --file ${KERI_DEMO_SCRIPT_DIR}/data/trans-wits-sample.json

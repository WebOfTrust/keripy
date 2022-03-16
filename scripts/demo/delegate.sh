#!/bin/bash
kli init --name delegate --nopasscode --config-dir ./scripts --config-file demo-witness-oobis --salt 0AMDEyMzQ1Njc4OWxtbm9wcQ
kli init --name delegator --nopasscode --config-dir ./scripts --config-file demo-witness-oobis --salt 0AMDEyMzQ1Njc4OWdoaWpsaw
kli incept --name delegator --alias delegator --file tests/app/cli/commands/delegate/delegator.json
kli oobi resolve --name delegate --oobi http://127.0.0.1:5642/oobi/E8AKUcbZyik8EdkOwXgnyAxO5mSIPJWGZ_o7zMhnNnjo/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo
kli incept --name delegate --alias delegate --file ./tests/app/cli/commands/delegate/delegatee.json

# In other console run the following:
# kli delegate confirm --name delegator --alias delegator
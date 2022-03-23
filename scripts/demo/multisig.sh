#!/bin/bash

kli init --name multisig1 --salt 0AMDEyMzQ1Njc4OWxtbm9wcQ --nopasscode --config-dir ./scripts --config-file demo-witness-oobis
kli incept --name multisig1 --alias multisig1 --file tests/app/cli/commands/multisig/multisig-1-sample.json

kli init --name multisig2 --salt 0AMDEyMzQ1Njc4OWdoaWpsaw --nopasscode --config-dir ./scripts --config-file demo-witness-oobis
kli incept --name multisig2 --alias multisig2 --file tests/app/cli/commands/multisig/multisig-2-sample.json

kli oobi resolve --name multisig1 --oobi http://127.0.0.1:5642/oobi/EozYHef4je02EkMOA1IKM65WkIdSjfrL7XWDk_JzJL9o/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo
kli oobi resolve --name multisig2 --oobi http://127.0.0.1:5642/oobi/E-4-PsMBN0YEKyTl3zL0zulWcBehdaaG6Go5cMc0BzQ8/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo

# In two seperate terminals, run the following commands:
# kli multisig incept --name multisig1 --alias multisig1 --group multisig --file tests/app/cli/commands/multisig/multisig-sample.json
# kli multisig incept --name multisig2 --alias multisig2 --group multisig --file tests/app/cli/commands/multisig/multisig-sample.json
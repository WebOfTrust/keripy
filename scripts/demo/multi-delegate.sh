#!/bin/bash

kli incept --name multisig1 --file tests/app/cli/commands/multisig/multisig-1-sample.json
kli incept --name multisig2 --file tests/app/cli/commands/multisig/multisig-2-sample.json
kli incept --name multisig3 --file tests/app/cli/commands/multisig/multisig-3-sample.json

kli query --name multisig1 --prefix EeS834LMlGVEOGR8WU3rzZ9M6HUv_vtF32pSXQXKP7jg --witness BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo
kli query --name multisig2 --prefix EeS834LMlGVEOGR8WU3rzZ9M6HUv_vtF32pSXQXKP7jg --witness BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo
kli query --name multisig3 --prefix EeS834LMlGVEOGR8WU3rzZ9M6HUv_vtF32pSXQXKP7jg --witness BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo

kli multisig demo --file tests/app/cli/commands/multisig/multisig-delegated-sample.json
#kli vc registry demo
#kli agent demo


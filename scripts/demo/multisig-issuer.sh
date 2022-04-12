#!/bin/bash

# Create local environments for multisig group
kli init --name multisig1 --salt 0AMDEyMzQ1Njc4OWxtbm9wcQ --nopasscode --config-dir ./scripts --config-file demo-witness-oobis
kli incept --name multisig1 --alias multisig1 --file tests/app/cli/commands/multisig/multisig-1-sample.json

# Incept both local identifiers for multisig group
kli init --name multisig2 --salt 0AMDEyMzQ1Njc4OWdoaWpsaw --nopasscode --config-dir ./scripts --config-file demo-witness-oobis
kli incept --name multisig2 --alias multisig2 --file tests/app/cli/commands/multisig/multisig-2-sample.json

# Exchange OOBIs between multisig group
kli oobi resolve --name multisig1 --oobi-alias multisig2 --oobi http://127.0.0.1:5642/oobi/EozYHef4je02EkMOA1IKM65WkIdSjfrL7XWDk_JzJL9o/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo
kli oobi resolve --name multisig2 --oobi-alias multisig1 --oobi http://127.0.0.1:5642/oobi/E-4-PsMBN0YEKyTl3zL0zulWcBehdaaG6Go5cMc0BzQ8/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo

# Create the identifier to which the credential will be issued
kli init --name holder --salt 0AMDEyMzQ1Njc4OWxtbm9qWc --nopasscode --config-dir ./scripts --config-file demo-witness-oobis
kli incept --name holder --alias holder --file tests/app/cli/gleif-sample.json

# Introduce multisig to Holder
kli oobi resolve --name holder --oobi-alias multisig2 --oobi http://127.0.0.1:5642/oobi/EozYHef4je02EkMOA1IKM65WkIdSjfrL7XWDk_JzJL9o/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo
kli oobi resolve --name holder --oobi-alias multisig1 --oobi http://127.0.0.1:5642/oobi/E-4-PsMBN0YEKyTl3zL0zulWcBehdaaG6Go5cMc0BzQ8/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo

# Introduce the holder to all participants in the multisig group
kli oobi resolve --name multisig1 --oobi-alias holder --oobi http://127.0.0.1:5642/oobi/EeWTHzoGK_dNn71CmJh-4iILvqHGXcqEoKGF4VUc6ZXI/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo
kli oobi resolve --name multisig2 --oobi-alias holder --oobi http://127.0.0.1:5642/oobi/EeWTHzoGK_dNn71CmJh-4iILvqHGXcqEoKGF4VUc6ZXI/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo

# Load Data OOBI for schema of credential to issue
kli oobi resolve --name multisig1 --oobi-alias holder --oobi http://127.0.0.1:7723/oobi/EWCeT9zTxaZkaC_3-amV2JtG6oUxNA36sCC0P5MI7Buw
kli oobi resolve --name multisig2 --oobi-alias holder --oobi http://127.0.0.1:7723/oobi/EWCeT9zTxaZkaC_3-amV2JtG6oUxNA36sCC0P5MI7Buw
kli oobi resolve --name holder --oobi-alias holder --oobi http://127.0.0.1:7723/oobi/EWCeT9zTxaZkaC_3-amV2JtG6oUxNA36sCC0P5MI7Buw

# In two seperate terminals, run the following commands:
# kli multisig incept --name multisig1 --alias multisig1 --group multisig --file tests/app/cli/commands/multisig/multisig-sample.json
# kli multisig incept --name multisig2 --alias multisig2 --group multisig --file tests/app/cli/commands/multisig/multisig-sample.json
# kli oobi resolve --name holder --oobi-alias multisig --oobi http://127.0.0.1:5642/oobi/EOWwyMU3XA7RtWdelFt-6waurOTH_aW_Z9VTaU-CshGk/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo

# Create a credential registry owned by the multisig issuer
# kli vc registry incept --name multisig1 --alias multisig --registry-name vLEI --nonce AHSNDV3ABI6U8OIgKaj3aky91ZpNL54I5_7-qwtC6q2s
# kli vc registry incept --name multisig2 --alias multisig --registry-name vLEI --nonce AHSNDV3ABI6U8OIgKaj3aky91ZpNL54I5_7-qwtC6q2s

# Rotate multisig keys:
# kli multisig rotate --name multisig1 --alias multisig
# kli multisig rotate --name multisig2 --alias multisig

# Issue Credential
# kli vc issue --name multisig1 --alias multisig --registry-name vLEI --schema EWCeT9zTxaZkaC_3-amV2JtG6oUxNA36sCC0P5MI7Buw --recipient EeWTHzoGK_dNn71CmJh-4iILvqHGXcqEoKGF4VUc6ZXI --data @scripts/demo/credential-data.json
# kli vc issue --name multisig2 --alias multisig --credential @./credential.json


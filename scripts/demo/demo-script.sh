start-demo.sh

# GETTING STARTED
rm -rf /usr/local/var/keri/*;

# NON-TRANSFERABLE
kli incept --name non-trans --file ./tests/app/cli/non-transferable-sample.json

kli rotate --name non-trans

# TRANSFERABLE

kli incept --name trans --file ./tests/app/cli/transferable-sample.json

kli rotate --name trans

kli rotate --name trans --data @./tests/app/cli/anchor.json

kli interact --name trans --data @./tests/app/cli/anchor.json

kli rotate --name trans --next-count 3 --sith 2

kli sign --name trans --text @tests/app/cli/anchor.json

kli verify --name trans --prefix Ep_l4FJyHxcZBc6JIP7sG3YKBfuMaLJe9dktrz1wX9x4 --text @tests/app/cli/anchor.json --signature AAr6xD1YJW4fFJkoHU7JhtnixOjE8ubouxzUdoe1Hmc4GKnu7KoeZN1s4BD9ctaQVmyxTq0QszqZSzdJAQhDBACw

kli verify --name trans --prefix Ep_l4FJyHxcZBc6JIP7sG3YKBfuMaLJe9dktrz1wX9x4 --text @tests/app/cli/anchor.json --signature ABEA7Wj4BDnM7UgCWspZKa9Cinnhh3G4P39umZGhUyMi-APp55oKQ-J2s5UuXmihLCCROtWFkpKY3kxmzqx-2LBw

kli verify --name trans --prefix Ep_l4FJyHxcZBc6JIP7sG3YKBfuMaLJe9dktrz1wX9x4 --text @tests/app/cli/anchor.json --signature ACSHdal6kHAAjbW_frH83sDDCoBHw_nNKFysW5Dj8PSsnwVPePCNw-kFmF6Z8H87q7D3abw_5u2i4jmzdnWFsRDQ


# ESTABLISHMENT ONLY
kli incept --name est-only --file tests/app/cli/estonly-sample.json

kli interact --name est-only --data @./tests/app/cli/anchor.json

kli rotate --name est-only

# WITNESSES
kli witness start --name non-trans --http 5631 --tcp 5632

kli witness demo

kli incept --name trans-wits --file ./tests/app/cli/trans-wits-sample.json

kli query --name trans --prefix Ezgv-1LmULy9ghlCP5Wt9mrQY-jJ-tQHcZZ9SteV7Hqo --witness BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw

kli rotate --name trans-wits --witness-cut Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c

kli rotate --name trans-wits --witness-add Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c

# VC REGISTRY
kli incept --name reg --file ./tests/app/cli/holder-sample.json

kli vc registry incept --name reg --registry-name reg

# DELEGATION

scripts/demo/start-agent.sh

kli delegate incept --name del --file tests/app/cli/commands/delegate/incept-sample.json

kli rotate --name del

#MULTISIG

rm -rf /usr/local/var/keri/*; kli witness demo

kli incept --name multisig1 --file tests/app/cli/commands/multisig/multisig-1-sample.json
kli incept --name multisig2 --file tests/app/cli/commands/multisig/multisig-2-sample.json
kli incept --name multisig3 --file tests/app/cli/commands/multisig/multisig-3-sample.json

kli multisig demo --file tests/app/cli/commands/multisig/multisig-sample.json

kli multisig list --name multisig3

# MULTISIG DELEGATION

rm -rf /usr/local/var/keri/*; kli witness demo

scripts/demo/start-agent.sh

scripts/demo/multi-delegate.sh

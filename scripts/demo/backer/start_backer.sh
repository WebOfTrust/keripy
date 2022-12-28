rm -r ~/.keri

kli init --name witroot --nopasscode --config-dir /Users/rodo/Code/LosDemas/keripy/scripts/demo/roots --config-file witroot

kli incept --name witroot --alias witroot --config /Users/rodo/Code/LosDemas/keripy/scripts/demo/roots --file witroot_cfg.json

kli backer start --name witroot --alias witroot -H 5666 -T 5665 --ledger cardano

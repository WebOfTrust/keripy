# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.backer module

Backer Info command line interface
"""
import argparse
import logging

from keri import __version__
from keri import help
from keri.app import directing, backering, habbing, keeping
from keri.ledger import cardaning
from keri.app.cli.common import existing

d = "Display registrar backer information"
parser = argparse.ArgumentParser(description=d)
parser.set_defaults(handler=lambda args: launch(args))
parser.add_argument('-V', '--version',
                    action='version',
                    version=__version__,
                    help="Prints out version of script runner.")
parser.add_argument('-n', '--name',
                    action='store',
                    default="backer",
                    help="Name of controller. Default is backer.")
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--alias', '-a', help='human readable alias for the new identifier prefix', required=True)
parser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran
parser.add_argument('--ledger', '-l', help='Ledger name. Available options: cardano',
                    required=False, default=None)

def launch(args):
    help.ogler.level = logging.CRITICAL
    help.ogler.reopen(name=args.name, temp=True, clear=True)

    logger = help.ogler.getLogger()


    ks = keeping.Keeper(name=args.name,
                    base=args.base,
                    temp=False,
                    reopen=True)
    aeid = ks.gbls.get('aeid')

    if aeid is None:
        print("No backer detected")
        exit(1)
    else:
        hby = existing.setupHby(name=args.name, base=args.base, bran=args.bran)

    hab = hby.habByName(name=args.alias)
    if hab is None:
        print("No backer detected")
        exit(1)
    if args.ledger == "cardano":
        cardaning.getInfo(args.alias, hab,ks)

    ks.close()


# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands.escrow module

"""
import argparse

from keri import help
from hio.base import doing
from keri.app.cli.common import existing
from keri.vdr import viring

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Clear escrows')
parser.set_defaults(handler=lambda args: handler(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--passcode', '-p', help='21 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran
parser.add_argument('--force', '-f', action="store_true", required=False,
                    help='True means perform clear without prompting the user')


def handler(args):
    if not args.force:
        print()
        print("This command will clear all escrows and is not reversible.")
        print()
        yn = input("Are you sure you want to continue? [y|N]: ")

        if yn not in ("y", "Y"):
            print("...exiting")
            return []

    kwa = dict(args=args)
    return [doing.doify(clear, **kwa)]


def clear(tymth, tock=0.0, **opts):
    """ Command line clear handler
    """
    _ = (yield tock)
    args = opts["args"]
    name = args.name
    base = args.base
    bran = args.bran
    logger.setLevel("INFO")

    with existing.existingHby(name=name, base=base, bran=bran) as hby:
        hby.db.clearEscrows()
        reger = viring.Reger(name=hby.name, db=hby.db, temp=False)
        reger.clearEscrows()


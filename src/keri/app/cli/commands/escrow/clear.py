# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands.escrow module

"""
import argparse

from hio.base import doing
from keri import help
from keri.app.cli.common import existing
from keri.app.cli.common.parsing import Parsery

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Clear escrows', 
                                 parents=[Parsery.keystore()])
parser.set_defaults(handler=lambda args: handler(args))
parser.add_argument('--force', action="store_true", required=False,
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

    with existing.existingHby(name=name, base=base, bran=bran) as hby:
        hby.db.clearEscrows()

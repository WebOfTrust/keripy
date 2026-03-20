# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands module

"""
import argparse

from hio.base import doing
from hio.help import ogler

from ..common import Parsery, printIdentifier, aliasInput, existingHby

from ...kering import ConfigurationError
from ...core import SerderKERI


logger = ogler.getLogger()

parser = argparse.ArgumentParser(description='View status of a local AID', 
                                 parents=[Parsery.keystore()])
parser.set_defaults(handler=lambda args: handler(args))
parser.add_argument('--alias', '-a', help='human readable alias for the new identifier prefix', default=None)
parser.add_argument("--verbose", "-V", help="print JSON of all current events", action="store_true")


def handler(args):
    kwa = dict(args=args)
    return [doing.doify(status, **kwa)]


def status(tymth, tock=0.0, **opts):
    """ Command line status handler

    """
    _ = (yield tock)
    args = opts["args"]
    name = args.name
    alias = args.alias
    base = args.base
    bran = args.bran

    try:
        with existingHby(name=name, base=base, bran=bran) as hby:
            if alias is None:
                alias = aliasInput(hby)

            hab = hby.habByName(alias)
            printIdentifier(hby, hab.pre)

            if args.verbose:
                print("\nWitnesses:\t")
                for idx, wit in enumerate(hab.kever.wits):
                    print(f'\t{idx+1}. {wit}')
                print()

                cloner = hab.db.clonePreIter(pre=hab.pre, fn=0)  # create iterator at 0
                for msg in cloner:
                    srdr = SerderKERI(raw=msg)
                    print(srdr.pretty(size=10000))
                    print()

    except ConfigurationError as e:
        print(f"identifier prefix for {name} does not exist, incept must be run first", )
        return -1

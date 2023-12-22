# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands module

"""
import argparse

from hio import help
from hio.base import doing

from keri.app.cli.common import displaying, existing
from keri.core import coring, serdering
from keri.kering import ConfigurationError

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='View status of a local AID')
parser.set_defaults(handler=lambda args: handler(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--alias', '-a', help='human readable alias for the new identifier prefix', default=None)
parser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran

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
        with existing.existingHby(name=name, base=base, bran=bran) as hby:
            if alias is None:
                alias = existing.aliasInput(hby)

            hab = hby.habByName(alias)
            displaying.printIdentifier(hby, hab.pre)

            if args.verbose:
                print("\nWitnesses:\t")
                for idx, wit in enumerate(hab.kever.wits):
                    print(f'\t{idx+1}. {wit}')
                print()

                cloner = hab.db.clonePreIter(pre=hab.pre, fn=0)  # create iterator at 0
                for msg in cloner:
                    srdr = serdering.SerderKERI(raw=msg)
                    print(srdr.pretty(size=10000))
                    print()

    except ConfigurationError as e:
        print(f"identifier prefix for {name} does not exist, incept must be run first", )
        return -1

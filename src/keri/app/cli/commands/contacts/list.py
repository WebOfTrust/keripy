# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands module

"""
import argparse

from hio import help
from hio.base import doing

from keri.app.cli.common import displaying, existing
from keri.core import coring
from keri.kering import ConfigurationError

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Initialize a prefix')
parser.set_defaults(handler=lambda args: handler(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran

parser.add_argument("--verbose", "-V", help="print JSON of all current events", action="store_true")


def handler(args):
    kwa = dict(args=args)
    return [doing.doify(list, **kwa)]


def list(tymth, tock=0.0, **opts):
    """ Command line status handler

    """
    _ = (yield tock)
    args = opts["args"]
    name = args.name
    prefix = args.prefix
    base = args.base
    bran = args.bran

    try:
        with existing.existingHby(name=name, base=base, bran=bran) as hby:



            if prefix not in hby.kevers:
                print(f"identifier prefix {prefix} is not known locally")
                return -1
            displaying.printExternal(hby, prefix)

            if args.verbose:
                cloner = hby.db.clonePreIter(pre=prefix, fn=0)  # create iterator at 0
                for msg in cloner:
                    srdr = coring.Serder(raw=msg)
                    print(srdr.pretty())
                    print()

    except ConfigurationError as e:
        print(f"identifier prefix for {name} does not exist, incept must be run first", )
        return -1

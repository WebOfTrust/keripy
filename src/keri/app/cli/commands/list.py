# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands module

"""
import argparse

from hio import help
from hio.base import doing

from keri.app.cli.common import existing
from keri.kering import ConfigurationError

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='List existing identifiers')
parser.set_defaults(handler=lambda args: list_identifiers(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--passcode', '-p', help='21 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran

parser.add_argument("--verbose", "-V", help="print JSON of all current events", action="store_true")


def list_identifiers(args):
    """ Command line list handler

    """
    kwa = dict(args=args)
    return [doing.doify(ids, **kwa)]


def ids(tymth, tock=0.0, **opts):
    _ = (yield tock)

    args = opts["args"]
    name = args.name
    base = args.base
    bran = args.bran

    with existing.existingHby(name=name, base=base, bran=bran) as hby:
        for hab in hby.habs.values():
            print(f"{hab.name} ({hab.pre})")

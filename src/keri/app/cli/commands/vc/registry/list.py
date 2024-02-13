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
from keri.vdr import credentialing

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='List credential registry names and identifiers')
parser.set_defaults(handler=lambda args: list_registries(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran

parser.add_argument("--verbose", "-V", help="print JSON of all current events", action="store_true")


def list_registries(args):
    """ Command line list credential registries handler

    """
    kwa = dict(args=args)
    return [doing.doify(registries, **kwa)]


def registries(tymth, tock=0.0, **opts):
    _ = (yield tock)

    args = opts["args"]
    name = args.name
    base = args.base
    bran = args.bran

    try:
        with existing.existingHby(name=name, base=base, bran=bran) as hby:
            rgy = credentialing.Regery(hby=hby, name=name, base=base)
            for registry in rgy.regs.values():
                print(registry.name, ":", registry.regk, ":", registry.hab.pre)

    except ConfigurationError as e:
        print(f"identifier prefix for {name} does not exist, incept must be run first", )
        return -1

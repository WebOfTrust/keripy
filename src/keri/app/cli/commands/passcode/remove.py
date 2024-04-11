# -*- encoding: utf-8 -*-
"""
keri.kli.common.passcode.remove module

"""
import argparse

from hio import help
from hio.base import doing

from keri.app.cli.common import existing
from keri.kering import ConfigurationError

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Initialize a prefix')
parser.set_defaults(handler=lambda args: remove(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--passcode', '-p', help='existing 21 character encryption passcode for keystore',
                    dest="bran", default=None)  # passcode => bran


def handler(args):
    """ Command line passcode remove handler

    """
    kwa = dict(args=args)
    return [doing.doify(remove, **kwa)]


def remove(tymth, tock=0.0, **opts):
    """ Command line status handler

    """
    _ = (yield tock)
    args = opts["args"]
    name = args.name
    base = args.base
    bran = args.bran

    try:
        with existing.existingHby(name=name, base=base, bran=bran) as hby:
            hby.mgr.updateAeid(None, None)
            print("Passcode removed and keystore unencrypted.")

    except ConfigurationError as e:
        print(f"identifier prefix for {name} does not exist, incept must be run first", )
        return -1

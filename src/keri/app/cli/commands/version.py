# -*- encoding: utf-8 -*-
"""
keri.app.cli.commands module

"""
import argparse

from hio.base import doing

import keri
from keri.app.cli.common import existing

parser = argparse.ArgumentParser(description='Print version of KLI')
parser.set_defaults(handler=lambda args: handler(args))
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=False,
                    default=None)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--passcode', '-p', help='21 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran


def handler(args):
    kwa = dict(args=args)
    return [doing.doify(version, **kwa)]


def version(tymth, tock=0.0, **opts):
    """ Command line version handler
    """
    _ = (yield tock)

    args = opts["args"]
    name = args.name
    base = args.base
    bran = args.bran

    print(f"Library version: {keri.__version__}")

    if name is not None:
        with existing.existingHby(name=name, base=base, bran=bran) as hby:
            print(f"Database version: {hby.db.version}")

# -*- encoding: utf-8 -*-
"""
keri.app.cli.commands module

"""
import argparse

from hio.base import doing

from keri import __version__

from ..common import Parsery, existingHby


parser = argparse.ArgumentParser(description='Print version of KLI', parents=[Parsery.keystore(required=False)])
parser.set_defaults(handler=lambda args: handler(args))

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

    print(f"Library version: {__version__}")

    if name is not None:
        with existingHby(name=name, base=base, bran=bran) as hby:
            print(f"Database version: {hby.db.version}")

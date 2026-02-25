# -*- encoding: utf-8 -*-
"""
keri.app.cli.commands.witness.clean module

"""
import argparse

from hio.base import doing

from keri.app.cli.common import existing

parser = argparse.ArgumentParser(description='Clean and re-verify witness database (offline)')
parser.set_defaults(handler=lambda args: handler(args))
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)


def handler(args):
    kwa = dict(args=args)
    return [doing.doify(clean, **kwa)]


def clean(tymth, tock=0.0, **opts):
    """ Command line clean handler

    Cleans and re-verifies the database by creating a verified clone
    and replacing the original. Must be run while witness is offline.
    """
    _ = (yield tock)

    args = opts["args"]
    name = args.name
    base = args.base
    bran = args.bran

    print(f"Cleaning database for {name}...")
    print("Database must be offline during this operation.")

    with existing.existingHby(name=name, base=base, bran=bran) as hby:
        hby.db.clean()

    print(f"Database cleaned successfully.")

# -*- encoding: utf-8 -*-
"""
keri.kli.commands module

"""
import argparse

from hio.base import doing

from keri import kering
from keri.app.cli.common import existing
from keri.core import indexing, coring, MtrDex

parser = argparse.ArgumentParser(description='Decrypt arbitrary data for AIDs with Ed25519 public keys only')
parser.set_defaults(handler=lambda args: handler(args))
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--alias', '-a', help='human readable alias for the new identifier prefix', required=True)
parser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran
parser.add_argument('--data', '-d', help='Encrypted data or file (starts with "@")', required=True)


def handler(args):
    """
    Verify signatures on arbitrary data

    Args:
        args(Namespace): arguments object from command line
    """
    kwa = dict(args=args)
    return [doing.doify(decrypt, **kwa)]


def decrypt(tymth, tock=0.0, **opts):
    """ Command line status handler

    """
    _ = (yield tock)
    args = opts["args"]

    name = args.name
    alias = args.alias
    base = args.base
    bran = args.bran

    try:
        with existing.existingHab(name=name, alias=alias, base=base, bran=bran) as (_, hab):

            data = args.data
            if data.startswith("@"):
                f = open(data[1:], "r")
                data = f.read()
            else:
                data = data

            m = coring.Matter(qb64=data)  # should refactor this to use Cipher
            d = coring.Matter(qb64=hab.decrypt(ser=m.raw))
            print(d.raw)

    except kering.ConfigurationError:
        print(f"prefix for {name} does not exist, incept must be run first", )
    except FileNotFoundError:
        print("unable to open file", args.text[1:])

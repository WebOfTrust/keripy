# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands module

"""
import argparse

from hio.base import doing

from keri import kering
from keri.app import habbing
from keri.app.cli.common import existing

parser = argparse.ArgumentParser(description='Sign an arbitrary string')
parser.set_defaults(handler=lambda args: handler(args))
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--alias', '-a', help='human readable alias for the new identifier prefix', required=True)
parser.add_argument('--passcode', '-p', help='21 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran
parser.add_argument('--text', '-t', help='Text or file (starts with "@") to sign', required=True)


def handler(args):
    """
    Sign arbitrary data

    Args:
        args(Namespace): arguments object from command line
    """
    kwa = dict(args=args)
    return [doing.doify(sign, **kwa)]


def sign(tymth, tock=0.0, **opts):
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

            txt = args.text
            if txt.startswith("@"):
                f = open(txt[1:], "r")
                data = f.read()
            else:
                data = txt

            sigers = hab.sign(ser=data.encode("utf-8"),
                              verfers=hab.kever.verfers,
                              indexed=True)

            for idx, siger in enumerate(sigers):
                print("{}. {}".format(idx+1, siger.qb64))

    except kering.ConfigurationError:
        print(f"prefix for {name} does not exist, incept must be run first", )
    except FileNotFoundError:
        print("unable to open file", args.text[1:])

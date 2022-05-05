# -*- encoding: utf-8 -*-
"""
keri.kli.commands module

"""
import argparse

from hio.base import doing

from keri import kering
from keri.app.cli.common import existing
from keri.core import coring

parser = argparse.ArgumentParser(description='Verify signature(s) on arbitrary data')
parser.set_defaults(handler=lambda args: handler(args))
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--alias', '-a', help='human readable alias for the new identifier prefix', required=True)
parser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran

parser.add_argument("--prefix", help="Identifier prefix of the signer", required=True)
parser.add_argument('--text', '-t', help='Original signed text or file (starts with "@")', required=True)
parser.add_argument('--signature', '-s', default=[], help='list of signatures to verify (can appear multiple times)',
                    action="append", required=True)


def handler(args):
    """
    Verify signatures on arbitrary data

    Args:
        args(Namespace): arguments object from command line
    """
    kwa = dict(args=args)
    return [doing.doify(verify, **kwa)]


def verify(tymth, tock=0.0, **opts):
    """ Command line status handler

    """
    _ = (yield tock)
    args = opts["args"]

    name = args.name
    alias = args.alias
    base = args.base
    bran = args.bran

    sigers = [coring.Siger(qb64=sig) for sig in args.signature]

    try:
        with existing.existingHab(name=name, alias=alias, base=base, bran=bran) as (_, hab):

            kever = hab.kevers[args.prefix]

            txt = args.text
            if txt.startswith("@"):
                f = open(txt[1:], "r")
                data = f.read()
            else:
                data = txt

            ser = data.encode("utf-8")
            verfers = kever.verfers
            for siger in sigers:
                if siger.index >= len(verfers):
                    raise kering.ValidationError("Index = {} to large for keys."
                                                 "".format(siger.index))
                siger.verfer = verfers[siger.index]  # assign verfer
                if siger.verfer.verify(siger.raw, ser):  # verify each sig
                    print("Signature {} is valid.".format(siger.index+1))
                else:
                    raise kering.ValidationError("Signature {} is invalid.".format(siger.index+1))

    except kering.ConfigurationError:
        print(f"prefix for {name} does not exist, incept must be run first", )
    except FileNotFoundError:
        print("unable to open file", args.text[1:])

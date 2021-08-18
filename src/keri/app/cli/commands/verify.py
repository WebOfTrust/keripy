# -*- encoding: utf-8 -*-
"""
keri.kli.commands module

"""
import argparse

from keri import kering
from keri.app import habbing
from keri.core import coring

parser = argparse.ArgumentParser(description='Sign an arbitrary string')
parser.set_defaults(handler=lambda args: handler(args))
parser.add_argument('--name', '-n', help='Human readable reference', required=True)
parser.add_argument("--prefix", "-p", help="Identifier prefix of the signer", required=True)
parser.add_argument('--text', '-t', help='Original signed text or file (starts with "@")', required=True)
parser.add_argument('--signature', '-s', default=[], help='list of signatures to verify (can appear multiple times)',
                    action="append", required=True)


def handler(args):

    name = args.name
    sigers = [coring.Siger(qb64=sig) for sig in args.signature]

    try:
        with habbing.existingHab(name=name) as hab:

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
                    print("Signature {} is invalid.".format(siger.index+1))



    except kering.ConfigurationError:
        print(f"prefix for {name} does not exist, incept must be run first", )
    except FileNotFoundError:
        print("unable to open file", args.text[1:])

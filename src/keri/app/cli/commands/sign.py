# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands module

"""
import argparse

from keri import kering
from keri.app import habbing

parser = argparse.ArgumentParser(description='Sign an arbitrary string')
parser.set_defaults(handler=lambda args: sign(args))
parser.add_argument('--name', '-n', help='Human readable reference', required=True)
parser.add_argument('--text', '-t', help='Text or file (starts with "@") to sign', required=True)


def sign(args):

    name = args.name

    try:
        with habbing.existingHab(name=name) as hab:

            txt = args.text
            if txt.startswith("@"):
                f = open(txt[1:], "r")
                data = f.read()
            else:
                data = txt

            sigers = hab.mgr.sign(ser=data.encode("utf-8"),
                                  verfers=hab.kever.verfers,
                                  indexed=True)

            for idx, siger in enumerate(sigers):
                print("{}. {}".format(idx+1, siger.qb64))

    except kering.ConfigurationError:
        print(f"prefix for {name} does not exist, incept must be run first", )
    except FileNotFoundError:
        print("unable to open file", args.text[1:])

# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands module

"""
import argparse

from hio import help
from keri.app import habbing
from keri.app.cli.common import displaying
from keri.kering import ConfigurationError

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Initialize a prefix')
parser.set_defaults(handler=lambda args: handler(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='Human readable reference', required=True)


def handler(args):

    name = args.name
    try:
        with habbing.existingHab(name=name) as hab:

            displaying.printIdentifier(hab, hab.pre)

            print()
            for pre in hab.prefixes:
                if pre == hab.pre:
                    continue
                print(f"Additional Prefix:\t\t{pre}")
            print()

    except ConfigurationError:
        print(f"identifier prefix for {name} does not exist, incept must be run first", )
        return -1

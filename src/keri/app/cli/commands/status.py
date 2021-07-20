# -*- encoding: utf-8 -*-
"""
keri.kli.commands module

"""
import argparse

from hio import help

from keri.app import habbing, keeping
from keri.db import basing
from keri.kering import ConfigurationError

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Initialize a prefix')
parser.set_defaults(handler=lambda args: handler(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='Human readable reference', required=True)


def handler(args):

    name = args.name
    with basing.openDB(name=name, temp=False, reload=True) as db, \
            keeping.openKS(name=name, temp=False) as ks:
        try:
            hab = habbing.Habitat(name=name, ks=ks, db=db, temp=False, create=False)
            print(f'Prefix\t\t{hab.pre}')
            for idx, verfer in enumerate(hab.kever.verfers):
                print(f'Public key {idx+1}:\t{verfer.qb64}')
            print()
        except ConfigurationError:
            print(f"prefix for {name} does not exist, incept must be run first", )

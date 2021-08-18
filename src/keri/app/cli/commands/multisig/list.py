# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands.multisig module

"""

import argparse

from keri import kering
from keri.app import keeping, habbing
from keri.app.cli.common import displaying
from keri.db import basing, dbing

parser = argparse.ArgumentParser(description='list group identifiers')
parser.add_argument('--name', '-n', help='Human readable reference', required=True)
parser.set_defaults(handler=lambda args: listGroupIdentifiers(args))


def listGroupIdentifiers(args):
    """
    Lists any group identifiers that the identifier represented by the provided name
    belongs to.

    Parameters:
        args (parseargs):  command line parameters

    """

    name = args.name
    with basing.openDB(name=name, temp=False, reload=True) as db, \
            keeping.openKS(name=name, temp=False) as ks:
        try:

            hab = habbing.Habitat(name=name, ks=ks, db=db, temp=False, create=False)
            displaying.printGroups(hab)
        except kering.ConfigurationError:
            print(f"prefix for {name} does not exist, incept must be run first", )



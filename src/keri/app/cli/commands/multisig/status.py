# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands.multisig module

"""

import argparse

from keri import kering
from keri.app import keeping, habbing
from keri.app.cli.common import displaying
from keri.core import coring
from keri.db import basing, dbing

parser = argparse.ArgumentParser(description='display status of group identifier')
parser.add_argument('--name', '-n', help='Human readable reference', required=True)
parser.add_argument("--verbose", "-V", help="print JSON of all current events", action="store_true")
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

            hab = habbing.Hab(name=name, ks=ks, db=db, temp=False)
            displaying.printGroups(hab)

            if args.verbose:
                group = hab.group()
                cloner = hab.db.clonePreIter(pre=group.gid, fn=0)  # create iterator at 0
                for msg in cloner:
                    srdr = coring.Serder(raw=msg)
                    print(srdr.pretty())
                    print()

        except kering.ConfigurationError:
            print(f"prefix for {name} does not exist, incept must be run first", )



# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands module

"""
import argparse

from hio import help
from keri.app import habbing
from keri.app.cli.common import displaying
from keri.core import coring
from keri.kering import ConfigurationError

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Initialize a prefix')
parser.set_defaults(handler=lambda args: handler(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='Human readable reference', required=True)
parser.add_argument("--verbose", "-V", help="print JSON of all current events", action="store_true")


def handler(args):

    name = args.name
    try:
        with habbing.existingHab(name=name) as hab:

            displaying.printIdentifier(hab, hab.pre)

            if len(hab.prefixes) > 1:
                print("\nAdditional Prefixes:")
                for pre in hab.prefixes:
                    if pre == hab.pre:
                        continue
                    print(f"\t{pre}")

            cnt = hab.db.gids.getCnt()
            if cnt > 0:
                print()
                print("Groups:")
                groups = hab.db.gids.getItemIter()
                idx = 1
                for (pre,), group in groups:
                    print("\t{}. {} ({})".format(idx, group.name, pre))
                    idx += 1
                print()

            if args.verbose:
                cloner = hab.db.clonePreIter(pre=hab.pre, fn=0)  # create iterator at 0
                for msg in cloner:
                    srdr = coring.Serder(raw=msg)
                    print(srdr.pretty())
                    print()

    except ConfigurationError as e:
        print(e)
        print(f"identifier prefix for {name} does not exist, incept must be run first", )
        return -1

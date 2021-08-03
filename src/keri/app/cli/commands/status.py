# -*- encoding: utf-8 -*-
"""
keri.kli.commands module

"""
import argparse

from hio import help

from keri.app import habbing, keeping
from keri.db import basing, dbing
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
            kev = hab.kever
            ser = kev.serder
            dgkey = dbing.dgKey(ser.preb, ser.digb)
            wigs = hab.db.getWigs(dgkey)

            print("Prefix:\t{}".format(hab.pre))
            print("Seq No:\t{}".format(kev.sn))
            print("\nWitnesses:")
            print("Count:\t\t{}".format(len(kev.wits)))
            print("Receipts:\t{}".format(len(wigs)))
            print("Threshold:\t{}".format(kev.toad))
            print("\nPublic Keys:\t")
            for idx, verfer in enumerate(kev.verfers):
                print(f'\t{idx+1}. {verfer.qb64}')
            print()
            for pre in hab.prefixes:
                if pre == hab.pre:
                    continue
                print(f"Additional Prefix:\t\t{pre}")
            print()
        except ConfigurationError:
            print(f"prefix for {name} does not exist, incept must be run first", )

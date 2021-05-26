# -*- encoding: utf-8 -*-
"""
keri.kli.commands module

"""
import argparse

from keri.base import keeping
from keri.base.basing import Habitat
from keri.db import dbing
from keri.vdr.issuing import Issuer

parser = argparse.ArgumentParser(description='Initialize a prefix')
parser.set_defaults(handler=lambda args: incept(args.name, args.prefix, args.with_establishment, args.backer_config))
parser.add_argument('--name', '-n', help='Humane reference')
parser.add_argument('--with-establishment', '-we', dest='with_establishment', action='store_true',
                    help='Force rotate on each issue and revoke')
parser.add_argument('--backer-config', '-bc', dest='backer_config', help='Not implemented')


def incept(name, prefix, with_establishment, backer_config):
    with dbing.openDB(name=name, temp=False) as db, keeping.openKS(name=name, temp=False) as ks:
        hab = Habitat(name=name, ks=ks, db=db, isith=1, icount=1, ncount=1, temp=False)

        Issuer(hab=hab, name=name + "_tel", noBackers=True, estOnly=with_establishment, toad=0)

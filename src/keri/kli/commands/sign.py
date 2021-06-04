# -*- encoding: utf-8 -*-
"""
keri.kli.commands module

"""
import argparse

from keri.app import keeping
from keri.app.habbing import Habitat
from keri.db import dbing, basing

parser = argparse.ArgumentParser(description='Sign an arbitrary string')
parser.set_defaults(handler=lambda args: sign(args.name, args.text))
parser.add_argument('--name', '-n', help='Humane reference')
parser.add_argument('--text', '-t', help='An arbitrary string')


def sign(name, text):
    with basing.openDB(name=name, temp=False) as db, keeping.openKS(name=name, temp=False) as ks:
        hab = Habitat(name=name, ks=ks, db=db, isith=1, icount=1, ncount=1, temp=False)

        print(hab.mgr.sign(ser=text.encode("utf-8"), verfers=hab.kever.verfers, indexed=False)[0].qb64)

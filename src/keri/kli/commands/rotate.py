# -*- encoding: utf-8 -*-
"""
keri.kli.commands module

"""
import argparse

from keri.app import keeping
from keri.app.habbing import Habitat
from keri.db import dbing, basing

parser = argparse.ArgumentParser(description='Rotate keys')
parser.set_defaults(handler=lambda args: rotate(args.name))
parser.add_argument('--name', '-n', help="Humane reference")


def rotate(name):
    with basing.openDB(name=name, temp=False) as db, keeping.openKS(name=name, temp=False) as ks:
        hab = Habitat(name=name, ks=ks, db=db, temp=False)
        hab.rotate()

        print(f"Rotated keys for {name}")
        print(f"New public key {hab.kever.verfers[0].qb64}")


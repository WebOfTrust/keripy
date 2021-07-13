# -*- encoding: utf-8 -*-
"""
keri.kli.commands module

"""
import argparse
import shutil

from keri.app import keeping
from keri.db import basing

parser = argparse.ArgumentParser(description='Delete existing KERI database')
parser.set_defaults(handler=lambda args: purge(args.name))
parser.add_argument('--name', '-n', help='Humane reference')


def purge(name):
    with basing.openDB(name=name, temp=False) as db, keeping.openKS(name=name, temp=False) as ks:
        db.close(clear=True)
        ks.close(clear=True)

    try:
        shutil.rmtree(f"/usr/local/var/keri/db/{name}_tel")
    except FileNotFoundError:
        pass



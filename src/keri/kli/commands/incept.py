# -*- encoding: utf-8 -*-
"""
keri.kli.commands module

"""
import argparse

from keri.base import keeping
from keri.base.basing import Habitat
from keri.db import dbing

parser = argparse.ArgumentParser(description='Initialize a prefix')
parser.set_defaults(handler=lambda args: incept(args.name, args.file))  # , args.file, args.with_tel
parser.add_argument('--name', '-n', help='Humane reference')
parser.add_argument('--file', '-f', help='Filename to use to create the identifier', default="")


# parser.add_argument('--with-tel', dest='with_tel', action='store_true', help='Initialize support TEL')


def incept(name, file):  # config, with_tel
    with dbing.openDB(name=name, temp=False) as db, keeping.openKS(name=name, temp=False) as ks:
        hab = Habitat(name=name, ks=ks, db=db, isith=1, icount=1, ncount=1, temp=False)

        pre = hab.kever.prefixer.qb64
        pub = hab.kever.verfers[0].qb64

        # if with_tel:
        #     Registry(name=name)

        print(f'{name} created')
        print(f'Prefix\t\t{pre}')
        print(f'Public key\t{pub}')
        print()
        print(f'Rotate keys:')
        print(f'kli rotate -n {name}')
        print()
        print(f'Issue a verifiable credential:')
        print(f'kli issue -n {name} -dsi {pre} --lei 506700GE1G29325QX363')
        print()

# -*- encoding: utf-8 -*-
"""
keri.kli.commands module

"""
import argparse

from hio.base import doing

from keri.app import habbing

parser = argparse.ArgumentParser(description='view info')
parser.set_defaults(handler=lambda args: InfoDoer(hab=args.hab))


class InfoDoer(doing.Doer):

    def __init__(self, tock=0.0, hab: habbing.Habitat = None, **kwa):
        self.hab = hab
        super(InfoDoer, self).__init__(**kwa)

    def do(self, tymth, tock=0.0, **opts):
        print(f'Prefix {self.hab.pre}')
        print(f'Public Key {self.hab.kever.verfers[0].qb64}')
        print(f'Current rotation index {self.hab.ridx}')

        return super().do(tymth, tock, **opts)

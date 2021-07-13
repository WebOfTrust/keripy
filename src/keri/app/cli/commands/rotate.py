# -*- encoding: utf-8 -*-
"""
keri.kli.commands module

"""
import argparse

from hio.base import doing

from ... import habbing

parser = argparse.ArgumentParser(description='Rotate keys')
parser.set_defaults(handler=lambda args: RotateDoer(hab=args.hab))


class RotateDoer(doing.Doer):

    def __init__(self, tock=0.0, hab: habbing.Habitat = None, **kwa):
        self.hab = hab
        super(RotateDoer, self).__init__(**kwa)

    def do(self, tymth, tock=0.0, **opts):
        self.hab.rotate()

        print(f"Rotated keys for {self.hab.name}")
        print(f"New public key {self.hab.kever.verfers[0].qb64}")

        return super().do(tymth, tock, **opts)

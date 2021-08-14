# -*- encoding: utf-8 -*-
"""
keri.kli.commands module

"""
import argparse

from hio.base import doing

from keri.app import habbing
from keri.vdr.issuing import Issuer

parser = argparse.ArgumentParser(description='Revoke a verifiable credential')
parser.set_defaults(handler=lambda args: RevokeDoer(vcdig=args.vcdig, hab=args.hab))
parser.add_argument('--vcdig', help='vcdig is hash digest of vc content qb64')


class RevokeDoer(doing.Doer):

    def __init__(self, vcdig, tock=0.0, hab: habbing.Habitat = None, **kwa):
        self.hab = hab
        self.vcdig = vcdig
        super(RevokeDoer, self).__init__(**kwa)

    def do(self, tymth, tock=0.0, **opts):
        iss = Issuer(hab=self.hab, name=self.hab.name)

        iss.revoke(vcdig=self.vcdig)

        print(f"Rotated keys for {self.hab.name}")
        print(f"New public key {self.hab.kever.verfers[0].qb64}")

        return super().do(tymth, tock, **opts)


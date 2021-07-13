# -*- encoding: utf-8 -*-
"""
keri.kli.commands module

"""
import argparse

from hio.base import doing

from keri.app import habbing

parser = argparse.ArgumentParser(description='Sign an arbitrary string')
parser.set_defaults(handler=lambda args: SignDoer(text=args.text, hab=args.hab))
parser.add_argument('--text', '-t', help='An arbitrary string')


class SignDoer(doing.Doer):

    def __init__(self, text, tock=0.0, hab: habbing.Habitat = None, **kwa):
        self.hab = hab
        self.text = text

        super(SignDoer, self).__init__(**kwa)

    def do(self, tymth, tock=0.0, **opts):
        print(self.hab.mgr.sign(ser=self.text.encode("utf-8"),
                                verfers=self.hab.kever.verfers,
                                indexed=False)[0].qb64)

        return super().do(tymth, tock, **opts)

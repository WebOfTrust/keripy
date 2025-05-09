# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands module

"""
import argparse
import sys

from hio import help
from hio.base import doing

from keri.app import habbing
from keri.app.cli.common import existing
from keri.app.cli.common.parsing import Parsery
from keri.core import coring, serdering, parsing

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Import key events in CESR stream format', 
                                 parents=[Parsery.keystore()])
parser.set_defaults(handler=lambda args: export(args))
parser.add_argument("--file", help="File of streamed CESR events to import", required=True)


def export(args):
    """ Command line list credential registries handler

    """

    ed = ImportDoer(name=args.name,
                    base=args.base,
                    bran=args.bran,
                    file=args.file)
    return [ed]


class ImportDoer(doing.DoDoer):

    def __init__(self, name, base, bran, file):
        self.file = file

        self.hby = existing.setupHby(name=name, base=base, bran=bran)

        doers = [doing.doify(self.exportDo), habbing.HaberyDoer(self.hby)]

        super(ImportDoer, self).__init__(doers=doers)

    def exportDo(self, tymth, tock=0.0, **kwa):
        """ Export credential from store and any related material

        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock (float): injected initial tock value

        Returns:  doifiable Doist compatible generator method

        """
        # enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        with open(self.file, 'rb') as f:
            ims = f.read()
            parsing.Parser(kvy=self.hby.kvy, rvy=self.hby.rvy, local=False).parse(ims=ims)
            self.hby.kvy.processEscrows()

        self.exit()
        return True

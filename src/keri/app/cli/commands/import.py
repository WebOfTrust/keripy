# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands module

"""
import argparse
import sys

from hio import help
from hio.base import doing

from keri.app import habbing, connecting
from keri.app.cli.common import existing
from keri.core import coring, serdering, parsing

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Import key events in CESR stream format')
parser.set_defaults(handler=lambda args: export(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--passcode', '-p', help='21 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran
parser.add_argument("--file", help="File of streamed CESR events to import", required=True)
parser.add_argument("--alias", help="alias for AID resolved from file import", required=False, default=None)


def export(args):
    """ Command line list credential registries handler

    """

    ed = ImportDoer(name=args.name,
                    base=args.base,
                    bran=args.bran,
                    file=args.file,
                    alias=args.alias)
    return [ed]


class ImportDoer(doing.DoDoer):

    def __init__(self, name, base, bran, file, alias):
        self.file = file
        self.alias = alias

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

            serder = serdering.SerderKERI(raw=ims)

            parsing.Parser(kvy=self.hby.kvy, rvy=self.hby.rvy, local=False).parse(ims=ims)
            self.hby.kvy.processEscrows()

            if serder.pre in self.hby.kevers and self.alias is not None:
                org = connecting.Organizer(hby=self.hby)
                org.update(pre=serder.pre, data=dict(alias=self.alias))

        self.exit()
        return True

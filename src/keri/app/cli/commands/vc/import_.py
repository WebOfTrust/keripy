# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands module

"""
import argparse

from hio import help
from hio.base import doing

from .... import habbing
from ...common import existing
from .....core import parsing
from .....vdr import eventing as teventing, verifying, credentialing

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Import an ACDC credential in CESR stream format')
parser.set_defaults(handler=lambda args: imprt(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--passcode', '-p', help='21 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran
parser.add_argument("--file", help="File of streamed CESR credential to import", required=True)
parser.add_argument("--said", "-s", help="SAID of the credential to expect.", required=False, default=None)


def imprt(args):
    """ Command line list credential registries handler

    """

    ed = ImportDoer(name=args.name,
                    base=args.base,
                    bran=args.bran,
                    file=args.file,
                    said=args.said)
    return [ed]


class ImportDoer(doing.DoDoer):

    def __init__(self, name, base, bran, file, said=None):
        self.file = file
        self.said = said

        self.hby = existing.setupHby(name=name, base=base, bran=bran)
        self.rgy = credentialing.Regery(hby=self.hby, name=name, base=base)
        self.tvy = teventing.Tevery(db=self.hby.db, reger=self.rgy.reger)
        self.vry = verifying.Verifier(hby=self.hby, reger=self.rgy.reger)

        doers = [doing.doify(self.importDo), habbing.HaberyDoer(self.hby)]

        super(ImportDoer, self).__init__(doers=doers)

    def importDo(self, tymth, tock=0.0, **kwa):
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

            parsing.Parser(kvy=self.hby.kvy, tvy=self.tvy, vry=self.vry, local=False).parse(ims=ims)
            self.tvy.processEscrows()
            self.vry.processEscrows()
            self.hby.kvy.processEscrows()

            if self.said:
                while self.vry.reger.creds.get(keys=self.said) is None:
                    self.tvy.processEscrows()
                    self.vry.processEscrows()
                    self.hby.kvy.processEscrows()
                    yield self.tock

                print("Credential successfully imported.")

        self.exit()
        return True

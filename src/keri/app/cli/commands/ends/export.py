# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands module

"""
import argparse

from hio import help
from hio.base import doing

from keri import kering
from keri.app.cli.common import existing
from keri.core import coring, eventing

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Export end points')
parser.set_defaults(handler=lambda args: export_ends(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--passcode', '-p', help='21 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran

parser.add_argument("--aid", "-a", help="qualified base64 of AID to export rpy messages for all endpoints.",
                    required=True)


def export_ends(args):
    """ Command line list credential registries handler

    """
    ld = ExportDoer(name=args.name,
                    base=args.base,
                    bran=args.bran,
                    aid=args.aid)
    return [ld]


class ExportDoer(doing.DoDoer):

    def __init__(self, name, base, bran, aid):
        self.aid = aid

        self.hby = existing.setupHby(name=name, base=base, bran=bran)

        doers = [doing.doify(self.exportDo)]

        super(ExportDoer, self).__init__(doers=doers)

    def exportDo(self, tymth, tock=0.0):
        """ Export any end reply messages previous saved for the provided AID

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

        for scheme in kering.Schemes:
            keys = (self.aid, scheme)
            said = self.hby.db.lans.get(keys=keys)
            if said is not None:
                serder = self.hby.db.rpys.get(keys=(said.qb64,))
                cigars = self.hby.db.scgs.get(keys=(said.qb64,))
                sigers = self.hby.db.ssgs.get(keys=(said.qb64,))

                if len(cigars) == 1:
                    (verfer, cigar) = cigars[0]
                    cigar.verfer = verfer
                else:
                    cigar = None
                print(eventing.messagize(serder=serder,
                                         cigars=[cigar],
                                         sigers=sigers,
                                         pipelined=True))

        return True

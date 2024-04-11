# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands module

"""
import argparse
import sys

from hio import help
from hio.base import doing

from keri.app.cli.common import existing
from keri.core import coring, serdering

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Export key events in CESR stream format')
parser.set_defaults(handler=lambda args: export(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--alias', '-a', help='human readable alias for the identifier to whom the credential was issued',
                    required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--passcode', '-p', help='21 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran
parser.add_argument("--files", help="export artifacts to individual files keyed off of AIDs or SAIDS, default is "
                                    "stdout", action="store_true")
parser.add_argument("--ends", help="export service end points", action="store_true")


def export(args):
    """ Command line list credential registries handler

    """

    ed = ExportDoer(name=args.name,
                    alias=args.alias,
                    base=args.base,
                    bran=args.bran,
                    ends=args.ends,
                    files=args.files,)
    return [ed]


class ExportDoer(doing.DoDoer):

    def __init__(self, name, alias, base, bran, ends, files):
        self.files = files
        self.ends = ends

        self.hby = existing.setupHby(name=name, base=base, bran=bran)
        self.hab = self.hby.habByName(alias)

        doers = [doing.doify(self.exportDo)]

        super(ExportDoer, self).__init__(doers=doers)

    def exportDo(self, tymth, tock=0.0):
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

        self.output(said=self.hab.pre)

    def output(self, said):
        self.outputKEL(pre=said)

        if self.ends:
            self.outputEnds(pre=said)

        sys.stdout.flush()

    def outputKEL(self, pre):
        f = None
        if self.files:
            f = open(f"{pre}-kel.cesr", "w")

        for msg in self.hby.db.clonePreIter(pre=pre):
            if f is not None:
                f.write(msg.decode("utf-8"))
            else:
                serder = serdering.SerderKERI(raw=msg)
                atc = msg[serder.size:]
                sys.stdout.write(serder.raw.decode("utf-8"))
                sys.stdout.write(atc.decode("utf-8"))

        if f is not None:
            f.close()

    def outputEnds(self, pre):
        f = None
        if self.files:
            f = open(f"{pre}-ends.cesr", "w")

        msgs = self.hab.replyToOobi(aid=pre, role="controller")
        for msg in msgs:
            if f is not None:
                f.write(msg.decode("utf-8"))
            else:
                serder = serdering.SerderKERI(raw=msg)
                atc = msg[serder.size:]
                sys.stdout.write(serder.raw.decode("utf-8"))
                sys.stdout.write(atc.decode("utf-8"))

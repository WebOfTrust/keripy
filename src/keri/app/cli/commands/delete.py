# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands module

"""
import argparse

from hio.base import doing

from keri import help
from keri.app.cli.common import existing
from keri.db.dbing import dgKey, snKey

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Remove an AID from the database')
parser.set_defaults(handler=lambda args: handler(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--prefix', help='qb64 identifier prefix to display', required=True)
parser.add_argument('--passcode', '-p', help='21 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran


def handler(args):
    kever = DeleteDoer(name=args.name, base=args.base, bran=args.bran, prefix=args.prefix)
    return [kever]


class DeleteDoer(doing.Doer):

    def __init__(self, name, base, bran, prefix, poll=False, verbose=False):
        self.prefix = prefix
        self.poll = poll
        self.verbose = verbose
        self.hby = existing.setupHby(name=name, base=base, bran=bran)
        super(DeleteDoer, self).__init__()

    def recur(self, tyme):
        """ Command line status handler

        """
        preb = self.prefix.encode("utf-8")

        if self.prefix not in self.hby.kevers:
            print(f"Identifier prefix {self.prefix} is not known locally")
            return True

        count = 0
        for _, fn, dig in self.hby.db.getFelItemPreIter(self.prefix):
            dgkeys = (self.prefix, dig)
            dgkey = dgKey(preb, dig)

            self.hby.db.delEvt(dgkey)
            self.hby.db.delWigs(dgkey)
            self.hby.db.delSigs(dgkey)
            self.hby.db.delDts(dgkey)
            self.hby.db.wits.rem(keys=dgkeys)
            self.hby.db.delKes(dgkey)
            self.hby.db.delAes(dgkey)
            self.hby.db.esrs.rem(dgkeys)
            self.hby.db.fons.rem(dgkey)
            count += 1

        for sn in range(count):
            self.hby.db.delKes(snKey(preb, sn))
            self.hby.db.delFe(snKey(preb, sn))

        self.hby.db.states.rem(keys=self.prefix)

        return True
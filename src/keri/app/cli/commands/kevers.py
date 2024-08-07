# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands module

"""
import argparse
import datetime

import sys
from hio import help
from hio.base import doing

from keri.app import indirecting
from keri.app.cli.common import displaying, existing
from keri.core import coring, serdering
from keri.help import helping

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Poll events at controller for prefix')
parser.set_defaults(handler=lambda args: handler(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--prefix', help='qb64 identifier prefix to display', required=True)
parser.add_argument('--passcode', '-p', help='21 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran
parser.add_argument("--poll", "-P", help="Poll mailboxes for any events", action="store_true")

parser.add_argument("--verbose", "-V", help="print JSON of all current events", action="store_true")


def handler(args):
    kwa = dict(args=args)
    kever = KeverDoer(name=args.name, base=args.base, bran=args.bran, prefix=args.prefix, poll=args.poll,
                      verbose=args.verbose)
    return [kever]


class KeverDoer(doing.DoDoer):

    def __init__(self, name, base, bran, prefix, poll=False, verbose=False):
        self.prefix = prefix
        self.poll = poll
        self.verbose = verbose
        self.hby = existing.setupHby(name=name, base=base, bran=bran)
        self.mbx = indirecting.MailboxDirector(hby=self.hby,
                                               topics=["/receipt", "/replay", "/multisig", "/credential", "/delegate",
                                                       "/challenge", "/oobi"])
        doers = [self.mbx, doing.doify(self.kevers)]
        super(KeverDoer, self).__init__(doers=doers)

    def kevers(self, tymth, tock=0.0, **opts):
        """ Command line status handler

        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield tock)

        if self.poll:
            end = helping.nowUTC() + datetime.timedelta(seconds=5)
            sys.stdout.write(f"Checking mailboxes for any events")
            sys.stdout.flush()
            while helping.nowUTC() < end:
                sys.stdout.write(".")
                sys.stdout.flush()
                yield 1.0
            print("\n")

        if self.prefix not in self.hby.kevers:
            print(f"identifier prefix {self.prefix} is not known locally")
        else:
            displaying.printExternal(self.hby, self.prefix)

            if self.verbose:
                kever = self.hby.kevers[self.prefix]
                print("\nWitnesses:\t")
                for idx, wit in enumerate(kever.wits):
                    print(f'\t{idx + 1}. {wit}')
                print()

                cloner = self.hby.db.clonePreIter(pre=self.prefix, fn=0)  # create iterator at 0
                for msg in cloner:
                    srdr = serdering.SerderKERI(raw=msg)
                    print(srdr.pretty())
                    print()

        self.remove([self.mbx])

        return True

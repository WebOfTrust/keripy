# -*- encoding: utf-8 -*-
"""
keri.kli.commands module

"""
import argparse
import datetime
import sys

from hio import help
from hio.base import doing
from keri.app import directing, agenting, indirecting, habbing
from keri.app.cli.common import displaying
from keri.app.cli.common import existing
from keri.help import helping

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Request KEL from Witness')
parser.set_defaults(handler=lambda args: query(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='Human readable reference', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--alias', '-a', help='human readable alias for the new identifier prefix', required=True)
parser.add_argument('--prefix', help='QB64 identifier to query', default="", required=True)

# Authentication for keystore
parser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran
parser.add_argument('--aeid', help='qualified base64 of non-transferable identifier prefix for  authentication '
                                   'and encryption of secrets in keystore', default=None)


def query(args):
    name = args.name

    qryDoer = QueryDoer(name=name, alias=args.alias, base=args.base, bran=args.bran, pre=args.prefix)
    return [qryDoer]


class QueryDoer(doing.DoDoer):

    def __init__(self, name, alias, base, bran, pre, **kwa):
        doers = []
        self.hby = existing.setupHby(name=name, base=base, bran=bran)
        self.hbyDoer = habbing.HaberyDoer(habery=self.hby)  # setup doer
        hab = self.hby.habByName(alias)
        self.hab = hab

        self.pre = pre

        self.mbd = indirecting.MailboxDirector(hby=self.hby, topics=["/replay", "/receipt"])
        self.witq = agenting.WitnessInquisitor(hby=self.hby)
        doers.extend([self.hbyDoer, self.mbd, self.witq])

        self.toRemove = list(doers)
        doers.extend([doing.doify(self.queryDo)])
        super(QueryDoer, self).__init__(doers=doers, **kwa)

    def queryDo(self, tymth, tock=0.0, **opts):
        """
        Returns:  doifiable Doist compatible generator method
        Usage:
            add result of doify on this method to doers list
        """
        # enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        self.witq.query(src=self.hab.pre, pre=self.pre)

        end = helping.nowUTC() + datetime.timedelta(seconds=5)
        sys.stdout.write(f"Checking mailboxes for any events")
        sys.stdout.flush()
        while helping.nowUTC() < end:
            sys.stdout.write(".")
            sys.stdout.flush()
            yield 1.0
        print("\n")

        displaying.printExternal(self.hby, self.pre)

        self.remove(self.toRemove)

        return

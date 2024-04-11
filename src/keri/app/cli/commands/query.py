# -*- encoding: utf-8 -*-
"""
keri.kli.commands module

"""
import argparse
import datetime
import json

from hio import help
from hio.base import doing
from hio.help import decking

from keri.app import indirecting, habbing, querying
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
parser.add_argument('--passcode', '-p', help='21 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran
parser.add_argument('--aeid', help='qualified base64 of non-transferable identifier prefix for  authentication '
                                   'and encryption of secrets in keystore', default=None)
parser.add_argument('--anchor', help='JSON file containing the anchor to search for', default=None, required=False)


def query(args):
    name = args.name

    qryDoer = LaunchDoer(name=name, alias=args.alias, base=args.base, bran=args.bran, pre=args.prefix,
                         anchor=args.anchor)
    return [qryDoer]


class LaunchDoer(doing.DoDoer):

    def __init__(self, name, alias, base, bran, pre, anchor, **kwa):
        doers = []
        self.hby = existing.setupHby(name=name, base=base, bran=bran)
        self.hbyDoer = habbing.HaberyDoer(habery=self.hby)  # setup doer
        hab = self.hby.habByName(alias)

        self.hab = hab
        self.logs = decking.Deck()

        self.pre = pre
        self.anchor = anchor
        self.loaded = False

        self.mbd = indirecting.MailboxDirector(hby=self.hby, topics=["/replay", "/receipt", "/reply"])
        doers.extend([self.hbyDoer, self.mbd])

        self.toRemove = list(doers)
        doers.extend([doing.doify(self.queryDo)])
        super(LaunchDoer, self).__init__(doers=doers, **kwa)

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

        end = helping.nowUTC() + datetime.timedelta(seconds=10)

        if self.anchor is not None:
            f = open(self.anchor)
            anchor = json.load(f)
            print(f"Checking for anchor {anchor}...")
            doer = querying.AnchorQuerier(hby=self.hby, hab=self.hab, pre=self.pre, anchor=anchor)
        else:
            print(f"Checking for updates...")
            doer = querying.QueryDoer(hby=self.hby, hab=self.hab, pre=self.pre, kvy=self.mbd.kvy)

        self.extend([doer])

        while helping.nowUTC() < end:
            if doer.done:
                break
            yield 1.0

        self.remove([doer])
        print("\n")

        displaying.printExternal(self.hby, self.pre)

        self.remove(self.toRemove)

        return

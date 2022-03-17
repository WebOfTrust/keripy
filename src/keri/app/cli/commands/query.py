# -*- encoding: utf-8 -*-
"""
keri.kli.commands module

"""
import argparse

from hio import help
from hio.base import doing
from keri.app import directing, agenting, indirecting, habbing
from keri.app.cli.common import displaying
from keri.app.cli.common import existing

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Request KEL from Witness')
parser.set_defaults(handler=lambda args: query(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='Human readable reference', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--alias', '-a', help='human readable alias for the new identifier prefix', required=True)
parser.add_argument('--witness', '-w', help='QB64 identifier of witness to query', default="", required=True)
parser.add_argument('--prefix', help='QB64 identifier to query', default="", required=True)

# Authentication for keystore
parser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran
parser.add_argument('--aeid', help='qualified base64 of non-transferable identifier prefix for  authentication '
                                   'and encryption of secrets in keystore', default=None)


def query(args):
    name = args.name

    qryDoer = QueryDoer(name=name, alias=args.alias, base=args.base, bran=args.bran, wit=args.witness, pre=args.prefix)
    return [qryDoer]


class QueryDoer(doing.DoDoer):

    def __init__(self, name, alias, base, bran, wit, pre, **kwa):
        doers = []
        self.hby = existing.setupHby(name=name, base=base, bran=bran)
        self.hbyDoer = habbing.HaberyDoer(habery=self.hby)  # setup doer
        hab = self.hby.habByName(alias)
        self.hab = hab

        self.wit = wit
        self.pre = pre
        self.cues = help.decking.Deck()

        self.mbd = indirecting.MailboxDirector(hby=self.hby, topics=["/replay", "/receipt"])
        self.witq = agenting.WitnessInquisitor(hhby=self.hby)
        doers.extend([self.hbyDoer, self.mbd, self.witq, doing.doify(self.cueDo)])

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

        self.witq.query(src=self.hab.pre, pre=self.pre, r="ksn")

        while True:
            yield self.tock
            if self.cues:
                cue = self.cues.popleft()
                serder = cue["serder"]
                if serder.pre == self.pre:
                    break

        displaying.printIdentifier(self.hby, self.pre)

        self.remove(self.toRemove)

        return

    def cueDo(self, tymth, tock=0.0, **opts):
        """

        Handle cues coming out of our external Mailbox listener and forward to controller
        mailbox if appropriate

        """
        self.wind(tymth)
        self.tock = tock
        yield self.tock

        while True:
            while self.mbd.kvy.cues:
                cue = self.mbd.kvy.cues.popleft()
                cueKin = cue["kin"]  # type or kind of cue
                if cueKin == "query":
                    qargs = cue["q"]
                    self.witq.query(**qargs)

                elif cueKin == "keyStateSaved":
                    self.cues.append(cue)

                yield self.tock
            yield self.tock


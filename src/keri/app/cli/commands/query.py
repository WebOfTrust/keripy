# -*- encoding: utf-8 -*-
"""
keri.kli.commands module

"""
import argparse

from hio import help
from hio.base import doing
from keri.app import directing, agenting, indirecting
from keri.app.cli.common import displaying
from keri.app.cli.common import existing

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Request KEL from Witness')
parser.set_defaults(handler=lambda args: query(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='Human readable reference', required=True)
parser.add_argument('--witness', '-w', help='QB64 identifier of witness to query', default="", required=True)
parser.add_argument('--prefix', '-p', help='QB64 identifier to query', default="", required=True)


def query(args):
    name = args.name

    qryDoer = QueryDoer(name=name, wit=args.witness, pre=args.prefix)
    directing.runController(doers=[qryDoer], expire=0.0)


class QueryDoer(doing.DoDoer):

    def __init__(self, name, wit, pre, **kwa):
        hab, doers = existing.openHabitat(name=name)
        self.hab = hab

        self.wit = wit
        self.pre = pre
        self.cues = help.decking.Deck()

        self.mbd = indirecting.MailboxDirector(hab=self.hab, topics=["/replay", "/receipt"])
        self.witq = agenting.WitnessInquisitor(hab=self.hab, wits=[self.wit])
        doers.extend([self.mbd, self.witq, doing.doify(self.cueDo)])

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

        self.witq.query(pre=self.pre, r="ksn")

        while True:
            yield self.tock
            if self.cues:
                cue = self.cues.popleft()
                serder = cue["serder"]
                if serder.pre == self.pre:
                    break

        displaying.printIdentifier(self.hab, self.pre)

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
                    self.witq.backoffQuery(**qargs)

                elif cueKin == "keyStateSaved":
                    self.cues.append(cue)

                yield self.tock
            yield self.tock


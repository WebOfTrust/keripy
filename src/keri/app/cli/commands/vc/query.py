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
from keri.core import coring
from keri.vdr import eventing, viring, verifying

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Request Transaction State from Witness or Backer')
parser.set_defaults(handler=lambda args: query(args))
parser.add_argument('--name', '-n', help='Human readable reference', required=True)
parser.add_argument('--witness', '-w', help='QB64 identifier of witness to query', default="", required=True)
parser.add_argument('--registry', '-r', help='QB64 identifier or registry to query', default="", required=True)
parser.add_argument('--vc', '-i', help='QB64 identifier or credential to query', default="", required=False)


def query(args):
    name = args.name

    qryDoer = QueryDoer(name=name, wit=args.witness, ri=args.registry, i=args.vc)
    directing.runController(doers=[qryDoer], expire=0.0)


class QueryDoer(doing.DoDoer):

    def __init__(self, name, wit, ri, i, **kwa):
        hab, doers = existing.openHabitat(name=name)
        self.hab = hab

        self.wit = wit
        self.ri = ri
        self.i = i
        self.cues = help.decking.Deck()

        reger = viring.Registry(name=self.hab.name)
        self.verifier = verifying.Verifier(hab=self.hab, reger=reger)
        self.mbd = indirecting.MailboxDirector(hab=self.hab, topics=["/replay", "/receipt"], verifier=self.verifier)
        self.witq = agenting.WitnessInquisitor(hab=self.hab, reger=reger)
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

        self.witq.telquery(r="tsn", ri=self.ri, i=self.i)

        rserder = None
        vcser = None
        while True:
            yield self.tock
            if self.cues:
                cue = self.cues.popleft()
                serder = cue["serder"]
                if serder.pre == self.ri:
                    rserder = serder
                elif serder.pre == self.i:
                    vcser = serder

                if rserder is not None and (self.i == "" or vcser is not None):
                    break

        print("Registry:\t", rserder.pre)
        print("Issuer: \t", rserder.ked["ii"])
        print("Sequence No.:\t", rserder.ked["s"])
        print("Last Event:\t", rserder.ked["et"])

        if vcser is not None:
            print()
            print("Credential:\t", vcser.pre)
            print("Sequence No.:\t", vcser.ked["s"])
            print("Last Event:\t", vcser.ked["et"])

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
                if cueKin == "telquery":
                    qargs = cue["q"]
                    self.witq.telquery(**qargs)

                elif cueKin == "txnStateSaved":
                    self.cues.append(cue)

                yield self.tock
            yield self.tock


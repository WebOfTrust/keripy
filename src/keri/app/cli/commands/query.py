# -*- encoding: utf-8 -*-
"""
keri.kli.commands module

"""
import argparse

from hio import help
from hio.base import doing
from hio.core.tcp import clienting

from keri.app import directing, obtaining
from keri.app.cli.common import displaying
from keri.app.cli.common import existing
from keri.core import eventing, parsing

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

        loc = obtaining.getwitnessbyprefix(self.wit)
        client = clienting.Client(host=loc.ip4, port=loc.tcp)
        clientDoer = clienting.ClientDoer(client=client)

        kevery = eventing.Kevery(db=self.hab.db,
                                 lax=False,
                                 local=False)

        self.parser = parsing.Parser(ims=client.rxbs,
                                     framed=True,
                                     kvy=kevery)

        doifiedDoer = doing.doify(self.msgDo)
        self.extend([clientDoer, doifiedDoer])
        self.toRemove.extend([clientDoer, doifiedDoer])

        msg = self.hab.query(self.pre, res="logs")  # Query for remote pre Event
        client.tx(msg)  # send to connected remote
        yield 2.0

        while self.pre not in kevery.kevers:
            yield self.tock

        displaying.printIdentifier(self.hab, self.pre)

        self.remove(self.toRemove)

        return

    def msgDo(self, tymth=None, tock=0.0, **opts):
        """
        Returns: doifiable Doist compatibile generator method (doer dog) to process
            incoming message stream of .kevery

        Doist Injected Attributes:
            g.tock = tock  # default tock attributes
            g.done = None  # default done state
            g.opts

        Parameters:
            tymth is injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock is injected initial tock value
            opts is dict of injected optional additional parameters

        Usage:
            add result of doify on this method to doers list
        """
        done = yield from self.parser.parsator()  # process messages continuously
        return done  # should nover get here except forced close

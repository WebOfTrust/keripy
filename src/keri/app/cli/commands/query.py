# -*- encoding: utf-8 -*-
"""
keri.kli.commands module

"""
import argparse

from hio import help
from hio.base import doing
from hio.core.tcp import clienting

from keri.app import habbing, keeping, directing, obtaining
from keri.core import eventing, parsing
from keri.db import basing, dbing

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Request KEL from Witness')
parser.set_defaults(handler=lambda args: handler(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='Human readable reference', required=True)
parser.add_argument('--witness', '-w', help='QB64 identifier of witness to query', default="", required=True)
parser.add_argument('--prefix', '-p', help='QB64 identifier to query', default="", required=True)


def handler(args):
    name = args.name

    qryDoer = QueryDoer(name=name, wit=args.witness, pre=args.prefix)
    directing.runController(doers=[qryDoer], expire=0.0)


class QueryDoer(doing.DoDoer):

    def __init__(self, name, wit, pre, **kwa):
        ks = keeping.Keeper(name=name, temp=False)  # not opened by default, doer opens
        self.ksDoer = keeping.KeeperDoer(keeper=ks)  # doer do reopens if not opened and closes
        db = basing.Baser(name=name, temp=False, reload=True)  # not opened by default, doer opens
        self.dbDoer = basing.BaserDoer(baser=db)  # doer do reopens if not opened and closes

        self.hab = habbing.Habitat(name=name, ks=ks, db=db, temp=False, create=False)
        self.habDoer = habbing.HabitatDoer(habitat=self.hab)  # setup doer

        self.wit = wit
        self.pre = pre

        doers = [self.ksDoer, self.dbDoer, self.habDoer, doing.doify(self.queryDo)]
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

        self.extend([clientDoer, doing.doify(self.msgDo)])

        msg = self.hab.query(self.pre, res="logs")  # Query for remote pre Event
        client.tx(msg)  # send to connected remote

        while self.pre not in kevery.kevers:
            yield self.tock


        kev = kevery.kevers[self.pre]
        ser = kev.serder
        dgkey = dbing.dgKey(ser.preb, ser.digb)
        wigs = self.hab.db.getWigs(dgkey)

        print("Prefix:\t{}".format(self.pre))
        print("Seq No:\t{}".format(kev.sn))
        print("\nWitnesses:")
        print("Count:\t\t{}".format(len(kev.wits)))
        print("Receipts:\t{}".format(len(wigs)))
        print("Threshold:\t{}".format(kev.toad))
        print("\nPublic Keys:\t")
        for idx, verfer in enumerate(kev.verfers):
            print(f'\t{idx+1}. {verfer.qb64}')

        self.remove([self.ksDoer, self.dbDoer, self.habDoer, self.msgDo, clientDoer])

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

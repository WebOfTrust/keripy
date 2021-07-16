# -*- encoding: utf-8 -*-
"""
KERI
keri.app.agenting module

"""
from hio.base import doing
from hio.core.tcp import clienting

from keri.app import obtaining
from keri.core import eventing, parsing, coring
from keri.db import dbing


class AgentController:
    """

    """

    def __init__(self, hab, issuer, **kwa):
        """

        Parameters:
            hab (Habitat):
            issuer (Issuer):

        """
        self.hab = hab
        self.issuer = issuer



class WitnessReceiptor(doing.DoDoer):

    def __init__(self, hab, doers=None, **kwa):
        """
        For the current event, gather the current set of witnesses, send the event,
        gather all receipts and send them to all other witnesses

        Parameters:
            hab: Habitat of the identifier to populate witnesses

        """
        self.hab = hab
        super(WitnessReceiptor, self).__init__(doers=[self.receiptDo], **kwa)


    @doing.doize()
    def receiptDo(self, tymth=None, tock=0.0, **opts):
        # enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        sn = self.hab.kever.sn
        wits = self.hab.kever.wits

        msg = self.hab.makeOwnEvent(sn=sn)

        for wit in wits:
            witer = Witnesser(hab=self.hab, wit=wit, msg=msg)
            self.extend([witer])
            _ = (yield self.tock)


class Witnesser(doing.DoDoer):
    def __init__(self, hab, wit, msg, doers=None, **kwa):
        """
        For the current event, gather the current set of witnesses, send the event,
        gather all receipts and send them to all other witnesses

        Parameters:
            hab: Habitat of the identifier to populate witnesses

        """
        self.hab = hab
        self.wit = wit
        self.msg = msg
        self.parser = None
        doers = doers if doers is not None else []
        doers.extend([self.receiptDo, self.msgDo])

        self.kevery = eventing.Kevery(db=self.hab.db,
                                      lax=False,
                                      local=True)

        super(Witnesser, self).__init__(doers=[self.receiptDo], **kwa)


    @doing.doize()
    def receiptDo(self, tymth=None, tock=0.0, **opts):
        # enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        ip = obtaining.getwitnessbyprefix(self.wit)
        client = clienting.Client(host=ip["ip4"], port=ip["ip4port"])
        self.parser = parsing.Parser(ims=client.rxbs,
                                     framed=True,
                                     kvy=self.kevery)

        clientDoer = clienting.ClientDoer(client=client)
        self.extend([clientDoer, self.msgDo])

        client.tx(self.msg)   # send to connected remote

        ser = coring.Serder(raw=self.msg)

        while True:
            dgkey = dbing.dgKey(ser.preb, ser.digb)

            rcts = self.hab.db.getWigs(dgkey)
            if len(rcts) == 1:
                break
            _ = yield self.tock

        print("got the receipts")

    @doing.doize()
    def msgDo(self, tymth=None, tock=0.0, **opts):
        """
        Returns Doist compatibile generator method (doer dog) to process
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
            add to doers list
        """
        done = yield from self.parser.parsator()  # process messages continuously
        return done  # should nover get here except forced close

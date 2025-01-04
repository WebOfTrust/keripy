# -*- encoding: utf-8 -*-
"""
KERI
keri.app.indirecting module

simple indirect mode demo support classes
"""

from hio.base import doing

from .. import help
from ..core import (eventing, parsing)

logger = help.ogler.getLogger()


class Indirector(doing.DoDoer):
    """
    Base class for Indirect Mode KERI Controller Doer with habitat and
    TCP Clients for talking to witnesses

    Subclass of DoDoer with doers list from do generator methods:
        .msgDo, .cueDo, and  .escrowDo.

    Enables continuous scheduling of doers (do generator instances or functions)

    Implements Doist like functionality to allow nested scheduling of doers.
    Each DoDoer runs a list of doers like a Doist but using the tyme from its
       injected tymist as injected by its parent DoDoer or Doist.

    Scheduling hierarchy: Doist->DoDoer...->DoDoer->Doers

    Attributes:
        .done is Boolean completion state:
            True means completed
            Otherwise incomplete. Incompletion maybe due to close or abort.
        .opts is dict of injected options for its generator .do
        .doers is list of Doers or Doer like generator functions

    Attributes:
        hab (Habitat: local controller's context
        client (serving.Client): hio TCP client instance.
            Assumes operated by another doer.

    Properties:
        tyme (float): relative cycle time of associated Tymist, obtained
            via injected .tymth function wrapper closure.
        tymth (function): function wrapper closure returned by Tymist .tymeth()
            method.  When .tymth is called it returns associated Tymist .tyme.
            .tymth provides injected dependency on Tymist tyme base.
        tock (float): desired time in seconds between runs or until next run,
            non negative, zero means run asap


    Methods:
        .wind  injects ._tymth dependency from associated Tymist to get its .tyme
        .__call__ makes instance callable
            Appears as generator function that returns generator
        .do is generator method that returns generator
        .enter is enter context action method
        .recur is recur context action method or generator method
        .clean is clean context action method
        .exit is exit context method
        .close is close context method
        .abort is abort context method


    Hidden:
       ._tymth is injected function wrapper closure returned by .tymen() of
            associated Tymist instance that returns Tymist .tyme. when called.
       ._tock is hidden attribute for .tock property

    """

    def __init__(self, hab, client, direct=True, doers=None, **kwa):
        """
        Initialize instance.

        Inherited Parameters:
            tymist is  Tymist instance
            tock is float seconds initial value of .tock
            doers is list of doers (do generator instances, functions or methods)

        Parameters:
            hab is Habitat instance of local controller's context
            client is TCP Client instance
            direct is Boolean, True means direwct mode process cured receipts
                               False means indirect mode don't process cue'ed receipts

        """
        self.hab = hab
        self.client = client  # use client for both rx and tx
        self.direct = True if direct else False
        self.kevery = eventing.Kevery(db=self.hab.db,
                                      lax=False,
                                      local=False,
                                      cloned=not self.direct,
                                      direct=self.direct)
        self.parser = parsing.Parser(ims=self.client.rxbs,
                                     framed=True,
                                     kvy=self.kevery)
        doers = doers if doers is not None else []
        doers.extend([doing.doify(self.msgDo),
                      doing.doify(self.escrowDo)])
        if self.direct:
            doers.extend([doing.doify(self.cueDo)])

        super(Indirector, self).__init__(doers=doers, **kwa)
        if self.tymth:
            self.client.wind(self.tymth)

    def wind(self, tymth):
        """
        Inject new tymist.tymth as new ._tymth. Changes tymist.tyme base.
        Updates winds .tymer .tymth
        """
        super(Indirector, self).wind(tymth)
        self.client.wind(tymth)

    def msgDo(self, tymth=None, tock=0.0):
        """
        Returns doifiable Doist compatibile generator method (doer dog) to process
            incoming message stream of .kevery

        Doist Injected Attributes:
            g.tock = tock  # default tock attributes
            g.done = None  # default done state
            g.opts

        Parameters:
            tymth is injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock is injected initial tock value

        Usage:
            add result of doify on this method to doers list
        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        if self.parser.ims:
            logger.debug("Client %s received:\n%s\n...\n", self.hab.pre, self.parser.ims[:1024])
        done = yield from self.parser.parsator(local=True)  # process messages continuously
        return done  # should nover get here except forced close

    def cueDo(self, tymth=None, tock=0.0):
        """
         Returns doifiable Doist compatibile generator method (doer dog) to process
            .kevery.cues deque

        Doist Injected Attributes:
            g.tock = tock  # default tock attributes
            g.done = None  # default done state
            g.opts

        Parameters:
            tymth is injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock is injected initial tock value

        Usage:
            add result of doify on this method to doers list
        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        while True:
            for msg in self.hab.processCuesIter(self.kevery.cues):
                self.sendMessage(msg, label="chit or receipt")
                yield  # throttle just do one cue at a time
            yield

    def escrowDo(self, tymth=None, tock=0.0):
        """
         Returns doifiable Doist compatibile generator method (doer dog) to process
            .kevery escrows.

        Doist Injected Attributes:
            g.tock = tock  # default tock attributes
            g.done = None  # default done state
            g.opts

        Parameters:
            tymth is injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock is injected initial tock value

        Usage:
            add result of doify on this method to doers list
        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        while True:
            self.kevery.processEscrows()
            yield

    def sendMessage(self, msg, label=""):
        """
        Sends message msg and loggers label if any
        """
        self.client.tx(msg)  # send to remote
        logger.debug("%s sent %s:\n%s\n\n", self.hab.pre, label, bytes(msg))












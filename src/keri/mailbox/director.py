# -*- encoding: utf-8 -*-
"""
KERI
keri.mailbox module

"""

from hio.base import doing
from hio.help import decking
from ordered_set import OrderedSet as oset

from .poller import Poller
from .. import help, kering
from ..core import (eventing, parsing, routing)
from ..vdr.eventing import Tevery

logger = help.ogler.getLogger()

class Director(doing.DoDoer):
    """
    Class for Indirect Mode KERI Controller Doer with habitat and
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
        hby (Habitat: local controller's context

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

    def __init__(self, hby, topics, ims=None, verifier=None, kvy=None, exc=None, rep=None, cues=None, rvy=None,
                 tvy=None, witnesses=True, **kwa):
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
        self.hby = hby
        self.verifier = verifier
        self.exchanger = exc
        self.rep = rep
        self.topics = topics
        self.pollers = list()
        self.prefixes = oset()
        self.cues = cues if cues is not None else decking.Deck()
        self.witnesses = witnesses

        self.ims = ims if ims is not None else bytearray()

        doers = []
        doers.extend([doing.doify(self.pollDo),
                      doing.doify(self.msgDo),
                      doing.doify(self.escrowDo)])

        self.rtr = routing.Router()
        self.rvy = rvy if rvy is not None else routing.Revery(db=self.hby.db, rtr=self.rtr, cues=cues,
                                                              lax=True, local=False)

        #  needs unique kevery with ims per remoter connnection
        self.kvy = kvy if kvy is not None else eventing.Kevery(db=self.hby.db,
                                                               cues=self.cues,
                                                               rvy=self.rvy,
                                                               lax=True,
                                                               local=False,
                                                               direct=False)
        self.kvy.registerReplyRoutes(self.rtr)

        if self.verifier is not None:
            self.tvy = tvy if tvy is not None else Tevery(reger=self.verifier.reger,
                                                          db=self.hby.db, rvy=self.rvy,
                                                          lax=True, local=False, cues=self.cues)
            self.tvy.registerReplyRoutes(self.rtr)
        else:
            self.tvy = None

        self.parser = parsing.Parser(ims=self.ims,
                                     framed=True,
                                     kvy=self.kvy,
                                     tvy=self.tvy,
                                     exc=self.exchanger,
                                     rvy=self.rvy,
                                     vry=self.verifier)

        super(Director, self).__init__(doers=doers, **kwa)

    def wind(self, tymth):
        """
        Inject new tymist.tymth as new ._tymth. Changes tymist.tyme base.
        Updates winds .tymer .tymth
        """
        super(Director, self).wind(tymth)

    def pollDo(self, tymth=None, tock=0.0):
        """
        Returns:
           doifiable Doist compatible generator method

        Usage:
            add result of doify on this method to doers list
        """
        # enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        habs = list(self.hby.habs.values())
        for hab in habs:
            if hab.accepted:
                self.addPollers(hab)
                _ = (yield self.tock)

        while True:
            pres = oset(self.hby.habs.keys())
            if new := pres - self.prefixes:
                for pre in new:
                    hab = self.hby.habs[pre]
                    if hab.accepted:
                        self.addPollers(hab=hab)
                        _ = (yield self.tock)

            for msg in self.processPollIter():
                self.ims.extend(msg)
                _ = (yield self.tock)
            _ = (yield self.tock)

    def addPollers(self, hab):
        """ add mailbox pollers for every witness for this prefix identifier

        Parameters:
            hab (Hab): the Hab of the prefix

        """
        for (_, erole, eid), end in hab.db.ends.getItemIter(keys=(hab.pre, kering.Roles.mailbox)):
            if end.allowed:
                poller = Poller(hab=hab, topics=self.topics, witness=eid)
                self.pollers.append(poller)
                self.extend([poller])

        if self.witnesses:
            wits = hab.kever.wits
            for wit in wits:
                poller = Poller(hab=hab, topics=self.topics, witness=wit)
                self.pollers.append(poller)
                self.extend([poller])

        self.prefixes.add(hab.pre)

    def addPoller(self, hab, witness):
        poller = Poller(hab=hab, topics=self.topics, witness=witness)
        self.pollers.append(poller)
        self.extend([poller])

    def processPollIter(self):
        """
        Iterate through cues and yields one or more responses for each cue.

        Parameters:
            cues is deque of cues

        """
        mail = []
        for poller in self.pollers:  # get responses from all behaviors
            while poller.msgs:
                msg = poller.msgs.popleft()
                mail.append(msg)

        while mail:  # iteratively process each response in responses
            msg = mail.pop(0)
            yield msg

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

        done = yield from self.parser.parsator(local=True)  # process messages continuously
        return done  # should nover get here except forced close

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
            self.kvy.processEscrows()
            self.rvy.processEscrowReply()
            if self.exchanger is not None:
                self.exchanger.processEscrow()
            if self.tvy is not None:
                self.tvy.processEscrows()
            if self.verifier is not None:
                self.verifier.processEscrows()

            yield

    @property
    def times(self):
        times = dict()
        for poller in self.pollers:  # get responses from all pollers
            times |= poller.times

        return times

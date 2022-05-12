# -*- encoding: utf-8 -*-
"""
KERI
keri.app.indirecting module

simple indirect mode demo support classes
"""
import falcon
import time
from  ordered_set import OrderedSet as oset

from hio.base import doing
from hio.core import http
from hio.core.tcp import serving
from hio.help import decking


from . import directing, storing, httping, forwarding, agenting
from .cli.common import oobiing
from .. import help, kering
from ..core import eventing, parsing, routing
from ..core.coring import Ilks
from ..db import basing
from ..end import ending
from ..help import helping
from ..peer import exchanging
from ..vdr import verifying, viring
from ..vdr.eventing import Tevery

logger = help.ogler.getLogger()


def setupWitness(hby, alias="witness", mbx=None, tcpPort=5631, httpPort=5632):
    """
    Setup witness controller and doers

    """
    cues = decking.Deck()
    doers = []

    # make hab
    hab = hby.habByName(name=alias)
    if hab is None:
        hab = hby.makeHab(name=alias, transferable=False)

    reger = viring.Reger(name=hab.name, db=hab.db, temp=False)
    verfer = verifying.Verifier(hby=hby, reger=reger)

    mbx = mbx if mbx is not None else storing.Mailboxer(name=alias, temp=hby.temp)
    forwarder = forwarding.ForwardHandler(hby=hby, mbx=mbx)
    exchanger = exchanging.Exchanger(hby=hby, handlers=[forwarder])
    app = falcon.App(cors_enable=True)
    ending.loadEnds(app=app, hby=hby)

    rep = storing.Respondant(hby=hby, mbx=mbx)

    rvy = routing.Revery(db=hby.db, cues=cues)
    kvy = eventing.Kevery(db=hby.db,
                          lax=True,
                          local=False,
                          rvy=rvy,
                          cues=cues)
    kvy.registerReplyRoutes(router=rvy.rtr)

    tvy = Tevery(reger=verfer.reger,
                 db=hby.db,
                 local=False,
                 cues=cues)

    tvy.registerReplyRoutes(router=rvy.rtr)
    parser = parsing.Parser(framed=True,
                            kvy=kvy,
                            tvy=tvy,
                            exc=exchanger,
                            rvy=rvy)

    httpEnd = HttpEnd(rxbs=parser.ims, mbx=mbx)
    app.add_route("/", httpEnd)

    server = http.Server(port=httpPort, app=app)
    httpServerDoer = http.ServerDoer(server=server)

    # setup doers
    regDoer = basing.BaserDoer(baser=verfer.reger)

    server = serving.Server(host="", port=tcpPort)
    serverDoer = serving.ServerDoer(server=server)

    directant = directing.Directant(hab=hab, server=server, verifier=verfer)
    obl = oobiing.OobiLoader(hby=hby, auto=True)

    witStart = WitnessStart(hab=hab, parser=parser, cues=cues,
                            kvy=kvy, tvy=tvy, rvy=rvy, exc=exchanger, replies=rep.reps,
                            responses=rep.cues, queries=httpEnd.qrycues)

    doers.extend([regDoer, exchanger, directant, serverDoer, httpServerDoer, rep, obl, witStart])

    return doers


class WitnessStart(doing.DoDoer):
    """ Doer to print witness prefix after initialization

    """

    def __init__(self, hab, parser, kvy, tvy, rvy, exc, cues=None, replies=None, responses=None, queries=None, **opts):
        self.hab = hab
        self.parser = parser
        self.kvy = kvy
        self.tvy = tvy
        self.rvy = rvy
        self.exc = exc
        self.queries = queries if queries is not None else decking.Deck()
        self.replies = replies if replies is not None else decking.Deck()
        self.responses = responses if responses is not None else decking.Deck()
        self.cues = cues if cues is not None else decking.Deck()

        doers = [doing.doify(self.start), doing.doify(self.msgDo),
                 doing.doify(self.exchangerDo), doing.doify(self.escrowDo), doing.doify(self.cueDo)]
        super().__init__(doers=doers, **opts)

    def start(self, tymth=None, tock=0.0):
        """ Prints witness name and prefix

        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock (float): injected initial tock value

        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        while not self.hab.inited:
            yield self.tock

        print("Witness", self.hab.name, ":", self.hab.pre)

    def msgDo(self, tymth=None, tock=0.0):
        """
        Returns doifiable Doist compatibile generator method (doer dog) to process
            incoming message stream of .kevery

        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock (float): injected initial tock value

        Usage:
            add result of doify on this method to doers list
        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        if self.parser.ims:
            logger.info("Client %s received:\n%s\n...\n", self.kvy, self.parser.ims[:1024])
        done = yield from self.parser.parsator()  # process messages continuously
        return done  # should nover get here except forced close

    def escrowDo(self, tymth=None, tock=0.0):
        """
         Returns doifiable Doist compatibile generator method (doer dog) to process
            .kevery and .tevery escrows.

        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock (float): injected initial tock value

        Usage:
            add result of doify on this method to doers list
        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        while True:
            self.kvy.processEscrows()
            self.rvy.processEscrowReply()
            if self.tvy is not None:
                self.tvy.processEscrows()
            self.exc.processEscrow()

            yield

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
            while self.cues:
                cue = self.cues.popleft()
                cueKin = cue["kin"]
                if cueKin == "stream":
                    self.queries.append(cue)
                else:
                    self.responses.append(cue)
                yield self.tock
            yield self.tock

    def exchangerDo(self, tymth=None, tock=0.0):
        """
        Returns doifiable Doist compatibile generator method (doer dog) to process
            .exc responses and pass them on to the HTTPRespondant

        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock (float): injected initial tock value

        Usage:
            add result of doify on this method to doers list
        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        while True:
            for rep in self.exc.processResponseIter():
                self.replies.append(rep)
                yield  # throttle just do one cue at a time
            yield


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
            logger.info("Client %s received:\n%s\n...\n", self.hab.pre, self.parser.ims[:1024])
        done = yield from self.parser.parsator()  # process messages continuously
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
        logger.info("%s sent %s:\n%s\n\n", self.hab.pre, label, bytes(msg))


class MailboxDirector(doing.DoDoer):
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

    def __init__(self, hby, topics, ims=None, verifier=None, kvy=None, exc=None, rep=None, cues=None, rvy=None, **kwa):
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

        self.ims = ims if ims is not None else bytearray()

        doers = []
        doers.extend([doing.doify(self.pollDo),
                      doing.doify(self.msgDo),
                      doing.doify(self.escrowDo)])

        self.rtr = routing.Router()
        self.rvy = rvy if rvy is not None else routing.Revery(db=self.hby.db, rtr=self.rtr, cues=cues,
                                                              lax=True, local=False)

        #  neeeds unique kevery with ims per remoter connnection
        self.kvy = kvy if kvy is not None else eventing.Kevery(db=self.hby.db,
                                                               cues=self.cues,
                                                               rvy=self.rvy,
                                                               lax=True,
                                                               local=False,
                                                               direct=False)
        self.kvy.registerReplyRoutes(self.rtr)

        if self.verifier is not None:
            self.tevery = Tevery(reger=self.verifier.reger,
                                 db=self.hby.db, rvy=self.rvy,
                                 local=False, cues=self.cues)
            self.tevery.registerReplyRoutes(self.rtr)
        else:
            self.tevery = None

        if self.exchanger is not None:
            doers.extend([doing.doify(self.exchangerDo)])

        self.parser = parsing.Parser(ims=self.ims,
                                     framed=True,
                                     kvy=self.kvy,
                                     tvy=self.tevery,
                                     exc=self.exchanger,
                                     rvy=self.rvy,
                                     vry=self.verifier)

        super(MailboxDirector, self).__init__(doers=doers, **kwa)

    def wind(self, tymth):
        """
        Inject new tymist.tymth as new ._tymth. Changes tymist.tyme base.
        Updates winds .tymer .tymth
        """
        super(MailboxDirector, self).wind(tymth)

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

        wits = hab.kever.wits
        for wit in wits:
            poller = Poller(hab=hab, topics=self.topics, witness=wit)
            self.pollers.append(poller)
            self.extend([poller])

        self.prefixes.add(hab.pre)

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

        done = yield from self.parser.parsator()  # process messages continuously
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
            if self.tevery is not None:
                self.tevery.processEscrows()
            if self.verifier is not None:
                self.verifier.processEscrows()

            yield

    def exchangerDo(self, tymth=None, tock=0.0):
        """
         Returns doifiable Doist compatibile generator method (doer dog) to process
            .tevery.cues deque

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
            self.exchanger.processEscrow()
            yield

            for rep in self.exchanger.processResponseIter():
                self.rep.reps.append(rep)
                yield  # throttle just do one cue at a time
            yield

    @property
    def times(self):
        times = dict()
        for poller in self.pollers:  # get responses from all pollers
            times |= poller.times

        return times


class Poller(doing.DoDoer):
    """
    Polls remote SSE endpoint for event that are KERI messages to be processed

    """

    def __init__(self, hab, witness, topics, msgs=None, retry=1000, **kwa):
        """
        Returns doist compatible doing.Doer that polls a witness for mailbox messages
        as SSE events

        Parameters:
            hab:
            witness:
            topics:
            msgs:

        """
        self.hab = hab
        self.pre = hab.pre
        self.witness = witness
        self.topics = topics
        self.retry = retry
        self.msgs = None if msgs is not None else decking.Deck()
        self.times = dict()

        doers = [doing.doify(self.eventDo)]

        super(Poller, self).__init__(doers=doers, **kwa)

    def eventDo(self, tymth=None, tock=0.0):
        """
        Returns:
           doifiable Doist compatible generator method

        Usage:
            add result of doify on this method to doers list
        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        witrec = self.hab.db.tops.get((self.pre, self.witness))
        if witrec is None:
            witrec = basing.TopicsRecord(topics=dict())

        while self.retry > 0:
            client, clientDoer = agenting.httpClient(self.hab, self.witness)
            self.extend([clientDoer])

            topics = dict()
            q = dict(pre=self.pre, topics=topics)
            for topic in self.topics:
                if topic in witrec.topics:
                    topics[topic] = witrec.topics[topic] + 1
                else:
                    topics[topic] = 0

            if self.hab.phab:
                msg = self.hab.phab.query(pre=self.pre, src=self.witness, route="mbx", query=q)
            else:
                msg = self.hab.query(pre=self.pre, src=self.witness, route="mbx", query=q)

            httping.createCESRRequest(msg, client)

            while client.requests:
                yield self.tock

            while True:
                if client.respondent.eventSource and client.respondent.eventSource.closed:
                    break

                while client.events:
                    evt = client.events.popleft()
                    if "retry" in evt:
                        self.retry = evt["retry"]
                    if "id" not in evt or "data" not in evt or "name" not in evt:
                        logger.error(f"bad mailbox event: {evt}")
                        continue
                    idx = evt["id"]
                    msg = evt["data"]
                    tpc = evt["name"]

                    if not idx or not msg or not tpc:
                        logger.error(f"bad mailbox event: {evt}")
                        continue

                    self.msgs.append(msg.encode("utf=8"))
                    yield self.tock

                    witrec.topics[tpc] = int(idx)
                    self.times[tpc] = helping.nowUTC()
                    self.hab.db.tops.pin((self.pre, self.witness), witrec)

                yield 0.25
            yield self.retry / 1000


class HttpEnd:
    """
    HTTP handler that accepts and KERI events POSTed as the body of a request with all attachments to
    the message as a CESR attachment HTTP header.  KEL Messages are processed and added to the database
    of the provided Habitat.

    This also handles `req`, `exn` and `tel` messages that respond with a KEL replay.
    """

    TimeoutQNF = 30
    TimeoutMBX = 5

    def __init__(self, rxbs=None, mbx=None, qrycues=None):
        """
        Create the KEL HTTP server from the Habitat with an optional Falcon App to
        register the routes with.

        Parameters
             rxbs (bytearray): output queue of bytes for message processing
             mbx (Mailboxer): Mailbox storage
             qrycues (Deck): inbound qry response queues

        """
        self.rxbs = rxbs if rxbs is not None else bytearray()

        self.mbx = mbx
        self.qrycues = qrycues if qrycues is not None else decking.Deck()

    def on_post(self, req, rep):
        """
        Handles POST for KERI event messages.

        Parameters:
              req (Request) Falcon HTTP request
              rep (Response) Falcon HTTP response

        ---
        summary:  Accept KERI events with attachment headers and parse
        description:  Accept KERI events with attachment headers and parse.
        tags:
           - Events
        requestBody:
           required: true
           content:
             application/json:
               schema:
                 type: object
                 description: KERI event message
        responses:
           200:
              description: Mailbox query response for server sent events
           204:
              description: KEL or EXN event accepted.
        """
        if req.method == "OPTIONS":
            rep.status = falcon.HTTP_200
            return

        rep.set_header('Cache-Control', "no-cache")
        rep.set_header('connection', "close")

        cr = httping.parseCesrHttpRequest(req=req)
        serder = eventing.Serder(ked=cr.payload, kind=eventing.Serials.json)
        msg = bytearray(serder.raw)
        msg.extend(cr.attachments.encode("utf-8"))

        self.rxbs.extend(msg)

        ilk = serder.ked["t"]
        if ilk in (Ilks.icp, Ilks.rot, Ilks.ixn, Ilks.dip, Ilks.drt, Ilks.exn, Ilks.rpy):
            rep.set_header('Content-Type', "application/json")
            rep.status = falcon.HTTP_204
        elif ilk in (Ilks.vcp, Ilks.vrt, Ilks.iss, Ilks.rev, Ilks.bis, Ilks.brv):
            rep.set_header('Content-Type', "application/json")
            rep.status = falcon.HTTP_204
        elif ilk in (Ilks.qry,):
            rep.set_header('Content-Type', "text/event-stream")
            rep.status = falcon.HTTP_200
            rep.stream = QryRpyMailboxIterable(mbx=self.mbx, cues=self.qrycues, said=serder.said)

    def on_post_mbx(self, req, rep):
        """
        Handles POST for KERI mailbox service.

        Parameters:
              req (Request) Falcon HTTP request
              rep (Response) Falcon HTTP response

        ---
        summary:  Stream Server-Sent Events for KERI mailbox for identifier
        description:  Stream Server-Sent Events for KERI mailbox for identifier
        tags:
           - Mailbox
        requestBody:
           required: true
           content:
             application/json:
               schema:
                 type: object
                 description: KERI event message
                 properties:
                    pre:
                       type: string
                       description: qb64 identifier prefix of mailbox to stream
                    topics:
                       type: object
                       description: map of topic names to current message index for topic
                       properties:
                          /reply:
                             type: integer
                             default: 0
                          /replay:
                             type: integer
                             default: 0
                          /receipt:
                             type: integer
                             default: 0
                          /challenge:
                             type: integer
                             default: 0
                          /multisig:
                             type: integer
                             default: 0


        responses:
           200:
              content:
                 text/event-stream:
                    schema:
                       type: object
              description: Mailbox query response for server sent events
           204:
              description: KEL or EXN event accepted.
        """
        if req.method == "OPTIONS":
            rep.status = falcon.HTTP_200
            return

        rep.set_header('Cache-Control', "no-cache")
        rep.set_header('connection', "close")

        body = req.get_media()
        pre = body["pre"]
        topics = body["topics"]

        rep.set_header('Content-Type', "text/event-stream")
        rep.status = falcon.HTTP_200
        rep.stream = MailboxIterable(mbx=self.mbx, pre=pre, topics=topics)

    def on_get_mbx(self, req, rep):
        """
        Handles GET requests as a stream of SSE events
        Parameters:
              req (Request) Falcon HTTP request
              rep (Response) Falcon HTTP response
        ---
        summary:  Stream Server-Sent Events for KERI mailbox for identifier
        description:  Stream Server-Sent Events for KERI mailbox for identifier
        tags:
           - Mailbox
        parameters:
          - in: query
            name: pre
            schema:
              type: string
            required: true
            description: qb64 identifier prefix of mailbox to read
          - in: query
            name: topics
            schema:
               type: array
               items:
                  type: string
        responses:
           200:
              content:
                 text/event-stream:
                    schema:
                       type: object
              description: Mailbox query response for server sent events
           204:
              description: KEL or EXN event accepted.
        """
        pre = req.params["pre"]
        pt = req.params["topics"]

        rep.set_header('Cache-Control', "no-cache")
        rep.set_header('connection', "close")
        rep.set_header('Content-Type', "text/event-stream")

        topics = dict()
        if isinstance(pt, list):
            for t in pt:
                key, val = t.split("=")
                topics[key] = int(val)
        else:
            key, val = pt.split("=")
            topics[key] = int(val)

        rep.stream = MailboxIterable(mbx=self.mbx, pre=pre, topics=topics)


class MailboxIterable:

    TimeoutMBX = 300

    def __init__(self, mbx, pre, topics, retry=5000):
        self.mbx = mbx
        self.pre = pre
        self.topics = topics
        self.retry = retry

    def __iter__(self):
        self.start = self.end = time.perf_counter()
        return self

    def __next__(self):
        if self.end - self.start < self.TimeoutMBX:
            if self.start == self.end:
                self.end = time.perf_counter()
                return bytearray(f"retry: {self.retry}\n\n".encode("utf-8"))

            data = bytearray()
            for topic, idx in self.topics.items():
                key = self.pre + topic
                for fn, _, msg in self.mbx.cloneTopicIter(key, idx):
                    data.extend(bytearray("id: {}\nevent: {}\nretry: {}\ndata: ".format(fn, topic, self.retry).encode(
                        "utf-8")))
                    data.extend(msg)
                    data.extend(b'\n\n')
                    idx = idx + 1
                    self.start = time.perf_counter()

                self.topics[topic] = idx
            self.end = time.perf_counter()
            return data

        raise StopIteration


class QryRpyMailboxIterable:

    def __init__(self, cues, mbx, said, retry=5000):
        self.mbx = mbx
        self.retry = retry
        self.cues = cues
        self.said = said
        self.iter = None

    def __iter__(self):
        return self

    def __next__(self):
        if self.iter is None:
            if self.cues:
                cue = self.cues.popleft()
                serder = cue["serder"]
                if serder.said == self.said:
                    kin = cue["kin"]
                    if kin == "stream":
                        self.iter = iter(MailboxIterable(mbx=self.mbx, pre=cue["pre"], topics=cue["topics"],
                                                         retry=self.retry))
                else:
                    self.cues.append(cue)

            return b''

        return next(self.iter)

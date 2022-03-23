# -*- encoding: utf-8 -*-
"""
KERI
keri.app.indirecting module

simple indirect mode demo support classes
"""
import json
import time

import falcon
from hio.base import doing
from hio.core import http
from hio.core.tcp import serving
from hio.help import decking
from orderedset import OrderedSet as oset

from . import directing, storing, httping, forwarding, agenting
from .cli.common import oobiing
from .. import help
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
    doers = []

    # make hab
    hab = hby.makeHab(name=alias, transferable=False)

    reger = viring.Reger(name=hab.name, db=hab.db, temp=False)
    verfer = verifying.Verifier(hby=hby, reger=reger)

    mbx = mbx if mbx is not None else storing.Mailboxer(name=alias, temp=hby.temp)
    forwarder = forwarding.ForwardHandler(hby=hby, mbx=mbx)
    exchanger = exchanging.Exchanger(hby=hby, handlers=[forwarder])
    app = falcon.App(cors_enable=True)
    ending.loadEnds(app=app, hby=hby)

    rep = storing.Respondant(hby=hby, mbx=mbx)
    httpEnd = HttpEnd(db=hab.db, app=app, rep=rep, verifier=verfer, mbx=mbx, exchanger=exchanger)
    app.add_route("/", httpEnd)

    server = http.Server(port=httpPort, app=app)
    httpServerDoer = http.ServerDoer(server=server)

    # setup doers
    regDoer = basing.BaserDoer(baser=verfer.reger)

    server = serving.Server(host="", port=tcpPort)
    serverDoer = serving.ServerDoer(server=server)

    directant = directing.Directant(hab=hab, server=server, verifier=verfer)
    obl = oobiing.OobiLoader(db=hby.db, auto=True)

    witStart = WitnessStart(name=alias, hab=hab)

    doers.extend([regDoer, exchanger, directant, serverDoer, httpServerDoer, httpEnd, rep, obl, witStart])

    return doers


class WitnessStart (doing.Doer):
    """ Doer to print witness prefix after initialization

    """
    def __init__(self, name, hab, **opts):
        self.hab = hab
        self.name = name
        super().__init__(**opts)

    def do(self,  tymth=None, tock=0.0, **opts):
        """ Prints witness name and prefix

        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock (float): injected initial tock value

        """
        while not self.hab.inited:
            yield self.tock

        print("Witness", self.name, ":", self.hab.pre)


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

    def msgDo(self, tymth=None, tock=0.0, **opts):
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
            opts is dict of injected optional additional parameters


        Usage:
            add result of doify on this method to doers list
        """
        yield  # enter context
        if self.parser.ims:
            logger.info("Client %s received:\n%s\n...\n", self.hab.pre, self.parser.ims[:1024])
        done = yield from self.parser.parsator()  # process messages continuously
        return done  # should nover get here except forced close

    def cueDo(self, tymth=None, tock=0.0, **opts):
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
            opts is dict of injected optional additional parameters

        Usage:
            add result of doify on this method to doers list
        """
        yield  # enter context
        while True:
            for msg in self.hab.processCuesIter(self.kevery.cues):
                self.sendMessage(msg, label="chit or receipt")
                yield  # throttle just do one cue at a time
            yield

    def escrowDo(self, tymth=None, tock=0.0, **opts):
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
            opts is dict of injected optional additional parameters

        Usage:
            add result of doify on this method to doers list
        """
        yield  # enter context
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
        self.rvy = rvy if rvy is not None else routing.Revery(db=self.hby.db, rtr=self.rtr,
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
                                     rvy=self.rvy)

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

    def msgDo(self, tymth=None, tock=0.0, **opts):
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
            opts is dict of injected optional additional parameters

        Usage:
            add result of doify on this method to doers list
        """
        yield  # enter context
        done = yield from self.parser.parsator()  # process messages continuously
        return done  # should nover get here except forced close

    def escrowDo(self, tymth=None, tock=0.0, **opts):
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
            opts is dict of injected optional additional parameters

        Usage:
            add result of doify on this method to doers list
        """
        yield  # enter context
        while True:
            self.kvy.processEscrows()
            self.rvy.processEscrowReply()
            if self.tevery is not None:
                self.tevery.processEscrows()

            yield

    def exchangerDo(self, tymth=None, tock=0.0, **opts):
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
            opts is dict of injected optional additional parameters

        Usage:
            add result of doify on this method to doers list
        """
        yield  # enter context
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
        for poller in self.pollers:  # get responses from all behaviors
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

    def eventDo(self, tymth=None, tock=0.0, **opts):
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
                while client.events:
                    evt = client.events.popleft()
                    if "id" not in evt or "data" not in evt or "name" not in evt:
                        print(f"bad mailbox event: {evt}")
                        continue

                    idx = evt["id"]
                    msg = evt["data"]
                    tpc = evt["name"]

                    if not idx or not msg or not tpc:
                        print(f"bad mailbox event: {evt}")
                        continue

                    self.msgs.append(msg.encode("utf=8"))
                    yield self.tock

                    witrec.topics[tpc] = int(idx)
                    self.times[tpc] = helping.nowUTC()
                    self.hab.db.tops.pin((self.pre, self.witness), witrec)

                yield 0.25


class HttpEnd(doing.DoDoer):
    """
    HTTP handler that accepts and KERI events POSTed as the body of a request with all attachments to
    the message as a CESR attachment HTTP header.  KEL Messages are processed and added to the database
    of the provided Habitat.

    This also handles `req`, `exn` and `tel` messages that respond with a KEL replay.
    """

    TimeoutQNF = 30
    TimeoutMBX = 120

    def __init__(self, db: basing.Baser, rep, verifier=None, exchanger=None, mbx=None, **kwa):
        """
        Create the KEL HTTP server from the Habitat with an optional Falcon App to
        register the routes with.

        Parameters
             db (Baser): the database in which to store any provided KEL
             mbx (Mailboxer): Mailbox storage

        """
        self.db = db
        self.rep = rep
        self.mbx = mbx

        self.verifier = verifier
        self.exc = exchanger
        self.kvycues = decking.Deck()
        self.qrycues = decking.Deck()
        self.tvycues = decking.Deck()

        self.rxbs = bytearray()

        self.rvy = routing.Revery(db=self.db)
        self.kevery = eventing.Kevery(db=self.db,
                                      lax=True,
                                      local=False,
                                      rvy=self.rvy)

        doers = [doing.doify(self.msgDo), doing.doify(self.cueDo), doing.doify(self.escrowDo)]

        if self.verifier is not None:
            self.tvy = Tevery(reger=self.verifier.reger,
                              db=self.db,
                              local=False)
            doers.extend([doing.doify(self.verifierDo)])
        else:
            self.tvy = None

        if self.exc is not None:
            doers.extend([doing.doify(self.exchangerDo)])

        self.kevery.registerReplyRoutes(router=self.rvy.rtr)

        self.parser = parsing.Parser(ims=self.rxbs,
                                     framed=True,
                                     kvy=self.kevery,
                                     tvy=self.tvy,
                                     exc=self.exc,
                                     rvy=self.rvy)

        super(HttpEnd, self).__init__(doers=doers, **kwa)

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
        rep.set_header('Connection', "keep-alive")

        cr = httping.parseCesrHttpRequest(req=req)
        serder = eventing.Serder(ked=cr.payload, kind=eventing.Serials.json)
        msg = bytearray(serder.raw)
        msg.extend(cr.attachments.encode("utf-8"))

        self.rxbs.extend(msg)

        ilk = serder.ked["t"]
        if ilk in (Ilks.icp, Ilks.rot, Ilks.ixn, Ilks.dip, Ilks.drt):
            rep.set_header('Content-Type', "application/json")
            rep.status = falcon.HTTP_204
        elif ilk in (Ilks.vcp, Ilks.vrt, Ilks.iss, Ilks.rev, Ilks.bis, Ilks.brv):
            rep.set_header('Content-Type', "application/json")
            rep.status = falcon.HTTP_204
        elif ilk in (Ilks.qry, ):
            rep.set_header('Content-Type', "text/event-stream")
            rep.status = falcon.HTTP_200
            rep.stream = self.qryrep(said=serder.said)

    def qryrep(self, said):
        """ Iterator to respond to mailbox queries

        Parameters:
            said (str): qb64 self addressing identifier of query message to track
        """

        while True:
            if self.qrycues:
                cue = self.qrycues.popleft()
                serder = cue["serder"]
                if serder.said == said:
                    kin = cue["kin"]
                    if kin == "stream":
                        pre = cue["pre"]
                        topics = cue["topics"]

                        yield from self.mailboxGenerator(pre=pre, topics=topics)
                        return
                else:
                    self.qrycues.append(cue)
            yield b''

    def kvyrep(self, said):
        """ Iterator to respond to KEL events

        Parameters:
            said (str): qb64 self addressing identifier of query message to track
        """
        while True:
            if self.kvycues:
                cue = self.kvycues.popleft()
                serder = cue["serder"]
                if said == serder.said:
                    yield json.dumps(cue).encode("utf-8")
                    return
                else:
                    self.kvycues.append(cue)
            yield b''

    def tvyrep(self, said):
        """ Iterator to respond to TEL events

        Parameters:
            said (str): qb64 self addressing identifier of query message to track
        """
        while True:
            if self.tvycues:
                cue = self.tvycues.popleft()
                serder = cue["serder"]
                if serder.said == said:
                    yield json.dumps(cue).encode("utf-8")
                    return
                else:
                    self.tvycues.append(cue)
            yield b''

    def mailboxGenerator(self, pre=None, topics=None):
        """

        Parameters:
            pre (str): qb64 identifier prefix of the mailbox to read
            topics (dict): list of topics to read messages from as strings

        """
        start = end = time.perf_counter()
        while end - start < self.TimeoutMBX:
            for topic, idx in topics.items():
                key = pre + topic
                for fn, _, msg in self.mbx.cloneTopicIter(key, idx):
                    data = bytearray("id: {}\nevent: {}\ndata: ".format(fn, topic).encode("utf-8"))
                    data.extend(msg)
                    data.extend(b'\n\n')
                    idx = idx + 1
                    yield data
                    start = time.perf_counter()
                topics[topic] = idx
            end = time.perf_counter()
            yield b''

        yield bytearray(f"event: close\ndata: test\nretry: 2000\n\n".encode("utf-8"))
        return b''

    def msgDo(self, tymth=None, tock=0.0, **opts):
        """
        Returns doifiable Doist compatibile generator method (doer dog) to process
            incoming message stream of .kevery

        Usage:
            add result of doify on this method to doers list
        """
        if self.parser.ims:
            logger.info("Client %s received:\n%s\n...\n", self.kevery, self.parser.ims[:1024])
        done = yield from self.parser.parsator()  # process messages continuously
        return done  # should nover get here except forced close

    def cueDo(self, tymth=None, tock=0.0, **opts):
        """
        Returns doifiable Doist compatibile generator method (doer dog) to process
            .kever.cues cues and pass them on to the HTTPResponant

        Usage:
            add result of doify on this method to doers list
        """
        while True:
            while self.kevery.cues:  # iteratively process each cue in cues
                cue = self.kevery.cues.popleft()
                cueKin = cue["kin"]
                if cueKin == "stream":
                    self.qrycues.append(cue)
                else:
                    self.kvycues.append(cue)
                    self.rep.cues.append(cue)
                yield  # throttle just do one cue at a time
            yield

    def exchangerDo(self, tymth=None, tock=0.0, **opts):
        """
        Returns doifiable Doist compatibile generator method (doer dog) to process
            .exc responses and pass them on to the HTTPRespondant

        Usage:
            add result of doify on this method to doers list
        """
        while True:
            for rep in self.exc.processResponseIter():
                self.rep.reps.append(rep)
                yield  # throttle just do one cue at a time
            yield

    def verifierDo(self, tymth=None, tock=0.0, **opts):
        """
         Returns doifiable Doist compatibile generator method (doer dog) to process
            .tevery.cues deque

        Usage:
            add to doers list
        """
        yield  # enter context
        while True:
            while self.tvy.cues:  # iteratively process each cue in cues
                cue = self.tvy.cues.popleft()
                self.tvycues.append(cue)
                self.rep.cues.append(cue)
                yield  # throttle just do one cue at a time
            yield

    def escrowDo(self, tymth=None, tock=0.0, **opts):
        """
         Returns doifiable Doist compatibile generator method (doer dog) to process
            .kevery and .tevery escrows.

        Usage:
            add result of doify on this method to doers list
        """
        yield  # enter context
        while True:
            self.kevery.processEscrows()
            if self.tvy is not None:
                self.tvy.processEscrows()

            yield

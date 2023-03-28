# -*- encoding: utf-8 -*-
"""
KERI
keri.app.backering module

class to support registrar backers
"""

import falcon
import time

from hio.base import doing
from hio.core import http
from hio.core.tcp import serving
from hio.help import decking

import keri.app.oobiing
from . import directing, storing, httping, forwarding, oobiing
from .. import help
from ..core import eventing, parsing, routing
from ..core.coring import Ilks
from ..db import basing
from ..end import ending
from ..peer import exchanging
from ..vdr import verifying, viring
from ..vdr.eventing import Tevery
from keri.core import coring

logger = help.ogler.getLogger()


def setupBacker(hby, alias="backer", mbx=None, tcpPort=5631, httpPort=5632, ledger=None):
    """
    Setup Registrar Backer controller and doers

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
    exchanger = exchanging.Exchanger(db=hby.db, handlers=[forwarder])
    clienter = httping.Clienter()
    oobiery = keri.app.oobiing.Oobiery(hby=hby, clienter=clienter)

    app = falcon.App(cors_enable=True)
    ending.loadEnds(app=app, hby=hby, default=hab.pre)
    oobiRes = oobiing.loadEnds(app=app, hby=hby, prefix="/ext")
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

    httpEnd = HttpEnd(rxbs=parser.ims, mbx=mbx, hab=hab, ledger=ledger)
    app.add_route("/", httpEnd)

    server = http.Server(port=httpPort, app=app)
    httpServerDoer = http.ServerDoer(server=server)

    # setup doers
    regDoer = basing.BaserDoer(baser=verfer.reger)

    server = serving.Server(host="", port=tcpPort)
    serverDoer = serving.ServerDoer(server=server)

    directant = directing.Directant(hab=hab, server=server, verifier=verfer)

    witStart = BackerStart(hab=hab, parser=parser, cues=cues,
                            kvy=kvy, tvy=tvy, rvy=rvy, exc=exchanger, replies=rep.reps,
                            responses=rep.cues, queries=httpEnd.qrycues)

    doers.extend(oobiRes)
    doers.extend([regDoer, exchanger, directant, serverDoer, httpServerDoer, rep, witStart, *oobiery.doers])

    return doers

class BackerStart(doing.DoDoer):
    """ Doer to print backer prefix after initialization

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
        """ Prints backer name and prefix

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

        print("Backer", self.hab.name, "ready", self.hab.pre)

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

class HttpEnd:
    """
    HTTP handler that accepts and KERI events POSTed as the body of a request with all attachments to
    the message as a CESR attachment HTTP header.  KEL Messages are processed and added to the database
    of the provided Habitat.

    This also handles `req`, `exn` and `tel` messages that respond with a KEL replay.
    """

    TimeoutQNF = 30
    TimeoutMBX = 5

    def __init__(self, rxbs=None, mbx=None, qrycues=None, hab=None, ledger=None):
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
        self.hab = hab
        self.ledger = ledger

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
            rep.stream = QryRpyMailboxIterable(mbx=self.mbx, cues=self.qrycues, said=serder.said, hab=self.hab, ledger=self.ledger)
        
        print("Post msg received of type", ilk)

class QryRpyMailboxIterable:

    def __init__(self, cues, mbx, said, retry=5000, hab=None, ledger=None):
        self.mbx = mbx
        self.retry = retry
        self.cues = cues
        self.said = said
        self.iter = None
        self.hab = hab
        self.ledger = ledger

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
                                                         retry=self.retry, hab=self.hab, ledger=self.ledger))
                else:
                    self.cues.append(cue)
            return b''

        return next(self.iter)

class MailboxIterable:
    TimeoutMBX = 30000000

    def __init__(self, mbx, pre, topics, retry=5000, hab=None, ledger=None):
        self.mbx = mbx
        self.pre = pre
        self.topics = topics
        self.retry = retry
        self.hab = hab
        self.ledger = ledger

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
                    data.extend(bytearray("id: {}\nevent: {}\nretry: {}\ndata: ".format(fn, topic, self.retry)
                                          .encode("utf-8")))
                    data.extend(msg)
                    data.extend(b'\n\n')
                    idx = idx + 1
                    self.start = time.perf_counter()

                    if self.ledger and topic == "/receipt":
                        try:
                            serder = coring.Serder(raw=msg)
                            event = eventing.loadEvent(self.hab.db, self.pre, serder.saidb)
                            self.ledger.publishEvent(event)
                            
                        except Exception as e:
                            logger.error(f"ledger error: {e}")
                self.topics[topic] = idx
            self.end = time.perf_counter()
            return data

        raise StopIteration

# -*- encoding: utf-8 -*-
"""
KERI
keri.app.indirecting module

simple indirect mode demo support classes
"""

import falcon
from hio.base import doing
from hio.core import http
from hio.core.tcp import serving
from hio.help import decking

from . import habbing, keeping, directing, storing, httping
from .. import help
from ..app import obtaining
from ..core import eventing, parsing
from ..db import basing
from ..peer import exchanging
from ..vdr import verifying
from ..vdr.eventing import Tevery

logger = help.ogler.getLogger()


def setupWitness(name="witness", hab=None, mbx=None, temp=False, tcpPort=5631, httpPort=5632):
    """
    """
    doers = []
    # setup habitat
    if hab is None:
        # setup databases  for dependency injection
        ks = keeping.Keeper(name=name, temp=temp)  # default is to not reopen
        ksDoer = keeping.KeeperDoer(keeper=ks)  # doer do reopens if not opened and closes
        db = basing.Baser(name=name, temp=temp, reload=True)  # default is to not reopen
        dbDoer = basing.BaserDoer(baser=db)  # doer do reopens if not opened and closes

        hab = habbing.Habitat(name=name, ks=ks, db=db, temp=temp, create=True, transferable=False)
        habDoer = habbing.HabitatDoer(habitat=hab)  # setup doer
        doers.extend([ksDoer, dbDoer, habDoer])

    print("Witness", name, ":", hab.pre)
    verfer = verifying.Verifier(name=name, hab=hab)
    app = falcon.App(cors_enable=True)

    mbx = mbx if mbx is not None else storing.Mailboxer(name=name, temp=temp)

    rep = storing.Respondant(hab=hab, mbx=mbx)
    httpHandler = HttpMessageHandler(hab=hab, app=app, rep=rep, verifier=verfer, mbx=mbx)
    mbxer = storing.MailboxServer(app=app, hab=hab, mbx=mbx)

    server = http.Server(port=httpPort, app=app)
    httpServerDoer = http.ServerDoer(server=server)

    # setup doers
    regDoer = basing.BaserDoer(baser=verfer.reger)

    server = serving.Server(host="", port=tcpPort)
    serverDoer = serving.ServerDoer(server=server)

    directant = directing.Directant(hab=hab, server=server, verifier=verfer)

    doers.extend([regDoer, directant, serverDoer, mbxer, httpServerDoer, httpHandler, rep])

    return doers


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

    def __init__(self, hab, topics, verifier=None, kvy=None, exc=None, rep=None, cues=None, **kwa):
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
        self.verifier = verifier
        self.exchanger = exc
        self.rep = rep
        self.topics = topics
        self.pollers = []
        self.cues = cues if cues is not None else decking.Deck()

        self.ims = bytearray()

        doers = []
        doers.extend([doing.doify(self.pollDo),
                      doing.doify(self.msgDo),
                      doing.doify(self.cueDo),
                      doing.doify(self.escrowDo)])

        #  neeeds unique kevery with ims per remoter connnection
        self.kvy = kvy if kvy is not None else eventing.Kevery(db=self.hab.db,
                                                               lax=False,
                                                               local=False,
                                                               direct=False)

        if self.verifier is not None:
            self.tevery = Tevery(reger=self.verifier.reger,
                                 db=self.hab.db,
                                 regk=None, local=False)
        else:
            self.tevery = None

        if self.exchanger is not None:
            doers.extend([doing.doify(self.exchangerDo)])

        self.parser = parsing.Parser(ims=self.ims,
                                     framed=True,
                                     kvy=self.kvy,
                                     tvy=self.tevery,
                                     exc=self.exchanger)

        super(MailboxDirector, self).__init__(doers=doers, **kwa)

    def wind(self, tymth):
        """
        Inject new tymist.tymth as new ._tymth. Changes tymist.tyme base.
        Updates winds .tymer .tymth
        """
        super(MailboxDirector, self).wind(tymth)

    def pollDo(self, tymth=None, tock=0.0, **opts):
        """
        Returns:
           doifiable Doist compatible generator method

        Usage:
            add result of doify on this method to doers list
        """
        yield  # enter context

        wits = self.hab.kever.wits

        group = self.hab.group()
        for wit in wits:
            poller = Poller(hab=self.hab, topics=self.topics, witness=wit)
            self.pollers.append(poller)
            self.extend([poller])

            if group is not None:
                poller = GroupPoller(hab=self.hab, group=group, topics=self.topics, witness=wit)
                self.pollers.append(poller)
                self.extend([poller])

            _ = (yield self.tock)

        while True:
            for msg in self.processPollIter():
                self.ims.extend(msg)
                _ = (yield self.tock)
            _ = (yield self.tock)

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
            while self.kvy.cues:
                cue = self.kvy.cues.popleft()
                self.cues.append(cue)
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
            self.kvy.processEscrows()
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
            for rep in self.exchanger.processResponseIter():
                self.rep.reps.append(rep)
                yield  # throttle just do one cue at a time
            yield


class Poller(doing.DoDoer):
    """
    Polls remote SSE endpoint for event that are KERI messages to be processed

    """

    def __init__(self, hab, witness, topics, msgs=None, **kwa):
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
        self.witness = witness
        self.topics = topics
        self.msgs = None if msgs is not None else decking.Deck()
        doers = [doing.doify(self.eventDo)]

        super(Poller, self).__init__(doers=doers, **kwa)

    def eventDo(self, tymth=None, tock=0.0, **opts):
        """
        Returns:
           doifiable Doist compatible generator method

        Usage:
            add result of doify on this method to doers list
        """
        loc = obtaining.getwitnessbyprefix(self.witness)

        client = http.clienting.Client(hostname=loc.ip4, port=loc.http)
        clientDoer = http.clienting.ClientDoer(client=client)
        self.extend([clientDoer])

        witrec = self.hab.db.tops.get(self.witness)
        if witrec is None:
            witrec = basing.TopicsRecord(topics=dict())

        topics = dict()
        q = dict(pre=self.hab.pre, topics=topics)
        for topic in self.topics:
            if topic in witrec.topics:
                topics[topic] = witrec.topics[topic] + 1
            else:
                topics[topic] = 0

        msg = self.hab.query(pre=self.hab.pre, res="mbx", query=q)
        httping.createCESRRequest(msg, client)

        while client.requests:
            yield self.tock

        while True:
            while client.events:
                evt = client.events.popleft()
                idx = evt["id"]
                msg = evt["data"]
                tpc = evt["name"]
                # ser = coring.Serder(raw=msg.encode("utf-8"))

                self.msgs.append(msg.encode("utf=8"))

                witrec.topics[tpc] = int(idx)
                self.hab.db.tops.pin(self.witness, witrec)
                yield
            yield


class GroupPoller(doing.DoDoer):
    """
    Polls remote SSE endpoint for event that are KERI messages to be processed for a group identifier
    if one exists

    """

    def __init__(self, hab, group, witness, topics, msgs=None, **kwa):
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
        self.group = group
        self.witness = witness
        self.topics = topics
        self.msgs = None if msgs is not None else decking.Deck()
        doers = [doing.doify(self.eventDo)]

        super(GroupPoller, self).__init__(doers=doers, **kwa)

    def eventDo(self, tymth=None, tock=0.0, **opts):
        """
        Returns:
           doifiable Doist compatible generator method

        Usage:
            add result of doify on this method to doers list
        """
        loc = obtaining.getwitnessbyprefix(self.witness)

        client = http.clienting.Client(hostname=loc.ip4, port=loc.http)
        clientDoer = http.clienting.ClientDoer(client=client)
        self.extend([clientDoer])

        tkey = "{}.{}".format(self.group.gid, self.witness)
        witrec = self.hab.db.tops.get(tkey)
        if witrec is None:
            witrec = basing.TopicsRecord(topics=dict())

        topics = dict()
        q = dict(pre=self.group.gid, topics=topics)
        for topic in self.topics:
            if topic in witrec.topics:
                topics[topic] = witrec.topics[topic] + 1
            else:
                topics[topic] = 0

        msg = self.hab.query(pre=self.group.gid, res="mbx", query=q)
        httping.createCESRRequest(msg, client)

        while client.requests:
            yield self.tock

        while True:
            while client.events:
                evt = client.events.popleft()
                idx = evt["id"]
                msg = evt["data"]
                tpc = evt["name"]
                # ser = coring.Serder(raw=msg.encode("utf-8"))

                self.msgs.append(msg.encode("utf=8"))

                witrec.topics[tpc] = int(idx)
                self.hab.db.tops.pin(tkey, witrec)
                yield
            yield


class HttpMessageHandler(doing.DoDoer):
    """
    HTTP handler that accepts and KERI events POSTed as the body of a request with all attachments to
    the message as a CESR attachment HTTP header.  KEL Messages are processed and added to the database
    of the provided Habitat.

    This also handles `req`, `exn` and `tel` messages that respond with a KEL replay.
    """

    def __init__(self, hab: habbing.Habitat, rep, verifier=None, exchanger=None, mbx=None, app=None, **kwa):
        """
        Create the KEL HTTP server from the Habitat with an optional Falcon App to
        register the routes with.

        Parameters
             hab (Habitat): the Habitat in which to store any provided KEL
             app (Falcon): optional Falcon app in which to register the KEL routes.

        """
        self.hab = hab
        self.rep = rep
        self.verifier = verifier
        self.exc = exchanger
        self.mbx = mbx

        self.rxbs = bytearray()

        self.app = app if app is not None else falcon.App(cors_enable=True)

        self.app.add_route("/kel", self)
        self.app.add_route("/req/logs", self, suffix="req")
        self.app.add_route("/req/ksn", self, suffix="req")

        self.kevery = eventing.Kevery(db=self.hab.db,
                                      lax=False,
                                      local=False)

        doers = [doing.doify(self.msgDo), doing.doify(self.cueDo), doing.doify(self.escrowDo)]

        if self.verifier is not None:
            self.app.add_route("/tel", self)
            self.app.add_route("/req/tels", self, suffix="req")
            self.tvy = Tevery(reger=self.verifier.reger,
                              db=self.hab.db,
                              regk=None, local=False)
            doers.extend([doing.doify(self.verifierDo)])
        else:
            self.tvy = None

        if self.exc is not None:
            self.app.add_sink(prefix="/exn", sink=self.on_post_exn)
            doers.extend([doing.doify(self.exchangerDo)])

        if self.mbx is not None:
            self.app.add_sink(prefix="/fwd", sink=self.on_post_fwd)

        self.parser = parsing.Parser(ims=self.rxbs,
                                     framed=True,
                                     kvy=self.kevery,
                                     tvy=self.tvy,
                                     exc=self.exc)

        super(HttpMessageHandler, self).__init__(doers=doers, **kwa)

    def on_post(self, req, rep):
        """
        Handles POST for KERI event messages.

        Parameters:
              req (Request) Falcon HTTP request
              rep (Response) Falcon HTTP response

        """
        if req.method == "OPTIONS":
            rep.status = falcon.HTTP_200
            return

        cr = httping.parseCesrHttpRequest(req=req)
        self.handle(cr, rep)

    def on_post_req(self, req, rep):
        """
        Handles POST for `req` messages.

        Parameters:
              req (Request) Falcon HTTP request
              rep (Response) Falcon HTTP response

        """
        if req.method == "OPTIONS":
            rep.status = falcon.HTTP_200
            return

        cr = httping.parseCesrHttpRequest(req=req, prefix="/req/")
        self.handle(cr, rep)

    def on_post_exn(self, req, rep):
        """
        Handles POST for `exn` messages
        Parameters:
              req (Request) Falcon HTTP request
              rep (Response) Falcon HTTP response

        """
        if req.method == "OPTIONS":
            rep.status = falcon.HTTP_200
            return

        cr = httping.parseCesrHttpRequest(req=req, prefix="/exn")

        serder = exchanging.exchange(route=cr.resource, date=cr.date, payload=cr.payload)
        msg = bytearray(serder.raw)
        msg.extend(cr.attachments.encode("utf-8"))

        self.rxbs.extend(msg)

        rep.status = falcon.HTTP_202  # This is the default status

    def on_post_fwd(self, req, rep):
        """
        Handles POST for `fwd` messages.  Parses out destination from resource and stores in mailbox
        Parameters:
              req (Request) Falcon HTTP request
              rep (Response) Falcon HTTP response

        """
        if req.method == "OPTIONS":
            rep.status = falcon.HTTP_200
            return

        cr = httping.parseCesrHttpRequest(req=req, prefix="/fwd/")

        # TODO: regenerate the fwd message and verify the SAID signature on it.
        serder = eventing.Serder(ked=cr.payload, kind=eventing.Serials.json)

        msg = bytearray(serder.raw)
        msg.extend(cr.attachments.encode("utf-8"))

        self.mbx.storeMsg(topic=cr.resource, msg=msg)

        rep.status = falcon.HTTP_202  # This is the default status

    def handle(self, cr, rep):
        """
        Handles POST requests that conform to CESR HTTP Requests.

        Converts the requests into KERI event messages and passes them on to
        the Parser to be parsed and processed by either the Kevery, Tevery or
        Exchanger.

        Parameters:
              cr (Request) Parsed CESR request
              rep (Response) Falcon HTTP response
              cr (CesrRequest) Result of converting HTTP Request to a CESR message

        """

        serder = eventing.Serder(ked=cr.payload, kind=eventing.Serials.json)
        msg = bytearray(serder.raw)
        msg.extend(cr.attachments.encode("utf-8"))

        self.rxbs.extend(msg)

        rep.status = falcon.HTTP_202  # This is the default status

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

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

from . import habbing, keeping, directing
from .. import help
from ..app import obtaining
from ..core import eventing, parsing, coring
from ..db import basing
from ..peer import exchanging, httping
from ..vdr import verifying
from ..vdr.eventing import Tevery

logger = help.ogler.getLogger()


def setupWitness(name="witness", hab=None, temp=False, tcpPort=5631, httpPort=5632):
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

    verfer = verifying.Verifier(name=name, hab=hab)
    app = falcon.App(cors_enable=True)

    exchanger = exchanging.Exchanger(hab=hab, handlers=[])

    mbx = exchanging.Mailboxer(name=name)
    storeExchanger = exchanging.StoreExchanger(hab=hab, mbx=mbx, exc=exchanger)

    repServer = httping.Respondant(hab=hab, mbx=mbx)
    exnServer = httping.AgentExnServer(exc=storeExchanger, app=app, rep=repServer)
    kelHandler = WitnessKelHandler(hab=hab, app=app, mbx=mbx)
    mbxer = httping.MailboxServer(app=app, hab=hab, mbx=mbx)

    server = http.Server(port=httpPort, app=app)
    httpServerDoer = http.ServerDoer(server=server)

    # setup doers
    regDoer = basing.BaserDoer(baser=verfer.reger)

    server = serving.Server(host="", port=tcpPort)
    serverDoer = serving.ServerDoer(server=server)

    directant = directing.Directant(hab=hab, server=server, verifier=verfer, exc=storeExchanger)

    doers.extend([regDoer, directant, serverDoer, mbxer, kelHandler, httpServerDoer, exnServer, repServer])

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

    def __init__(self, hab, verifier=None, exc=None, rep=None, **kwa):
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
        self.pollers = []

        self.ims = bytearray()

        doers = []
        doers.extend([doing.doify(self.pollDo),
                      doing.doify(self.msgDo),
                      doing.doify(self.cueDo),
                      doing.doify(self.escrowDo)])

        #  neeeds unique kevery with ims per remoter connnection
        self.kevery = eventing.Kevery(db=self.hab.db,
                                      lax=False,
                                      local=False)

        if self.verifier is not None:
            self.tevery = Tevery(tevers=self.verifier.tevers,
                                 reger=self.verifier.reger,
                                 db=self.hab.db,
                                 regk=None, local=False)
            doers.extend([doing.doify(self.verifierDo)])
        else:
            self.tevery = None

        if self.exchanger is not None:
            doers.extend([doing.doify(self.exchangerDo)])

        self.parser = parsing.Parser(ims=self.ims,
                                     framed=True,
                                     kvy=self.kevery,
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

        for wit in wits:
            poller = Poller(hab=self.hab, witness=wit)
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
        if self.parser.ims:
            logger.info("Server %s: %s received:\n%s\n...\n", self.hab.name,
                        self.hab.pre, self.parser.ims[:1024])
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
                # self.sendMessage(msg, label="chit or receipt or replay")
                print(msg)
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



    def verifierDo(self, tymth=None, tock=0.0, **opts):
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
                self.rep.msgs.append(rep)
                yield  # throttle just do one cue at a time
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
                # self.sendMessage(msg, label="response")
                print(rep["msg"])
                yield  # throttle just do one cue at a time
            yield



class Poller(doing.DoDoer):
    """
    Polls remote SSE endpoint for event that are KERI messages to be processed

    """

    def __init__(self, hab, witness, msgs=None, **kwa):
        """

        Parameters:
            client: http client from which to poll for SSE KERI event messages
        """

        self.hab = hab
        self.witness = witness
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

        witrec = self.hab.db.wits.get(self.witness)
        if witrec is None:
            witrec = basing.WitnessRecord(idx=0)
        else:
            witrec.idx += 1

        msg = self.hab.query(pre=self.hab.pre, res="/mbx", sn=witrec.idx)

        httping.createCESRRequest(msg, client)

        while client.requests:
            yield self.tock

        while True:
            while client.events:
                evt = client.events.popleft()
                idx = evt["id"]
                msg = evt["data"]
                ser = coring.Serder(raw=msg.encode("utf-8"))
                self.msgs.append(msg.encode("utf=8"))

                witrec.idx = int(idx)
                self.hab.db.wits.pin(self.witness, witrec)
                yield
            yield


class WitnessKelHandler(doing.DoDoer):
    """
    Witness HTTP handler that accepts KEL events POSTed as the body of a request with all attachments to
    the message as a CESR attachment HTTP header.  Messages are processed and added to the database of the provided
    Habitat.

    This also handles `req` messages that respond with a KEL replay.


    """

    def __init__(self, hab: habbing.Habitat, mbx=None, app=None, **kwa):
        """
        Create the KEL HTTP server from the Habitat with an optional Falcon App to
        register the routes with.

        Parameters
             hab (Habitat): the Habitat in which to store any provided KEL
             app (Falcon): optional Falcon app in which to register the KEL routes.

        """
        self.hab = hab
        self.mbx = mbx if mbx is not None else exchanging.Mailboxer(name=hab.name)
        self.rxbs = bytearray()

        self.app = app if app is not None else falcon.App(cors_enable=True)

        self.app.add_route("/kel", self)
        self.app.add_route("/tel", self)
        self.app.add_route("/req/logs", self)
        self.app.add_route("/req/tels", self)

        self.kevery = eventing.Kevery(db=self.hab.db,
                                      lax=False,
                                      local=False)

        self.parser = parsing.Parser(ims=self.rxbs,
                                     framed=True,
                                     kvy=self.kevery)

        doers = [doing.doify(self.msgDo), doing.doify(self.cueDo)]

        super(WitnessKelHandler, self).__init__(doers=doers, **kwa)


    def on_post(self, req, rep):
        """
        Handles POST requests

        Parameters:
              req (Request) Falcon HTTP request
              rep (Response) Falcon HTTP response

        """

        cr = httping.parseCesrHttpRequest(req=req)

        serder = eventing.Serder(ked=cr.payload, kind=eventing.Serials.json)
        msg = bytearray(serder.raw)
        msg.extend(cr.attachments.encode("utf-8"))

        self.rxbs.extend(msg)

        rep.status = falcon.HTTP_202  # This is the default status


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
        if self.parser.ims:
            logger.info("Client %s received:\n%s\n...\n", self.kevery, self.parser.ims[:1024])
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
            while self.kevery.cues:  # iteratively process each cue in cues
                msg = bytearray()
                cue = self.kevery.cues.popleft()
                cueKin = cue["kin"]  # type or kind of cue

                if cueKin in ("receipt",):  # cue to receipt a received event from other pre
                    serder = cue["serder"]  # Serder of received event for other pre
                    msg.extend(self.hab.receipt(serder))

                    self.mbx.storeMsg(dest=serder.preb, msg=msg)
                elif cueKin in ("replay",):
                    dest = cue["dest"]
                    msgs = cue["msgs"]
                    self.mbx.storeMsg(dest=dest, msg=msgs)

                yield self.tock

            yield self.tock

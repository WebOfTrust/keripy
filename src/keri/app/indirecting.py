# -*- encoding: utf-8 -*-
"""
KERI
keri.app.indirecting module

simple indirect mode demo support classes
"""
import datetime
import platform
import falcon
import time
import sys
import traceback
from ordered_set import OrderedSet as oset

from hio.base import doing
from hio.core import http, tcp
from hio.core.tcp import serving
from hio.help import decking, ogler

from ..kering import (Vrsn_1_0, Roles, Ilks, Kinds,
                      MissingEntryError)
from ..recording import TopicsRecord
from ..core import (Kevery, parsing, routing, coring, serdering,
                    Counter, receipt, Codens)
from ..db import BaserDoer
from ..end import loadEndingEnds
from ..help import nowUTC
from ..peer import Exchanger

from .habbing import GroupHab
from .directing import Directant
from .storing import Mailboxer, Respondant
from .httping import Clienter, createCESRRequest, parseCesrHttpRequest, CESR_CONTENT_TYPE
from .forwarding import ForwardHandler
from .agenting import httpClient
from .oobiing import Oobiery, loadOobiingEnds

logger = ogler.getLogger()


def setupWitness(hby, alias="witness", mbx=None, aids=None, tcpPort=5631, httpPort=5632,
                 keypath=None, certpath=None, cafilepath=None):
    """Set up a witness controller and return its list of doers.

    Creates or retrieves the witness Hab, wires up a Verifier, Mailboxer,
    ForwardHandler, Exchanger, HTTP and (optionally) TCP servers, and all
    associated Doers required to run a witness node.

    Args:
        hby (Habery): Habery instance that manages Hab creation and lookup.
        alias (str): Name of the witness Hab. Created if it does not exist.
            Defaults to ``"witness"``.
        mbx (Mailboxer, optional): Mailbox storage instance. A new
            ``Mailboxer`` is created when ``None``. Defaults to ``None``.
        aids (list, optional): Allowlist of AIDs this witness will receipt.
            ``None`` means no restriction. Defaults to ``None``.
        tcpPort (int): Port for the TCP server. Pass ``None`` to disable TCP.
            Defaults to ``5631``.
        httpPort (int): Port for the HTTP server. Defaults to ``5632``.
        keypath (str, optional): File path to the TLS private key.
            Defaults to ``None``.
        certpath (str, optional): File path to the TLS signed certificate.
            Defaults to ``None``.
        cafilepath (str, optional): File path to the TLS CA certificate chain.
            Defaults to ``None``.

    Returns:
        list: Doers that must be scheduled to operate the witness.

    Raises:
        RuntimeError: If the HTTP server cannot bind to ``httpPort``.
        RuntimeError: If the TCP server cannot bind to ``tcpPort`` (when
            ``tcpPort`` is not ``None``).
    """
    host = "0.0.0.0"
    if platform.system() == "Windows":
        host = "127.0.0.1"
    cues = decking.Deck()
    doers = []

    # make hab
    hab = hby.habByName(name=alias)
    if hab is None:
        hab = hby.makeHab(name=alias, transferable=False)

    from ..vdr import Reger,Verifier  # dynamic import because of circular import

    reger = Reger(name=hab.name, db=hab.db, temp=False)
    verfer = Verifier(hby=hby, reger=reger)

    mbx = mbx if mbx is not None else Mailboxer(name=alias, temp=hby.temp)
    forwarder = ForwardHandler(hby=hby, mbx=mbx)
    exchanger = Exchanger(hby=hby, handlers=[forwarder])
    clienter = Clienter()
    oobiery = Oobiery(hby=hby, clienter=clienter)

    app = falcon.App(cors_enable=True)
    loadEndingEnds(app=app, hby=hby, default=hab.pre)
    loadOobiingEnds(app=app, hby=hby, prefix="/ext")
    rep = Respondant(hby=hby, mbx=mbx, aids=aids)

    rvy = routing.Revery(db=hby.db, cues=cues)
    kvy = Kevery(db=hby.db,
                lax=True,
                local=False,
                rvy=rvy,
                cues=cues)
    kvy.registerReplyRoutes(router=rvy.rtr)

    from ..vdr import Tevery  # dynamic import because of circular import

    tvy = Tevery(reger=verfer.reger,
                 db=hby.db,
                 local=False,
                 cues=cues)

    tvy.registerReplyRoutes(router=rvy.rtr)
    parser = parsing.Parser(framed=True,
                            kvy=kvy,
                            tvy=tvy,
                            exc=exchanger,
                            rvy=rvy,
                            version=Vrsn_1_0)

    httpEnd = HttpEnd(rxbs=parser.ims, mbx=mbx)
    app.add_route("/", httpEnd)
    receiptEnd = ReceiptEnd(hab=hab, inbound=cues, aids=aids)
    app.add_route("/receipts", receiptEnd)
    queryEnd = QueryEnd(hab=hab, reger=reger)
    app.add_route("/query", queryEnd)

    server = createHttpServer(host, httpPort, app, keypath, certpath, cafilepath)
    if not server.reopen():
        raise RuntimeError(f"cannot create http server on port {httpPort}")
    httpServerDoer = http.ServerDoer(server=server)

    # setup doers
    regDoer = BaserDoer(baser=reger)

    if tcpPort is not None:
        server = serving.Server(host="", port=tcpPort)
        if not server.reopen():
            raise RuntimeError(f"cannot create tcp server on port {tcpPort}")
        serverDoer = serving.ServerDoer(server=server)

        directant = Directant(hab=hab, server=server, verifier=verfer)
        doers.extend([directant, serverDoer])

    witStart = WitnessStart(hab=hab, parser=parser, cues=receiptEnd.outbound,
                            kvy=kvy, tvy=tvy, rvy=rvy, exc=exchanger, replies=rep.reps,
                            responses=rep.cues, queries=httpEnd.qrycues)

    doers.extend([regDoer, httpServerDoer, rep, witStart, receiptEnd, *oobiery.doers])
    return doers


def createHttpServer(host, port, app, keypath=None, certpath=None, cafilepath=None):
    """Create an HTTP or HTTPS server depending on whether TLS key material is present.

    Args:
        host (str): Hostname or IP address to bind. Use ``"0.0.0.0"`` for all
            interfaces.
        port (int): Port to listen on.
        app: WSGI application instance passed to the ``http.Server``.
        keypath (str, optional): File path to the TLS private key.
            Defaults to ``None``.
        certpath (str, optional): File path to the TLS signed certificate
            (public key). Defaults to ``None``.
        cafilepath (str, optional): File path to the TLS CA certificate chain.
            Defaults to ``None``.

    Returns:
        hio.core.http.Server: Configured HTTP or HTTPS server instance.
    """
    if keypath is not None and certpath is not None and cafilepath is not None:
        servant = tcp.ServerTls(certify=False,
                                keypath=keypath,
                                certpath=certpath,
                                cafilepath=cafilepath,
                                port=port)
        server = http.Server(host=host, port=port, app=app, servant=servant)
    else:
        server = http.Server(host=host, port=port, app=app)
    return server


class WitnessStart(doing.DoDoer):
    """DoDoer that prints the witness prefix after Hab initialization and then
    continuously processes incoming messages, escrows, and receipt cues.

    This is an internal orchestration doer used by :func:`setupWitness`. It
    composes four sub-doers: ``start``, ``msgDo``, ``escrowDo``, and
    ``cueDo``.

    Attributes:
        hab (Hab): Local witness Hab.
        parser (Parser): CESR stream parser whose ``ims`` buffer receives
            inbound bytes.
        kvy (Kevery): KEL event processor.
        tvy (Tevery): TEL event processor.
        rvy (Revery): Reply-event router/processor.
        exc (Exchanger): Exchange (``exn``) message handler.
        cues (Deck): Inbound receipt cues from ``ReceiptEnd``.
        replies (Deck): Inbound reply messages from the Respondant.
        responses (Deck): Outbound response cues that are not ``stream``-kind.
        queries (Deck): Outbound queue for ``stream``-kind cues routed to
            HTTP query handlers.
    """

    def __init__(self, hab, parser, kvy, tvy, rvy, exc, cues=None, replies=None, responses=None, queries=None, **opts):
        """Initialize WitnessStart.

        Args:
            hab (Hab): Local witness Hab.
            parser (Parser): CESR stream parser.
            kvy (Kevery): KEL event processor.
            tvy (Tevery): TEL event processor.
            rvy (Revery): Reply-event router/processor.
            exc (Exchanger): Exchange (``exn``) message handler.
            cues (Deck, optional): Inbound receipt cues from ``ReceiptEnd``.
                A new ``Deck`` is created when ``None``. Defaults to ``None``.
            replies (Deck, optional): Reply messages from the Respondant.
                A new ``Deck`` is created when ``None``. Defaults to ``None``.
            responses (Deck, optional): Non-stream outbound response cues.
                A new ``Deck`` is created when ``None``. Defaults to ``None``.
            queries (Deck, optional): Stream-kind cues forwarded to HTTP query
                handlers. A new ``Deck`` is created when ``None``.
                Defaults to ``None``.
            **opts: Keyword arguments forwarded to ``doing.DoDoer.__init__``.
        """
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

        doers = [doing.doify(self.start), doing.doify(self.msgDo), doing.doify(self.escrowDo), doing.doify(self.cueDo)]
        super().__init__(doers=doers, **opts)

    def start(self, tymth=None, tock=0.0, **kwa):
        """Doer generator that waits for Hab initialization and prints the
        witness name and AID prefix to stdout.

        Args:
            tymth (callable, optional): Tymist tyme accessor closure injected
                by the parent Doist or DoDoer.
            tock (float): Initial tock value in seconds. Defaults to ``0.0``.
            **kwa: Keyword arguments.

        Yields:
            float: Tock value to the scheduler.
        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        while not self.hab.inited:
            yield self.tock

        print("Witness", self.hab.name, ":", self.hab.pre)

    def msgDo(self, tymth=None, tock=0.0, **kwa):
        """Doer generator that continuously processes the inbound CESR message
        stream via ``self.parser``.

        Args:
            tymth (callable, optional): Tymist tyme accessor closure injected
                by the parent Doist or DoDoer.
            tock (float): Initial tock value in seconds. Defaults to ``0.0``.
            **kwa: Keyword arguments.

        Yields:
            float: Tock value to the scheduler.

        Returns:
            bool: Completion flag from ``parser.parsator``; only returned on
                forced close.
        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        if self.parser.ims:
            logger.debug("Client %s received:\n%s\n...\n", self.kvy, self.parser.ims[:1024])
        done = yield from self.parser.parsator(local=True)  # process messages continuously
        return done  # should nover get here except forced close

    def escrowDo(self, tymth=None, tock=0.0, **kwa):
        """Doer generator that continuously drains the escrow queues of
        ``self.kvy``, ``self.rvy``, ``self.tvy``, and ``self.exc``.

        Args:
            tymth (callable, optional): Tymist tyme accessor closure injected
                by the parent Doist or DoDoer.
            tock (float): Initial tock value in seconds. Defaults to ``0.0``.
            **kwa: Keyword arguments.

        Yields:
            float: Tock value to the scheduler (``0.0`` to run each cycle).
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

    def cueDo(self, tymth=None, tock=0.0, **kwa):
        """Doer generator that routes cues from ``self.cues`` to either
        ``self.queries`` (for ``stream``-kind cues) or ``self.responses``
        (for all other kinds).

        Args:
            tymth (callable, optional): Tymist tyme accessor closure injected
                by the parent Doist or DoDoer.
            tock (float): Initial tock value in seconds. Defaults to ``0.0``.
            **kwa: Keyword arguments.

        Yields:
            float: Tock value to the scheduler.
        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        while True:
            while self.cues:
                cue = self.cues.pull()  # self.cues.popleft()
                cueKin = cue["kin"]
                if cueKin == "stream":
                    self.queries.append(cue)
                else:
                    self.responses.append(cue)
                yield self.tock
            yield self.tock

class Indirector(doing.DoDoer):
    """DoDoer for an Indirect Mode KERI controller that communicates with
    witnesses over a single TCP client connection.

    Composes ``msgDo`` and ``escrowDo`` sub-doers, and optionally ``cueDo``
    when operating in direct mode. Part of the scheduling hierarchy:
    Doist->DoDoer...->DoDoer->Doers

    Attributes:
        hab (Hab): Local controller Hab.
        client (hio.core.tcp.Client): TCP client used for both sending and
            receiving.
        direct (bool): ``True`` when running in direct mode (receipt cues are
            processed and sent back); ``False`` for indirect mode (receipt cues
            are ignored).
        kevery (Kevery): KEL event processor bound to ``client.rxbs``.
        parser (Parser): CESR stream parser reading from ``client.rxbs``.
    """

    def __init__(self, hab, client, direct=True, doers=None, **kwa):
        """Initialize Indirector.

        Args:
            hab (Hab): Local controller Hab.
            client (hio.core.tcp.Client): TCP client for sending and receiving.
            direct (bool): ``True`` enables direct mode, which processes
                receipt cues and sends chits back to the remote. ``False``
                disables cue processing (indirect/cloned mode).
                Defaults to ``True``.
            doers (list, optional): Additional doers to include. Defaults to
                ``None``.
            **kwa: Keyword arguments forwarded to ``doing.DoDoer.__init__``.
        """
        self.hab = hab
        self.client = client  # use client for both rx and tx
        self.direct = True if direct else False
        self.kevery = Kevery(db=self.hab.db,
                            lax=False,
                            local=False,
                            cloned=not self.direct,
                            direct=self.direct)
        self.parser = parsing.Parser(ims=self.client.rxbs,
                                     framed=True,
                                     kvy=self.kevery,
                                     version=Vrsn_1_0)
        doers = doers if doers is not None else []
        doers.extend([doing.doify(self.msgDo),
                      doing.doify(self.escrowDo)])
        if self.direct:
            doers.extend([doing.doify(self.cueDo)])

        super(Indirector, self).__init__(doers=doers, **kwa)
        if self.tymth:
            self.client.wind(self.tymth)

    def wind(self, tymth):
        """Inject a new Tymist tyme accessor and propagate it to the TCP client.

        Args:
            tymth (callable): Tymist tyme accessor closure.
        """
        super(Indirector, self).wind(tymth)
        self.client.wind(tymth)

    def msgDo(self, tymth=None, tock=0.0, **kwa):
        """Doer generator that continuously processes the inbound CESR message
        stream read from ``self.client.rxbs`` via ``self.parser``.

        Args:
            tymth (callable, optional): Tymist tyme accessor closure injected
                by the parent Doist or DoDoer.
            tock (float): Initial tock value in seconds. Defaults to ``0.0``.
            **kwa: Keyword arguments

        Yields:
            float: Tock value to the scheduler.

        Returns:
            bool: Completion flag from ``parser.parsator``; only returned on
                forced close.
        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        if self.parser.ims:
            logger.debug("Client %s received:\n%s\n...\n", self.hab.pre, self.parser.ims[:1024])
        done = yield from self.parser.parsator(local=True)  # process messages continuously
        return done  # should never get here except forced close

    def cueDo(self, tymth=None, tock=0.0, **kwa):
        """Doer generator that processes ``self.kevery.cues`` one at a time,
        sending the resulting chit or receipt message to the remote via
        ``self.client``.

        Only scheduled when ``self.direct`` is ``True``.

        Args:
            tymth (callable, optional): Tymist tyme accessor closure injected
                by the parent Doist or DoDoer.
            tock (float): Initial tock value in seconds. Defaults to ``0.0``.
            **kwa: Keyword arguments

        Yields:
            float: Tock value to the scheduler.
        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        while True:
            for msg in self.hab.processCuesIter(self.kevery.cues):
                self.sendMessage(msg, label="chit or receipt")
                yield  # throttle just do one cue at a time
            yield

    def escrowDo(self, tymth=None, tock=0.0, **kwa):
        """Doer generator that continuously drains ``self.kevery``'s escrow
        queue.

        Args:
            tymth (callable, optional): Tymist tyme accessor closure injected
                by the parent Doist or DoDoer.
            tock (float): Initial tock value in seconds. Defaults to ``0.0``.
            **kwa: Keyword arguments

        Yields:
            float: Tock value to the scheduler (``0.0`` to run each cycle).
        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        while True:
            self.kevery.processEscrows()
            yield

    def sendMessage(self, msg, label=""):
        """Transmit a message to the remote and log it.

        Args:
            msg (bytes | bytearray): Serialized CESR message to send.
            label (str): Human-readable label for log output.
                Defaults to ``""``.
        """
        self.client.tx(msg)  # send to remote
        logger.debug("%s sent %s:\n%s\n\n", self.hab.pre, label, bytes(msg))


class MailboxDirector(doing.DoDoer):
    """DoDoer that polls witness mailboxes for indirect-mode KERI controllers
    and feeds the retrieved messages through a shared parser pipeline.

    Manages a dynamic set of :class:`Poller` sub-doers, one per witness (or
    mailbox endpoint) per controlled prefix. New Habs discovered in ``hby``
    are picked up automatically on each ``pollDo`` cycle. Part of the
    scheduling hierarchy: Doist->DoDoer...->DoDoer->Doers

    Attributes:
        hby (Habery): Habery whose Habs are monitored for new prefixes.
        verifier (Verifier): TEL event acceptor and validator. May be ``None``.
        exchanger (Exchanger): Exchange (``exn``) message handler. May be
            ``None``.
        rep (Respondant): Respondant for reply messages. May be ``None``.
        topics (list[str]): Mailbox topic names to poll (e.g.
            ``["/receipt", "/replay"]``).
        pollers (list[Poller]): Active Poller sub-doers.
        prefixes (OrderedSet): AID prefixes for which pollers have already
            been created.
        cues (Deck): Shared cue queue populated by Kevery, Kever, and Tevery.
        witnesses (bool): When ``True``, also add pollers for each Hab's
            declared witnesses in addition to explicit mailbox role endpoints.
        ims (bytearray): Inbound message stream buffer fed by pollers and
            consumed by ``self.parser``.
        rtr (Router): Reply-event router shared across Kevery, Tevery, and
            Revery.
        rvy (Revery): Reply-event processor.
        kvy (Kevery): KEL event processor.
        tvy (Tevery | None): TEL event processor; ``None`` when no verifier is
            provided.
        parser (Parser): CESR stream parser consuming ``self.ims``.
    """

    def __init__(self, hby, topics, ims=None, verifier=None, kvy=None, exc=None, rep=None, cues=None, rvy=None,
                 tvy=None, witnesses=True, **kwa):
        """Initialize MailboxDirector.

        Args:
            hby (Habery): Habery instance whose Habs are polled for mailbox
                messages.
            topics (list[str]): Mailbox topic paths to subscribe to.
            ims (bytearray, optional): Shared inbound message stream buffer.
                A new ``bytearray`` is created when ``None``.
                Defaults to ``None``.
            verifier (Verifier, optional): TEL event verifier. When provided,
                a ``Tevery`` is also created. Defaults to ``None``.
            kvy (Kevery, optional): Pre-constructed KEL event processor.
                A new ``Kevery`` is created when ``None``.
                Defaults to ``None``.
            exc (Exchanger, optional): Exchange (``exn``) message handler.
                Defaults to ``None``.
            rep (Respondant, optional): Respondant for reply messages.
                Defaults to ``None``.
            cues (Deck, optional): Shared cue queue. A new ``Deck`` is created
                when ``None``. Defaults to ``None``.
            rvy (Revery, optional): Pre-constructed reply-event processor.
                A new ``Revery`` is created when ``None``.
                Defaults to ``None``.
            tvy (Tevery, optional): Pre-constructed TEL event processor. Only
                used when ``verifier`` is also provided. A new ``Tevery`` is
                created when ``None`` and ``verifier`` is set.
                Defaults to ``None``.
            witnesses (bool): When ``True``, add pollers for each Hab's
                declared witnesses in addition to explicit mailbox role
                endpoints. Defaults to ``True``.
            **kwa: Keyword arguments forwarded to ``doing.DoDoer.__init__``.
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
        self.kvy = kvy if kvy is not None else Kevery(db=self.hby.db,
                                                        cues=self.cues,
                                                        rvy=self.rvy,
                                                        lax=True,
                                                        local=False,
                                                        direct=False)
        self.kvy.registerReplyRoutes(self.rtr)

        if self.verifier is not None:
            from ..vdr import Tevery  # dynamic import because of circular import

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
                                     vry=self.verifier,
                                     version=Vrsn_1_0)

        super(MailboxDirector, self).__init__(doers=doers, **kwa)

    def wind(self, tymth):
        """Inject a new Tymist tyme accessor.

        Args:
            tymth (callable): Tymist tyme accessor closure.
        """
        super(MailboxDirector, self).wind(tymth)

    def pollDo(self, tymth=None, tock=0.0, **kwa):
        """Doer generator that creates :class:`Poller` sub-doers for accepted
        Habs and continuously appends new poller messages to ``self.ims``.

        On startup, pollers are created for all already-accepted Habs. On each
        subsequent cycle, newly discovered prefixes are checked and pollers are
        added as needed.

        Args:
            tymth (callable, optional): Tymist tyme accessor closure injected
                by the parent Doist or DoDoer.
            tock (float): Initial tock value in seconds. Defaults to ``0.0``.

        Yields:
            float: Tock value to the scheduler.
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
        """Create and register :class:`Poller` sub-doers for every mailbox
        role endpoint and, when ``self.witnesses`` is ``True``, for every
        declared witness of ``hab``.

        Marks ``hab.pre`` in ``self.prefixes`` so it is not processed again.

        Args:
            hab (Hab): The Hab whose mailbox endpoints and witnesses are polled.
        """
        for (_, erole, eid), end in hab.db.ends.getTopItemIter(keys=(hab.pre, Roles.mailbox)):
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
        """Create and register a single :class:`Poller` sub-doer for a
        specific witness.

        Args:
            hab (Hab): The Hab whose mailbox is being polled.
            witness (str): QB64 AID of the witness to poll.
        """
        poller = Poller(hab=hab, topics=self.topics, witness=witness)
        self.pollers.append(poller)
        self.extend([poller])

    def processPollIter(self):
        """Collect and yield all pending messages from every active poller.

        Drains each poller's ``msgs`` deque in order, then yields the
        collected messages one at a time.

        Yields:
            bytes | bytearray: The next raw CESR message from a poller.
        """
        mail = []
        for poller in self.pollers:  # get responses from all behaviors
            while poller.msgs:
                msg = poller.msgs.popleft()
                mail.append(msg)

        while mail:  # iteratively process each response in responses
            msg = mail.pop(0)
            yield msg

    def msgDo(self, tymth=None, tock=0.0, **kwa):
        """Doer generator that continuously processes the inbound CESR message
        stream in ``self.ims`` via ``self.parser``.

        Args:
            tymth (callable, optional): Tymist tyme accessor closure injected
                by the parent Doist or DoDoer.
            tock (float): Initial tock value in seconds. Defaults to ``0.0``.

        Yields:
            float: Tock value to the scheduler.

        Returns:
            bool: Completion flag from ``parser.parsator``; only returned on
                forced close.
        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        done = yield from self.parser.parsator(local=True)  # process messages continuously
        return done  # should nover get here except forced close

    def escrowDo(self, tymth=None, tock=0.0, **kwa):
        """Doer generator that continuously drains the escrow queues of
        ``self.kvy``, ``self.rvy``, ``self.exchanger``, ``self.tvy``, and
        ``self.verifier``.

        Args:
            tymth (callable, optional): Tymist tyme accessor closure injected
                by the parent Doist or DoDoer.
            tock (float): Initial tock value in seconds. Defaults to ``0.0``.

        Yields:
            float: Tock value to the scheduler (``0.0`` to run each cycle).
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
        """Aggregate the latest poll timestamps across all active pollers.

        Returns:
            dict[str, datetime]: Mapping of topic name to the UTC datetime of
                the most recent message received on that topic, merged from
                all pollers. Later entries overwrite earlier ones for the same
                topic.
        """
        times = dict()
        for poller in self.pollers:  # get responses from all pollers
            times |= poller.times

        return times


class Poller(doing.DoDoer):
    """DoDoer that polls a single witness SSE mailbox endpoint for a given
    prefix and appends received CESR messages to ``self.msgs``.

    Uses :func:`~keri.app.agenting.httpClient` to open an HTTP connection,
    sends a CESR ``qry`` request for ``mbx`` topics, and streams SSE events
    in a 30-second window before reconnecting.

    Attributes:
        hab (Hab): Local controller Hab.
        pre (str): QB64 AID prefix being polled.
        witness (str): QB64 AID of the witness being polled.
        topics (list[str]): Mailbox topic paths to subscribe to.
        retry (int): SSE retry interval in milliseconds. Updated from server
            ``retry`` events. Defaults to ``1000``.
        msgs (Deck): Output queue of raw encoded CESR messages received from
            the witness.
        times (dict[str, datetime]): Mapping of topic name to the UTC datetime
            of the most recent message received on that topic.
    """

    def __init__(self, hab, witness, topics, msgs=None, retry=1000, **kwa):
        """Initialize Poller.

        Args:
            hab (Hab): Local controller Hab used to build query messages.
            witness (str): QB64 AID of the witness mailbox to poll.
            topics (list[str]): Mailbox topic paths to subscribe to.
            msgs (Deck, optional): Output message queue. A new ``Deck`` is
                created when ``None``. Defaults to ``None``.
            retry (int): Initial SSE retry interval in milliseconds.
                Defaults to ``1000``.
            **kwa: Keyword arguments forwarded to ``doing.DoDoer.__init__``.
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

    def eventDo(self, tymth=None, tock=0.0, **kwa):
        """Doer generator that repeatedly opens an HTTP connection to the
        witness, sends a CESR ``mbx`` query, and consumes SSE events for up
        to 30 seconds before reconnecting.

        Received event data is appended to ``self.msgs`` as UTF-8 encoded
        bytes. Topic offsets are persisted to ``hab.db.tops`` after each
        event so polling resumes from the correct position on reconnect.

        Args:
            tymth (callable, optional): Tymist tyme accessor closure injected
                by the parent Doist or DoDoer.
            tock (float): Initial tock value in seconds. Defaults to ``0.0``.
            **kwa: Keyword arguments

        Yields:
            float: Tock value to the scheduler.
        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        witrec = self.hab.db.tops.get((self.pre, self.witness))
        if witrec is None:
            witrec = TopicsRecord(topics=dict())

        while self.retry > 0:
            try:
                client, clientDoer = httpClient(self.hab, self.witness)
            except MissingEntryError as e:
                traceback.print_exception(e, file=sys.stderr)  # logging
                yield self.tock
                continue

            self.extend([clientDoer])

            topics = dict()
            q = dict(pre=self.pre, topics=topics)
            for topic in self.topics:
                if topic in witrec.topics:
                    topics[topic] = witrec.topics[topic] + 1
                else:
                    topics[topic] = 0

            if isinstance(self.hab, GroupHab):
                msg = self.hab.mhab.query(pre=self.pre, src=self.witness, route="mbx", query=q)
            else:
                msg = self.hab.query(pre=self.pre, src=self.witness, route="mbx", query=q)

            createCESRRequest(msg, client, dest=self.witness)

            while client.requests:
                yield self.tock

            created = nowUTC()
            while True:

                now = nowUTC()
                if now - created > datetime.timedelta(seconds=30):
                    self.remove([clientDoer])
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
                    self.times[tpc] = nowUTC()
                    self.hab.db.tops.pin((self.pre, self.witness), witrec)

                yield 0.25
            yield self.retry / 1000


class HttpEnd:
    """Falcon HTTP endpoint for receiving KERI CESR events and serving mailbox streams.

    This endpoint supports ingestion of KERI events via HTTP POST and raw byte
    streams via PUT. It also handles mailbox query (``qry``) messages with route
    ``mbx`` by returning a Server-Sent Events (SSE) stream.

    POST requests expect a JSON-encoded KERI event with CESR attachments
    provided in the ``CESR-Attachment`` header. Parsed messages are appended
    to a shared byte buffer for downstream processing.

    Attributes:
        TimeoutQNF (int): Timeout in seconds for query-not-found conditions.
        TimeoutMBX (int): Timeout in seconds for mailbox SSE streams.
        rxbs (bytearray): Shared inbound byte buffer for serialized messages.
        mbx (Mailboxer): Mailbox storage used for SSE replay streams.
        qrycues (Deck): Queue of query cues used for mailbox streaming.
    """

    TimeoutQNF = 30
    TimeoutMBX = 5

    def __init__(self, rxbs=None, mbx=None, qrycues=None):
        """Initialize the KEL HTTP server.

        Args:
            rxbs (bytearray, optional): Shared inbound byte buffer. If not
                provided, a new ``bytearray`` is created.
            mbx (Mailboxer, optional): Mailbox storage for serving SSE streams.
            qrycues (Deck, optional): Queue for inbound query cues. If not
                provided, a new ``Deck`` instance is created.
        """
        self.rxbs = rxbs if rxbs is not None else bytearray()

        self.mbx = mbx
        self.qrycues = qrycues if qrycues is not None else decking.Deck()

    def on_post(self, req, rep):
        """Handle HTTP POST requests containing KERI CESR events.

        The request is parsed into a KERI event and associated CESR attachments.
        The serialized result is appended to ``self.rxbs`` for processing.

        Response behavior depends on the message type:
            - Mailbox query (``qry`` with route ``mbx``): returns an SSE stream
              with HTTP 200 status.
            - All other valid KERI message types: returns HTTP 204 (No Content).

        Args:
            req (falcon.Request): Incoming HTTP request containing a KERI event.
            rep (falcon.Response): HTTP response object to populate.
        """
        sadder = coring.Sadder(ked=cr.payload, kind=Kinds.json)
        msg = bytearray(sadder.raw)
        msg.extend(cr.attachments.encode("utf-8"))

        self.rxbs.extend(msg)

        if sadder.proto in ("ACDC",):
            rep.set_header('Content-Type', "application/json")
            rep.status = falcon.HTTP_204
        else:
            ilk = sadder.ked["t"]
            if ilk in (Ilks.icp, Ilks.rot, Ilks.ixn, Ilks.dip, Ilks.drt, Ilks.exn, Ilks.rpy):
                rep.set_header('Content-Type', "application/json")
                rep.status = falcon.HTTP_204
            elif ilk in (Ilks.vcp, Ilks.vrt, Ilks.iss, Ilks.rev, Ilks.bis, Ilks.brv):
                rep.set_header('Content-Type', "application/json")
                rep.status = falcon.HTTP_204
            elif ilk in (Ilks.qry,):
                if sadder.ked["r"] in ("mbx",):
                    rep.set_header('Content-Type', "text/event-stream")
                    rep.status = falcon.HTTP_200
                    rep.stream = QryRpyMailboxIterable(mbx=self.mbx, cues=self.qrycues, said=sadder.said)
                else:
                    rep.set_header('Content-Type', "application/json")
                    rep.status = falcon.HTTP_204

    def on_put(self, req, rep):
        """Handle HTTP PUT requests containing raw CESR byte streams.

        The entire request body is read as a byte stream and appended directly
        to ``self.rxbs`` without parsing.

        Always responds with HTTP 204 (No Content).

        Args:
            req (falcon.Request): Incoming HTTP request containing raw bytes.
            rep (falcon.Response): HTTP response object to populate.

        .. code-block:: none

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

        self.rxbs.extend(req.bounded_stream.read())

        rep.set_header('Content-Type', "application/json")
        rep.status = falcon.HTTP_204


class QryRpyMailboxIterable:
    """Synchronous iterator that waits for a matching ``stream`` cue from
    ``self.cues`` and then delegates to a :class:`MailboxIterable`.

    Used as ``rep.stream`` in Falcon to serve SSE responses for ``qry``
    messages with route ``mbx``. On each call to ``__next__``, it inspects
    ``self.cues`` for a cue whose ``serder.said`` matches ``self.said``. Once
    matched, it creates a :class:`MailboxIterable` and yields from it for the
    remainder of the request lifetime.  Non-matching cues are put back into
    the deck.

    Attributes:
        mbx (Mailboxer): Mailbox storage passed to :class:`MailboxIterable`.
        retry (int): SSE retry interval in milliseconds passed to
            :class:`MailboxIterable`. Defaults to ``5000``.
        cues (Deck): Queue of query cues produced by ``WitnessStart.cueDo``.
        said (str): SAID of the ``qry`` event whose response stream is being
            served.
        iter (iterator | None): Active :class:`MailboxIterable` iterator once
            a matching cue has been found; ``None`` beforehand.
    """

    def __init__(self, cues, mbx, said, retry=5000):
        """Initialize QryRpyMailboxIterable.

        Args:
            cues (Deck): Queue of ``stream``-kind query cues.
            mbx (Mailboxer): Mailbox storage for event replay.
            said (str): SAID of the originating ``qry`` event; used to match
                the correct cue.
            retry (int): SSE retry interval in milliseconds forwarded to
                :class:`MailboxIterable`. Defaults to ``5000``.
        """
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
                cue = self.cues.pull()
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


class MailboxIterable:
    """Iterator that streams Server-Sent Events (SSE) from a mailbox source.

    This iterator produces byte-encoded SSE frames for messages stored in a
    :class:`~keri.app.storing.Mailboxer`. On the first iteration, a ``retry:``
    directive is emitted. Subsequent iterations poll the mailbox for new
    messages across configured topics and yield formatted SSE event frames.

    Iteration continues until no new messages are emitted within a configured
    timeout window, after which ``StopIteration`` is raised.

    Class Attributes:
        TimeoutMBX (int): Maximum idle duration in microseconds (based on
            ``time.perf_counter``) before iteration stops. Defaults to
            ``30000000`` (~30 seconds).

    Attributes:
        mbx (Mailboxer): Mailbox storage instance used to retrieve messages.
        pre (str): QB64 AID prefix whose mailbox events are streamed.
        topics (dict[str, int]): Mapping of topic names to the next sequence
            number to retrieve. Updated in place as messages are consumed.
        retry (int): SSE retry interval in milliseconds included in emitted
            frames.
    """
    TimeoutMBX = 30000000

    def __init__(self, mbx, pre, topics, retry=5000):
        """Initialize the MailboxIterable.

        Args:
            mbx (Mailboxer): Mailbox storage instance used for retrieving
                messages.
            pre (str): QB64 AID prefix identifying the mailbox.
            topics (dict[str, int]): Mapping of topic names to starting
                sequence numbers. This mapping is updated in place.
            retry (int, optional): SSE retry interval in milliseconds.
                Defaults to ``5000``.
        """
        self.mbx = mbx
        self.pre = pre
        self.topics = topics
        self.retry = retry

    def __iter__(self):
        """Return the iterator instance and initialize timing state.

        Resets the internal start and end timestamps used to track inactivity
        for timeout purposes.

        Returns:
            MailboxIterable: The iterator instance.
        """
        self.start = self.end = time.perf_counter()
        return self

    def __next__(self):
        """Return the next SSE-formatted message batch.

        On the first call after iteration begins, emits a ``retry:`` directive.
        On subsequent calls, polls the mailbox for new messages across all
        configured topics and returns them formatted as SSE frames.

        The iterator stops when the elapsed time since the last emitted message
        exceeds :attr:`TimeoutMBX`.

        Returns:
            bytearray: Byte-encoded SSE data containing zero or more event
                frames. May be empty if no new messages are available.

        Raises:
            StopIteration: If no messages are received within the timeout
                window.
        """
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

                self.topics[topic] = idx
            self.end = time.perf_counter()
            return data

        raise StopIteration

class ReceiptEnd(doing.DoDoer):
    """Falcon HTTP endpoint and DoDoer for witness receipt operations.

    Provides two HTTP handlers:

    ``POST /receipts`` — Accepts a KERI event, verifies that this witness is
    listed in the event's witness set, issues a receipt, and returns it
    inline (``200``) or defers with ``202`` when the event is still in escrow.

    ``GET /receipts`` — Retrieves a previously issued receipt for an event
    identified by ``pre`` plus either ``sn`` or ``said``.

    The ``interceptDo`` generator monitors ``self.inbound`` for ``receipt``
    cues and forwards them to ``self.outbound``, suppressing duplicates that
    were already returned inline by the POST handler.

    Attributes:
        hab (Hab): Local witness Hab used to issue receipts.
        inbound (Deck): Cue queue populated by Kevery (shared with the
            witness cue pipeline).
        outbound (Deck): Cue queue consumed by ``WitnessStart.cueDo``
            (fed into the Respondant / reply pipeline).
        aids (list | None): Allowlist of AIDs this endpoint will receipt.
            ``None`` means no restriction.
        receipts (set): SAIDs of events receipted inline by POST; used to
            suppress duplicate outbound cues.
        psr (Parser): Parser used to process the inbound event and the
            issued receipt locally.
    """

    def __init__(self, hab, inbound=None, outbound=None, aids=None):
        """Initialize ReceiptEnd.

        Args:
            hab (Hab): Local witness Hab.
            inbound (Deck, optional): Inbound cue queue from Kevery. A new
                ``Deck`` is created when ``None``. Defaults to ``None``.
            outbound (Deck, optional): Outbound cue queue consumed by the
                witness cue pipeline. A new ``Deck`` is created when ``None``.
                Defaults to ``None``.
            aids (list, optional): Allowlist of AIDs to receipt. ``None``
                means no restriction. Defaults to ``None``.
        """
        self.hab = hab
        self.inbound = inbound if inbound is not None else decking.Deck()
        self.outbound = outbound if outbound is not None else decking.Deck()
        self.aids = aids
        self.receipts = set()
        self.psr = parsing.Parser(framed=True,
                                  kvy=self.hab.kvy,
                                  version=Vrsn_1_0)

        super(ReceiptEnd, self).__init__(doers=[doing.doify(self.interceptDo)])

    def on_post(self, req, rep):
        """Handle POST requests to issue a witness receipt for a KERI event.

        Parses the event, verifies this witness is in the event's witness set,
        and returns the receipt inline. When the event is not yet in
        ``self.hab.kevers`` (still in escrow), responds with ``202 Accepted``.

        Args:
            req (falcon.Request): Incoming Falcon HTTP request.
            rep (falcon.Response): Outgoing Falcon HTTP response.

        Raises:
            falcon.HTTPBadRequest: If ``pre`` is not in ``self.aids`` (when
                the allowlist is set), the event type is not receipable, or
                this witness is not listed in the event's witness set.
        """

        if req.method == "OPTIONS":
            rep.status = falcon.HTTP_200
            return

        rep.set_header('Cache-Control', "no-cache")
        rep.set_header('connection', "close")

        cr = parseCesrHttpRequest(req=req)
        serder = serdering.SerderKERI(sad=cr.payload, kind=Kinds.json)

        pre = serder.ked["i"]
        if self.aids is not None and pre not in self.aids:
            raise falcon.HTTPBadRequest(description=f"invalid AID={pre} for witnessing receipting")

        ilk = serder.ked["t"]
        if ilk not in (Ilks.icp, Ilks.rot, Ilks.ixn, Ilks.dip, Ilks.drt):
            raise falcon.HTTPBadRequest(description=f"invalid event type ({ilk})for receipting")

        msg = bytearray(serder.raw)
        msg.extend(cr.attachments.encode("utf-8"))

        self.psr.parseOne(ims=msg, local=True)

        if pre in self.hab.kevers:
            kever = self.hab.kevers[pre]
            wits = kever.wits

            if self.hab.pre not in wits:
                raise falcon.HTTPBadRequest(description=f"{self.hab.pre} is not a valid witness for {pre} event at "
                                                        f"{serder.sn}: wits={wits}")

            rct = self.hab.receipt(serder)

            self.psr.parseOne(bytes(rct))

            rep.set_header('Content-Type', CESR_CONTENT_TYPE)
            rep.status = falcon.HTTP_200
            rep.data = rct
        else:
            rep.status = falcon.HTTP_202

    def on_get(self, req, rep):
        """Handle GET requests to retrieve a previously issued witness receipt.

        Looks up the event by ``pre`` and either ``sn`` or ``said``, assembles
        the receipt with indexed witness signatures from ``hab.db.wigs``, and
        returns it as CESR bytes.

        Args:
            req (falcon.Request): Incoming Falcon HTTP request. Expected query
                parameters:

                - ``pre`` (str, required): AID prefix of the event.
                - ``sn`` (int, optional): Sequence number of the event.
                - ``said`` (str, optional): SAID of the event. Required when
                  ``sn`` is omitted.

            rep (falcon.Response): Outgoing Falcon HTTP response.

        Raises:
            falcon.HTTPBadRequest: If ``pre`` is missing, both ``sn`` and
                ``said`` are missing, or this witness is not in the event's
                witness set.
            falcon.HTTPNotFound: If the event cannot be found in the database.
        """
        pre = req.get_param("pre")
        sn = req.get_param_as_int("sn")
        said = req.get_param("said")

        if pre is None:
            raise falcon.HTTPBadRequest(description="query param 'pre' is required")

        preb = pre.encode("utf-8")

        if sn is None and said is None:
            raise falcon.HTTPBadRequest(description="either 'sn' or 'said' query param is required")

        if sn is not None:
            said = self.hab.db.kels.getLast(keys=preb, on=sn)
        if said is None:
            raise falcon.HTTPNotFound(description=f"event for {pre} at {sn} ({said}) not found")
        said = said.encode("utf-8")
        if not (serder := self.hab.db.evts.get(keys=(preb, said))):
            raise falcon.HTTPNotFound(description="Missing event for dig={}.".format(said))
        if serder.sn > 0:
            wits = [wit.qb64 for wit in self.hab.kvy.fetchWitnessState(pre, serder.sn)]
        else:
            wits = serder.ked["b"]

        if self.hab.pre not in wits:
            raise falcon.HTTPBadRequest(description=f"{self.hab.pre} is not a valid witness for {pre} event at "
                                                    f"{serder.sn}, {wits}")
        rserder = receipt(pre=pre,
                          sn=sn,
                          said=said.decode("utf-8"))
        rct = bytearray(rserder.raw)
        if wigers := self.hab.db.wigs.get(keys=(preb, said)):
            rct.extend(Counter(Codens.WitnessIdxSigs, count=len(wigers),
                               version=Vrsn_1_0).qb64b)
            for wiger in wigers:
                rct.extend(wiger.qb64b)

        rep.set_header('Content-Type', CESR_CONTENT_TYPE)
        rep.status = falcon.HTTP_200
        rep.data = rct

    def interceptDo(self, tymth=None, tock=0.0, **kwa):
        """Doer generator that monitors ``self.inbound`` for ``receipt`` cues
        and forwards them to ``self.outbound``, suppressing duplicates for
        events already receipted inline by :meth:`on_post`.

        Non-``receipt`` cues are forwarded to ``self.outbound`` unconditionally.

        Args:
            tymth (callable, optional): Tymist tyme accessor closure injected
                by the parent Doist or DoDoer.
            tock (float): Initial tock value in seconds. Defaults to ``0.0``.

        Yields:
            float: Tock value to the scheduler.
        """
        # enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        while True:
            while self.inbound:  # iteratively process each cue in cues
                cue = self.inbound.popleft()
                cueKin = cue["kin"]  # type or kind of cue

                if cueKin in ("receipt",):  # cue to receipt a received event from other pre
                    serder = cue["serder"]  # Serder of received event for other pre
                    if serder.saidb in self.receipts:
                        self.receipts.remove(serder.saidb)
                    else:
                        self.outbound.append(cue)

                else:
                    self.outbound.append(cue)

                yield self.tock

            yield self.tock


class QueryEnd:
    """Falcon HTTP endpoint for querying KEL and TEL events.

    This endpoint handles ``GET /query`` requests and streams events from the
    local witness databases. Responses are returned as raw CESR-encoded bytes
    with ``Content-Type: application/cesr``.

    Supported query types:

    - ``typ=kel``: Streams all KEL events for a given identifier prefix
      (``pre``). Optionally filters events starting from a given sequence
      number (``sn``).
    - ``typ=tel``: Streams TEL events for a registry (``reg``), a credential
      (``vcid``), or both.

    Attributes:
        hab (Hab): Local witness habitat used to access the KEL database.
        reger (Reger): Registry database interface used for TEL queries.
    """

    def __init__(self, hab, reger):
        """Initialize the QueryEnd endpoint.

        Args:
            hab (Hab): Local witness habitat. Its associated database is used
                to retrieve KEL events, and is also passed to the registry
                handler for TEL queries.
        """
        self.hab = hab
        self.reger = reger

    def on_get(self, req, rep):
        """Handle HTTP GET requests for querying events.

        Depending on the ``typ`` query parameter, this method retrieves and
        streams either KEL or TEL events.

        Args:
            req (falcon.Request): Incoming HTTP request. Expected query
                parameters:

                - ``typ`` (str): Required. Specifies query type. Must be either
                  ``"kel"`` or ``"tel"``.
                - ``pre`` (str): Required when ``typ="kel"``. Identifier prefix
                  whose KEL events are requested.
                - ``sn`` (int): Optional when ``typ="kel"``. If provided,
                  returns events with sequence number greater than or equal
                  to this value.
                - ``reg`` (str): Optional when ``typ="tel"``. Registry prefix
                  whose TEL events are requested.
                - ``vcid`` (str): Optional when ``typ="tel"``. Credential SAID
                  whose TEL events are requested.

            rep (falcon.Response): Outgoing HTTP response. On success, the
                response contains CESR-encoded event bytes with
                ``Content-Type: application/cesr``.

        Raises:
            falcon.HTTPBadRequest: If required query parameters are missing or
                invalid for the selected query type.

        Notes:
            - For ``typ="kel"``, the ``pre`` parameter is required.
            - For ``typ="tel"``, at least one of ``reg`` or ``vcid`` must be
              provided.
            - If an invalid ``typ`` is provided, a 400 response is returned
              with a JSON content type.

        Examples:
            GET /query?typ=kel&pre=<prefix>

            GET /query?typ=kel&pre=<prefix>&sn=5

            GET /query?typ=tel&reg=<registry_prefix>&vcid=<credential_said>
        """

        typ = req.get_param("typ")

        if not typ:
            raise falcon.HTTPBadRequest(description="'typ' query param is required")

        if typ == "kel":
            pre = req.get_param("pre")

            if not pre:
                raise falcon.HTTPBadRequest(description="'pre' query param is required")

            evnts = bytearray()

            sn = req.get_param_as_int("sn")
            if sn is not None: ## query for event with seq-num >= sn
                dig = self.hab.db.kels.getLast(keys=pre, on=sn)
                if dig is None:
                    raise falcon.HTTPBadRequest(description=f"non-existant event at seq-num {sn}")
                for dig in self.hab.db.kels.getAllIter(keys=pre, on=sn):
                    try:
                        dig = dig.encode("utf-8")
                        msg = self.hab.db.cloneEvtMsg(pre=pre, fn=0, dig=dig)
                    except Exception:
                        continue  # skip this event
                    evnts.extend(msg)
            else:
                for msg in self.hab.db.clonePreIter(pre=pre):
                    evnts.extend(msg)


            rep.set_header('Content-Type', CESR_CONTENT_TYPE)
            rep.status = falcon.HTTP_200
            rep.data = bytes(evnts)

        elif typ == "tel":
            regk = req.get_param("reg")
            vcid = req.get_param("vcid")

            if not regk and not vcid:
                raise falcon.HTTPBadRequest(description="Either 'reg' or 'vcid' query param is required for TEL query")

            evnts = bytearray()
            if regk is not None:
                cloner = self.reger.clonePreIter(pre=regk)
                for msg in cloner:
                    evnts.extend(msg)

            if vcid is not None:
                cloner = self.reger.clonePreIter(pre=vcid)
                for msg in cloner:
                    evnts.extend(msg)

            rep.set_header('Content-Type', CESR_CONTENT_TYPE)
            rep.status = falcon.HTTP_200
            rep.data = bytes(evnts)

        else:
            rep.set_header('Content-Type', "application/json")
            rep.text = "unkown query type."
            rep.status = falcon.HTTP_400

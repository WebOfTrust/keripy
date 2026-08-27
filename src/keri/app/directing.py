# -*- encoding: utf-8 -*-
"""
KERI
keri.app.directing module

simple direct mode demo support classes
"""
import itertools
from hio.base import doing

from .. import help, kering
from ..core import eventing, routing
from ..core import parsing
from ..vdr.eventing import Tevery

logger = help.ogler.getLogger()


class Director(doing.Doer):
    """
    Base class for Direct Mode KERI Controller Doer with habitat and TCP Client

    Attributes:
        hab (Habitat: local controller's context
        client (serving.Client): hio TCP client instance.
            Assumes operated by another doer.

    Inherited Properties:
        tyme (float): relative cycle time of associated Tymist, obtained
            via injected .tymth function wrapper closure.
        tymth (function): function wrapper closure returned by Tymist .tymeth()
            method.  When .tymth is called it returns associated Tymist .tyme.
            .tymth provides injected dependency on Tymist tyme base.
        tock (float): desired time in seconds between runs or until next run,
            non negative, zero means run asap

    Properties:

    Inherited Methods:
        .__call__ makes instance callable return generator
        .do is generator function returns generator

    Methods:

    Hidden:
       ._tymth is injected function wrapper closure returned by .tymen() of
            associated Tymist instance that returns Tymist .tyme. when called.
       ._tock is hidden attribute for .tock property
    """

    def __init__(self, hab, client, **kwa):
        """
        Initialize instance.

        Inherited Parameters:
            tymist is  Tymist instance
            tock is float seconds initial value of .tock

        Parameters:
            hab is Habitat instance
            client is TCP Client instance. Assumes opened/closed elsewhere

        """
        super(Director, self).__init__(**kwa)
        self.hab = hab
        self.client = client  # use client to initiate comms
        if self.tymth:
            self.client.wind(self.tymth)

    def wind(self, tymth):
        """
        Inject new tymist.tymth as new ._tymth. Changes tymist.tyme base.
        Updates winds .tymer .tymth
        """
        super(Director, self).wind(tymth)
        self.client.wind(tymth)

    def sendOwnEvent(self, sn):
        """
        Utility to send own event at sequence number sn
        """
        msg = self.hab.makeOwnEvent(sn=sn)
        # send to connected remote
        self.client.tx(msg)
        logger.info("%s: %s sent event:\n%s\n\n", self.hab.name, self.hab.pre, bytes(msg))

    def sendOwnInception(self):
        """
        Utility to send own inception on client
        """
        self.sendOwnEvent(sn=0)


class Reactor(doing.DoDoer):
    """
    Reactor Subclass of DoDoer with doers list from do generator methods:
        .msgDo, .cueDo, and  .escrowDo.
    Enables continuous scheduling of doers (do generator instances or functions)

    Implements Doist like functionality to allow nested scheduling of doers.
    Each DoDoer runs a list of doers like a Doist but using the tyme from its
       injected tymist as injected by its parent DoDoer or Doist.

    Scheduling hierarchy: Doist->DoDoer...->DoDoer->Doers

    Inherited Attributes:
        .done is Boolean completion state:
            True means completed
            Otherwise incomplete. Incompletion maybe due to close or abort.
        .opts is dict of injected options for its generator .do
        .doers is list of Doers or Doer like generator functions

    Attributes:
        .hab is Habitat instance of local controller's context
        .client is TCP Client instance.
        .kevery is Kevery instance


    Inherited Properties:
        .tyme is float relative cycle time of associated Tymist .tyme obtained
            via injected .tymth function wrapper closure.
        .tymth is function wrapper closure returned by Tymist .tymeth() method.
            When .tymth is called it returns associated Tymist .tyme.
            .tymth provides injected dependency on Tymist tyme base.
        .tock is float, desired time in seconds between runs or until next run,
                 non negative, zero means run asap

    Properties:

    Inherited Methods:
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

    Overidden Methods:

    Hidden:
       ._tymth is injected function wrapper closure returned by .tymen() of
            associated Tymist instance that returns Tymist .tyme. when called.
       ._tock is hidden attribute for .tock property

    """

    def __init__(self, hab, client, verifier=None, exchanger=None, direct=True, doers=None, **kwa):
        """
        Initialize instance.

        Inherited Parameters:
            tymist is  Tymist instance
            tock is float seconds initial value of .tock
            doers is list of doers (do generator instances, functions or methods)

        Parameters:
            hab is Habitat instance of local controller's context
            client is TCP Client instance
            verifier is Verifier instance of local controller's TEL context
            direct is Boolean, True means direct mode so process cue'd receipts
                    False means indirect mode so don't process cue'ed receipts

        """
        self.hab = hab
        self.client = client  # use client for both rx and tx
        self.verifier = verifier
        self.exc = exchanger
        self.direct = True if direct else False
        doers = doers if doers is not None else []
        doers.extend([doing.doify(self.msgDo, tock=hab.tocks["reactorMsg"]),
                      doing.doify(self.escrowDo, tock=hab.tocks["reactorEscrow"]),
                      doing.doify(self.cueDo, tock=hab.tocks["reactorCue"])])

        self.kevery = eventing.Kevery(db=self.hab.db,
                                      lax=False,
                                      local=False,
                                      direct=self.direct)

        if self.verifier is not None:
            self.tvy = Tevery(reger=self.verifier.reger,
                              db=self.hab.db,
                              local=False)
        else:
            self.tvy = None

        self.parser = parsing.Parser(ims=self.client.rxbs,
                                     framed=True,
                                     kvy=self.kevery,
                                     tvy=self.tvy,
                                     exc=self.exc)


        super(Reactor, self).__init__(doers=doers, **kwa)
        if self.tymth:
            self.client.wind(self.tymth)

    def wind(self, tymth):
        """
        Inject new tymist.tymth as new ._tymth. Changes tymist.tyme base.
        Updates winds .tymer .tymth
        """
        super(Reactor, self).wind(tymth)
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
        self.wind(tymth)
        _ = (yield tock)  # enter context
        if self.parser.ims:
            logger.info("Client %s received:\n%s\n...\n", self.hab.name, self.parser.ims[:1024])
        parser = self.parser.parsator(local=True)
        while True:
            try:
                next(parser)
            except StopIteration as ex:
                return ex.value  # should never get here except forced close
            yield tock


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
        self.wind(tymth)
        _ = (yield tock)  # enter context
        while True:
            for msg in self.hab.processCuesIter(self.kevery.cues):
                self.sendMessage(msg, label="chit or receipt")
                yield tock  # throttle just do one cue at a time
            yield tock
        return False  # should never get here except forced close

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
        self.wind(tymth)
        _ = (yield tock)  # enter context
        while True:
            self.kevery.processEscrows()
            if self.tvy is not None:
                self.tvy.processEscrows()
            yield tock
        return False  # should never get here except forced close

    def sendMessage(self, msg, label=""):
        """
        Sends message msg and loggers label if any
        """
        self.client.tx(msg)  # send to remote
        logger.info("%s sent %s:\n%s\n\n", self.hab.name, label, bytes(msg))


class Directant(doing.DoDoer):
    """Supervise inbound direct-mode TCP connections with one Reactant each.

    HIO owns each accepted raw-TCP ``Remoter`` while Directant owns its
    corresponding ``Reactant`` application lifecycle. HIO ``cutoff`` means only
    that receive is closed, so it is a transition into draining rather than
    permission to discard accepted input or generated responses. HIO
    ``txCutoff`` independently reports that sending has become terminal.

    HIO may remove a Remoter after a transport error. Before scheduling its
    children, Directant removes any Reactant whose exact Remoter is no longer
    registered at its connection address.

    During draining, Directant waits for the active parser to end or fail,
    response production to settle, and ``txbs`` to empty. Terminal ``txCutoff``
    or an absolute, non-refreshing deadline may end draining as an explicit
    failure; the parser, producer, and unsent-output state is logged before
    removal.
    These are local lifecycle facts and do not prove remote processing or
    durable storage.

    Doer generator methods:
        .serviceDo

    Attributes:
        hab: Local habitat whose database and routing context process messages.
        server: TCP server containing active Remoters in ``server.ixes``.
        rants: Reactants indexed by their Remoter connection addresses.
        drainTymeout: Positive whole-drain deadline duration in seconds.
        drainStops: Absolute, non-refreshing stop tyme for each draining Remoter.
    """

    DrainTymeout = 30.0  # force TCP teardown, bounding txbs drain after peer/local EOF

    def __init__(self, hab, server, verifier=None, exchanger=None, doers=None,
                 drainTymeout=None, **kwa):
        """Initialize the supervisor for an existing raw-TCP server.

        Parameters:
            hab: Local habitat used to construct per-connection Reactants.
            server: TCP server whose accepted Remoters are supervised.
            verifier: Optional TEL verifier supplied to each Reactant.
            exchanger: Optional EXN exchanger supplied to each Reactant.
            doers: Additional doers to run alongside ``serviceDo``.
            drainTymeout: Positive whole-drain deadline in seconds. Defaults to
                ``DrainTymeout`` and is independent of the Remoter idle timer.
        """
        self.hab = hab
        self.verifier = verifier
        self.exchanger = exchanger
        self.server = server  # use server for cx
        self.rants = dict()
        self.drainTymeout = (float(drainTymeout) if drainTymeout is not None
                             else self.DrainTymeout)
        if not 0.0 < self.drainTymeout < float("inf"):
            raise ValueError("drainTymeout must be finite and positive")
        self.drainStops = dict()
        doers = doers if doers is not None else []
        doers.extend([doing.doify(self.serviceDo)])
        super(Directant, self).__init__(doers=doers, **kwa)
        if self.tymth:
            self.server.wind(self.tymth)

    def wind(self, tymth):
        """Propagate a scheduler time base to this doer and its TCP server.

        Parameters:
            tymth: Callable returning the scheduler's current time.
        """
        super(Directant, self).wind(tymth)
        self.server.wind(tymth)

    def recur(self, tyme, deeds=None):
        """Reconcile transport-owned connections before scheduling children."""
        self._reconcileStaleReactants()
        return super(Directant, self).recur(tyme=tyme, deeds=deeds)

    def _reconcileStaleReactants(self):
        """Remove Reactants whose Remoters left the HIO connection registry."""
        for ca, rant in list(self.rants.items()):
            if self.server.ixes.get(ca) is rant.remoter:
                continue

            ix = rant.remoter
            if (ix.rxbs or ix.txbs or rant.messageInProgress or
                    not rant.responseSettled):
                self._logDrainFailure(ca=ca, ix=ix, rant=rant,
                                      reason="transport removed connection")

            self.remove([rant])
            del self.rants[ca]
            self.drainStops.pop(ca, None)

    def serviceDo(self, tymth=None, tock=0.0, **opts):
        """Create, retain, drain, and remove per-connection Reactants.

        Each recurrence inspects the server's active Remoters. Peer receive EOF
        enters draining immediately. A transmit-only failure or expired idle
        timer first services bytes already waiting at the socket and then calls
        ``shutdownReceive()``; directional HIO keeps ordinary sends enabled.

        The first draining transition records one absolute deadline. Buffered
        input gets a Reactant even when receive closed before construction.
        Connections remain scheduled until ingress and response production
        settle and either ``txbs`` empties or ``txCutoff`` makes sending
        terminal. The whole-drain deadline bounds parser, producer, and egress
        work and logs their remaining state before forced removal.

        A receive-closed Remoter with no Reactant and no input closes
        immediately. Any queued ``txbs`` is logged as output without an
        application owner instead of creating a speculative drain phase.

        Yields:
            Once per connection-supervision recurrence.
        """
        yield  # enter context
        while True:
            for ca, ix in list(self.server.ixes.items()):
                if not ix.cutoff:
                    if ix.txCutoff:
                        # Sending is terminal. Accept any bytes already waiting
                        # at the socket before closing the receive direction.
                        ix.serviceReceives()
                        ix.shutdownReceive()
                    elif ix.tymeout > 0.0 and ix.tymer.expired:
                        # Receive once before enforcing inactivity so bytes at
                        # the boundary may refresh the Remoter timer.
                        ix.serviceReceives()
                        if not ix.cutoff and ix.tymer.expired:
                            ix.shutdownReceive()

                if ca not in self.rants and ix.cutoff and not ix.rxbs:
                    if ix.txbs:
                        reason = ("transmit cutoff" if ix.txCutoff else
                                  "queued output without Reactant")
                        self._logDrainFailure(ca=ca, ix=ix, reason=reason)
                    self.closeConnection(ca)
                    continue

                if ix.cutoff and ca not in self.drainStops:
                    self.drainStops[ca] = self.tyme + self.drainTymeout

                if ca not in self.rants:  # create Reactant and extend doers with it
                    rant = Reactant(tymth=self.tymth, hab=self.hab, verifier=self.verifier,
                                    exchanger=self.exchanger, remoter=ix)
                    self.rants[ca] = rant
                    # add Reactant (rant) doer to running doers
                    self.extend(doers=[rant])  # open and run rant as doer

                if ix.cutoff:
                    rant = self.rants[ca]
                    rxSettled = rant.rxDrained or rant.rxFailed
                    outputDrained = rant.responseSettled and not ix.txbs
                    deadlineExpired = self.tyme >= self.drainStops[ca]

                    if rxSettled and outputDrained:
                        self.closeConnection(ca)
                    elif rxSettled and ix.txCutoff:
                        self._logDrainFailure(ca=ca, ix=ix, rant=rant,
                                              reason="transmit cutoff")
                        self.closeConnection(ca)
                    elif deadlineExpired:
                        self._logDrainFailure(ca=ca, ix=ix, rant=rant,
                                              reason="drain deadline expired")
                        self.closeConnection(ca)

            yield

    @staticmethod
    def _logDrainFailure(ca, ix, reason, rant=None):
        """Log application and transport work abandoned by terminal close.

        Parameters:
            ca: Connection address used by ``server.ixes``.
            ix: Remoter whose accepted or queued bytes are being abandoned.
            reason: Stable human-readable terminal close reason.
            rant: Optional Reactant containing parser and producer state.
        """
        logger.error("Closing direct connection %s after %s; "
                     "rxbs=%d, messageInProgress=%s, responseSettled=%s, "
                     "txbs=%d, txCutoff=%s",
                     ca,
                     reason,
                     len(ix.rxbs),
                     rant.messageInProgress if rant is not None else False,
                     rant.responseSettled if rant is not None else True,
                     len(ix.txbs),
                     ix.txCutoff)

    def closeConnection(self, ca):
        """Remove a settled or explicitly failed Remoter and its Reactant.

        ``serviceDo`` calls this after successful ingress/producer/egress
        settlement, terminal transmit failure, or whole-drain deadline expiry.
        It never performs an opportunistic final send; recurrent send service
        belongs to the server doer before this terminal removal.

        Parameters:
            ca: Connection address used by ``server.ixes``, ``rants``, and
                ``drainStops``.
        """
        if ca in self.server.ixes:  # remoter still there
            self.server.removeIx(ca)
        if ca in self.rants:  # remove rant (Reactant) if any
            self.remove([self.rants[ca]])  # close and remove rant from doers list
            del self.rants[ca]
        self.drainStops.pop(ca, None)


class Reactant(doing.DoDoer):
    """Process one accepted direct-mode TCP connection.

    Each Reactant binds a per-connection Parser to KEL, optional TEL, EXN, and
    reply handlers. The Parser consumes the same mutable byte buffer exposed as
    both ``remoter.rxbs`` and ``parser.ims``. ``msgDo`` dispatches inbound CESR
    messages, ``cueDo`` queues protocol responses on the same Remoter, and
    ``escrowDo`` advances deferred event processing. Directant owns the
    Reactant's lifetime.

    ``messageInProgress`` distinguishes a true empty message boundary from a
    parser that has consumed bytes but still needs a body or attachments.
    ``responseSettled`` combines queued cues with the active cue iterator so a
    temporary empty cue deque cannot look settled between response fragments.

    Attributes:
        hab: Local habitat providing the database and protocol context.
        remoter: TCP connection used for both inbound and outbound bytes.
        parser: Per-connection CESR parser backed by ``remoter.rxbs``.
        messageInProgress: Whether one CESR message awaits completion.
        cueInProgress: Whether a popped cue may still generate more output.
        rxError: Terminal error for incomplete input at receive cutoff.
    """

    def __init__(self, hab, remoter, verifier=None, exchanger=None, doers=None, **kwa):
        """Initialize protocol handlers for one accepted TCP connection.

        Parameters:
            hab: Local habitat whose database receives parsed protocol state.
            remoter: Accepted TCP Remoter supplying the shared receive buffer.
            verifier: Optional TEL verifier used to construct a Tevery.
            exchanger: Optional EXN exchanger registered with the Parser.
            doers: Additional doers to run with message, cue, and escrow work.
        """
        self.hab = hab
        self.verifier = verifier
        self.exchanger = exchanger
        self.remoter = remoter  # use remoter for both rx and tx
        self.messageInProgress = False
        self.cueInProgress = False
        self.rxError = None

        doers = doers if doers is not None else []
        doers.extend([doing.doify(self.msgDo, tock=hab.tocks["reactantMsg"]),
                      doing.doify(self.cueDo, tock=hab.tocks["reactantCue"]),
                      doing.doify(self.escrowDo, tock=hab.tocks["reactantEscrow"])])

        #  needs unique kevery with ims per remoter connnection
        rvy = routing.Revery(db=hab.db)
        self.kevery = eventing.Kevery(db=self.hab.db,
                                      lax=False,
                                      local=False,
                                      rvy=rvy)

        if self.verifier is not None:
            self.tevery = Tevery(reger=self.verifier.reger,
                                 db=self.hab.db,
                                 local=False, rvy=rvy)
            self.tevery.registerReplyRoutes(router=rvy.rtr)
        else:
            self.tevery = None

        self.kevery.registerReplyRoutes(router=rvy.rtr)

        self.parser = parsing.Parser(ims=self.remoter.rxbs,
                                     framed=True,
                                     kvy=self.kevery,
                                     tvy=self.tevery,
                                     exc=self.exchanger,
                                     rvy=rvy)

        super(Reactant, self).__init__(doers=doers, **kwa)
        if self.tymth:
            self.remoter.wind(self.tymth)

    def wind(self, tymth):
        """Propagate a scheduler time base to this doer and its Remoter.

        Parameters:
            tymth: Callable returning the scheduler's current time.
        """
        super(Reactant, self).wind(tymth)
        self.remoter.wind(tymth)

    def msgDo(self, tymth=None, tock=0.0, **opts):
        """Incrementally parse and dispatch complete inbound CESR messages.

        Parsing starts only after the first byte arrives. A local
        ``onceParsator`` then runs until one complete message and its attachments
        have been dispatched. Normal iterator completion marks a message
        boundary; a yield means the parser needs more bytes.

        ``messageInProgress`` remains true during that wait, so destructively
        consumed input and an empty ``parser.ims`` cannot be mistaken for drain.
        If receive has closed when the parser yields, the active message fails
        with ``ShortageError`` reporting the remaining buffered byte count
        before the unusable remainder is cleared.

        Complete buffered successors continue one message per recurrence until
        ``rxDrained`` reaches a successful empty boundary.

        Yields:
            The configured ``tock`` while idle and after each parser step.
        """
        self.wind(tymth)
        _ = (yield tock)  # enter context
        while True:
            while not self.parser.ims:
                yield tock

            logger.info("Server %s: received:\n%s\n...\n", self.hab.name,
                        self.parser.ims[:1024])
            messageParser = self.parser.onceParsator(local=True)
            self.messageInProgress = True
            try:
                while True:
                    try:
                        next(messageParser)
                    except StopIteration:
                        break

                    if self.remoter.cutoff:
                        remaining = len(self.parser.ims)
                        self.rxError = kering.ShortageError(
                            f"incomplete CESR message at EOF from "
                            f"{self.remoter.ca}; {remaining} buffered bytes remain")
                        del self.parser.ims[:]
                        logger.error(str(self.rxError))
                        break

                    yield tock
            finally:
                messageParser.close()
                self.messageInProgress = False

            yield tock

    @property
    def rxDrained(self):
        """Whether parsing is at a successful empty message boundary.

        True requires no receiver error, no message in progress, and no bytes
        in ``parser.ims``. Directant treats this as terminal only after receive
        closure; an open idle connection may receive more.
        """
        return self.rxError is None and not self.messageInProgress and not self.parser.ims

    @property
    def rxFailed(self):
        """Whether receive closure exposed an incomplete CESR message."""
        return self.rxError is not None

    @property
    def responseSettled(self):
        """Whether queued and active response production is locally settled."""
        return not self.cueInProgress and not self.kevery.cues

    def cueDo(self, tymth=None, tock=0.0, **opts):
        """Generate and queue protocol responses from Kevery cues.

        ``hab.processCuesIter`` may produce one or more messages for a cue.
        ``cueInProgress`` remains true across every yielded response so
        ``responseSettled`` stays false after the cue has been popped.
        Fragment lists are flattened before each response is queued, and one
        scheduler yield follows every response.

        Queueing bytes on the Remoter proves neither transport delivery nor peer
        processing.

        Yields:
            The configured ``tock`` after each response and while no cues exist.
        """
        self.wind(tymth)
        _ = (yield tock)  # enter context
        while True:
            self.cueInProgress = bool(self.kevery.cues)
            try:
                for msg in self.hab.processCuesIter(self.kevery.cues):
                    if isinstance(msg, list):
                        msg = bytearray(itertools.chain(*msg))

                    self.sendMessage(msg, label="chit or receipt or replay")
                    yield tock  # throttle just do one cue at a time
            finally:
                self.cueInProgress = False
            yield tock
        return False  # should never get here except forced close

    def escrowDo(self, tymth=None, tock=0.0, **opts):
        """Advance deferred KEL and optional TEL processing once per recurrence.

        Escrow processing may unblock protocol validation, but it does not define
        the receiver-drain boundary and does not control connection teardown.

        Yields:
            The configured ``tock`` after each escrow-processing pass.
        """
        self.wind(tymth)
        _ = (yield tock)  # enter context
        while True:
            self.kevery.processEscrows()
            if self.tevery is not None:
                self.tevery.processEscrows()
            yield tock
        return False  # should never get here except forced close

    def sendMessage(self, msg, label=""):
        """Queue response bytes on the Remoter and log the local operation.

        Returning means only that bytes entered the local transport buffer; it
        is not acknowledgement of transport drain or peer processing.

        Parameters:
            msg: Bytes to queue on the connection.
            label: Optional description included in the log entry.
        """
        self.remoter.tx(msg)  # send to remote
        logger.info("Server %s: sent %s:\n%d\n\n", self.hab.name,
                    label, len(msg))


def runController(doers, expire=0.0):
    """
    Utiitity Function to create doist to run doers
    """
    tock = 0.03125
    doist = doing.Doist(limit=expire, tock=tock, real=True)
    doist.do(doers=doers)

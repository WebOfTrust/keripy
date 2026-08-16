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
    """Supervise inbound direct-mode TCP connections with Reactant per connection.

    Directant owns per-connection ``Remoter`` lifetimes and its one corresponding
    ``Reactant``. A peer cutoff or local connection timeout is a request to close,
    not a parsing completion signal for already accepted bytes from the socket.
    When buffered input exists, ``serviceDo`` preserves or creates the Reactant
    and waits for receiver completion. Responses generated by that input must
    also drain from the Remoter, or reach terminal send failure, before removal.

    Doer generator methods:
        .serviceDo

    Attributes:
        hab: Local habitat whose database and routing context process messages.
        server: TCP server containing active Remoters in ``server.ixes``.
        rants: Reactants indexed by their Remoter connection addresses.
        closeReq: Connection addresses whose receive side is closed.
        txFailed: Connection addresses whose remaining output cannot be sent.
    """

    def __init__(self, hab, server, verifier=None, exchanger=None, doers=None, **kwa):
        """Initialize the supervisor for an existing TCP server.

        Parameters:
            hab: Local habitat used to construct per-connection Reactants.
            server: TCP server whose accepted Remoters are supervised.
            verifier: Optional TEL verifier supplied to each Reactant.
            exchanger: Optional EXN exchanger supplied to each Reactant.
            doers: Additional doers to run alongside ``serviceDo``.
        """
        self.hab = hab
        self.verifier = verifier
        self.exchanger = exchanger
        self.server = server  # use server for cx
        self.rants = dict()
        self.closeReq = set()
        self.txFailed = set()
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


    def serviceDo(self, tymth=None, tock=0.0, **opts):
        """For each TCP connection and Remoter pair from the HIO Server, create,
        retain, and clean up corresponding per-connection Reactants.

        Each recur inspects the server's active Remoters. Before turning
        an expired connection into a close request, it services pending receives
        once so new activity can refresh the timeout. A cutoff Remoter with
        buffered bytes is assigned a Reactant even when cutoff was observed
        before that Reactant could be created so received bytes may be parsed.

        Close-requested connections remain scheduled until inbound parsing
        reports ``rxDrained`` or ``rxFailed`` and outbound response cues have
        drained or sending has failed. Peer EOF is ``cutoff``; local timeout
        uses separate receive-closed state so it does not make HIO's send path
        unwritable.

        Yields:
            Once per connection-supervision recurrence.
        """
        yield tock  # enter context
        while True:
            for ca, ix in list(self.server.ixes.items()):
                # Cleanup check - which connections to request close
                if ix.cutoff:
                    self.closeReq.add(ca)
                if (ca not in self.closeReq and
                        ix.tymeout > 0.0 and
                        ix.tymer.expired):
                    # final, opportunistic socket drain cleanup prior to idle timeout enforcement
                    # avoids discarding received socket bytes on Directant shutdown before this
                    # turns into a close request. TCP receive refreshes the timer, canceling close.
                    ix.serviceReceives()
                    if ix.cutoff:
                        self.closeReq.add(ca)
                    elif ix.tymer.expired:
                        ix.shutdownReceive()
                        self.closeReq.add(ca)

                # Create - add Reactants for new connections
                if ca not in self.rants:  # create Reactant when input needs parsing
                    if ca in self.closeReq and not ix.rxbs:
                        if ix.txbs:
                            self._serviceSends(ca)
                        if not ix.txbs or ca in self.txFailed:
                            self.closeConnection(ca)
                        continue

                    rant = Reactant(tymth=self.tymth, hab=self.hab, verifier=self.verifier,
                                    exchanger=self.exchanger, remoter=ix)
                    self.rants[ca] = rant
                    # add Reactant (rant) doer to running doers
                    self.extend(doers=[rant])  # open and run rant as doer

                # Perform clean up - connections with a close request
                if ca in self.closeReq:
                    rant = self.rants[ca]
                    rant.rxClosed = True

                    if ix.txbs:
                        self._serviceSends(ca)

                    # if both TCP receive and send finish or fail, then close
                    if ((rant.rxDrained or rant.rxFailed) and
                            (rant.txDrained or ca in self.txFailed)):
                        self.closeConnection(ca)  # also removes rant

            yield tock

    def _serviceSends(self, ca):
        """Advance pending output once after receive closure.

        HIO uses ``Remoter.cutoff`` for receive EOF and suppresses
        ``serviceSends`` while it is true, even though a half-closed TCP peer
        may still receive. Temporarily clear that guard for one nonblocking
        send attempt, then restore the peer-cutoff fact. A send-side cutoff or
        ``OSError`` is terminal for the remaining output.
        """
        ix = self.server.ixes[ca]
        cutoff = ix.cutoff
        ix.cutoff = False
        try:
            ix.serviceSends()
        except OSError as ex:
            self.txFailed.add(ca)
            ix.cutoff = True
            logger.error("Unable to finish sending to %s: %s", ca, ex)
        else:
            if ix.cutoff:
                self.txFailed.add(ca)
                logger.error("Unable to finish sending to %s", ca)
        finally:
            ix.cutoff = cutoff or ix.cutoff

    def closeConnection(self, ca):
        """Remove a terminal Remoter and its Reactant from the scheduler.

        ``serviceDo`` calls this only after receiver TCP processing and response
        transmission have both reached successful or failed terminal states.

        Parameters:
            ca: Connection address used as the key in ``server.ixes`` and
                ``rants``.
        """
        if ca in self.server.ixes:
            self.server.removeIx(ca)
        if ca in self.rants:  # remove rant (Reactant) if any
            self.remove([self.rants[ca]])  # close and remove rant from doers list
            del self.rants[ca]
        self.closeReq.discard(ca)
        self.txFailed.discard(ca)


class Reactant(doing.DoDoer):
    """Process one accepted direct-mode TCP connection.

    Each Reactant binds a per-connection Parser to KEL, optional TEL, EXN, and
    reply handlers. The Parser consumes the same mutable byte buffer exposed as both
    ``remoter.rxbs`` and ``parser.ims``. ``msgDo`` dispatches inbound CESR
    messages, ``cueDo`` queues protocol responses on the same Remoter, and
    ``escrowDo`` advances deferred event processing. Directant owns the
    Reactant's lifetime and removes it only after receiver and response-output
    completion or failure.

    ``msgInProgress`` distinguishes a true empty message boundary from a parser
    that has consumed the available bytes but still needs attachments. Together
    with ``rxError`` and the remaining ``parser.ims`` bytes, it defines the
    ``rxDrained`` and ``rxFailed`` receiver contract. ``txDrained`` additionally
    requires every generated response cue to be queued and the send buffer empty.

    Attributes:
        hab: Local habitat providing the database and protocol context.
        remoter: TCP connection used for both inbound and outbound bytes.
        parser: Per-connection CESR parser backed by ``remoter.rxbs``.
        msgInProgress: Whether one CESR message is awaiting completion.
        rxClosed: Whether Directant has stopped accepting input.
        rxError: Terminal error for an incomplete message observed at EOF.
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
        self.msgInProgress = False
        self.rxClosed = False
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

        Parsing starts only after the first byte arrives. A local ``onceParsator``
        then continues until one complete message and its attachments have been
        dispatched. Normal iterator completion marks a message boundary; a yielded
        iterator is waiting for more bytes. ``msgInProgress`` remains true during
        that wait, so an empty ``parser.ims`` alone cannot be mistaken for receiver drain.

        While the connection is open, a shortage simply yields for more input.
        After peer cutoff or local receive closure, no more input can arrive,
        so the same shortage becomes a terminal ``ShortageError``: the
        unusable remainder is cleared and
        ``rxFailed`` allows Directant to tear down the connection. Complete
        buffered messages continue one at a time until ``rxDrained`` becomes
        true.

        Yields:
            The configured ``tock`` while idle and after each parser step.
        """
        self.wind(tymth)
        _ = (yield tock)  # enter context
        while True:
            while not self.parser.ims:  # wait on initial message bytes
                yield tock

            logger.info("Server %s: received:\n%s\n...\n", self.hab.name,
                        self.parser.ims[:1024])
            msgParser = self.parser.onceParsator(local=True)
            self.msgInProgress = True
            try:  # parse a single, complete message
                while True:
                    try:
                        next(msgParser)
                    except StopIteration:
                        # One complete message parsed and dispatched.
                        # This boundary is the receiver completion signal.
                        break

                    # onceParsator yields only when it needs more bytes.
                    # After receive closure those bytes cannot arrive, so fail.
                    if self.rxClosed or self.remoter.cutoff:
                        remaining = len(self.parser.ims)
                        self.rxError = kering.ShortageError(
                            f"incomplete CESR message at EOF from "
                            f"{self.remoter.ca}; {remaining} buffered bytes remain"
                        )
                        del self.parser.ims[:]
                        logger.error(str(self.rxError))
                        break

                    # Preserve one parser step per scheduler recurrence.
                    yield tock
            finally:
                msgParser.close()
                self.msgInProgress = False

            # One msg parser step per scheduler tick following terminal completion or failure.
            yield tock

    @property
    def rxDrained(self):
        """Whether parsing is at a successful empty message boundary.

        True requires no receiver error, no message in progress, and no bytes
        in ``parser.ims``. Directant treats this as terminal only after the
        Remoter has reported cutoff; an open idle connection may receive more.
        """
        return (self.rxError is None and
                not self.msgInProgress and
                not self.parser.ims)

    @property
    def rxFailed(self):
        """Whether EOF exposed a terminally incomplete CESR message."""
        return self.rxError is not None

    @property
    def txDrained(self):
        """Whether all generated responses reached an empty send buffer."""
        return not self.kevery.cues and not self.remoter.txbs


    def cueDo(self, tymth=None, tock=0.0, **opts):
        """Generate and queue protocol responses from Kevery cues.

        ``hab.processCuesIter`` converts each cue into response bytes. Fragment
        lists are flattened before the response is queued on the connection,
        and yielding after every response limits work to one cue per recurrence.
        Queueing bytes on the Remoter does not prove transport delivery or peer
        processing.

        Yields:
            The configured ``tock`` after each response and while no cues exist.
        """
        self.wind(tymth)
        _ = (yield tock)  # enter context
        while True:
            for msg in self.hab.processCuesIter(self.kevery.cues):
                if isinstance(msg, list):
                    msg = bytearray(itertools.chain(*msg))

                self.sendMessage(msg, label="chit or receipt or replay")
                yield tock  # throttle just do one cue at a time
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

        Returning means only that the bytes were added to the local transport;
        it is not acknowledgement of transport drain or peer processing.

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

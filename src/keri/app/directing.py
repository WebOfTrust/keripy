# -*- encoding: utf-8 -*-
"""
KERI
keri.app.directing module

simple direct mode demo support classes

"""
import itertools
from hio.base import doing
from hio.help import ogler

from .. import Vrsn_1_0
from ..core import Kevery, Revery, Parser
from ..vdr import Tevery

logger = ogler.getLogger()


class Director(doing.Doer):
    """Base class for Direct Mode KERI Controller Doer with habitat and TCP client.

    Attributes:
        hab (Habitat): Local controller's Habitat instance.
        client (Client): hio TCP client instance. Assumed to be operated
            by a separate doer.

    Inherited Properties:
        tyme (float): relative cycle time of associated Tymist, obtained
            via injected .tymth function wrapper closure.
        tymth (function): function wrapper closure returned by Tymist .tymeth()
            method.  When .tymth is called it returns associated Tymist .tyme.
            .tymth provides injected dependency on Tymist tyme base.
        tock (float): desired time in seconds between runs or until next run,
            non negative, zero means run asap

    Inherited Methods:
        .__call__ makes instance callable return generator
        .do is generator function returns generator

    Hidden:
       ._tymth is injected function wrapper closure returned by .tymen() of
            associated Tymist instance that returns Tymist .tyme. when called.

       ._tock is hidden attribute for .tock property
    """

    def __init__(self, hab, client, **kwa):
        """Initialize instance.

        Parameters:
            tymist (Tymist): Tymist instance.
            tock (float): Seconds initial value of .tock.
            hab (Habitat): Habitat instance.
            client (Client): TCP Client instance. Assumes opened/closed elsewhere.
        """
        super(Director, self).__init__(**kwa)
        self.hab = hab
        self.client = client  # use client to initiate comms
        if self.tymth:
            self.client.wind(self.tymth)

    def wind(self, tymth):
        """Inject new tymist.tymth as new ._tymth. Changes tymist.tyme base.
        
        Updates winds .tymer .tymth
        """
        super(Director, self).wind(tymth)
        self.client.wind(tymth)

    def sendOwnEvent(self, sn):
        """Utility to send own event at sequence number sn"""
        msg = self.hab.makeOwnEvent(sn=sn)
        # send to connected remote
        self.client.tx(msg)
        logger.info("%s: %s sent event:\n%s\n\n", self.hab.name, self.hab.pre, bytes(msg))

    def sendOwnInception(self):
        """Utility to send own inception on client"""
        self.sendOwnEvent(sn=0)


class Reactor(doing.DoDoer):
    """
    Reactor Subclass of DoDoer with doers list from do generator methods: .msgDo, .cueDo, and .escrowDo.
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
        hab (Habitat): Local controller's Habitat instance.
        client (TCP Client): TCP client used for both receive and transmit.
        verifier (Verifier): Optional Verifier instance for TEL context.
            None if TEL processing is not required.
        exc: Optional Exchanger instance for peer-to-peer key-event exchange
            messages. None if not required.
        direct (bool): True means direct mode; cue'd receipts are processed
            immediately. False means indirect mode; cue'd receipts are skipped.
        kevery (Kevery): Event processor for incoming key events.
        tvy (Tevery): Event processor for incoming transaction events.
            None when verifier is None.
        parser (Parser): Stream parser bound to client.rxbs.
        done (bool): Completion state set by DoDoer. True means completed
            normally. False or None means incomplete.
        opts (dict): Injected options passed to the .do generator.
        doers (list): Scheduled Doer instances or generator functions.

    Inherited Properties:
        .tyme is float relative cycle time of associated Tymist .tyme obtained
            via injected .tymth function wrapper closure.

        .tymth is function wrapper closure returned by Tymist .tymeth() method.
            When .tymth is called it returns associated Tymist .tyme.
            .tymth provides injected dependency on Tymist tyme base.

        .tock is float, desired time in seconds between runs or until next run,
            non negative, zero means run asap

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

    Hidden:
       ._tymth is injected function wrapper closure returned by .tymen() of
            associated Tymist instance that returns Tymist .tyme. when called.

       ._tock is hidden attribute for .tock property
    """

    def __init__(self, hab, client, verifier=None, exchanger=None, direct=True, doers=None, **kwa):
        """Initialize instance and extend doers with msgDo, escrowDo, cueDo.

        Inherited Parameters:
            tymist is  Tymist instance
            tock is float seconds initial value of .tock
            doers is list of doers (do generator instances, functions or methods)

        Parameters:
            hab (Habitat): Local controller's Habitat instance.
            client (TCP Client): TCP client used for both receive and transmit.
            verifier (Verifier): Verifier instance providing TEL
                context. When provided a Tevery is created and bound to the
                parser. Defaults to None.
            exchanger: Exchanger instance for exn message processing. Defaults to None.
            direct (bool): True to process cue'd receipts in direct
                mode. False to skip cue'd receipt processing. Defaults to True.
            doers (list): Initial list of Doer instances or generator
                functions to schedule. msgDo, escrowDo, and cueDo are always
                appended. Defaults to None.
            **kwa: Additional keyword arguments forwarded to DoDoer.__init__.
        """
        self.hab = hab
        self.client = client  # use client for both rx and tx
        self.verifier = verifier
        self.exc = exchanger
        self.direct = True if direct else False
        doers = doers if doers is not None else []
        doers.extend([doing.doify(self.msgDo),
                      doing.doify(self.escrowDo),
                      doing.doify(self.cueDo)])

        self.kevery = Kevery(db=self.hab.db,
                                      lax=False,
                                      local=False,
                                      direct=self.direct)

        if self.verifier is not None:
            self.tvy = Tevery(reger=self.verifier.reger,
                              db=self.hab.db,
                              local=False)
        else:
            self.tvy = None

        self.parser = Parser(ims=self.client.rxbs,
                             framed=True,
                             kvy=self.kevery,
                             tvy=self.tvy,
                             exc=self.exc,
                             version=Vrsn_1_0)


        super(Reactor, self).__init__(doers=doers, **kwa)
        if self.tymth:
            self.client.wind(self.tymth)

    def wind(self, tymth):
        """Inject a new tymth closure and propagate it to the TCP client.

        Overrides DoDoer.wind to ensure client.wind is called whenever the
            Tymist dependency changes.

        Parameters:
            tymth (callable): Closure returned by Tymist.tymeth() that, when
                called, returns the current Tymist.tyme.
        """
        super(Reactor, self).wind(tymth)
        self.client.wind(tymth)


    def msgDo(self, tymth=None, tock=0.0, **opts):
        """Doer that continuously parses the incoming TCP message stream.

        Delegates to Parser.parsator, which reads from client.rxbs and feeds
        events to kevery (and tvy when present).

        Doist Injected Attributes:
            g.tock = tock  # default tock attributes
            g.done = None  # default done state
            g.opts

        Parameters:
            tymth (callable): Injected tymth closure from the Doist.
                Defaults to None.
            tock (float): Injected initial tock value in seconds.
                Defaults to 0.0.
            **opts: Additional injected options from the Doist.

        Yields:
            None: Yields control back to the scheduler on each cycle.

        Returns:
            bool: Done state from Parser.parsator. Only reached on forced close.
        """
        yield  # enter context
        if self.parser.ims:
            logger.info("Client %s received:\n%s\n...\n", self.hab.name, self.parser.ims[:1024])
        done = yield from self.parser.parsator(local=True)  # process messages continuously
        return done  # should nover get here except forced close


    def cueDo(self, tymth=None, tock=0.0, **opts):
        """Doer that drains kevery.cues and sends resulting receipt messages.

        In each cycle, iterates hab.processCuesIter over kevery.cues and
        transmits each produced message via sendMessage. Yields after each
        message to throttle output, then yields again at end of each cycle.

        Doist Injected Attributes:
            g.tock = tock  # default tock attributes
            g.done = None  # default done state
            g.opts

        Parameters:
            tymth (callable): Injected tymth closure from the Doist.
                Defaults to None.
            tock (float): Injected initial tock value in seconds.
                Defaults to 0.0.
            **opts: Additional injected options from the Doist.

        Yields:
            None: Yields control back to the scheduler on each cycle.

        Returns:
            bool: Always False. Only reached on forced close.
        """
        yield  # enter context
        while True:
            for msg in self.hab.processCuesIter(self.kevery.cues):
                self.sendMessage(msg, label="chit or receipt")
                yield  # throttle just do one cue at a time
            yield
        return False  # should never get here except forced close

    def escrowDo(self, tymth=None, tock=0.0, **opts):
        """Doer that processes escrowed events on every cycle.

        Calls kevery.processEscrows() each cycle and, when tvy is present,
        also calls tvy.processEscrows().

        Doist Injected Attributes:
            g.tock = tock  # default tock attributes
            g.done = None  # default done state
            g.opts

        Parameters:
            tymth (callable): Injected tymth closure from the Doist.
                Defaults to None.
            tock (float): Injected initial tock value in seconds.
                Defaults to 0.0.
            **opts: Additional injected options from the Doist.

        Yields:
            None: Yields control back to the scheduler on each cycle.

        Returns:
            bool: Always False. Only reached on forced close.
        """
        yield  # enter context
        while True:
            self.kevery.processEscrows()
            if self.tvy is not None:
                self.tvy.processEscrows()
            yield
        return False  # should never get here except forced close

    def sendMessage(self, msg, label=""):
        """Transmit a message over the TCP client and log it.

        Parameters:
            msg (bytes): Serialized message to transmit.
            label (str): Descriptive label used in the log line.
                Defaults to empty string.
        """
        self.client.tx(msg)  # send to remote
        logger.info("%s sent %s:\n%s\n\n", self.hab.name, label, bytes(msg))


class Directant(doing.DoDoer):
    """Subclass of DoDoer that accepts TCP connections and manages Reactants.

    Responds to initiated connections from a remote Director by creating and
    running a Reactant per connection and scheduling it as a live doer. Connections
    that are cut off or whose timer has expired are closed and their Reactants
    removed. Only one scheduled doer is added directly: serviceDo.

    Part of the scheduling hierarchy: Doist -> DoDoer -> ... -> Doers.

    Attributes:
        hab (Habitat): Local controller's Habitat instance.
        verifier (Verifier): Optional Verifier for TEL context processing.
            None if TEL processing is not required.
        exchanger: Optional Exchanger for exn message processing.
            None if not required.
        server (TCP Server): TCP server instance, operated by a separate doer.
        rants (dict): Active Reactant instances keyed by connection address.
        done (bool): Completion state set by DoDoer. True means completed
            normally. False or None means incomplete.
        opts (dict): Injected options passed to the .do generator.
        doers (list): Scheduled Doer instances or generator functions.

    Inherited Properties:
        .tyme is float relative cycle time of associated Tymist .tyme obtained
            via injected .tymth function wrapper closure.
        .tymth is function wrapper closure returned by Tymist .tymeth() method.
            When .tymth is called it returns associated Tymist .tyme.
            .tymth provides injected dependency on Tymist tyme base.
        .tock is desired time in seconds between runs or until next run,
                 non negative, zero means run asap

    Inherited Methods:
        .wind  injects ._tymth dependency from associated Tymist to get its .tyme
        .__call__ makes instance callable and appears as generator function
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

    def __init__(self, hab, server, verifier=None, exchanger=None, doers=None, **kwa):
        """Initialize instance and extend doers with serviceDo.

        Parameters:
            hab (Habitat): Local controller's Habitat instance.
            server (TCP Server): TCP server instance used to accept and
                track inbound connections.
            verifier (Verifier): Verifier instance providing TEL
                context. Forwarded to each spawned Reactant. Defaults to None.
            exchanger: Exchanger instance for exn message processing.
                Forwarded to each spawned Reactant. Defaults to None.
            doers (list): Initial list of Doer instances or generator
                functions to schedule. serviceDo is always appended.
                Defaults to None.
            **kwa: Additional keyword arguments forwarded to DoDoer.__init__.
        """
        self.hab = hab
        self.verifier = verifier
        self.exchanger = exchanger
        self.server = server  # use server for cx
        self.rants = dict()
        doers = doers if doers is not None else []
        doers.extend([doing.doify(self.serviceDo)])
        super(Directant, self).__init__(doers=doers, **kwa)
        if self.tymth:
            self.server.wind(self.tymth)

    def wind(self, tymth):
        """Inject a new tymth closure and propagate it to the TCP server.

        Overrides DoDoer.wind to ensure server.wind is called whenever the
        Tymist dependency changes.

        Parameters:
            tymth (callable): Closure returned by Tymist.tymeth() that, when
                called, returns the current Tymist.tyme.
        """
        super(Directant, self).wind(tymth)
        self.server.wind(tymth)


    def serviceDo(self, tymth=None, tock=0.0, **opts):
        """Doer that services inbound connections and manages Reactant lifecycle.

        Each cycle iterates server.ixes. For each connection address:

        - If the connection is cut off, closeConnection is called.
        - If no Reactant exists for the address yet, one is created and
          extended into the running doers via self.extend.
        - If the connection has a positive tymeout and its timer has expired,
          closeConnection is called.

        Doist Injected Attributes:
            g.tock = tock  # default tock attributes
            g.done = None  # default done state
            g.opts

        Parameters:
            tymth (callable): Injected tymth closure from the Doist.
                Defaults to None.
            tock (float): Injected initial tock value in seconds.
                Defaults to 0.0.
            **opts: Additional injected options from the Doist.

        Yields:
            None: Yields control back to the scheduler on each cycle.
        """
        yield  # enter context
        while True:
            for ca, ix in list(self.server.ixes.items()):
                if ix.cutoff:
                    self.closeConnection(ca)
                    continue

                if ca not in self.rants:  # create Reactant and extend doers with it
                    rant = Reactant(tymth=self.tymth, hab=self.hab, verifier=self.verifier,
                                    exchanger=self.exchanger, remoter=ix)
                    self.rants[ca] = rant
                    # add Reactant (rant) doer to running doers
                    self.extend(doers=[rant])  # open and run rant as doer

                if ix.tymeout > 0.0 and ix.tymer.expired:
                    self.closeConnection(ca)  # also removes rant

            yield

    def closeConnection(self, ca):
        """Flush, close, and clean up a connection and its associated Reactant.

        Flushes pending send bytes on the remoter before removing it from the
        server. If a Reactant exists for the address, it is closed and removed
        from the doers list.

        Parameters:
            ca (tuple): Connection address key used in server.ixes and rants.
        """
        if ca in self.server.ixes:  # remoter still there
            self.server.ixes[ca].serviceSends()  # send final bytes to socket
        self.server.removeIx(ca)
        if ca in self.rants:  # remove rant (Reactant) if any
            self.remove([self.rants[ca]])  # close and remove rant from doers list
            del self.rants[ca]


class Reactant(doing.DoDoer):
    """Subclass of DoDoer that processes incoming KERI message streams from a TCP remoter.

    Wires together a TCP remoter, a Kevery (and optionally a Tevery), a Revery,
    and a Parser into three continuously-scheduled doers: msgDo, cueDo, and
    escrowDo. Each Reactant instance owns its own Kevery and parser bound to
    the remoter's receive buffer, so multiple simultaneous remote connections
    each get independent processing state.
    Part of the scheduling hierarchy: Doist -> DoDoer -> ... -> Doers.

    Attributes:
        hab (Habitat): Local controller's Habitat instance.
        verifier (Verifier): Optional Verifier instance for TEL context.
            None if TEL processing is not required.
        exchanger: Optional Exchanger instance for exn message processing.
            None if not required.
        remoter (TCP Remoter): TCP remoter used for both receive and transmit.
        kevery (Kevery): Event processor for incoming key events.
        tevery (Tevery): Event processor for incoming transaction events.
            None when verifier is None.
        parser (Parser): Stream parser bound to remoter.rxbs.
        done (bool): Completion state set by DoDoer. True means completed
            normally. False or None means incomplete.
        opts (dict): Injected options passed to the .do generator.
        doers (list): Scheduled Doer instances or generator functions.

    Inherited Properties:
        .tyme is float relative cycle time of associated Tymist .tyme obtained
            via injected .tymth function wrapper closure.
        .tymth is function wrapper closure returned by Tymist .tymeth() method.
            When .tymth is called it returns associated Tymist .tyme.
            .tymth provides injected dependency on Tymist tyme base.
        .tock is float, desired time in seconds between runs or until next run,
                 non negative, zero means run asap

    Inherited Methods:
        .wind  injects ._tymth dependency from associated Tymist to get its .tyme
        .__call__ makes instance callable and appears as generator function
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

    def __init__(self, hab, remoter, verifier=None, exchanger=None, doers=None, **kwa):
        """Initialize instance and extend doers with msgDo, cueDo, escrowDo.

        A Revery is always created and its router is registered on both
        kevery and, when verifier is provided, tevery.

        Inherited Parameters:
            tymist is  Tymist instance
            tock is float seconds initial value of .tock
            doers is list of doers (do generator instancs or functions)

        Parameters:
            hab (Habitat): Local controller's Habitat instance.
            remoter (TCP Remoter): TCP remoter used for both receive and
                transmit.
            verifier (Verifier): Verifier instance providing TEL
                context. When provided a Tevery is created, bound to the
                parser, and its reply routes are registered. Defaults to None.
            exchanger: Exchanger instance for exn message processing. Defaults to None.
            doers (list): Initial list of Doer instances or generator
                functions to schedule. msgDo, cueDo, and escrowDo are always
                appended. Defaults to None.
            **kwa: Additional keyword arguments forwarded to DoDoer.__init__.
        """
        self.hab = hab
        self.verifier = verifier
        self.exchanger = exchanger
        self.remoter = remoter  # use remoter for both rx and tx

        doers = doers if doers is not None else []
        doers.extend([doing.doify(self.msgDo),
                      doing.doify(self.cueDo),
                      doing.doify(self.escrowDo)])

        #  needs unique kevery with ims per remoter connnection
        rvy = Revery(db=hab.db)
        self.kevery = Kevery(db=self.hab.db,
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

        self.parser = Parser(ims=self.remoter.rxbs,
                             framed=True,
                             kvy=self.kevery,
                             tvy=self.tevery,
                             exc=self.exchanger,
                             rvy=rvy,
                             version=Vrsn_1_0)

        super(Reactant, self).__init__(doers=doers, **kwa)
        if self.tymth:
            self.remoter.wind(self.tymth)

    def wind(self, tymth):
        """Inject a new tymth closure and propagate it to the TCP remoter.

        Overrides DoDoer.wind to ensure remoter.wind is called whenever the
        Tymist dependency changes.

        Parameters:
            tymth (callable): Closure returned by Tymist.tymeth() that, when
                called, returns the current Tymist.tyme.
        """
        super(Reactant, self).wind(tymth)
        self.remoter.wind(tymth)


    def msgDo(self, tymth=None, tock=0.0, **opts):
        """Doer that continuously parses the incoming TCP message stream.

        Delegates to Parser.parsator, which reads from remoter.rxbs and feeds
        events to kevery (and tevery when present).

        Doist Injected Attributes:
            g.tock = tock  # default tock attributes
            g.done = None  # default done state
            g.opts

        Parameters:
            tymth (callable): Injected tymth closure from the Doist.
                Defaults to None.
            tock (float): Injected initial tock value in seconds.
                Defaults to 0.0.
            **opts: Additional injected options from the Doist.

        Yields:
            None: Yields control back to the scheduler on each cycle.

        Returns:
            bool: Done state from Parser.parsator. Only reached on forced close.
        """
        yield  # enter context
        if self.parser.ims:
            logger.info("Server %s: received:\n%s\n...\n", self.hab.name,
                        self.parser.ims[:1024])
        done = yield from self.parser.parsator(local=True)  # process messages continuously
        return done  # should nover get here except forced close


    def cueDo(self, tymth=None, tock=0.0, **opts):
        """Doer that drains kevery.cues and sends resulting receipt messages.

        In each cycle, iterates hab.processCuesIter over kevery.cues. Each
        produced message is coerced to bytearray if it arrives as a list of
        chunks, then transmitted via sendMessage. Yields after each message
        to throttle output, then yields again at end of each cycle.

        Doist Injected Attributes:
            g.tock = tock  # default tock attributes
            g.done = None  # default done state
            g.opts

        Parameters:
            tymth (callable): Injected tymth closure from the Doist.
                Defaults to None.
            tock (float): Injected initial tock value in seconds.
                Defaults to 0.0.
            **opts: Additional injected options from the Doist.

        Yields:
            None: Yields control back to the scheduler on each cycle.

        Returns:
            bool: Always False. Only reached on forced close.
        """
        yield  # enter context
        while True:
            for msg in self.hab.processCuesIter(self.kevery.cues):
                if isinstance(msg, list):
                    msg = bytearray(itertools.chain(*msg))

                self.sendMessage(msg, label="chit or receipt or replay")
                yield  # throttle just do one cue at a time
            yield
        return False  # should never get here except forced close


    def escrowDo(self, tymth=None, tock=0.0, **opts):
        """Doer that processes escrowed events on every cycle.

        Calls kevery.processEscrows() each cycle and, when tevery is present,
        also calls tevery.processEscrows().

        Doist Injected Attributes:
            g.tock = tock  # default tock attributes
            g.done = None  # default done state
            g.opts

        Parameters:
            tymth (callable): Injected tymth closure from the Doist.
                Defaults to None.
            tock (float): Injected initial tock value in seconds.
                Defaults to 0.0.
            **opts: Additional injected options from the Doist.

        Yields:
            None: Yields control back to the scheduler on each cycle.

        Returns:
            bool: Always False. Only reached on forced close.
        """
        yield  # enter context
        while True:
            self.kevery.processEscrows()
            if self.tevery is not None:
                self.tevery.processEscrows()
            yield
        return False  # should never get here except forced close

    def sendMessage(self, msg, label=""):
        """Transmit a message over the TCP remoter and log it.

        Parameters:
            msg (bytes): Serialized message to transmit.
            label (str): Descriptive label used in the log line.
                Defaults to empty string.
        """
        self.remoter.tx(msg)  # send to remote
        logger.info("Server %s: sent %s:\n%d\n\n", self.hab.name,
                    label, len(msg))


def runController(doers, expire=0.0):
    """Utiitity Function to create doist to run doers"""
    tock = 0.03125
    doist = doing.Doist(limit=expire, tock=tock, real=True)
    doist.do(doers=doers)

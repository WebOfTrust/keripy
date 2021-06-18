# -*- encoding: utf-8 -*-
"""
keri.peer.exchanging module

"""

from datetime import timedelta

from hio.base import doing

from ..core import eventing, coring
from ..help import decking, helping
from ..kering import ValidationError, MissingSignatureError


ExchangeMessageTimeWindow = timedelta(seconds=10)


class Exchanger(doing.DoDoer):
    """
     Peer to Peer KERI message Exchanger.
    """

    def __init__(self, kevers=None, cues=None, delta=ExchangeMessageTimeWindow, **kwa):
        """
        Initialize instance

        Parameters:
            hab (Habitat): instance of local controller's context
            cues (Deck):  of Cues i.e. notices of requests needing response
            delta (timedelta): message timeout window
        """

        super(Exchanger, self).__init__(doers=[], **kwa)

        self.kevers = kevers
        self.delta = delta
        self.routes = dict()
        self.cues = cues if cues is not None else decking.Deck()  # subclass of deque


    def wind(self, tymth):
        """
        Inject new tymist.tymth as new ._tymth. Changes tymist.tyme base.
        Updates winds .tymer .tymth
        """
        super(Exchanger, self).wind(tymth)


    def processEvent(self, serder, pre, sigers):
        """
        Process one serder event with attached indexed signatures representing 
        a Peer to Peer exchange message.          
        
        Parameters:
            serder (Serder) instance of event to process
            pre (qb64) identifier prefix of event sender
            sigers (list) of Siger instances of attached controller indexed sigs

        """

        route = serder.ked["r"]
        payload = serder.ked["q"]
        dts = serder.ked["dt"]

        behavior = self.routes[route]
        if behavior is None:
            raise AttributeError("unregistered route {} for exchange message = {}"
                                 "".format(route, serder.pretty()))

        delta = behavior.delta if behavior.delta is not None else self.delta
        msgDt = helping.fromIso8601(dts)
        now = helping.nowUTC()

        if now - msgDt > delta:
            raise ValidationError("message received outside time window with delta {} message={}"
                                  "".format(delta, serder.pretty()))


        msg = dict(
            pre=pre,
            payload=payload,
            serder=serder,
            sigers=sigers,
        )

        behavior.msgs.append(msg)


    def registerBehavior(self, route, behave):
        """
        Creates and registers a behavior for the specified route that
        executes the provide func.  The func needs to have the following
        signature:

           func(payload, pre, sigers, verfers)

        func must return a route and return message if a response is required
        or (None, None)


        Parameters:
            route (string) is the route to register
            behave (Behavior) is the code to execute for this behavior
        """

        if route in self.routes:
            return ValidationError("unable to register behavior {}, it has already been registered"
                                   "".format(route))

        behave.exc = self
        self.routes[route] = behave
        self.extend(doers=[behave.msgDo])


    def processMsgsIter(self, msgs):
        """
        Loop over msgs processing them one at a time.  Verifies signatures against the
        current signing keys of the controller of pre, the identifier prefix

        Parameters:
            msgs (list) of incoming messages to process
        """
        while msgs:
            msg = msgs.popleft()
            #  load the signers kever

            pre = msg['pre']
            payload = msg['payload']
            serder = msg['serder']
            sigers = msg['sigers']

            sever = self.kevers[pre.qb64]

            #  Verify provided sigers using verfers
            sigers, indices = eventing.verifySigs(serder=serder, sigers=sigers, verfers=sever.verfers)
            if not sever.tholder.satisfy(indices):  # at least one but not enough
                self.escrowPSEvent(serder=serder, sigers=sigers)
                raise MissingSignatureError("Failure satisfying sith = {} on sigs for {}"
                                            " for evt = {}.".format(sever.tholder.sith,
                                                                    [siger.qb64 for siger in sigers],
                                                                    serder.ked))

            yield payload, pre, sigers, sever.verfers


    def escrowPSEvent(self, serder, sigers):
        """
        Escrow event that does not have enough signatures.

        Parameters:
            serder is Serder instance of event
            sigers is list of Siger instances of indexed controller sigs
        """
        pass


class Behavior:
    """
    A Behavior encapsulates the execution environment for an exchange message endpoint.


    """

    def __init__(self, func, cues=None, delta=None):
        """
        Creates a behavior for that executes the provide func.  The func needs
        to have the following signature:

           func(payload, pre, sigers, verfers)

        func must return a route and return payload if a response is required
        or (None, None)

        Parameters:
            func (function) code to execute when messages arrive for this behavior
            cues (Deck):  of Cues i.e. notices of requests needing response
            delta (timedelta): message timeout window for this behavior.  Orderrides
              delta for Exchanger


        """
        self.msgs = decking.Deck()
        self.delta = delta
        self.cues = cues if cues is not None else decking.Deck()
        self.func = func


    @property
    def exc(self):
        return self._exc

    @exc.setter
    def exc(self, exc):
        self._exc = exc


    @doing.doize()
    def msgDo(self, tymth=None, tock=0.0, **opts):
        """
         Returns Doist compatibile generator method (doer dog) to process
            .msgs deque

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
            add to doers list
        """
        while True:
            for payload, pre, sigers, verfers in self._exc.processMsgsIter(self.msgs):
                rr, resp = self.func(payload, pre, sigers, verfers)
                if rr is not None:
                    self.cueResponse(rr, resp)
                yield  # throttle just do one msg at a time
            yield
        return False  # should never get here except forced close


    def cueResponse(self, rr, resp):
        """
        Create a response message from the response of a behavior,
        signs it and cues it for return

        Parameters:
              rr (string) is the return route for the response
              resp (dict) is the response payload
        """

        excSrdr = exchange(route=rr, payload=resp)
        self.cues.append(excSrdr.raw)


def exchange(route, payload, version=coring.Version, kind=coring.Serials.json):
    """
    Create an `exn` message with the specified route and payload
    Parameters:
        route (string) to destination route of the message
        payload (dict) body of message to deliver to route
        version (Version) is Version instance
        kind (Serials) is serialization kind

    """
    vs = coring.Versify(version=version, kind=kind, size=0)
    ilk = eventing.Ilks.exn

    ked = dict(v=vs,
               t=ilk,
               dt=helping.nowIso8601(),
               r=route,
               q=payload
               )

    return eventing.Serder(ked=ked)  # return serialized ked


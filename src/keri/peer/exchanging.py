# -*- encoding: utf-8 -*-
"""
keri.peer.exchanging module

"""
import logging
from datetime import timedelta

from hio.base import doing
from hio.help import decking

from .. import help
from ..core import eventing, coring
from ..help import helping
from ..kering import ValidationError, MissingSignatureError, AuthZError

ExchangeMessageTimeWindow = timedelta(seconds=1010000)

logger = help.ogler.getLogger()


class Exchanger(doing.DoDoer):
    """
     Peer to Peer KERI message Exchanger.
    """

    def __init__(self, hab, handlers, controller=None, cues=None, delta=ExchangeMessageTimeWindow, **kwa):
        """
        Initialize instance

        Parameters:
            hab (Habitat): instance of local controller's
            handler(list): list of Handlers capable of responding to exn messages
            controller (str) qb64 prefix of the controlling identifier
            cues (Deck):  of Cues i.e. notices of requests needing response
            delta (timedelta): message timeout window
        """

        self.hab = hab
        self.controller = controller
        self.kevers = hab.kvy.kevers
        self.delta = delta
        self.routes = dict()
        self.cues = cues if cues is not None else decking.Deck()  # subclass of deque

        doers = []
        for handler in handlers:
            if handler.resource in self.routes:
                raise ValidationError("unable to register behavior {}, it has already been registered"
                                      "".format(handler.resource))

            self.routes[handler.resource] = handler
            doers.append(handler)

        super(Exchanger, self).__init__(doers=doers, **kwa)

    def processEvent(self, serder, source, sigers):
        """
        Process one serder event with attached indexed signatures representing
        a Peer to Peer exchange message.

        Parameters:
            serder (Serder) instance of event to process
            source (Prefixer) identifier prefix of event sender
            sigers (list) of Siger instances of attached controller indexed sigs

        """

        route = serder.ked["r"]
        payload = serder.ked["d"]
        dts = serder.ked["dt"]

        if route not in self.routes:
            raise AttributeError("unregistered route {} for exchange message = {}"
                                 "".format(route, serder.pretty()))

        behavior = self.routes[route]

        # delta = behavior.delta if behavior.delta is not None else self.delta
        delta = self.delta
        msgDt = helping.fromIso8601(dts)
        now = helping.nowUTC()

        if now - msgDt > delta:
            raise ValidationError("message received outside time window with delta {} message={}"
                                  "".format(delta, serder.pretty()))

        if source.qb64 not in self.hab.kevers:
            self.escrowPSEvent(serder=serder, source=source, sigers=sigers)
            self.cues.append(dict(kin="query", q=dict(r="logs", pre=source.qb64)))
            raise MissingSignatureError("Unable to find sender {} in kevers"
                                        " for evt = {}.".format(source, serder))

        kever = self.hab.kevers[source.qb64]
        tholder, verfers = self.hab.verifiage(pre=source.qb64, sn=kever.lastEst.s)

        if self.controller is not None and self.controller != source.qb64:
            raise AuthZError("Message {} is from invalid source {}"
                             "".format(payload, source.qb64))

        #  Verify provided sigers using verfers
        ssigers, indices = eventing.verifySigs(serder=serder, sigers=sigers, verfers=verfers)
        if not tholder.satisfy(indices):  # at least one but not enough
            self.escrowPSEvent(serder=serder, source=source, sigers=sigers)
            self.cues.append(dict(kin="query", q=dict(r="logs", pre=source.qb64)))
            raise MissingSignatureError("Failure satisfying sith = {} on sigs for {}"
                                        " for evt = {}.".format(tholder.sith,
                                                                [siger.qb64 for siger in sigers],
                                                                serder.ked))

        msg = dict(
            payload=payload,
            pre=source,
            sigers=ssigers,
            verfers=verfers,
        )

        behavior.msgs.append(msg)

    def processResponseIter(self):
        """
        Iterate through cues and yields one or more responses for each cue.

        Parameters:
            cues is deque of cues

        """
        responses = []
        for _, behavior in self.routes.items():  # get responses from all behaviors
            while behavior.cues:
                cue = behavior.cues.popleft()
                responses.append(cue)

        while responses:  # iteratively process each response in responses
            msg = responses.pop(0)
            yield msg

    def processEscrow(self):
        """
        Process all escrows for `exn` messages

        """
        self.processEscrowPartialSigned()


    def escrowPSEvent(self, serder, source, sigers):
        """
        Escrow event that does not have enough signatures.

        Parameters:
            serder is Serder instance of event
            source is Prefixer of the origin of the exn
            sigers is list of Siger instances of indexed controller sigs
        """
        dig = serder.digb
        self.hab.db.epse.put(keys=dig, val=serder)
        self.hab.db.esigs.put(keys=dig, vals=sigers)
        self.hab.db.esrc.put(keys=dig, val=source)


    def processEscrowPartialSigned(self):
        for (dig,), serder in self.hab.db.epse.getItemIter():
            sigers = self.hab.db.esigs.get(keys=dig)
            source = self.hab.db.esrc.get(keys=dig)

            try:

                self.processEvent(serder=serder, source=source, sigers=sigers)

            except MissingSignatureError as ex:
                if logger.isEnabledFor(logging.DEBUG):
                    logger.info("Exchange partially signed unescrow failed: %s\n", ex.args[0])
                else:
                    logger.info("Exchange partially signed failed: %s\n", ex.args[0])
            except Exception as ex:
                self.hab.db.epse.rem(dig)
                self.hab.db.esigs.rem(dig)
                self.hab.db.esrc.rem(dig)
                if logger.isEnabledFor(logging.DEBUG):
                    logger.info("Exchange partially signed unescrowed: %s\n", ex.args[0])
                else:
                    logger.info("Exchange partially signed unescrowed: %s\n", ex.args[0])
            else:
                self.hab.db.epse.rem(dig)
                self.hab.db.esigs.rem(dig)
                self.hab.db.esrc.rem(dig)
                logger.info("Exchanger unescrow succeeded in valid exchange: "
                            "creder=\n%s\n", serder.pretty())




def exchange(route, payload, date=None, modifiers=None, version=coring.Version,
             kind=coring.Serials.json):
    """
    Create an `exn` message with the specified route and payload
    Parameters:
        route (string) to destination route of the message
        payload (dict) body of message to deliver to route
        date (str) Iso8601 formatted date string to use for this request
        modifiers (dict) equivalent of query string of uri, modifiers for the request that are not
                         part of the payload
        version (Version) is Version instance
        kind (Serials) is serialization kind

    """
    vs = coring.Versify(version=version, kind=kind, size=0)
    ilk = eventing.Ilks.exn
    dt = date if date is not None else helping.nowIso8601()

    ked = dict(v=vs,
               t=ilk,
               dt=dt,
               r=route,
               d=payload,
               q=modifiers
               )

    if modifiers is None:
        del ked["q"]

    return eventing.Serder(ked=ked)  # return serialized ked


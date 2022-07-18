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

ExchangeMessageTimeWindow = timedelta(seconds=300)

logger = help.ogler.getLogger()


class Exchanger(doing.DoDoer):
    """
     Peer to Peer KERI message Exchanger.
    """

    def __init__(self, hby, handlers, controller=None, cues=None, delta=ExchangeMessageTimeWindow, **kwa):
        """ Initialize instance

        Parameters:
            hab (Hab): instance of local controller's
            handler(list): list of Handlers capable of responding to exn messages
            controller (str) qb64 prefix of the controlling identifier
            cues (Deck):  of Cues i.e. notices of requests needing response
            delta (timedelta): message timeout window
        """

        self.hby = hby
        self.controller = controller
        self.kevers = self.hby.kevers
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

    def addHandler(self, handler):
        if handler.resource in self.routes:
            raise ValidationError("unable to register behavior {}, it has already been registered"
                                  "".format(handler.resource))

        self.routes[handler.resource] = handler
        self.doers.append(handler)

    def processEvent(self, serder, source=None, sigers=None, cigars=None, **kwargs):
        """ Process one serder event with attached indexed signatures representing a Peer to Peer exchange message.

        Parameters:
            serder (Serder): instance of event to process
            source (Prefixer): identifier prefix of event sender
            sigers (list): of Siger instances of attached controller indexed sigs
            cigars (list): of Cigar instances of attached non-trans sigs

        """
        route = serder.ked["r"]
        payload = serder.ked["a"]
        # dts = serder.ked["dt"]
        modifiers = serder.ked["q"] if 'q' in serder.ked else dict()
        pathed = kwargs["pathed"] if "pathed" in kwargs else []

        if route not in self.routes:
            raise AttributeError("unregistered route {} for exchange message = {}"
                                 "".format(route, serder.pretty()))

        behavior = self.routes[route]

        if self.controller is not None and self.controller != source.qb64:
            raise AuthZError("Message {} is from invalid source {}"
                             "".format(payload, source.qb64))

        # delta = behavior.delta if behavior.delta is not None else self.delta
        # delta = self.delta
        # msgDt = helping.fromIso8601(dts)
        # now = helping.nowUTC()

        # if now - msgDt > delta:
        #     raise ValidationError("message received outside time window with delta {} message={}"
        #                           "".format(delta, serder.pretty()))

        if source is not None and sigers is not None:
            if source.qb64 not in self.hby.kevers:
                if self.escrowPSEvent(serder=serder, source=source, sigers=sigers, pathed=pathed):
                    self.cues.append(dict(kin="query", q=dict(r="ksn", pre=source.qb64)))
                raise MissingSignatureError(f"Unable to find sender {source.qb64} in kevers"
                                            f" for evt = {serder.ked}.")

            kever = self.hby.kevers[source.qb64]
            tholder, verfers = self.hby.resolveVerifiers(pre=source.qb64, sn=kever.lastEst.s)

            #  Verify provided sigers using verfers
            ssigers, indices = eventing.verifySigs(raw=serder.raw, sigers=sigers, verfers=verfers)
            if not tholder.satisfy(indices):  # at least one but not enough
                psigers = self.hby.db.esigs.get(keys=(serder.said,))
                if self.escrowPSEvent(serder=serder, source=source, sigers=sigers, pathed=pathed):
                    self.cues.append(dict(kin="query", q=dict(r="ksn", pre=source.qb64)))
                raise MissingSignatureError("Failure satisfying sith = {} on sigs for {}"
                                            " for evt = {}.".format(tholder.sith,
                                                                    [siger.qb64 for siger in sigers],
                                                                    serder.ked))
        elif cigars is not None:
            for cigar in cigars:
                if not cigar.verfer.verify(cigar.raw, serder.raw):  # cig not verify
                    raise MissingSignatureError("Failure satisfying exn on cigs for {}"
                                                " for evt = {}.".format(cigar,
                                                                        serder.ked))

        a = coring.Pather(path=["a"])
        attachments = []
        for pattach in pathed:
            pather = coring.Pather(qb64b=pattach, strip=True)
            if pather.startswith(a):
                np = pather.strip(a)
                attachments.append((np, pattach))

        msg = dict(
            payload=payload,
            modifiers=modifiers,
            pre=source,
            attachments=attachments,
        )

        behavior.msgs.append(msg)

    def processResponseIter(self):
        """ Iterate through cues and yields one or more responses for each cue.

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
        """ Process all escrows for `exn` messages

        """
        self.processEscrowPartialSigned()

    def escrowPSEvent(self, serder, source, sigers, pathed):
        """ Escrow event that does not have enough signatures.

        Parameters:
            serder (Serder): instance of event
            source (Prefixer): of the origin of the exn
            sigers (list): of Siger instances of indexed controller sigs
            pathed (list): list of bytes of attached paths

        """
        dig = serder.said
        for siger in sigers:
            self.hby.db.esigs.add(keys=(dig,), val=siger)
        self.hby.db.epath.pin(keys=(dig,), vals=[bytes(p) for p in pathed])
        self.hby.db.esrc.put(keys=(dig,), val=source)
        return self.hby.db.epse.put(keys=(dig,), val=serder)

    def processEscrowPartialSigned(self):
        """ Process escrow of partially signed messages """
        for (dig,), serder in self.hby.db.epse.getItemIter():
            sigers = self.hby.db.esigs.get(keys=(dig,))
            source = self.hby.db.esrc.get(keys=(dig,))
            pathed = [bytearray(p.encode("utf-8")) for p in self.hby.db.epath.get(keys=(dig,))]

            try:
                self.processEvent(serder=serder, source=source, sigers=sigers, pathed=pathed)

            except MissingSignatureError as ex:
                if logger.isEnabledFor(logging.DEBUG):
                    logger.info("Exchange partially signed unescrow failed: %s\n", ex.args[0])
                else:
                    logger.info("Exchange partially signed failed: %s\n", ex.args[0])
            except Exception as ex:
                self.hby.db.epse.rem(dig)
                self.hby.db.esigs.rem(dig)
                self.hby.db.esrc.rem(dig)
                if logger.isEnabledFor(logging.DEBUG):
                    logger.info("Exchange partially signed unescrowed: %s\n", ex.args[0])
                else:
                    logger.info("Exchange partially signed unescrowed: %s\n", ex.args[0])
            else:
                self.hby.db.epse.rem(dig)
                self.hby.db.esigs.rem(dig)
                self.hby.db.esrc.rem(dig)
                logger.info("Exchanger unescrow succeeded in valid exchange: "
                            "creder=\n%s\n", serder.pretty())


def exchange(route, payload, date=None, modifiers=None, version=coring.Version, kind=coring.Serials.json):
    """ Create an `exn` message with the specified route and payload

    Parameters:
        route (str): to destination route of the message
        payload (Optional(dict, list)): body of message to deliver to route
        date (str): Iso8601 formatted date string to use for this request
        modifiers (dict): equivalent of query string of uri, modifiers for the request that are not
                         part of the payload
        version (Version): is Version instance
        kind (Serials): is serialization kind

    """
    vs = coring.versify(version=version, kind=kind, size=0)
    ilk = eventing.Ilks.exn
    dt = date if date is not None else helping.nowIso8601()

    ked = dict(v=vs,
               t=ilk,
               d="",
               r=route,
               q=modifiers,
               a=payload
               )
    _, ked = coring.Saider.saidify(sad=ked)

    if modifiers is None:
        del ked["q"]

    return eventing.Serder(ked=ked)  # return serialized ked

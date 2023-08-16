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
from ..kering import ValidationError, MissingSignatureError

ExchangeMessageTimeWindow = timedelta(seconds=300)

logger = help.ogler.getLogger()


class Exchanger(doing.DoDoer):
    """
     Peer to Peer KERI message Exchanger.
    """

    def __init__(self, db, handlers, local=False, cues=None, delta=ExchangeMessageTimeWindow, **kwa):
        """ Initialize instance

        Parameters:
            db (Baser): database environment
            handler(list): list of Handlers capable of responding to exn messages
            local (bool): True means local event that should not process behavior and always persist event
            cues (Deck):  of Cues i.e. notices of requests needing response
            delta (timedelta): message timeout window
        """

        self.db = db
        self.kevers = self.db.kevers
        self.delta = delta
        self.local = local
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

    def processEvent(self, serder, tsgs=None, cigars=None, **kwargs):
        """ Process one serder event with attached indexed signatures representing a Peer to Peer exchange message.

        Parameters:
            serder (Serder): instance of event to process
            tsgs (list): tuples (quadruples) of form
                           (prefixer, seqner, diger, [sigers]) where:
                           prefixer is pre of trans endorser
                           seqner is sequence number of trans endorser's est evt for keys for sigs
                           diger is digest of trans endorser's est evt for keys for sigs
                           [sigers] is list of indexed sigs from trans endorser's keys from est evt
            cigars (list): of Cigar instances of attached non-trans sigs

        """
        route = serder.ked["r"]
        payload = serder.ked["a"]
        embeds = serder.ked["e"]
        sender = serder.ked["i"]

        modifiers = serder.ked["q"] if 'q' in serder.ked else dict()
        pathed = kwargs["pathed"] if "pathed" in kwargs else []

        if not self.local and route not in self.routes:
            raise AttributeError("unregistered route {} for exchange message = {}"
                                 "".format(route, serder.pretty()))

        behavior = self.routes[route] if route in self.routes else None

        if tsgs is not None:
            for prefixer, seqner, ssaider, sigers in tsgs:  # iterate over each tsg
                if sender != prefixer.qb64:  # sig not by aid
                    raise MissingSignatureError("Exchange process: skipped signature not from aid="
                                                "%s on exn msg=\n%s\n", sender, serder.pretty())

                if prefixer.qb64 not in self.kevers or self.kevers[prefixer.qb64].sn < seqner.sn:
                    if self.escrowPSEvent(serder=serder, tsgs=tsgs, pathed=pathed):
                        self.cues.append(dict(kin="query", q=dict(r="ksn", pre=prefixer.qb64)))
                    raise MissingSignatureError(f"Unable to find sender {prefixer.qb64} in kevers"
                                                f" for evt = {serder.ked}.")

                # Verify the signatures are valid and that the signature threshold as of the signing event is met
                tholder, verfers = self.db.resolveVerifiers(pre=prefixer.qb64, sn=seqner.sn, dig=ssaider.qb64)
                _, indices = eventing.verifySigs(serder.raw, sigers, verfers)

                if not tholder.satisfy(indices):  # We still don't have all the sigers, need to escrow
                    if self.escrowPSEvent(serder=serder, tsgs=tsgs, pathed=pathed):
                        self.cues.append(dict(kin="query", q=dict(r="ksn", pre=prefixer.qb64)))
                    raise MissingSignatureError(f"Unable to find sender {prefixer.qb64} in kevers"
                                                f" for evt = {serder.ked}.")

        elif cigars is not None:
            for cigar in cigars:
                if sender != cigar.verfer.qb64:  # cig not by aid
                    raise MissingSignatureError(" process: skipped cig not from aid="
                                                "%s on exn msg=\n%s\n", sender, serder.pretty())

                if not cigar.verfer.verify(cigar.raw, serder.raw):  # cig not verify
                    raise MissingSignatureError("Failure satisfying exn on cigs for {}"
                                                " for evt = {}.".format(cigar,
                                                                        serder.ked))
        else:
            raise MissingSignatureError("Failure satisfying exn, no cigs or sigs"
                                        " for evt = {}.".format(serder.ked))

        e = coring.Pather(path=["e"])
        attachments = []
        for p in pathed:
            pattach = bytearray(p)
            pather = coring.Pather(qb64b=pattach, strip=True)
            if pather.startswith(e):
                np = pather.strip(e)
                attachments.append((np, pattach))

        # Always persis local events and events where the behavior has indicated persistence is required
        if self.local or (hasattr(behavior, 'persist') and behavior.persist):
            try:
                self.logEvent(serder, pathed, tsgs, cigars)
            except Exception as ex:
                print(ex)

        # Do not execute behavior for local events, just validate and save
        if not self.local:
            msg = dict(
                payload=payload,
                embeds=embeds,
                modifiers=modifiers,
                pre=coring.Prefixer(qb64=sender),
                serder=serder,
                attachments=attachments
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

    def escrowPSEvent(self, serder, tsgs, pathed):
        """ Escrow event that does not have enough signatures.

        Parameters:
            serder (Serder): instance of event
            tsgs (list): quadlet of prefixer seqner, saider, sigers
            pathed (list): list of bytes of attached paths

        """
        dig = serder.said
        for prefixer, seqner, ssaider, sigers in tsgs:  # iterate over each tsg
            quadkeys = (serder.said, prefixer.qb64, f"{seqner.sn:032x}", ssaider.qb64)
            for siger in sigers:
                self.db.esigs.add(keys=quadkeys, val=siger)

        self.db.epath.pin(keys=(dig,), vals=[bytes(p) for p in pathed])
        return self.db.epse.put(keys=(dig,), val=serder)

    def processEscrowPartialSigned(self):
        """ Process escrow of partially signed messages """
        for (dig,), serder in self.db.epse.getItemIter():
            tsgs = []
            klases = (coring.Prefixer, coring.Seqner, coring.Saider)
            args = ("qb64", "snh", "qb64")
            sigers = []
            old = None  # empty keys
            for keys, siger in self.db.esigs.getItemIter(keys=(dig, "")):
                quad = keys[1:]
                if quad != old:  # new tsg
                    if sigers:  # append tsg made for old and sigers
                        prefixer, seqner, saider = helping.klasify(sers=old, klases=klases, args=args)

                        tsgs.append((prefixer, seqner, saider, sigers))
                        sigers = []
                    old = quad
                sigers.append(siger)
            if sigers and old:
                prefixer, seqner, saider = helping.klasify(sers=old, klases=klases, args=args)
                tsgs.append((prefixer, seqner, saider, sigers))

            pathed = [bytearray(p.encode("utf-8")) for p in self.db.epath.get(keys=(dig,))]

            try:
                self.processEvent(serder=serder, tsgs=tsgs, pathed=pathed)

            except MissingSignatureError as ex:
                if logger.isEnabledFor(logging.DEBUG):
                    logger.info("Exchange partially signed unescrow failed: %s\n", ex.args[0])
                else:
                    logger.info("Exchange partially signed failed: %s\n", ex.args[0])
            except Exception as ex:
                self.db.epse.rem(dig)
                self.db.esigs.rem(dig)
                if logger.isEnabledFor(logging.DEBUG):
                    logger.info("Exchange partially signed unescrowed: %s\n", ex.args[0])
                else:
                    logger.info("Exchange partially signed unescrowed: %s\n", ex.args[0])
            else:
                self.db.epse.rem(dig)
                self.db.esigs.rem(dig)
                logger.info("Exchanger unescrow succeeded in valid exchange: "
                            "creder=\n%s\n", serder.pretty())

    def logEvent(self, serder, pathed=None, tsgs=None, cigars=None):
        dig = serder.said
        pathed = pathed or []
        tsgs = tsgs or []
        cigars = cigars or []

        for prefixer, seqner, ssaider, sigers in tsgs:  # iterate over each tsg
            quadkeys = (serder.said, prefixer.qb64, f"{seqner.sn:032x}", ssaider.qb64)
            for siger in sigers:
                self.db.esigs.add(keys=quadkeys, val=siger)
        for cigar in cigars:
            self.db.ecigs.add(keys=(dig,), vals=[(cigar.verfer, cigar)])

        self.db.epath.pin(keys=(dig,), vals=[bytes(p) for p in pathed])
        self.db.exns.put(keys=(dig,), val=serder)


def exchange(route,
             payload,
             sender,
             recipient=None,
             date=None,
             dig=None,
             modifiers=None,
             embeds=None,
             version=coring.Version,
             kind=coring.Serials.json):
    """ Create an `exn` message with the specified route and payload

    Parameters:
        route (str): to destination route of the message
        payload (list | dict): body of message to deliver to route
        sender (str): qb64 AID of sender of the exn
        recipient (str) optional qb64 AID recipient of exn
        date (str): Iso8601 formatted date string to use for this request
        dig (str) qb64 SAID of previous event if any
        modifiers (dict): equivalent of query string of uri, modifiers for the request that are not
                         part of the payload
        embeds (dict): named embeded KERI event CESR stream with attachments
        version (Version): is Version instance
        kind (Serials): is serialization kind

    """
    vs = coring.versify(version=version, kind=kind, size=0)
    ilk = eventing.Ilks.exn
    dt = date if date is not None else helping.nowIso8601()
    p = dig if dig is not None else ""
    embeds = embeds if embeds is not None else {}

    e = dict()
    end = bytearray()
    for label, msg in embeds.items():
        serder = coring.Serder(raw=msg)
        e[label] = serder.ked
        atc = bytes(msg[serder.size:])
        if not atc:
            continue

        pathed = bytearray()
        pather = coring.Pather(path=["e", label])
        pathed.extend(pather.qb64b)
        pathed.extend(atc)
        end.extend(coring.Counter(code=coring.CtrDex.PathedMaterialQuadlets,
                                  count=(len(pathed) // 4)).qb64b)
        end.extend(pathed)

    attrs = dict(
    )

    if recipient is not None:
        attrs['i'] = recipient

    attrs |= payload

    ked = dict(v=vs,
               t=ilk,
               d="",
               i=sender,
               p=p,
               dt=dt,
               r=route,
               q=modifiers if modifiers is not None else {},  # q field required
               a=attrs,
               e=e)

    _, ked = coring.Saider.saidify(sad=ked)
    return eventing.Serder(ked=ked), end  # return serialized ked


def cloneMessage(hby, said):
    """ Load and verify signatures on message exn

    Parameters:
        hby (Habery): database environment from which to clone message
        said (str): qb64 SAID of message exn to load

    Returns:
        tuple: (serder, list) of message exn and pathed signatures on embedded attachments

    """
    exn = hby.db.exns.get(keys=(said,))
    verify(hby=hby, serder=exn)

    pathed = [p for p in hby.db.epath.get(keys=(exn.said,))]
    return exn, pathed


def verify(hby, serder):
    """  Verify that the signatures in the database are valid for the provided exn

    Parameters:
        hby (Habery): database environment from which to verify message
        serder (Serder): exn serder to load and verify signatures for

    Returns:
        bool: True means threshold satisfyig signatures were loaded and verified successfully

    """
    tsgs = []
    klases = (coring.Prefixer, coring.Seqner, coring.Saider)
    args = ("qb64", "snh", "qb64")
    sigers = []
    old = None  # empty keys
    for keys, siger in hby.db.esigs.getItemIter(keys=(serder.said, "")):
        quad = keys[1:]
        if quad != old:  # new tsg
            if sigers:  # append tsg made for old and sigers
                prefixer, seqner, saider = helping.klasify(sers=old, klases=klases, args=args)

                tsgs.append((prefixer, seqner, saider, sigers))
                sigers = []
            old = quad
        sigers.append(siger)
    if sigers and old:
        prefixer, seqner, saider = helping.klasify(sers=old, klases=klases, args=args)
        tsgs.append((prefixer, seqner, saider, sigers))

    accepted = False
    for prefixer, seqner, ssaider, sigers in tsgs:
        if prefixer.qb64 not in hby.kevers or hby.kevers[prefixer.qb64].sn < seqner.sn:
            raise MissingSignatureError(f"Unable to find sender {prefixer.qb64} in kevers"
                                        f" for evt = {serder.ked}.")

        # Verify the signatures are valid and that the signature threshold as of the signing event is met
        tholder, verfers = hby.db.resolveVerifiers(pre=prefixer.qb64, sn=seqner.sn, dig=ssaider.qb64)
        _, indices = eventing.verifySigs(serder.raw, sigers, verfers)

        if not tholder.satisfy(indices):  # We still don't have all the sigers, need to escrow
            raise MissingSignatureError(f"Unable to find sender {prefixer.qb64} in kevers"
                                        f" for evt = {serder.ked}.")
        accepted = True

    cigars = hby.db.ecigs.get(keys=(serder.said,))
    for cigar in cigars:
        if not cigar.verfer.verify(cigar.raw, serder.raw):  # cig not verify
            raise MissingSignatureError("Failure satisfying exn on cigs for {}"
                                        " for evt = {}.".format(cigar,
                                                                serder.ked))
        accepted = True

    if not accepted:
        raise MissingSignatureError(f"No valid signatures stored for evt = {serder.ked}")



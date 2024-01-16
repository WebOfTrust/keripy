# -*- encoding: utf-8 -*-
"""
keri.peer.exchanging module

"""
import logging
from datetime import timedelta

from hio.help import decking

from .. import help, kering
from ..app import habbing
from ..core import eventing, coring, serdering
from ..help import helping
from ..kering import ValidationError, MissingSignatureError

ExchangeMessageTimeWindow = timedelta(seconds=300)

logger = help.ogler.getLogger()


class Exchanger:
    """
     Peer to Peer KERI message Exchanger.
    """

    def __init__(self, hby, handlers, cues=None, delta=ExchangeMessageTimeWindow):
        """ Initialize instance

        Parameters:
            hby (Haberyu): database environment
            handlers(list): list of Handlers capable of responding to exn messages
            cues (Deck):  of Cues i.e. notices of requests needing response
            delta (timedelta): message timeout window
        """

        self.hby = hby
        self.kevers = self.hby.db.kevers
        self.delta = delta
        self.routes = dict()
        self.cues = cues if cues is not None else decking.Deck()  # subclass of deque

        for handler in handlers:
            if handler.resource in self.routes:
                raise ValidationError("unable to register behavior {}, it has already been registered"
                                      "".format(handler.resource))

            self.routes[handler.resource] = handler

    def addHandler(self, handler):
        if handler.resource in self.routes:
            raise ValidationError("unable to register behavior {}, it has already been registered"
                                  "".format(handler.resource))

        self.routes[handler.resource] = handler

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
        sender = serder.ked["i"]
        pathed = kwargs["pathed"] if "pathed" in kwargs else []

        behavior = self.routes[route] if route in self.routes else None
        if tsgs is not None:
            for prefixer, seqner, ssaider, sigers in tsgs:  # iterate over each tsg
                if sender != prefixer.qb64:  # sig not by aid
                    raise MissingSignatureError(f"Exchange process: skipped signature not from aid="
                                                f"{sender}, from {prefixer.qb64} on exn msg=\n{serder.pretty()}\n")

                if prefixer.qb64 not in self.kevers or self.kevers[prefixer.qb64].sn < seqner.sn:
                    if self.escrowPSEvent(serder=serder, tsgs=tsgs, pathed=pathed):
                        self.cues.append(dict(kin="query", q=dict(r="logs", pre=prefixer.qb64, sn=seqner.snh)))
                    raise MissingSignatureError(f"Unable to find sender {prefixer.qb64} in kevers"
                                                f" for evt = {serder.ked}.")

                # Verify the signatures are valid and that the signature threshold as of the signing event is met
                tholder, verfers = self.hby.db.resolveVerifiers(pre=prefixer.qb64, sn=seqner.sn, dig=ssaider.qb64)
                _, indices = eventing.verifySigs(serder.raw, sigers, verfers)

                if not tholder.satisfy(indices):  # We still don't have all the sigers, need to escrow
                    if self.escrowPSEvent(serder=serder, tsgs=tsgs, pathed=pathed):
                        self.cues.append(dict(kin="query", q=dict(r="logs", pre=prefixer.qb64, sn=seqner.snh)))
                    raise MissingSignatureError(f"Not enough signatures in  {indices}"
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

        # Perform behavior specific verification, think IPEX chaining requirements
        try:
            if not behavior.verify(serder=serder, attachments=attachments):
                logger.info(f"exn event for route {route} failed behavior verfication.  exn={serder.ked}")
                return

        except AttributeError:
            logger.info(f"Behavior for {route} missing or does not have verify for exn={serder.ked}")

        # Always persis events
        self.logEvent(serder, pathed, tsgs, cigars)
        self.cues.append(dict(kin="saved", said=serder.said))

        # Execute any behavior specific handling, not sure if this should be different than verify
        try:
            behavior.handle(serder=serder, attachments=attachments)
        except AttributeError:
            logger.info(f"Behavior for {route} missing or does not have handle for exn={serder.ked}")

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
                self.hby.db.esigs.add(keys=quadkeys, val=siger)

        self.hby.db.epath.pin(keys=(dig,), vals=[bytes(p) for p in pathed])
        return self.hby.db.epse.put(keys=(dig,), val=serder)

    def processEscrowPartialSigned(self):
        """ Process escrow of partially signed messages """
        for (dig,), serder in self.hby.db.epse.getItemIter():
            tsgs = []
            klases = (coring.Prefixer, coring.Seqner, coring.Saider)
            args = ("qb64", "snh", "qb64")
            sigers = []
            old = None  # empty keys
            for keys, siger in self.hby.db.esigs.getItemIter(keys=(dig, "")):
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

            pathed = [bytearray(p.encode("utf-8")) for p in self.hby.db.epath.get(keys=(dig,))]

            try:
                self.processEvent(serder=serder, tsgs=tsgs, pathed=pathed)

            except MissingSignatureError as ex:
                if logger.isEnabledFor(logging.DEBUG):
                    logger.info("Exchange partially signed unescrow failed: %s\n", ex.args[0])
                else:
                    logger.info("Exchange partially signed failed: %s\n", ex.args[0])
            except Exception as ex:
                self.hby.db.epse.rem(dig)
                self.hby.db.esigs.rem(dig)
                if logger.isEnabledFor(logging.DEBUG):
                    logger.info("Exchange partially signed unescrowed: %s\n", ex.args[0])
                else:
                    logger.info("Exchange partially signed unescrowed: %s\n", ex.args[0])
            else:
                self.hby.db.epse.rem(dig)
                self.hby.db.esigs.rem(dig)
                logger.info("Exchanger unescrow succeeded in valid exchange: "
                            "creder=\n%s\n", serder.pretty())

    def logEvent(self, serder, pathed=None, tsgs=None, cigars=None):
        dig = serder.said
        pdig = serder.ked['p']
        pathed = pathed or []
        tsgs = tsgs or []
        cigars = cigars or []

        for prefixer, seqner, ssaider, sigers in tsgs:  # iterate over each tsg
            quadkeys = (serder.said, prefixer.qb64, f"{seqner.sn:032x}", ssaider.qb64)
            for siger in sigers:
                self.hby.db.esigs.add(keys=quadkeys, val=siger)
        for cigar in cigars:
            self.hby.db.ecigs.add(keys=(dig,), val=(cigar.verfer, cigar))

        saider = coring.Saider(qb64=serder.said)
        self.hby.db.epath.pin(keys=(dig,), vals=[bytes(p) for p in pathed])
        if pdig:
            self.hby.db.erpy.pin(keys=(pdig,), val=saider)

        self.hby.db.exns.put(keys=(dig,), val=serder)

    def lead(self, hab, said):
        """ Determines is current member represented by hab is the lead of an exn message

        Lead is the signer of the exn with the lowest signing index

        Parameters:
            hab (Hab): Habitat for sending of exchange message represented by SAID
            said (str): qb64 SAID of exchange message

        Returns:
            bool: True means hab is the lead

        """
        if not isinstance(hab, habbing.GroupHab):
            return True

        keys = [verfer.qb64 for verfer in hab.kever.verfers]
        tsgs = eventing.fetchTsgs(self.hby.db.esigs, coring.Saider(qb64=said))
        if not tsgs:  # otherwise it contains a list of sigs
            return False

        (_, _, _, sigers) = tsgs[0]
        windex = min([siger.index for siger in sigers])

        # True if Elected to send an EXN to its recipient
        return hab.mhab.kever.verfers[0].qb64 == keys[windex]

    def complete(self, said):
        """

        Args:
            said (str): qb64 said of exchange message to check status

        Returns:
            bool: True means exchange message is has been saved
        """
        serder = self.hby.db.exns.get(keys=(said,))
        if not serder:
            return False
        else:
            if serder.said != said:
                raise kering.ValidationError(f"invalid exchange escrowed event {serder.said}-{said}")

        return True


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
        serder = coring.Sadder(raw=msg)
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

    if e:
        e["d"] = ""
        _, e = coring.Saider.saidify(sad=e, label=coring.Saids.d)

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
    return serdering.SerderKERI(sad=ked), end  # return serialized ked


def cloneMessage(hby, said):
    """ Load and verify signatures on message exn

    Parameters:
        hby (Habery): database environment from which to clone message
        said (str): qb64 SAID of message exn to load

    Returns:
        tuple: (serder, list) of message exn and pathed signatures on embedded attachments

    """
    exn = hby.db.exns.get(keys=(said,))
    if exn is None:
        return None, None

    verify(hby=hby, serder=exn)

    pathed = dict()
    e = coring.Pather(path=["e"])
    for p in hby.db.epath.get(keys=(exn.said,)):
        pb = bytearray(p.encode("utf-8"))
        pather = coring.Pather(qb64b=pb, strip=True)
        if pather.startswith(e):
            np = pather.strip(e)
            nesting(np.path, pathed, pb)

    return exn, pathed


def serializeMessage(hby, said, pipelined=False):
    atc = bytearray()

    exn = hby.db.exns.get(keys=(said,))
    if exn is None:
        return None, None

    atc.extend(exn.raw)

    tsgs, cigars = verify(hby=hby, serder=exn)

    if len(tsgs) > 0:
        for (prefixer, seqner, saider, sigers) in tsgs:
            atc.extend(coring.Counter(coring.CtrDex.TransIdxSigGroups, count=1).qb64b)
            atc.extend(prefixer.qb64b)
            atc.extend(seqner.qb64b)
            atc.extend(saider.qb64b)

            atc.extend(coring.Counter(code=coring.CtrDex.ControllerIdxSigs, count=len(sigers)).qb64b)
            for siger in sigers:
                atc.extend(siger.qb64b)

    if len(cigars) > 0:
        atc.extend(coring.Counter(code=coring.CtrDex.NonTransReceiptCouples, count=len(cigars)).qb64b)
        for cigar in cigars:
            if cigar.verfer.code not in coring.NonTransDex:
                raise ValueError("Attempt to use tranferable prefix={} for "
                                 "receipt.".format(cigar.verfer.qb64))
            atc.extend(cigar.verfer.qb64b)
            atc.extend(cigar.qb64b)

    # Smash the pathed components on the end
    for p in hby.db.epath.get(keys=(exn.said,)):
        atc.extend(coring.Counter(code=coring.CtrDex.PathedMaterialQuadlets,
                                  count=(len(p) // 4)).qb64b)
        atc.extend(p.encode("utf-8"))

    msg = bytearray()

    if pipelined:
        if len(atc) % 4:
            raise ValueError("Invalid attachments size={}, nonintegral"
                             " quadlets.".format(len(atc)))
        msg.extend(coring.Counter(code=coring.CtrDex.AttachedMaterialQuadlets,
                                  count=(len(atc) // 4)).qb64b)

    msg.extend(atc)
    return msg


def nesting(paths, acc, val):
    if len(paths) == 0:
        return val
    else:
        first_value = paths[0]
        nacc = dict()
        acc[first_value] = nesting(paths[1:], nacc, val)
        return acc


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
            raise MissingSignatureError(f"Not enough signatures in  {indices}"
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

    return tsgs, cigars

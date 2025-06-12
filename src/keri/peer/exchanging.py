# -*- encoding: utf-8 -*-
"""
keri.peer.exchanging module

"""
import datetime
import logging
from datetime import timedelta

from hio.help import decking

from .. import help, kering, core
from ..app import habbing
from ..core import eventing, coring, serdering
from ..help import helping
from ..kering import ValidationError, MissingSignatureError, Vrsn_1_0, Vrsn_2_0

ExchangeMessageTimeWindow = timedelta(seconds=300)

logger = help.ogler.getLogger()


class Exchanger:
    """
     Peer to Peer KERI message Exchanger.
    """

    TimeoutPSE = 10  # seconds to timeout partially signed or delegated escrows

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

    def processEvent(self, serder, tsgs=None, cigars=None, ptds=None, essrs=None, **kwa):
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
            ptds (list[bytes]): pathed Cesr Streams
            essrs (list[Texter]): ESSR streams as Texters

        """
        ptds = ptds if ptds is not None else []
        essrs = essrs if essrs is not None else []
        route = serder.ked["r"]
        sender = serder.ked["i"]


        behavior = self.routes[route] if route in self.routes else None
        if tsgs:
            for prefixer, seqner, ssaider, sigers in tsgs:  # iterate over each tsg
                if sender != prefixer.qb64:  # sig not by aid
                    msg = (f"Skipped signature not from aid = "
                           f"{sender}, from {prefixer.qb64} on exn msg = {serder.said}")
                    logger.info(msg)
                    logger.debug("Exchange message body=\n%s\n", serder.pretty())
                    raise MissingSignatureError(msg)

                if prefixer.qb64 not in self.kevers or self.kevers[prefixer.qb64].sn < seqner.sn:
                    if self.escrowPSEvent(serder=serder, tsgs=tsgs, pathed=ptds):
                        self.cues.append(dict(kin="query", q=dict(r="logs", pre=prefixer.qb64, sn=seqner.snh)))
                    msg = f"Unable to find sender {prefixer.qb64} in kevers for evt = {serder.said}"
                    logger.info(msg)
                    logger.debug("Exchange message body=\n%s\n", serder.pretty())
                    raise MissingSignatureError(msg)

                # Verify the signatures are valid and that the signature threshold as of the signing event is met
                tholder, verfers = self.hby.db.resolveVerifiers(pre=prefixer.qb64, sn=seqner.sn, dig=ssaider.qb64)
                _, indices = eventing.verifySigs(serder.raw, sigers, verfers)

                if not tholder.satisfy(indices):  # We still don't have all the sigers, need to escrow
                    if self.escrowPSEvent(serder=serder, tsgs=tsgs, pathed=ptds):
                        self.cues.append(dict(kin="query", q=dict(r="logs", pre=prefixer.qb64, sn=seqner.snh)))
                    msg = (f"Not enough signatures in idx={indices} route={route} "
                           f"for evt = {serder.said} recipient={serder.ked.get('rp', '')}")
                    logger.info(msg)
                    logger.debug("Exchange message body=\n%s\n", serder.pretty())
                    raise MissingSignatureError(msg)

        elif cigars:
            for cigar in cigars:
                if sender != cigar.verfer.qb64:  # cig not by aid
                    msg = (f"Skipped cig not from aid={sender} route={route} "
                           f"for exn evt = {serder.said} recipient={serder.ked.get('rp', '')}")
                    logger.info(msg)
                    logger.debug("Exchange message body=\n%s\n", serder.pretty())
                    raise MissingSignatureError(msg)

                if not cigar.verfer.verify(cigar.raw, serder.raw):  # cig not verify
                    msg = (f"Failure satisfying exn on cigs for {cigar} route={route} "
                           f"for evt = {serder.said} recipient={serder.ked.get('rp', '')}")
                    logger.info(msg)
                    logger.debug("Exchange message body=\n%s\n", serder.pretty())
                    raise MissingSignatureError(msg)
        else:
            self.escrowPSEvent(serder=serder, tsgs=[], pathed=ptds)
            msg = (
                f"Failure satisfying exn, no cigs or sigs for evt = {serder.said} "
                f"on route {route} recipient = {serder.ked.get('rp', '')}")
            logger.info(msg)
            logger.debug("Exchange message body=\n%s\n", serder.pretty())
            raise MissingSignatureError(msg)

        e = coring.Pather(parts=["e"])

        kwa = dict()
        attachments = []
        for p in ptds:
            pattach = bytearray(p)
            pather = coring.Pather(qb64b=pattach, strip=True)
            if pather.startswith(e):
                np = pather.strip(e)
                attachments.append((np, pattach))

        kwa["attachments"] = attachments
        if essrs:
            kwa["essr"] = b''.join([texter.raw for texter in essrs])

        if isinstance(serder.seals, str):
            if 'essr' not in kwa:
                raise ValidationError("at least one essr attachment is required")

            essr = kwa['essr']
            dig = serder.seals
            diger = coring.Diger(qb64=dig)
            if not diger.verify(ser=essr):
                raise ValidationError(f"essr diger={diger.qb64} is invalid against content")

        # Perform behavior specific verification, think IPEX chaining requirements
        try:
            if not behavior.verify(serder=serder, **kwa):
                logger.error("exn event for route %s failed behavior verification. said=%s", route, serder.said)
                logger.debug(f"Event=\n%s\n", serder.pretty())
                return

        except AttributeError:
            logger.debug("Behavior for %s missing or does not have verify for said %s", route, serder.said)
            logger.debug("Exn Event Body=\n%s\n", serder.pretty())

        # Always persist events
        self.logEvent(serder, ptds, tsgs, cigars, essrs)
        self.cues.append(dict(kin="saved", said=serder.said))

        # Execute any behavior specific handling, not sure if this should be different than verify
        try:
            behavior.handle(serder=serder, **kwa)
        except AttributeError:
            logger.debug("Behavior for %s missing or does not have handle for SAID=%s", route, serder.said)
            logger.debug("Event=\n%s\n", serder.pretty())

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

        self.hby.db.epsd.put(keys=(dig,), val=coring.Dater())
        self.hby.db.epath.pin(keys=(dig,), vals=[bytes(p) for p in pathed])
        return self.hby.db.epse.put(keys=(dig,), val=serder)

    def processEscrowPartialSigned(self):
        """ Process escrow of partially signed messages """
        for (dig,), serder in self.hby.db.epse.getItemIter():
            try:
                tsgs = []
                klases = (coring.Prefixer, coring.Seqner, coring.Saider)
                args = ("qb64", "snh", "qb64")
                sigers = []

                dtnow = helping.nowUTC()
                dater = self.hby.db.epsd.get(keys=(dig,))
                if dater is None:
                    raise ValidationError("Missing exn escrowed event datetime "
                                          f"at dig = {dig}.")

                dte = dater.datetime
                if (dtnow - dte) > datetime.timedelta(seconds=self.TimeoutPSE):
                    # escrow stale so raise ValidationError which unescrows below
                    raise ValidationError("Stale exn event escrow "
                                          f"at dig = {dig}.")

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
                essrs = [texter for texter in self.hby.db.essrs.get(keys=(dig,))]

                self.processEvent(serder=serder, tsgs=tsgs, ptds=pathed, essrs=essrs)

            except MissingSignatureError as ex:
                if logger.isEnabledFor(logging.TRACE):
                    logger.trace("Exchange partially signed unescrow failed: %s\n", ex.args[0])
                    logger.debug(f"Event body=\n%s\n", serder.pretty())
            except Exception as ex:
                self.hby.db.epse.rem(dig)
                self.hby.db.epsd.rem(dig)
                self.hby.db.esigs.rem(dig)
                if logger.isEnabledFor(logging.DEBUG):
                    logger.exception("Exchange partially signed unescrowed: %s", ex.args[0])
                else:
                    logger.error("Exchange partially signed unescrowed: %s", ex.args[0])
            else:
                self.hby.db.epse.rem(dig)
                self.hby.db.esigs.rem(dig)
                logger.info("Exchanger unescrow succeeded in valid exchange: creder=%s", serder.said)
                logger.debug("Event=\n%s\n", serder.pretty())

    def logEvent(self, serder, pathed=None, tsgs=None, cigars=None, essrs=None):
        dig = serder.said
        pdig = serder.ked['p']
        pathed = pathed or []
        tsgs = tsgs or []
        cigars = cigars or []
        essrs = essrs or []

        for prefixer, seqner, ssaider, sigers in tsgs:  # iterate over each tsg
            quadkeys = (serder.said, prefixer.qb64, f"{seqner.sn:032x}", ssaider.qb64)
            for siger in sigers:
                self.hby.db.esigs.add(keys=quadkeys, val=siger)
        for cigar in cigars:
            self.hby.db.ecigs.add(keys=(dig,), val=(cigar.verfer, cigar))

        saider = coring.Saider(qb64=serder.said)
        self.hby.db.epath.pin(keys=(dig,), vals=[bytes(p) for p in pathed])
        for texter in essrs:
            self.hby.db.essrs.add(keys=(dig,), val=texter)
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


def exincept(sender="",
            receiver="",
            route="",
            modifiers=None,
            attributes=None,
            nonce=None,
            stamp=None,
            pvrsn=Vrsn_2_0,
            gvrsn=None,
            kind=coring.Kinds.json):
    """Utility function to automate creation of exchange incept, 'xip', messages.
    Xincept 'xip' message is a SAD item with an associated derived SAID in its
    'd' field.  Only defined for KERI v2.

    Returns:
        xincept (SerderKERI): xincept 'xip' message.

    Fields in order:
    (v, t, d, u, ri, dt, r, q, a),


    Parameters:
        sender (str): qb64 of sender identifier (AID)
        receiver (str): qb64 of receiver identifier (AID)
        route (str):  '/' delimited path identifier of data flow handler
               (behavior) to processs the reply if any
        modifiers (dict): modifiers
        attributes (dict): attributes
        nonce (str|None): qb64 of UUID salty nonce. When None generate nonce.
        stamp (str):  date-time-stamp RFC-3339 profile of ISO-8601 datetime of
                      creation of message or data, default is now.
        pvrsn (Versionage): KERI protocol version
        gvrsn (Versionage): CESR genus vrsion
        kind (str): serialization kind value of Serials

    Version 2:
    {
      "v" : "KERI10JSON00011c_",
      "t" : "rpy",
      "d": "EZ-i0d8JZAoTNZH3ULaU6JR2nmwyvYAfSVPzhzS6b5CM",
      "u": '0AAwMTIzNDU2Nzg5YWJjZGVm',
      "i": "EAoTNZH3ULvYAfSVPzhzS6baU6JR2nmwyZ-i0d8JZ5CM",
      "ri": "EBPzhzS6baU6JR2nmwyZ-i0d8JZ5CMAoTNZH3ULvYAfS",
      "dt": "2020-08-22T17:50:12.988921+00:00",
      "r" : "/logs/processor",
      "q":
      {
           "name": "Zoe",
           "color": "Blue"
      }
      "a":
      {
          "d": "EaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM"
      }
    }
    """
    pvrsn = pvrsn if pvrsn is not None else Vrsn_2_0
    vs = kering.versify(pvrsn=pvrsn, kind=kind, size=0, gvrsn=gvrsn)

    ilk = kering.Ilks.xip

    sad = dict(v=vs,  # version string
               t=ilk, # message type
               d="",  # message said
               u=nonce if nonce is not None else coring.Noncer(),
               i=sender,  # sender aid qb64
               ri=receiver,  # receiver aid qb64
               dt=stamp if stamp is not None else helping.nowIso8601(),
               r=route if route is not None else "",  # route
               q=modifiers if modifiers is not None else {},  # modifiers
               a=attributes if attributes is not None else {},  # attributes
               )

    serder = serdering.SerderKERI(sad=sad, makify=True)
    return serder


def exchange(route,
             sender,
             payload=None,
             diger=None,
             recipient=None,
             date=None,
             dig="",
             xid="",
             modifiers=None,
             embeds=None,
             version=coring.Version,
             pvrsn=None,
             gvrsn=None,
             kind=coring.Kinds.json):
    """ Create an `exn` message with the specified route and payload

    Parameters:
        route (str): to destination route of the message
        sender (str): qb64 AID of sender of the exn
        payload (list | dict): body of message to deliver to route
        diger (Diger): qb64 digest of payload
        xid (str): qb64 of exchange ID  SAID of exchange inception 'xip' if any
        recipient (str) optional qb64 AID recipient of exn
        date (str): Iso8601 formatted date string to use for this request
        dig (str) qb64 SAID of previous event if any
        modifiers (dict): equivalent of query string of uri, modifiers for the request that are not
                         part of the payload
        embeds (dict): named embeded KERI event CESR stream with attachments
        version (Versionage): KERI protocol default version if psvrsn is None
        pvrsn (Versionage): KERI protocol version
        gvrsn (Versionage): CESR genus vrsion
        kind (Serials): is serialization kind

    """
    pvrsn = pvrsn if pvrsn is not None else version
    vs = coring.versify(pvrsn=pvrsn, kind=kind, size=0, gvrsn=gvrsn)

    ilk = eventing.Ilks.exn
    dt = date if date is not None else helping.nowIso8601()
    xid = xid if xid is not None else ""
    p = dig if dig is not None else ""
    ri = recipient if recipient is not None else ""
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
        pather = coring.Pather(parts=["e", label])
        pathed.extend(pather.qb64b)
        pathed.extend(atc)
        if len(pathed) // 4 < 4096:
            end.extend(core.Counter(core.Codens.PathedMaterialGroup,
                                      count=(len(pathed) // 4),
                                      version=kering.Vrsn_1_0).qb64b)
        else:
            end.extend(core.Counter(core.Codens.BigPathedMaterialGroup,
                                      count=(len(pathed) // 4),
                                      version=kering.Vrsn_1_0).qb64b)
        end.extend(pathed)

    if e:
        e["d"] = ""
        _, e = coring.Saider.saidify(sad=e, label=coring.Saids.d)

    modifiers = modifiers if modifiers is not None else {}

    # Attr field 'a' can be either a said or a nested block and the fields
    # of the nested block can be saids of further nested block or nested blocks
    if pvrsn.major == Vrsn_1_0.major:
        if diger is None:
            attrs = dict()

            if recipient is not None:
                attrs['i'] = recipient

            attrs |= payload

        else:
            attrs = diger.qb64

        sad = dict(v=vs,
                   t=ilk,
                   d="",
                   i=sender,
                   rp=ri,
                   p=p,
                   dt=dt,
                   r=route,
                   q=modifiers if modifiers is not None else {},  # q field required
                   a=attrs,
                   e=e)
    else:
        attrs = {}
        if e:
            attrs['e'] = e

        attrs |= payload

        sad = dict(v=vs,
                   t=ilk,
                   d="",
                   i=sender,
                   ri=ri,
                   x=xid,
                   p=p,
                   dt=dt,
                   r=route,
                   q=modifiers if modifiers is not None else {},  # q field required
                   a=attrs)

    return serdering.SerderKERI(sad=sad, makify=True), end  # return serialized ked


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
    e = coring.Pather(parts=["e"])
    for p in hby.db.epath.get(keys=(exn.said,)):
        pb = bytearray(p.encode("utf-8"))
        pather = coring.Pather(qb64b=pb, strip=True)
        if pather.startswith(e):
            np = pather.strip(e)
            nesting(np.rparts, pathed, pb)  # no unit test for this

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
            atc.extend(core.Counter(core.Codens.TransIdxSigGroups, count=1,
                                    version=kering.Vrsn_1_0).qb64b)
            atc.extend(prefixer.qb64b)
            atc.extend(seqner.qb64b)
            atc.extend(saider.qb64b)

            atc.extend(core.Counter(core.Codens.ControllerIdxSigs, count=len(sigers),
                                    version=kering.Vrsn_1_0).qb64b)
            for siger in sigers:
                atc.extend(siger.qb64b)

    if len(cigars) > 0:
        atc.extend(core.Counter(core.Codens.NonTransReceiptCouples,
                                count=len(cigars), version=kering.Vrsn_1_0).qb64b)
        for cigar in cigars:
            if cigar.verfer.code not in coring.NonTransDex:
                raise ValueError("Attempt to use tranferable prefix={} for "
                                 "receipt.".format(cigar.verfer.qb64))
            atc.extend(cigar.verfer.qb64b)
            atc.extend(cigar.qb64b)

    # Smash the pathed components on the end
    for p in hby.db.epath.get(keys=(exn.said,)):
        atc.extend(core.Counter(core.Codens.PathedMaterialGroup,
                                  count=(len(p) // 4), version=kering.Vrsn_1_0).qb64b)
        atc.extend(p.encode("utf-8"))

    msg = bytearray()

    if pipelined:
        if len(atc) % 4:
            raise ValueError("Invalid attachments size={}, nonintegral"
                             " quadlets.".format(len(atc)))
        msg.extend(core.Counter(core.Codens.AttachmentGroup,
                                  count=(len(atc) // 4), version=kering.Vrsn_1_0).qb64b)

    msg.extend(atc)
    return msg


def nesting(paths, acc, val):
    """Nesting Pather parts

    Parameters:
        paths (list[list]): list of path parts
    """
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
            msg = f"Unable to find sender {prefixer.qb64} in kevers for evt = {serder.said}"
            logger.info(msg)
            logger.debug("Exn Body=\n%s\n", serder.pretty())
            raise MissingSignatureError(msg)

        # Verify the signatures are valid and that the signature threshold as of the signing event is met
        tholder, verfers = hby.db.resolveVerifiers(pre=prefixer.qb64, sn=seqner.sn, dig=ssaider.qb64)
        _, indices = eventing.verifySigs(serder.raw, sigers, verfers)

        if not tholder.satisfy(indices):  # We still don't have all the sigers, need to escrow
            msg = f"Not enough signatures in idx={indices} for evt = {serder.said}"
            logger.info(msg)
            logger.debug("Exn Body=\n%s\n", serder.pretty())
            raise MissingSignatureError(msg)
        accepted = True

    cigars = hby.db.ecigs.get(keys=(serder.said,))
    for cigar in cigars:
        if not cigar.verfer.verify(cigar.raw, serder.raw):  # cig not verify
            msg = f"Failure satisfying exn on cigs for {cigar} for evt = {serder.said}"
            logger.info(msg)
            logger.debug("Exn Body=\n%s\n", serder.pretty())
            raise MissingSignatureError(msg)
        accepted = True

    if not accepted:
        msg = f"No valid signatures stored for evt = {serder.said}"
        logger.info(msg)
        logger.debug("Exn Body=\n%s\n", serder.pretty())
        raise MissingSignatureError(msg)

    return tsgs, cigars

# -*- encoding: utf-8 -*-
"""
keri.peer.exchanging module
"""
import datetime
import logging
from datetime import timedelta

from hio.help import decking, ogler

from ..kering import (Vrsn_1_0, Vrsn_2_0, Ilks,
                      Kinds, Version, versify,
                      ValidationError, MissingSignatureError)
from ..core import (Counter, Pather, Dater, Diger, Number,
                    Prefixer, Seqner, Saider,
                    Serder, SerderKERI, Texter,
                    Saids, Codens, FirstSeen, SealEvent, Parser,
                    messagize,
                    verifySigs)
from ..db import fetchTsgs
from ..help import helping

ExchangeMessageTimeWindow = timedelta(seconds=300)

logger = ogler.getLogger()


class Exchanger:
    """
     Peer to Peer KERI message Exchanger."""

    TimeoutPSE = 10  # seconds to timeout partially signed or delegated escrows

    def __init__(self, hby, handlers, cues=None, delta=ExchangeMessageTimeWindow):
        """ Initialize instance

        Parameters:
            hby (Haberyu): database environment
            handlers (list): list of Handlers capable of responding to exn messages
            cues (Deck):  of Cues i.e. notices of requests needing response
            delta (timedelta): message timeout window"""

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

    def _raiseMissingKeyState(self, serder, missing):
        """Request missing KEL events and reject the current exchange."""
        seen = set()
        for prefixer, number in missing:
            sn = number.snh if number is not None else None
            key = (prefixer.qb64, sn)
            if key in seen:
                continue
            seen.add(key)

            query = dict(r="logs", pre=prefixer.qb64)
            if sn is not None:
                query["sn"] = sn
            self.cues.append(dict(kin="query", q=query))

        msg = f"Missing key state for attached evidence on evt={serder.said}"
        logger.info(msg)
        logger.debug("Exchange message body=\n%s\n", serder.pretty())
        raise MissingSignatureError(msg)

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
            kwa (dict): optional parsed attachment groups:
                nests contains parsed V2 nested substreams
                lsgs contains last-establishment signature groups
                ulgs contains unresolved foreign signer prefixes
                sscs contains sender-implied source seal couples
                ssts contains explicit source seal triples

        """
        ptds = ptds if ptds is not None else []
        essrs = essrs if essrs is not None else []
        route = serder.ked["r"]
        sender = serder.ked["i"]
        nests = kwa.get("nests")
        lsgs = list(kwa.get("lsgs", []))
        unresolvedLsgs = list(kwa.get("ulgs", []))
        sscs = kwa.get("sscs", [])
        ssts = kwa.get("ssts", [])

        behavior = self.routes[route] if route in self.routes else None
        tsgs = list(tsgs or [])
        cigars = list(cigars or [])

        # A seal couple implies the sender AID. Store both attachment forms as
        # an explicit sealing AID and historical event reference.
        sourceSeals = [(Prefixer(qb64=sender), number, diger)
                       for number, diger in sscs]
        sourceSeals.extend(ssts)

        senderTsgs = [tsg for tsg in tsgs if tsg[0].qb64 == sender]
        extraTsgs = [tsg for tsg in tsgs if tsg[0].qb64 != sender]
        extraLsgs = [lsg for lsg in lsgs if lsg[0].qb64 != sender]
        senderSourceSeals = [seal for seal in sourceSeals
                             if seal[0].qb64 == sender]
        extraSourceSeals = [seal for seal in sourceSeals
                            if seal[0].qb64 != sender]

        evidenceVerifier = getattr(behavior, "verifyEvidence", None)
        if senderTsgs and evidenceVerifier is None:
            # Routes without an evidence policy preserve the existing
            # TSG-over-cigar precedence. A sender TSG causes all cigars to be
            # ignored.
            senderCigars = []
            extraCigars = []
        else:
            senderCigars = [cigar for cigar in cigars
                            if cigar.verfer.qb64 == sender]
            extraCigars = [cigar for cigar in cigars
                           if cigar.verfer.qb64 != sender]
        if evidenceVerifier is None:
            extraSourceSeals = []

        (_, _, validSenderSourceSeals, _,
         missingSenderSourceSeals) = verifyAttachments(
            hby=self.hby, serder=serder, sourceSeals=senderSourceSeals)
        if missingSenderSourceSeals:
            self._raiseMissingKeyState(serder, missingSenderSourceSeals)

        validSenderTsgs = []
        validSenderCigars = []
        if validSenderSourceSeals:
            # A valid sender seal authenticates the EXN. Retain only valid
            # optional sender TSGs and do not fail on invalid ones.
            validSenderTsgs, _, _, _, _ = verifyAttachments(
                hby=self.hby, serder=serder, tsgs=senderTsgs)

        elif senderTsgs:
            for tsg in senderTsgs:
                prefixer, snumber, sdiger, sigers = tsg
                if prefixer.qb64 not in self.kevers or self.kevers[prefixer.qb64].sn < snumber.sn:
                    if self.escrowPSEvent(serder=serder, tsgs=tsgs, pathed=ptds,
                                          cigars=cigars, sourceSeals=sourceSeals,
                                          nests=nests):
                        self.cues.append(dict(kin="query", q=dict(r="logs", pre=prefixer.qb64, sn=snumber.snh)))
                    msg = f"Unable to find sender {prefixer.qb64} in kevers for evt = {serder.said}"
                    logger.info(msg)
                    logger.debug("Exchange message body=\n%s\n", serder.pretty())
                    raise MissingSignatureError(msg)

                tholder, verfers = self.hby.db.resolveVerifiers(
                    pre=prefixer.qb64, sn=snumber.sn, dig=sdiger.qb64)
                vsigers, indices = verifySigs(serder.raw, sigers, verfers)
                if not tholder.satisfy(indices):
                    if self.escrowPSEvent(serder=serder, tsgs=tsgs, pathed=ptds,
                                          cigars=cigars, sourceSeals=sourceSeals,
                                          nests=nests):
                        self.cues.append(dict(kin="query", q=dict(r="logs", pre=prefixer.qb64, sn=snumber.snh)))
                    msg = (f"Not enough signatures in idx={indices} route={route} "
                           f"for evt = {serder.said} receiver={serder.ked.get('rp', '')}")
                    logger.info(msg)
                    logger.debug("Exchange message body=\n%s\n", serder.pretty())
                    raise MissingSignatureError(msg)

                validSenderTsgs.append(
                    (prefixer, snumber, sdiger, vsigers))

        elif senderCigars:
            for cigar in senderCigars:
                if (cigar.verfer.transferable or
                        not cigar.verfer.verify(cigar.raw, serder.raw)):
                    msg = (f"Failure satisfying exn on cigs for {cigar} route={route} "
                           f"for evt = {serder.said} receiver={serder.ked.get('rp', '')}")
                    logger.info(msg)
                    logger.debug("Exchange message body=\n%s\n", serder.pretty())
                    raise MissingSignatureError(msg)

                validSenderCigars.append(cigar)

        elif not validSenderSourceSeals:
            # Do not escrow unsupported foreign-only evidence as missing sender
            # authentication on routes without an evidence policy.
            if (evidenceVerifier is None and
                    (extraTsgs or extraLsgs or extraCigars or unresolvedLsgs)):
                msg = (f"Skipped evidence not from aid={sender} route={route} "
                       f"for exn evt={serder.said}")
                logger.info(msg)
                logger.debug("Exchange message body=\n%s\n", serder.pretty())
                raise MissingSignatureError(msg)

            self.escrowPSEvent(serder=serder, tsgs=tsgs, pathed=ptds,
                               cigars=cigars, sourceSeals=sourceSeals,
                               nests=nests)
            msg = (
                f"Failure satisfying exn, no sender authentication for evt = {serder.said} "
                f"on route {route} receiver = {serder.ked.get('rp', '')}")
            logger.info(msg)
            logger.debug("Exchange message body=\n%s\n", serder.pretty())
            raise MissingSignatureError(msg)

        # A sender authenticated above may still carry unsupported foreign
        # evidence, which routes without an evidence policy must reject before
        # persistence.
        if (evidenceVerifier is None and
                (extraTsgs or extraLsgs or extraCigars or unresolvedLsgs)):
            msg = (f"Skipped evidence not from aid={sender} route={route} "
                   f"for exn evt={serder.said}")
            logger.info(msg)
            logger.debug("Exchange message body=\n%s\n", serder.pretty())
            raise MissingSignatureError(msg)

        (validExtraTsgs,
         validExtraCigars,
         validExtraSourceSeals,
         invalidExtra,
         missingExtra) = verifyAttachments(
             hby=self.hby,
             serder=serder,
             tsgs=extraTsgs,
             lsgs=extraLsgs,
             cigars=extraCigars,
             sourceSeals=extraSourceSeals,
             unresolved=unresolvedLsgs,
         )
        if missingExtra:
            self._raiseMissingKeyState(serder, missingExtra)

        e = Pather(parts=["e"])

        kwa = dict()
        attachments = []
        for p in ptds:
            pattach = bytearray(p)
            pather = Pather(qb64b=pattach, strip=True)
            if pather.startswith(e):
                np = pather.strip(e)
                attachments.append((np, pattach))

        kwa["attachments"] = attachments
        if nests and (route.startswith("/multisig") or route.startswith("/ipex")):
            kwa["nests"] = nests
        if essrs:
            kwa["essr"] = b''.join([texter.raw for texter in essrs])

        if isinstance(serder.seals, str):
            if 'essr' not in kwa:
                raise ValidationError("at least one essr attachment is required")

            essr = kwa['essr']
            dig = serder.seals
            diger = Diger(qb64=dig)
            if not diger.verify(ser=essr):
                raise ValidationError(f"essr diger={diger.qb64} is invalid against content")

        # Perform behavior specific verification, think IPEX chaining requirements
        try:
            if not behavior.verify(serder=serder, **kwa):
                logger.error("exn event for route %s failed behavior verification. said=%s", route, serder.said)
                logger.debug("Event=\n%s\n", serder.pretty())
                return

        except AttributeError:
            logger.debug("Behavior for %s missing or does not have verify for said %s", route, serder.said)
            logger.debug("Exn Event Body=\n%s\n", serder.pretty())

        if evidenceVerifier is None:
            acceptedExtras = ([], [], [])
        else:
            acceptedExtras = evidenceVerifier(
                serder=serder,
                tsgs=validExtraTsgs,
                cigars=validExtraCigars,
                sourceSeals=validExtraSourceSeals,
                invalid=invalidExtra,
            )
            if acceptedExtras is None:
                logger.error("exn evidence for route %s failed behavior verification. said=%s",
                             route, serder.said)
                logger.debug("Exn Event Body=\n%s\n", serder.pretty())
                return

        acceptedTsgs, acceptedCigars, acceptedSourceSeals = acceptedExtras
        tsgs = validSenderTsgs + acceptedTsgs
        cigars = validSenderCigars + acceptedCigars
        sourceSeals = validSenderSourceSeals + acceptedSourceSeals

        # Always persist events
        self.logEvent(serder, ptds, tsgs, cigars, essrs,
                      sourceSeals=sourceSeals, nests=nests)
        self.cues.append(dict(kin="saved", said=serder.said))

        # Execute any behavior specific handling, not sure if this should be different than verify
        try:
            behavior.handle(serder=serder, **kwa)
        except AttributeError:
            logger.debug("Behavior for %s missing or does not have handle for SAID=%s", route, serder.said)
            logger.debug("Event=\n%s\n", serder.pretty())

    def processEscrow(self):
        """ Process all escrows for `exn` messages"""
        self.processEscrowPartialSigned()

    def escrowPSEvent(self, serder, tsgs, pathed, cigars=None,
                      sourceSeals=None, nests=None):
        """ Escrow event that does not have enough signatures.

        Parameters:
            serder (Serder): instance of event
            tsgs (list): quadlet of prefixer seqner, saider, sigers
            pathed (list): list of bytes of attached paths
            cigars (list | None): nontransferable signatures to preserve
            sourceSeals (list | None): source seal triples to preserve
            nests (list | None): parsed V2 nested substreams to preserve

        """
        dig = serder.said
        cigars = cigars or []
        sourceSeals = sourceSeals or []
        for prefixer, seqner, ssaider, sigers in tsgs:
            quadkeys = (serder.said, prefixer.qb64,
                        f"{seqner.sn:032x}", ssaider.qb64)
            for siger in sigers:
                self.hby.db.esigs.add(keys=quadkeys, val=siger)
        for cigar in cigars:
            self.hby.db.ecigs.add(keys=(dig,), val=(cigar.verfer, cigar))
        for prefixer, number, diger in sourceSeals:
            self.hby.db.ests.add(keys=(serder.said, prefixer.qb64),
                                 val=(number, diger))

        self.hby.db.epsd.put(keys=(dig,), val=Dater())
        self.hby.db.epath.pin(keys=(dig,), vals=[bytes(p) for p in pathed])
        if nests:
            self.hby.db.enst.pin(keys=(dig,),
                                 vals=[bytes(serializeParsedSubstream(nest)) for nest in nests])
        return self.hby.db.epse.put(keys=(dig,), val=serder)

    def processEscrowPartialSigned(self):
        """ Process escrow of partially signed messages"""
        for (dig,), serder in self.hby.db.epse.getTopItemIter():
            if self.hby.db.exns.get(keys=(dig,)) is not None:
                self.hby.db.epse.rem(dig)
                self.hby.db.epsd.rem(dig)
                continue

            try:
                tsgs = []
                klases = (Prefixer, Seqner, Saider)
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
                for keys, siger in self.hby.db.esigs.getTopItemIter(keys=(dig, "")):
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
                cigars = []
                for verfer, cigar in self.hby.db.ecigs.get(keys=(dig,)):
                    cigar.verfer = verfer
                    cigars.append(cigar)
                sourceSeals = []
                for keys, (number, diger) in self.hby.db.ests.getTopItemIter(
                        keys=(dig, "")):
                    sourceSeals.append((Prefixer(qb64=keys[1]), number, diger))
                nests = loadParsedNestedSubstreams(self.hby, dig)

                # The same stores hold escrowed and accepted evidence. Remove
                # the temporary branches so processEvent writes back only the
                # evidence that passes current verification and policy.
                self.hby.db.esigs.trim(keys=(dig, ""))
                self.hby.db.ecigs.rem(keys=(dig,))
                self.hby.db.ests.trim(keys=(dig, ""))
                self.processEvent(serder=serder, tsgs=tsgs, cigars=cigars,
                                  ptds=pathed,
                                  essrs=essrs, ssts=sourceSeals, nests=nests)

            except MissingSignatureError as ex:
                for prefixer, seqner, ssaider, sigers in tsgs:
                    quadkeys = (serder.said, prefixer.qb64,
                                f"{seqner.sn:032x}", ssaider.qb64)
                    for siger in sigers:
                        self.hby.db.esigs.add(keys=quadkeys, val=siger)
                for cigar in cigars:
                    self.hby.db.ecigs.add(
                        keys=(serder.said,), val=(cigar.verfer, cigar))
                for prefixer, number, diger in sourceSeals:
                    self.hby.db.ests.add(
                        keys=(serder.said, prefixer.qb64),
                        val=(number, diger))
                if logger.isEnabledFor(logging.TRACE):
                    logger.trace("Exchange partially signed unescrow failed: %s\n", ex.args[0])
                    logger.debug("Event body=\n%s\n", serder.pretty())
            except Exception as ex:
                saved = self.hby.db.exns.get(keys=(dig,)) is not None
                self.hby.db.epse.rem(dig)
                self.hby.db.epsd.rem(dig)
                if not saved:
                    self.hby.db.esigs.trim(keys=(dig, ""))
                    self.hby.db.ecigs.rem(keys=(dig,))
                    self.hby.db.ests.trim(keys=(dig, ""))
                    self.hby.db.epath.rem(keys=(dig,))
                    self.hby.db.enst.rem(keys=(dig,))
                if logger.isEnabledFor(logging.DEBUG):
                    logger.exception("Exchange partially signed unescrowed: %s", ex.args[0])
                else:
                    logger.error("Exchange partially signed unescrowed: %s", ex.args[0])
            else:
                saved = self.hby.db.exns.get(keys=(dig,)) is not None
                self.hby.db.epse.rem(dig)
                self.hby.db.epsd.rem(dig)
                if not saved:
                    self.hby.db.esigs.trim(keys=(dig, ""))
                    self.hby.db.ecigs.rem(keys=(dig,))
                    self.hby.db.ests.trim(keys=(dig, ""))
                    self.hby.db.epath.rem(keys=(dig,))
                    self.hby.db.enst.rem(keys=(dig,))
                    logger.info("Exchanger unescrow rejected exchange: said=%s", serder.said)
                    continue
                logger.info("Exchanger unescrow succeeded in valid exchange: creder=%s", serder.said)
                logger.debug("Event=\n%s\n", serder.pretty())

    def logEvent(self, serder, pathed=None, tsgs=None, cigars=None, essrs=None,
                 sourceSeals=None, nests=None):
        dig = serder.said
        pdig = serder.ked['p']
        pathed = pathed or []
        tsgs = tsgs or []
        cigars = cigars or []
        essrs = essrs or []
        sourceSeals = sourceSeals or []

        escrowed = (self.hby.db.exns.get(keys=(dig,)) is None and
                    self.hby.db.epse.get(keys=(dig,)) is not None)
        if escrowed:
            self.hby.db.esigs.trim(keys=(dig, ""))
            self.hby.db.ecigs.rem(keys=(dig,))
            self.hby.db.ests.trim(keys=(dig, ""))
            self.hby.db.epath.rem(keys=(dig,))
            self.hby.db.enst.rem(keys=(dig,))

        for prefixer, seqner, ssaider, sigers in tsgs:
            quadkeys = (serder.said, prefixer.qb64,
                        f"{seqner.sn:032x}", ssaider.qb64)
            for siger in sigers:
                self.hby.db.esigs.add(keys=quadkeys, val=siger)
        for cigar in cigars:
            self.hby.db.ecigs.add(keys=(dig,), val=(cigar.verfer, cigar))

        exnDiger = Diger(qb64=serder.said)
        self.hby.db.epath.pin(keys=(dig,), vals=[bytes(p) for p in pathed])
        if nests:
            self.hby.db.enst.pin(keys=(dig,),
                                 vals=[bytes(serializeParsedSubstream(nest)) for nest in nests])
        for texter in essrs:
            self.hby.db.essrs.add(keys=(dig,), val=texter)
        for prefixer, number, diger in sourceSeals:
            self.hby.db.ests.add(keys=(serder.said, prefixer.qb64),
                                 val=(number, diger))
        if pdig:
            self.hby.db.erpy.pin(keys=(pdig,), val=exnDiger)

        self.hby.db.exns.put(keys=(dig,), val=serder)
        if escrowed:
            self.hby.db.epse.rem(dig)
            self.hby.db.epsd.rem(dig)

    def lead(self, hab, said):
        """ Determines is current member represented by hab is the lead of an exn message

        Lead is the signer of the exn with the lowest signing index

        Parameters:
            hab (Hab): Habitat for sending of exchange message represented by SAID
            said (str): qb64 SAID of exchange message

        Returns:
            bool: True means hab is the lead"""
        from ..app import GroupHab

        if not isinstance(hab, GroupHab):
            return True

        keys = [verfer.qb64 for verfer in hab.kever.verfers]
        tsgs = fetchTsgs(self.hby.db.esigs, Diger(qb64=said))
        if not tsgs:  # otherwise it contains a list of sigs
            return False

        (_, _, _, sigers) = tsgs[0]
        windex = min([siger.index for siger in sigers])

        # True if Elected to send an EXN to its receiver
        return hab.mhab.kever.verfers[0].qb64 == keys[windex]

    def complete(self, said):
        """

        Parameters:
            said (str): qb64 said of exchange message to check status

        Returns:
            bool: True means exchange message is has been saved"""
        serder = self.hby.db.exns.get(keys=(said,))
        if not serder:
            return False
        else:
            if serder.said != said:
                raise ValidationError(f"invalid exchange escrowed event {serder.said}-{said}")

        return True



def exchangeOld(*,
             sender="",
             receiver="",
             xid="",
             prior="",
             route="",
             modifiers=None,
             attributes=None,
             diger=None,
             embeds=None,
             stamp=None,
             version=Version,
             pvrsn=None,
             gvrsn=None,
             kind=Kinds.json,):
    """ Create an `exn` message with the specified route and payload

    Parameters:
        sender (str): qb64 of sender identifier (AID)
        receiver (str): qb64 of receiver identifier (AID)
        xid (str): qb64 of exchange ID which is SAID of exchange inception 'xip'
            if any
        prior (str): qb64 of prior exchange event including 'xip" if any
        route (str):  '/' delimited path identifier of data flow handler
            (behavior) to processs the reply if any (equivalent of
            url path to resource)
        modifiers (dict): modifiers field map (equvalent of http query string)
        attributes (dict): attributes field map (payload body)
        stamp (str):  date-time-stamp RFC-3339 profile of ISO-8601 datetime of
            creation of message or data, default is now.
        version (Versionage): KERI protocol default version if psvrsn is None
        pvrsn (Versionage): KERI protocol version
        gvrsn (Versionage): CESR Genus version for attachment group codes or
            nesting group code (useful when serder.gvrsn < 2)
            gvrsn = max(svrsn, gvrsn) where svrsn = serder.gvrsn
                if serder.gvrsn else serder.pvrsn
        kind (str): serialization for key event message
            one of Kinds ("json","cbor","mgpk","cesr")
        diger (Diger): qb64 digest of attributes section (payload)
        embeds (dict): named embeded KERI event CESR stream with attachments"""
    pvrsn = pvrsn if pvrsn is not None else version
    vs = versify(pvrsn=pvrsn, kind=kind, size=0, gvrsn=gvrsn)

    #ilk = Ilks.exn
    #dt = stamp if stamp is not None else helping.nowIso8601()
    #xid = xid if xid is not None else ""
    #p = prior if prior is not None else ""
    #ri = receiver if receiver is not None else ""
    #modifiers = modifiers if modifiers is not None else {}

    end = bytearray()

    if pvrsn.major == Vrsn_1_0.major:
        embeds = embeds if embeds is not None else {}
        e = dict()
        for label, msg in embeds.items():
            serder = Serder(raw=msg)
            e[label] = serder.sad
            atc = bytes(msg[serder.size:])
            if not atc:
                continue

            pathed = bytearray()
            pather = Pather(parts=["e", label])
            pathed.extend(pather.qb64b)
            pathed.extend(atc)
            if len(pathed) // 4 < 4096:
                end.extend(Counter(Codens.PathedMaterialCouples,
                                   count=(len(pathed) // 4),
                                          version=Vrsn_1_0).qb64b)
            else:
                end.extend(Counter(Codens.BigPathedMaterialCouples,
                                   count=(len(pathed) // 4),
                                          version=Vrsn_1_0).qb64b)
            end.extend(pathed)

        if e:
            e["d"] = ""
            _, e = Saider.saidify(sad=e, label=Saids.d)

        if diger is None:
            #attrs = dict()
            if receiver:  # not (empty or None)
                attributes = attributes if attributes is not None else {}
                attributes['i'] = receiver
                #attrs['i'] = receiver
            #attrs |= attributes

        else:
            # only in v1 exn can the attributes field 'a' be either a said or
            # a field map.  In v2 it must be a field map.
            attributes = diger.qb64  # SAID of ESSR encrypted attachment

        sad = dict(v=vs,
                   t=Ilks.exn,
                   d="", # computed by SerderKERI init
                   i=sender if sender is not None else "",
                   rp=receiver if receiver is not None else "",
                   p=prior if prior is not None else "",
                   dt=stamp if stamp is not None else helping.nowIso8601(),
                   r=route if route is not None else "",
                   q=modifiers if modifiers is not None else {},  # q field required
                   a=attributes if attributes is not None else {},
                   e=e)
    else:
        if end or diger:
            raise ValueError(f"Invalid diger or embeds not supported in "
                             f"version {pvrsn.major} exchange")

        sad = dict(v=vs,
                   t=Ilks.exn,
                   d="",  # computed by SerderKERI init
                   i=sender if sender is not None else "",
                   ri=receiver if receiver is not None else "",
                   x=xid if xid is not None else "",
                   p=prior if prior is not None else "",
                   dt=stamp if stamp is not None else helping.nowIso8601(),
                   r=route if route is not None else "",
                   q=modifiers if modifiers is not None else {},  # q field required
                   a=attributes if attributes is not None else {}
                   )

    return SerderKERI(sad=sad, makify=True)  # return serialized ked
    #return SerderKERI(sad=sad, makify=True), end  # return serialized ked


def specialExchange(*,
             sender="",
             receiver="",
             xid="",
             prior="",
             route="",
             modifiers=None,
             attributes=None,
             diger=None,
             embeds=None,
             stamp=None,
             version=Vrsn_1_0,
             pvrsn=None,
             gvrsn=None,
             kind=Kinds.json,):
    """Create an `exn` with either an ESSR attachment or embeds with path
    attachment as determined by the presence of diger or embeds parameters
    repectively

    Parameters:
        sender (str): qb64 of sender identifier (AID)
        receiver (str): qb64 of receiver identifier (AID)
        xid (str): qb64 of exchange ID which is SAID of exchange inception 'xip'
            if any
        prior (str): qb64 of prior exchange event including 'xip" if any
        route (str):  '/' delimited path identifier of data flow handler
            (behavior) to processs the reply if any (equivalent of
            url path to resource)
        modifiers (dict): modifiers field map (equvalent of http query string)
        attributes (dict): attributes field map (payload body)
        stamp (str):  date-time-stamp RFC-3339 profile of ISO-8601 datetime of
            creation of message or data, default is now.
        version (Versionage): KERI protocol default version if psvrsn is None
        pvrsn (Versionage): KERI protocol version
        gvrsn (Versionage): CESR Genus version for attachment group codes or
            nesting group code (useful when serder.gvrsn < 2)
            gvrsn = max(svrsn, gvrsn) where svrsn = serder.gvrsn
                if serder.gvrsn else serder.pvrsn
        kind (str): serialization for key event message
            one of Kinds ("json","cbor","mgpk","cesr")
        diger (Diger): qb64 digest of attributes section (payload)
        embeds (dict): named embeded KERI event CESR stream with attachments

    Returns:
        embedded (SerderKeri, bytearray): of form (exchange, attachments) where
        exchange: serder of exchange message and atc is serialized path
            attachments of embeds"""
    pvrsn = pvrsn if pvrsn is not None else version
    vs = versify(pvrsn=pvrsn, kind=kind, size=0, gvrsn=gvrsn)

    #ilk = Ilks.exn
    #dt = stamp if stamp is not None else helping.nowIso8601()
    #xid = xid if xid is not None else ""
    #p = prior if prior is not None else ""
    #ri = receiver if receiver is not None else ""
    #modifiers = modifiers if modifiers is not None else {}

    if pvrsn.major == Vrsn_1_0.major:
        end = bytearray()
        embeds = embeds if embeds is not None else {}
        e = dict()

        for label, msg in embeds.items():
            serder = Serder(raw=msg)
            e[label] = serder.sad
            atc = bytes(msg[serder.size:])
            if not atc:
                continue

            pathed = bytearray()
            pather = Pather(parts=["e", label])
            pathed.extend(pather.qb64b)
            pathed.extend(atc)
            if len(pathed) // 4 < 4096:
                end.extend(Counter(Codens.PathedMaterialCouples,
                                          count=(len(pathed) // 4),
                                          version=Vrsn_1_0).qb64b)
            else:
                end.extend(Counter(Codens.BigPathedMaterialCouples,
                                          count=(len(pathed) // 4),
                                          version=Vrsn_1_0).qb64b)
            end.extend(pathed)

        if e:
            e["d"] = ""
            _, e = Saider.saidify(sad=e, label=Saids.d)


        if diger is None:
            if receiver:  # not (empty or None)
                attributes = attributes if attributes is not None else {}
                attributes['i'] = receiver

        else:
            # only in v1 exn can the attributes field 'a' be either a said or
            # a field map.  In v2 it must be a field map.
            attributes = diger.qb64  # SAID of ESSR encrypted attachment

        sad = dict(v=vs,
                   t=Ilks.exn,
                   d="",  # computed by SerderKERI init
                   i=sender if sender is not None else "",
                   rp=receiver if receiver is not None else "",
                   p=prior if prior is not None else "",
                   dt=stamp if stamp is not None else helping.nowIso8601(),
                   r=route if route is not None else "",
                   q=modifiers if modifiers is not None else {},  # q field required
                   a=attributes if attributes is not None else {},
                   e=e)
    else:
        raise ValueError(f"Invalid specialExchange not supported in version"
                             f" {pvrsn.major} exchange")


    return SerderKERI(sad=sad, makify=True), end  # return serialized ked


def cloneMessage(hby, said):
    """ Load and verify signatures on message exn

    Parameters:
        hby (Habery): database environment from which to clone message
        said (str): qb64 SAID of message exn to load

    Returns:
        tuple: (serder, list) of message exn and pathed signatures on embedded attachments"""
    exn = hby.db.exns.get(keys=(said,))
    if exn is None:
        return None, None

    verify(hby=hby, serder=exn)

    pathed = dict()
    e = Pather(parts=["e"])
    for p in hby.db.epath.get(keys=(exn.said,)):
        pb = bytearray(p.encode("utf-8"))
        pather = Pather(qb64b=pb, strip=True)
        if pather.startswith(e):
            np = pather.strip(e)
            nesting(np.rparts, pathed, pb)  # no unit test for this

    return exn, pathed


def serializeMessage(hby, said, framed=False):
    """Fetch message and attachments from hby.db by said and then serialize them

    Parameters:
        hby (Habery): environment with db
        said (str): of message
        framed (bool): True means may assume each message plus its attachments
            is isolated as frame when parsing so do not need
            attachment group when messagizing
        False means may not assume eash message plus its attachments
            is isolated as frame when parsing so do need
            attachment group when messagizing

    Returns:
        msg (bytearray):  message by said with attachments

    """
    exn = hby.db.exns.get(keys=(said,))
    if exn is None:
        return None, None

    tsgs, cigars = verify(hby=hby, serder=exn)
    pathed = hby.db.epath.get(keys=(exn.said,))
    nests = hby.db.enst.get(keys=(exn.said,))
    sourceSeals = []
    for keys, (number, diger) in hby.db.ests.getTopItemIter(keys=(exn.said, "")):
        _, pre = keys
        sourceSeals.append(SealEvent(i=Prefixer(qb64=pre), s=number, d=diger))

    if exn.pvrsn.major >= Vrsn_2_0.major and not pathed:
        return messagize(serder=exn,
                         tsgs=tsgs or None,
                         cigars=cigars or None,
                         bonds=sourceSeals or None,
                         nests=[bytearray(nest.encode("utf-8") if hasattr(nest, "encode") else nest)
                                for nest in nests] or None,
                         framed=framed,
                         gvrsn=exn.gvrsn if exn.gvrsn else exn.pvrsn)

    aims = bytearray()
    if tsgs or cigars or sourceSeals:
        # Authenticator attachments via messagize; framed=True so we can append
        # pathed embeds after (pathed material is outside messagize support).
        full = messagize(exn, tsgs=tsgs or None, cigars=cigars or None,
                         bonds=sourceSeals or None,
                         framed=True, gvrsn=Vrsn_1_0)
        aims.extend(full[exn.size:])

    # Pathed embeds are outside current messagize support — deliberate special
    # case until messagize gains path-material encoding.
    for p in pathed:
        aims.extend(Counter(Codens.PathedMaterialCouples,
                            count=(len(p) // 4), version=Vrsn_1_0).qb64b)
        aims.extend(p.encode("utf-8"))

    msg = bytearray(exn.raw)
    if aims:
        if len(aims) % 4:
            raise ValueError("Invalid attachments size={}, nonintegral"
                             " quadlets.".format(len(aims)))
        if not framed:
            msg.extend(Counter(Codens.AttachmentGroup,
                               count=(len(aims) // 4), version=Vrsn_1_0).qb64b)
        msg.extend(aims)

    return msg


def nesting(paths, acc, val):
    """Nesting Pather parts

    Parameters:
        paths (list[list]): list of path parts"""
    if len(paths) == 0:
        return val
    else:
        first_value = paths[0]
        nacc = dict()
        acc[first_value] = nesting(paths[1:], nacc, val)
        return acc


def verifyAttachments(hby, serder, *, tsgs=None, lsgs=None, cigars=None,
                      sourceSeals=None, unresolved=None):
    """Cryptographically verify exchange authentication attachments.

    Parameters:
        hby (Habery): database environment with signer key state
        serder (Serder): exchange message signed or sealed by the attachments
        tsgs (list): transferable signature groups with establishment references
        lsgs (list): transferable signature groups without establishment references
        cigars (list): non-transferable signatures
        sourceSeals (list): source seal triples
        unresolved (list): signer prefixes whose attachments could not be
            reconstructed without their KEL

    Returns:
        tuple: Valid transferable signature groups, non-transferable signatures,
            source seal triples, an invalid attachment flag, and missing KEL
            coordinates.
    """
    tsgs = list(tsgs or [])
    lsgs = lsgs or []
    cigars = cigars or []
    sourceSeals = sourceSeals or []
    unresolved = unresolved or []
    invalid = False
    missing = [(prefixer, None) for prefixer in unresolved]

    for prefixer, sigers in lsgs:
        if prefixer.qb64 not in hby.kevers:
            missing.append((prefixer, None))
            continue

        kever = hby.kevers[prefixer.qb64]
        tsgs.append((prefixer,
                     Number(sn=kever.lastEst.s),
                     Diger(qb64=kever.lastEst.d),
                     sigers))

    validTsgs = []
    for prefixer, number, diger, sigers in tsgs:
        if not prefixer.transferable:
            invalid = True
            continue

        sdig = hby.db.kels.getLast(keys=prefixer.qb64b, on=number.sn)
        if sdig is None:
            missing.append((prefixer, number))
            continue

        aserder = hby.db.evts.get(
            keys=(prefixer.qb64b, bytes(sdig, "utf-8")))
        if aserder is None:
            missing.append((prefixer, number))
            continue

        if sdig != diger.qb64:
            invalid = True
            continue

        try:
            tholder, verfers = hby.db.resolveVerifiers(
                pre=prefixer.qb64, sn=number.sn, dig=diger.qb64)
        except ValidationError:
            invalid = True
            continue

        vsigers, indices = verifySigs(serder.raw, sigers, verfers)
        if not tholder.satisfy(indices):
            invalid = True
            continue

        validTsgs.append((prefixer, number, diger, vsigers))

    validCigars = []
    for cigar in cigars:
        if (cigar.verfer.transferable or
                not cigar.verfer.verify(cigar.raw, serder.raw)):
            invalid = True
            continue

        validCigars.append(cigar)

    validSourceSeals = []
    for prefixer, number, diger in sourceSeals:
        if not prefixer.transferable:
            invalid = True
            continue

        sdig = hby.db.kels.getLast(keys=prefixer.qb64b, on=number.sn)
        if sdig is None:
            missing.append((prefixer, number))
            continue

        aserder = hby.db.evts.get(
            keys=(prefixer.qb64b, bytes(sdig, "utf-8")))
        if aserder is None:
            missing.append((prefixer, number))
            continue

        if (sdig != diger.qb64 or
                not any(isinstance(seal, dict) and
                        seal.get("d") == serder.said
                        for seal in aserder.seals or [])):
            invalid = True
            continue

        validSourceSeals.append((prefixer, number, diger))

    return validTsgs, validCigars, validSourceSeals, invalid, missing


def verify(hby, serder):
    """Verify all stored authentication and evidence for an exchange message.

    Any invalid stored attachment fails verification. Source seals are
    verified but omitted from the legacy two-item return tuple;
    ``serializeMessage`` reloads them for wire reconstruction.

    Parameters:
        hby (Habery): database environment from which to verify message
        serder (Serder): exn serder to load and verify signatures for

    Returns:
        tuple: Transferable signature groups and non-transferable signatures.
    """
    tsgs = []
    klases = (Prefixer, Seqner, Saider)
    args = ("qb64", "snh", "qb64")
    sigers = []
    old = None  # empty keys
    for keys, siger in hby.db.esigs.getTopItemIter(keys=(serder.said, "")):
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

    sourceSeals = []
    for keys, (number, diger) in hby.db.ests.getTopItemIter(
            keys=(serder.said, "")):
        _, pre = keys
        sourceSeals.append((Prefixer(qb64=pre), number, diger))

    cigars = []
    for verfer, cigar in hby.db.ecigs.get(keys=(serder.said,)):
        cigar.verfer = verfer
        cigars.append(cigar)

    tsgs, cigars, sourceSeals, invalid, missing = verifyAttachments(
        hby=hby,
        serder=serder,
        tsgs=tsgs,
        cigars=cigars,
        sourceSeals=sourceSeals,
    )
    if invalid or missing:
        msg = f"Invalid stored authentication or evidence for evt = {serder.said}"
        logger.info(msg)
        logger.debug("Exn Body=\n%s\n", serder.pretty())
        raise MissingSignatureError(msg)

    authenticated = any(prefixer.qb64 == serder.pre
                        for prefixer, _, _, _ in tsgs)
    authenticated |= any(cigar.verfer.qb64 == serder.pre
                         for cigar in cigars)
    authenticated |= any(prefixer.qb64 == serder.pre
                         for prefixer, _, _ in sourceSeals)

    if not authenticated:
        msg = f"No valid sender authentication stored for evt = {serder.said}"
        logger.info(msg)
        logger.debug("Exn Body=\n%s\n", serder.pretty())
        raise MissingSignatureError(msg)

    return tsgs, cigars


def serializeParsedSubstream(parsed, gvrsn=Vrsn_2_0):
    """Serialize a parsed message subtree as a nested CESR substream."""
    parsed = parsed if isinstance(parsed, dict) else parsed.__dict__

    if any(parsed.get(name) for name in ("rsgs", "ptds", "essrs")):
        raise ValueError("Unsupported attachments for nested substream serialization")

    serder = parsed["serder"]
    sigers = parsed.get("sigers") or None
    tsgs = parsed.get("tsgs") or None
    lsgs = parsed.get("lsgs") or None
    if sigers and (tsgs or lsgs):
        raise ValueError("Unsupported mixed signature groups for nested substream serialization")

    bonds = []
    for name in ("sscs", "ssts", "tdcs", "bsqs", "bsss", "tmqs"):
        bonds.extend(parsed.get(name) or [])
    for item in parsed.get("frcs") or []:
        bonds.append(item if isinstance(item, FirstSeen) else FirstSeen(*item))

    wigers = parsed.get("wigers") or None
    cigars = parsed.get("cigars") or None
    nests = [serializeParsedSubstream(nest, gvrsn=gvrsn)
             for nest in (parsed.get("nests") or [])]

    # Support bare nested artifacts, such as ACDCs carried inside IPEX messages.
    # These have no signatures or attachment groups of their own, so rebuild the
    # nested body-with-attachments wrapper directly from the parsed serder body.
    if not (sigers or tsgs or lsgs or bonds or wigers or cigars or nests):
        body = bytearray(serder.raw)
        if serder.kind != Kinds.cesr:
            body = Counter.enclose(qb64=Texter(raw=body).qb64b,
                                   code=Codens.NonNativeBodyGroup,
                                   version=gvrsn)

        empty = Counter.enclose(qb64=b'',
                                code=Codens.ControllerIdxSigs,
                                version=gvrsn)
        nested = bytearray(body)
        nested.extend(Counter.enclose(qb64=empty,
                                      code=Codens.AttachmentGroup,
                                      version=gvrsn))
        return Counter.enclose(qb64=nested,
                               code=Codens.BodyWithAttachmentGroup,
                               version=gvrsn)

    return messagize(serder=serder,
                     sigers=sigers,
                     tsgs=tsgs,
                     lsgs=lsgs,
                     bonds=bonds or None,
                     wigers=wigers,
                     cigars=cigars,
                     nests=nests or None,
                     nested=True,
                     gvrsn=gvrsn)


def loadParsedNestedSubstreams(hby, said):
    """Load and parse stored nested child substreams for an exchange message."""
    parsed = []
    for nest in hby.db.enst.get(keys=(said,)):
        ims = bytearray(nest.encode("utf-8") if hasattr(nest, "encode") else nest)
        substreams = Parser(version=Vrsn_2_0).parse(ims=ims,
                                                    framed=True,
                                                    processive=False)
        if not substreams:
            raise ValueError("Stored nested substream missing message content")
        if len(substreams) != 1:
            raise ValueError("Expected one stored nested substream")
        parsed.append(substreams[0])

    return parsed

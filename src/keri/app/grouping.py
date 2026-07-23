# -*- encoding: utf-8 -*-
"""
KERI
keri.app.grouping module

module for enveloping and forwarding KERI message
"""

from hio.base import doing
from hio.help import ogler

from ..kering import ValidationError, Version, Vrsn_1_0, Vrsn_2_0, Kinds, Ilks
from ..core import (Counter, Number, Diger, Saider,
                    Prefixer, Kevery, Router,
                    Revery, Parser, SerderKERI,
                    Serder, Codens, NumDex, exchange)
from ..peer import Exchanger, specialExchange, cloneMessage

from .delegating import Anchorer
from .agenting import Receiptor, WitnessInquisitor
from .habbing import serializeParsedSubstream

logger = ogler.getLogger()


class Counselor(doing.DoDoer):
    """
    Multisig event handling coordinator for group multisig events including delegation events.
    Handles escrows for partially signed multisig events, delegation events, and witness receipts.

    Doers:
        - swain (Anchorer): handles delegation anchoring
        - witq (WitnessInquisitor): queries witnesses for receipts
        - witDoer (Receiptor): sends witness receipts
        - escrowDo: processes escrows of group multisig identifiers waiting to be completed.
    """

    def __init__(self, hby, swain=None, proxy=None, version=None, kind=None, **kwa):
        """
        Initialize Counselor.

        Parameters:
            hby (Habery): database environment for local Habs
            swain (Anchorer): optional Anchorer for delegation anchoring
            proxy (Hab): optional proxy Hab to use for delegation anchoring if not using local Hab
            version (Versionage | None): optional explicit protocol version for
                delegation queries and the default Anchorer.
            kind (str | None): optional explicit serialization kind for
                delegation queries and the default Anchorer.
        """

        self.hby = hby
        self.version = version
        self.kind = kind if kind is not None else Kinds.json
        self.swain = swain if swain is not None else Anchorer(hby=self.hby,
                                                              version=self.version,
                                                              kind=self.kind)
        self.proxy = proxy
        self.witDoer = Receiptor(hby=self.hby)
        self.witq = WitnessInquisitor(hby=hby)

        doers = [self.swain, self.witq, self.witDoer, doing.doify(self.escrowDo)]

        super(Counselor, self).__init__(doers=doers, **kwa)

    def start(self, ghab, prefixer, number, diger):
        """ Begin processing of escrowed group multisig identifier

        Escrow identifier for multisigs, witness receipts and delegation anchor

        Parameters:

            ghab (Hab): group Habitat
            prefixer (Prefixer): prefixer of group identifier
            number (Number): number of event of group identifier
            diger (Diger): diger of event of group identifier

        """
        # used just for the log message
        evt = ghab.msgOwnEvent(sn=number.sn, allowPartiallySigned=True, framed=True)
        serder = SerderKERI(raw=evt)  # used just for the log message
        logger.info("Waiting for other signatures on %s for %s:%s...",
                    serder.ilk, prefixer.qb64, number.sn)
        return self.hby.db.gpse.add(keys=(prefixer.qb64,), val=(number, diger))

    def complete(self, prefixer, number, diger=None):
        """ Check for completed multsig protocol for the specific event

        Parameters:
            prefixer (Prefixer): qb64 identifier prefix of event to check
            number (Number): sequence number of event to check
            diger (Diger): optional digest of event to verify

        Returns:

        """
        cdiger = self.hby.db.cgms.get(keys=(prefixer.qb64, number.qb64))
        if not cdiger:
            return False
        else:
            if diger and (cdiger.qb64 != diger.qb64):
                raise ValidationError(f"invalid multisig protocol escrowed event {cdiger.qb64}-{diger.qb64}")

        return True

    def escrowDo(self, tymth, tock=1.0, **kwa):
        """ Process escrows of group multisig identifiers waiting to be completed.

        Steps involve:
           1. Sending local event with sig to other participants
           2. Waiting for signature threshold to be met.
           3. If elected and delegated identifier, send complete event to delegator
           4. If delegated, wait for delegator's anchored seal
           5. If elected, send event to witnesses and collect receipts.
           6. Otherwise, wait for fully receipted event

        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock (float): injected initial tock value.  Default to 1.0 to slow down processing

        """
        # enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        while True:
            self.processEscrows()
            yield 0.5

    def processEscrows(self):
        """Process group multisig event escrows."""
        self.processPartialSignedEscrow()
        self.processDelegateEscrow()
        self.processPartialWitnessEscrow()

    def processPartialSignedEscrow(self):
        """
        Process escrow of partially signed multisig group KEL events.  Message
        processing will send this local controllers signature to all other participants
        then this escrow waits for signatures from all other participants

        """
        for (pre,), (number, diger) in self.hby.db.gpse.getTopItemIter():  # group partially signed escrow
            sdig = self.hby.db.kels.getLast(keys=pre, on=number.sn)
            if sdig:
                sdig = sdig.encode("utf-8")
                self.hby.db.gpse.rem(keys=(pre,))
                ghab = self.hby.habs[pre]
                kever = ghab.kever
                keys = [verfer.qb64 for verfer in kever.verfers]
                sigers = self.hby.db.sigs.get(keys=(pre, sdig))
                if not sigers:  # otherwise its a list of sigs
                    continue

                windex = min([siger.index for siger in sigers])

                # True if Elected to perform delegation and witnessing
                witered = ghab.mhab.kever.verfers[0].qb64 == keys[windex]

                if kever.delegated and kever.ilk in (Ilks.dip, Ilks.drt):
                    # We are a delegated identifier, must wait for delegator approval for dip and drt
                    if witered:  # We are elected to perform delegation and witnessing messaging
                        logger.info("AID %s...%s: We are the witnesser, sending %s to delegator", pre[:4], pre[-4:], pre)
                        self.swain.delegation(pre=pre, sn=number.sn)
                    else:
                        anchor = dict(i=pre, s=number.snh, d=diger.qb64)
                        kwa = dict(version=self.version, gvrsn=self.version, kind=self.kind) if self.version is not None else {}
                        if self.proxy:
                            self.witq.query(hab=self.proxy, pre=kever.delpre, anchor=anchor,
                                            **kwa)
                        else:
                            self.witq.query(src=ghab.mhab.pre, pre=kever.delpre, anchor=anchor,
                                            **kwa)

                    logger.info("AID %s...%s: Waiting for delegation approval...", pre[:4], pre[-4:])
                    self.hby.db.gdee.add(keys=(pre,), val=(number, diger))
                else:  # Non-delegation, move on to witnessing
                    if witered:  # We are elected witnesser, send off event to witnesses
                        logger.info(
                            "AID %s...%s: We are the fully signed witnesser %s, sending to witnesses",
                            pre[:4], pre[-4:], number.sn)
                        self.witDoer.msgs.append(dict(pre=pre, sn=number.sn))

                    # Move to escrow waiting for witness receipts
                    logger.info("AID %s...%s: Waiting for fully signed witness receipts for %s",
                                pre[:4], pre[-4:], number.sn)
                    self.hby.db.gpwe.add(keys=(pre,), val=(number, diger))

    def processDelegateEscrow(self):
        """
        Process escrow of delegate group multisig identifiers that are
        waiting for delegator approval of a recent establishment event.

        """
        for (pre,), (number, diger) in self.hby.db.gdee.getTopItemIter():  # group delegatee escrow
            anchor = dict(i=pre, s=number.numh, d=diger.qb64)
            ghab = self.hby.habs[pre]
            kever = ghab.kevers[pre]

            keys = [verfer.qb64 for verfer in kever.verfers]
            witer = ghab.mhab.kever.verfers[0].qb64 == keys[0]  # We are elected to perform delegation and witnessing

            if witer:  # We are elected witnesser, We've already done out part in Boatswain, we are done.
                if self.swain.complete(prefixer=kever.prefixer, number=Number(num=kever.sn, code=NumDex.Huge)):
                    self.hby.db.gdee.rem(keys=(pre,))
                    logger.info("AID %s...%s: Delegation approval for %s received.", pre[:4], pre[-4:], pre)

                    self.hby.db.cgms.put(keys=(pre, number.qb64), val=diger)

            else:  # Not witnesser, we need to look for the anchor and then wait for receipts
                if serder := self.hby.db.fetchLastSealingEventByEventSeal(kever.delpre,
                                                                          seal=anchor):
                    sner = Number(num=serder.sn, code=NumDex.Huge)
                    adiger = Diger(qb64b=serder.saidb)
                    self.hby.db.aess.pin(keys=(pre, diger.qb64b),
                                         val=(sner, adiger))  # authorizer event seal (delegator/issuer)
                    self.hby.db.gdee.rem(keys=(pre,))
                    logger.info("AID %s...%s: Delegation approval for %s received.", pre[:4], pre[-4:], pre)

                    # Move to escrow waiting for witness receipts
                    logger.info("AID %s...%s: Waiting for witness receipts for %s", pre[:4], pre[-4:], pre)
                    self.hby.db.gdee.rem(keys=(pre,))
                    self.hby.db.gpwe.add(keys=(pre,), val=(number, diger))

    def processPartialWitnessEscrow(self):
        """
        Process escrow of group multisig events that do not have a full complement of receipts
        from witnesses yet.  When receipting is complete, remove from escrow and cue up a message
        that the event is complete.

        """
        for (pre,), (number, diger) in self.hby.db.gpwe.getTopItemIter():  # group partial witness escrow
            kever = self.hby.kevers[pre]

            # Load all the witness receipts we have so far
            wigers = self.hby.db.wigs.get(keys=(pre, diger.qb64))
            ghab = self.hby.habs[pre]
            keys = [verfer.qb64 for verfer in kever.verfers]
            witer = ghab.mhab.kever.verfers[0].qb64 == keys[0]
            if len(wigers) == len(kever.wits):  # We have all of them, this event is finished
                if witer and len(kever.wits) > 0:
                    witnessed = False
                    for cue in self.witDoer.cues:
                        if cue["pre"] == ghab.pre and cue["sn"] == number.sn:
                            witnessed = True
                    if not witnessed:
                        continue
                logger.info("AID %s...%s: Witness receipts complete, %s confirmed.", pre[:4], pre[-4:], pre)
                self.hby.db.gpwe.rem(keys=(pre,))
                self.hby.db.cgms.put(keys=(pre, number.qb64), val=diger)
            elif not witer:
                self.witDoer.gets.append(dict(pre=pre, sn=number.sn))


class MultisigNotificationHandler:
    """
    Handler for multisig coordination EXN messages

    """

    def __init__(self, resource, mux):
        """ Create an exn handler for multisig messages

        Parameters:
            resource:
            mux:
        """
        self.resource = resource
        self.mux = mux

    def handle(self, serder, attachments=None, nests=None):
        """  Do route specific processsing of multisig exn messages

        Parameters:
            serder (Serder): Serder of the exn multisig message
            attachments (list): list of tuples of pather, CESR SAD path attachments to the exn event

        """
        logger.info("Notification for %s event SAID=%s", self.resource, serder.said)
        logger.debug("EXN Body=\n%s\n", serder.pretty())
        self.mux.add(serder=serder, nests=nests)


def loadHandlers(exc, mux):
    """ Load handlers for the peer-to-peer distributed group multisig protocol

    Parameters:
        exc (Exchanger): Peer-to-peer message router
        mux (Multiplexor): Multisig communication coordinator

    """
    exc.addHandler(MultisigNotificationHandler(resource="/multisig/icp", mux=mux))
    exc.addHandler(MultisigNotificationHandler(resource="/multisig/rot", mux=mux))
    exc.addHandler(MultisigNotificationHandler(resource="/multisig/ixn", mux=mux))
    exc.addHandler(MultisigNotificationHandler(resource="/multisig/vcp", mux=mux))
    exc.addHandler(MultisigNotificationHandler(resource="/multisig/iss", mux=mux))
    exc.addHandler(MultisigNotificationHandler(resource="/multisig/rev", mux=mux))
    exc.addHandler(MultisigNotificationHandler(resource="/multisig/exn", mux=mux))
    exc.addHandler(MultisigNotificationHandler(resource="/multisig/rpy", mux=mux))


def multisigInceptExn(hab, smids, rmids, icp, delegator=None, version=None, kind=None):
    """

    Args:
        hab (Hab): habitat of local multisig member AID
        smids (list): list of qb64 AIDs of members with signing authority
        rmids (list): list of qb64 AIDs of members with rotation authority
        icp (bytes): serialized inception event with CESR streamed attachments
        delegator (str): qb64 AID of Delegator is group multisig is a delegated AID
        version(Versionage | None): optional explicit protocol version
        kind (str | None): optional explicit serialization kind
 
    Returns:
        tuple: (Serder, bytes): Serder of exn message and CESR attachments

    """
    rmids = rmids if rmids is not None else smids
    serder = SerderKERI(raw=icp)
    data = dict(
        gid=serder.pre,
        smids=smids,
        rmids=rmids,
    )

    embeds = dict(
        icp=icp,
    )

    if delegator is not None:
        data |= dict(delegator=delegator)

    kind = kind if kind is not None else Kinds.json

    if version and version.major == Vrsn_1_0.major:
        exn, end = specialExchange(sender=hab.pre,
                                   route="/multisig/icp",
                                   modifiers=dict(),
                                   attributes=data,
                                   embeds=embeds,
                                   version=version, 
                                   kind=kind)
        ims = hab.endorse(serder=exn, last=False, framed=True, gvrsn=version)
        del ims[:exn.size]
        ims.extend(end)

        return exn, ims

    version = version if version is not None else Version

    # Sign the wrapped child by SAID directly in the outer payload
    data = dict(data)
    data["d"] = serder.said

    # Parse the child using its own stream version before re-emitting it
    parsed = Parser(version=serder.gvrsn if serder.gvrsn else serder.pvrsn).parse(ims=bytearray(icp),
                                                                                  framed=True,
                                                                                  processive=False)
    if not parsed:
        raise ValueError("V2 multisig payloads must be framed CESR streams")
    if len(parsed) != 1:
        raise ValueError("Expected one multisig payload stream")

    # Re-encode the child as one nested V2 substream
    nests = serializeParsedSubstream(parsed[0], gvrsn=version)

    # Build the outer multisig exn
    exn = exchange(sender=hab.pre,
                   route="/multisig/icp",
                   modifiers=dict(),
                   attributes=data,
                   version=version,
                   pvrsn=version,
                   gvrsn=version,
                   kind=kind)

    # Endorse the outer exn and attach the one nested child stream
    ims = hab.endorse(serder=exn,
                      last=False,
                      framed=False,
                      gvrsn=version,
                      nests=[nests])

    exn = SerderKERI(raw=ims)

    return exn, bytearray(ims[exn.size:])


def multisigRotateExn(ghab, smids, rmids, rot, version=None, kind=None):
    """

    Args:
        ghab (GroupHab): habitat of group multisig AID
        smids (list): list of qb64 AIDs of members with signing authority
        rmids (list): list of qb64 AIDs of members with rotation authority
        rot (bytes): serialized rotation event with CESR streamed attachments
        version(Versionage | None): optional explicit protocol version
        kind (str | None): optional explicit serialization kind

    Returns:
        tuple: (Serder, bytes): Serder of exn message and CESR attachments

    """
    embeds = dict(
        rot=rot,
    )

    data = dict(gid=ghab.pre,
                smids=smids,
                rmids=rmids)
    kind = kind if kind is not None else Kinds.json

    if version and version.major == Vrsn_1_0.major:
        exn, end = specialExchange(sender=ghab.mhab.pre,
                                   route="/multisig/rot", modifiers=dict(),
                                   attributes=data,
                                   embeds=embeds,
                                   version=version, 
                                   kind=kind)
        ims = ghab.mhab.endorse(serder=exn, last=False, framed=True, gvrsn=version)
        atc = bytearray(ims[exn.size:])
        atc.extend(end)

        return exn, atc

    version = version if version is not None else Version

    # Sign the wrapped child by SAID directly in the outer payload
    data = dict(data)
    serder = Serder(raw=rot)
    data["d"] = serder.said

    # Parse the child using its own stream version before re-emitting it
    parsed = Parser(version=serder.gvrsn if serder.gvrsn else serder.pvrsn).parse(ims=bytearray(rot),
                                                                                  framed=True,
                                                                                  processive=False)
    if not parsed:
        raise ValueError("V2 multisig payloads must be framed CESR streams")
    if len(parsed) != 1:
        raise ValueError("Expected one multisig payload stream")

    # Re-encode the child as one nested V2 substream
    nests = serializeParsedSubstream(parsed[0], gvrsn=version)

    # Build the outer multisig exn
    exn = exchange(sender=ghab.mhab.pre,
                   route="/multisig/rot",
                   modifiers=dict(),
                   attributes=data,
                   version=version,
                   pvrsn=version,
                   gvrsn=version,
                   kind=kind)

    # Endorse the outer exn and attach the one nested child stream
    ims = ghab.mhab.endorse(serder=exn,
                            last=False,
                            framed=False,
                            gvrsn=version,
                            nests=[nests])

    exn = SerderKERI(raw=ims)

    return exn, bytearray(ims[exn.size:])


def multisigInteractExn(ghab, aids, ixn, version=None, kind=None):
    """ Create a peer to peer message to propose a multisig group interaction event

    Parameters:
        ghab (GroupHab): group Hab to endorse the message
        aids (list): qb64 identifier prefixes to include in the interaction event
        ixn (bytes): serialized interaction event with CESR streamed attachments
        version(Versionage | None): optional explicit protocol version
        kind (str | None): optional explicit serialization kind

    Returns:
        tuple: (Serder, bytes): Serder of exn message and CESR attachments
    """

    embeds = dict(
        ixn=ixn,
    )

    data = dict(gid=ghab.pre,
                smids=aids)

    kind = kind if kind is not None else Kinds.json

    if version and version.major == Vrsn_1_0.major:
        exn, end = specialExchange(sender=ghab.mhab.pre,
                                   route="/multisig/ixn",
                                   modifiers=dict(),
                                   attributes=data,
                                   embeds=embeds,
                                   version=version, 
                                   kind=kind)
        ims = ghab.mhab.endorse(serder=exn, last=False, framed=True, gvrsn=version)
        atc = bytearray(ims[exn.size:])
        atc.extend(end)

        return exn, atc

    version = version if version is not None else Version

    # Sign the wrapped child by SAID directly in the outer payload
    data = dict(data)
    serder = Serder(raw=ixn)
    data["d"] = serder.said

    parsed = Parser(version=serder.gvrsn if serder.gvrsn else serder.pvrsn).parse(ims=bytearray(ixn),
                                                                                  framed=True,
                                                                                  processive=False)
    if not parsed:
        raise ValueError("V2 multisig payloads must be framed CESR streams")
    if len(parsed) != 1:
        raise ValueError("Expected one multisig payload stream")

    nests = serializeParsedSubstream(parsed[0], gvrsn=version)

    exn = exchange(sender=ghab.mhab.pre,
                   route="/multisig/ixn",
                   modifiers=dict(),
                   attributes=data,
                   version=version,
                   pvrsn=version,
                   gvrsn=version,
                   kind=kind)

    ims = ghab.mhab.endorse(serder=exn,
                            last=False,
                            framed=False,
                            gvrsn=version,
                            nests=[nests])

    exn = SerderKERI(raw=ims)

    return exn, bytearray(ims[exn.size:])


def multisigRegistryInceptExn(ghab, usage, vcp, anc, version=None, kind=None):
    """ Create a peer to peer message to propose a credential registry inception from a multisig group identifier

    Either rot or ixn are required but not both

    Parameters:
        ghab (GroupHab): identifier Hab for ensorsing the message to send
        usage (str): human readable reason for creating the credential registry
        vcp (bytes): serialized Credentials registry inception event
        anc (bytes): CESR stream of serialized and signed event anchoring registry inception event
        version(Versionage | None): optional explicit protocol version
        kind (str | None): optional explicit serialization kind

    Returns:
        tuple: (Serder, bytes): Serder of exn message and CESR attachments

    """

    embeds = dict(
        vcp=vcp,
        anc=anc
    )
    version = version if version is not None else Vrsn_1_0
    kind = kind if kind is not None else Kinds.json

    exn, end = specialExchange(sender=ghab.mhab.pre,
                               route="/multisig/vcp",
                               attributes={'gid': ghab.pre, 'usage': usage},
                               embeds=embeds,
                               version=version,
                               kind=kind)
    evt = ghab.mhab.endorse(serder=exn, last=False, framed=True, gvrsn=version)
    atc = bytearray(evt[exn.size:])
    atc.extend(end)

    return exn, atc


def multisigIssueExn(ghab, acdc, iss, anc, version=None, kind=None):
    """ Create a peer to peer message to propose a credential creation from a multisig group identifier

    Either rot or ixn are required but not both

    Parameters:
        ghab (GroupHab): identifier Hab for ensorsing the message to send
        acdc (bytes): serialized Credential
        iss (bytes): CESR stream of serialized and TEL issuance event
        anc (bytes): CESR stream of serialized and signed anchoring event anchoring creation
        version(Versionage | None): optional explicit protocol version
        kind (str | None): optional explicit serialization kind

    Returns:
        tuple: (Serder, bytes): Serder of exn message and CESR attachments

    """

    embeds = dict(
        acdc=acdc,
        iss=iss,
        anc=anc
    )
    version = version if version is not None else Vrsn_1_0
    kind = kind if kind is not None else Kinds.json

    exn, end = specialExchange(sender=ghab.mhab.pre,
                               route="/multisig/iss",
                               attributes={'gid': ghab.pre},
                               embeds=embeds,
                               version=version,
                               kind=kind)
    evt = ghab.mhab.endorse(serder=exn, last=False, framed=True, gvrsn=version)
    atc = bytearray(evt[exn.size:])
    atc.extend(end)

    return exn, atc


def multisigRevokeExn(ghab, said, rev, anc, version=None, kind=None):
    """ Create a peer to peer message to propose a credential revocation from a multisig group identifier

    Either rot or ixn are required but not both

    Parameters:
        ghab (GroupHab): identifier Hab for ensorsing the message to send
        said (str): qb64 SAID of credential being revoked
        rev (bytes): CESR stream of serialized and TEL revocation event
        anc (bytes): CESR stream of serialized and signed anchoring event anchoring revocation
        version(Versionage | None): optional explicit protocol version
        kind (str | None): optional explicit serialization kind

    Returns:
        tuple: (Serder, bytes): Serder of exn message and CESR attachments

    """

    embeds = dict(
        rev=rev,
        anc=anc
    )
    version = version if version is not None else Vrsn_1_0
    kind = kind if kind is not None else Kinds.json

    exn, end = specialExchange(sender=ghab.mhab.pre,
                               route="/multisig/rev",
                               attributes={'gid': ghab.pre, 'said': said},
                               embeds=embeds,
                               version=version,
                               kind=kind)
    evt = ghab.mhab.endorse(serder=exn, last=False, framed=True, gvrsn=version)
    atc = bytearray(evt[exn.size:])
    atc.extend(end)

    return exn, atc


def multisigRpyExn(ghab, rpy, version=None, kind=None):
    """ Create a peer to peer message to propose a credential revocation from a multisig group identifier

    Either rot or ixn are required but not both

    Parameters:
        ghab (GroupHab): identifier Hab for ensorsing the message to send
        rpy (bytes): CESR stream of serialized and reply event
        version(Versionage | None): optional explicit protocol version
        kind (str | None): optional explicit serialization kind

    Returns:
        tuple: (Serder, bytes): Serder of exn message and CESR attachments

    """

    embeds = dict(
        rpy=rpy
    )

    data = {'gid': ghab.pre}
    kind = kind if kind is not None else Kinds.json

    if version and version.major == Vrsn_1_0.major:
        exn, end = specialExchange(sender=ghab.mhab.pre,
                                   route="/multisig/rpy",
                                   attributes=data,
                                   embeds=embeds,
                                   version=version, 
                                   kind=kind)
        evt = ghab.mhab.endorse(serder=exn, last=False, framed=True, gvrsn=version)
        atc = bytearray(evt[exn.size:])
        atc.extend(end)

        return exn, atc

    version = version if version is not None else Version

    data = dict(data)
    serder = Serder(raw=rpy)
    data["d"] = serder.said

    parsed = Parser(version=serder.gvrsn if serder.gvrsn else serder.pvrsn).parse(ims=bytearray(rpy),
                                                                                  framed=True,
                                                                                  processive=False)
    if not parsed:
        raise ValueError("V2 multisig payloads must be framed CESR streams")
    if len(parsed) != 1:
        raise ValueError("Expected one multisig payload stream")

    nests = serializeParsedSubstream(parsed[0], gvrsn=version)

    exn = exchange(sender=ghab.mhab.pre,
                   route="/multisig/rpy",
                   modifiers=dict(),
                   attributes=data,
                   version=version,
                   pvrsn=version,
                   gvrsn=version,
                   kind=kind)

    ims = ghab.mhab.endorse(serder=exn,
                            last=False,
                            framed=False,
                            gvrsn=version,
                            nests=[nests])

    exn = SerderKERI(raw=ims)

    return exn, bytearray(ims[exn.size:])


def multisigExn(ghab, exn, version=None, kind=None):
    """ Create a peer to peer message to propose a credential issuance from a multisig group identifier

    Either rot or ixn are required but not both

    Parameters:
        ghab (GroupHab): identifier Hab for ensorsing the message to send
        exn (bytes): CESR stream of serialized echange message, with signatures

    Returns:
        tuple: (Serder, bytes): Serder of exn message and CESR attachments

    """
    embeds = dict(
        exn=exn
    )
    version = version if version is not None else Vrsn_1_0
    kind = kind if kind is not None else Kinds.json

    wexn, end = specialExchange(sender=ghab.mhab.pre,
                                route="/multisig/exn",
                                attributes={'gid': ghab.pre},
                                embeds=embeds,
                                version=version,
                                kind=kind)
    evt = ghab.mhab.endorse(serder=wexn, last=False, framed=True, gvrsn=version)
    atc = bytearray(evt[wexn.size:])
    atc.extend(end)

    return wexn, atc


def getEscrowedEvent(db, pre, sn):
    vals = db.pses.getLast(keys=pre, on=sn)
    dig = vals if vals else None
    if dig is None:
        dig = db.kels.getLast(keys=pre, on=sn)
    dig = dig.encode("utf-8")
    serder = db.evts.get(keys=(pre, dig))
    sigers = db.sigs.get(keys=(pre, dig))
    duple = db.aess.get(keys=(pre, dig))

    msg = bytearray()
    msg.extend(serder.raw)
    msg.extend(Counter(Codens.ControllerIdxSigs,
                            count=len(sigers), version=Vrsn_1_0).qb64b)  # attach cnt
    for siger in sigers:
        msg.extend(siger.qb64b)  # attach siger

    if duple is not None:
        number, diger = duple
        msg.extend(Counter(Codens.SealSourceCouples,
                                count=1, version=Vrsn_1_0).qb64b)
        msg.extend(number.qb64b + diger.qb64b)

    return msg


class Multiplexor:
    """ Multiplexor (mux) is responsible for coordinating peer-to-peer messages between group multisig participants

    When new messages arrive the Mux will associate the SAID of the embedded messages with the exn message said
    as well as the sender.  This will allow the controller of the participant in the group multisig to have knowledge
    of who has sent what messages and whether they match.  In addition, if the controller of the local participant
    has already approved the messages embedded in this exn, the messages will be passed thru a non-local parser.

    Attributes:
        hby (habbing.Habery): database environment for local Habs
        rtr (Router): routes reply 'rpy' messages
        rvy (Revery): factory that processes reply 'rpy' messages
        exc (Exchanger): processor and router for peer-to-peer msgs
        kvy (Kevery): factory for local processing of local event msgs
        psr (Parser):  parses local messages for .kvy .rvy
        notifier (notifying.Notifier): stores notices for numan consumption

        Parameters:
            hby (habbing.Habery): database environment for local Habs
            notifier (notifying.Notifier): stores notices for numan consumption


    """

    def __init__(self, hby, notifier):
        """ Create Multiplexor for local database and Habs

        Parameters:
            hby (habbing.Habery): database environment for local Habs
            notifier (notifying.Notifier): stores notices for numan consumption

        """
        self.hby = hby
        self.rtr = Router()
        self.rvy = Revery(db=self.hby.db, rtr=self.rtr)
        self.exc = Exchanger(hby=self.hby, handlers=[])
        self.kvy = Kevery(db=self.hby.db, lax=False, local=False, rvy=self.rvy)
        self.kvy.registerReplyRoutes(router=self.rtr)
        self.psr = Parser(framed=True, kvy=self.kvy, rvy=self.rvy,
                                  exc=self.exc, version=Vrsn_1_0)

        self.notifier = notifier

    def add(self, serder, nests=None):
        """Process a /multisig exn by associating it with its wrapped event payload.

        Adds the exn message contained in `serder` to the set of messages received
        for a given wrapped event payload. Ensures this is a /multisig message with
        the correct properties and then stores the SAID of the exn message and the
        prefix of the sender associated with the wrapped event payload. Also sends
        the controller of the local participant a notice.

        This method will extract and parse the wrapped events if the local
        participant has already approved them so any additional signatures can be
        processed.

        Parameters:
            serder (SerderKERI): peer-to-peer exn "/multisig" message to coordinate
                from other participants
            nests (list | None): parsed nested substreams for single-child V2
                exchanges

        Returns:

        """
        ked = serder.ked
        embed = ked.get('e')
        nests = nests if nests is not None else []
        payload = ked['a']
        sender = ked['i']
        route = ked['r']
        ovrsn = serder.gvrsn if serder.gvrsn else serder.pvrsn

        if ovrsn.major == Vrsn_1_0.major:
            if embed is None or "d" not in embed:
                return

            # Preserve the legacy V1 aggregation key for both single- and multi-child wrappers
            esaid = embed["d"]
        else:
            if len(nests) != 1:
                raise ValidationError(f"invalid multisig nested substreams count={len(nests)}, expected 1")

            signed = payload.get("d") if isinstance(payload, dict) else None
            if route in ("/multisig/icp", "/multisig/rot", "/multisig/ixn", "/multisig/rpy") and signed is None:
                raise ValidationError(f"invalid multisig payload missing signed child SAID for route {route}")

            nserder = nests[0]["serder"] if isinstance(nests[0], dict) else nests[0].serder
            if signed is not None and nserder.said != signed:
                raise ValidationError(f"invalid multisig nested substream: {nserder.said} != {signed}")

            # Derive the legacy single-child embed digest so V2 proposals aggregate
            # with the same key as their V1 wrapper shape
            label = route.rsplit("/", 1)[-1]
            _, esad = Saider.saidify(sad={label: nserder.sad, "d": ""})
            esaid = esad["d"]

        # Route specific logic to ensure this is a valid exn for a local participant.
        match route.split("/"):
            case ["", "multisig", "icp"]:
                mids = payload["smids"]
                if "rmids" in payload:
                    mids.extend(payload["rmids"])
                member = any([True for mid in mids if mid in self.hby.kevers])
                if not member:
                    raise ValueError(f"invalid request to join group, not member in mids={mids}")

            case ["", "multisig", "rot"]:
                gid = payload["gid"]
                if gid not in self.hby.habs:
                    mids = payload["smids"]
                    mids.extend(payload["rmids"])
                    member = any([True for mid in mids if mid in self.hby.kevers])
                    if not member:
                        raise ValueError(f"invalid request to join group, not member in mids={mids}")

            case ["", "multisig", *_]:
                gid = payload["gid"]
                if gid not in self.hby.habs:
                    raise ValueError(f"invalid request to participate in group, not member of gid={gid}")

            case _:
                raise ValueError(f"invalid route {route} for multiplexed exn={ked}")

        if len(self.hby.db.meids.get(keys=(esaid,))) == 0:  # No one has submitted this message yet
            if sender not in self.hby.habs:  # We are not sending this one, notify us
                # Notify once when a remote participant first introduces this proposal
                data = dict(
                    r=route,
                    d=serder.said
                )

                self.notifier.add(attrs=data)

        self.hby.db.meids.add(keys=(esaid,), val=Saider(qb64=serder.said))
        self.hby.db.maids.add(keys=(esaid,), val=Prefixer(qb64=serder.pre))

        submitters = self.hby.db.maids.get(keys=(esaid,))
        if sender not in self.hby.habs:  # We are not sending this one, need to parse if already approved

            # If we've already submitted an identical payload, parse this one because we've approved it
            approved = any([True for sub in submitters if sub.qb64 in self.hby.kevers])
            if approved:
                # Clone exn from database, ensuring it is stored with valid signatures
                ims = bytearray()
                if embed is not None:
                    exn, paths = cloneMessage(self.hby, said=serder.said)
                    e = exn.ked['e']

                    # Loop through all the embedded events, extract the attachments for those events...
                    for key, val in e.items():
                        if not isinstance(val, dict):
                            continue

                        serder = Serder(sad=val)
                        ims.extend(serder.raw)
                        if key in paths:
                            atc = paths[key]
                            ims.extend(atc)

                    # ... and parse
                    self.psr.parse(ims=ims, local=True)
                else:
                    # Rebuild the approved nested child stream and parse it as V2
                    for nest in nests:
                        ims.extend(serializeParsedSubstream(nest))

                    parser = Parser(framed=True, kvy=self.kvy, rvy=self.rvy,
                                    exc=self.exc, version=Vrsn_2_0)
                    parser.parse(ims=ims, local=True)

            else:
                # Should we prod the user with another submission if we haven't already approved it?
                route = ked['r']
                # Notify with the shared child SAID so follow-up approvals join the same bucket
                data = dict(
                    r=route,
                    d=serder.said,
                    e=esaid
                )

                self.notifier.add(attrs=data)

    def get(self, esaid):
        digers = self.hby.db.meids.get(keys=(esaid,))

        exns = []
        for diger in digers:
            exn, paths = cloneMessage(hby=self.hby, said=diger.qb64)
            exns.append(dict(
                exn=exn.ked,
                paths={k: path.decode("utf-8") for k, path in paths.items()},
            ))

        return exns

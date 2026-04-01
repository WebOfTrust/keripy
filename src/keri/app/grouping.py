# -*- encoding: utf-8 -*-
"""
KERI
keri.app.grouping module

module for enveloping and forwarding KERI message
"""

from hio.base import doing
from hio.help import ogler

from ..kering import ValidationError, Vrsn_1_0, Ilks
from ..core import (Counter, Number, Diger, Saider,
                    Prefixer, Sadder, Kevery, Router,
                    Revery, Parser, SerderKERI,
                    Codens, NumDex)
from ..peer import Exchanger, exchange, cloneMessage

from .delegating import Anchorer
from .agenting import Receiptor, WitnessInquisitor

logger = ogler.getLogger()


class Counselor(doing.DoDoer):
    """Multisig event handling coordinator for group multisig events including delegation events.

    Handles escrows for partially signed multisig events, delegation events, and witness
    receipts.

    Attributes:
        hby (Habery): Database environment for local Habs.
        swain (Anchorer): Handles delegation anchoring.
        proxy (Hab): Proxy Hab used when querying the delegator for anchor confirmation
            instead of using the local member Hab.
        witDoer (Receiptor): Sends events to witnesses and collects receipts.
        witq (WitnessInquisitor): Queries witnesses for receipts on behalf of
            non-elected participants.
    """

    def __init__(self, hby, swain=None, proxy=None, **kwa):
        """Initialize Counselor.

        Args:
            hby (Habery): Database environment for local Habs.
            swain (Anchorer, optional): Anchorer for delegation anchoring. Defaults to a
                new Anchorer instance if not provided.
            proxy (Hab, optional): Proxy Hab used to query the delegator for anchor
                confirmation when the local member Hab should not be used directly.
        """
        self.hby = hby
        self.swain = swain if swain is not None else Anchorer(hby=self.hby)
        self.proxy = proxy
        self.witDoer = Receiptor(hby=self.hby)
        self.witq = WitnessInquisitor(hby=hby)

        doers = [self.swain, self.witq, self.witDoer, doing.doify(self.escrowDo)]

        super(Counselor, self).__init__(doers=doers, **kwa)

    def start(self, ghab, prefixer, number, diger):
        """Escrow a group multisig event and begin waiting for completion.

        Adds the event identified by prefixer/number/diger to the partially signed
        group escrow (gpse) so that subsequent signature collection and delegation /
        witnessing steps can proceed.

        Args:
            ghab (Hab): Group Habitat.
            prefixer (Prefixer): Prefixer of the group identifier.
            number (Number): Sequence number of the group event.
            diger (Diger): Digest of the group event.

        Returns:
            bool: Result of the escrow add operation.
        """
        evt = ghab.makeOwnEvent(sn=number.sn, allowPartiallySigned=True)  # used just for the log message
        serder = SerderKERI(raw=evt)                            # used just for the log message
        logger.info("Waiting for other signatures on %s for %s:%s...", serder.ilk, prefixer.qb64, number.sn)
        return self.hby.db.gpse.add(keys=(prefixer.qb64,), val=(number, diger))

    def complete(self, prefixer, number, diger=None):
        """Check whether the multisig protocol for a specific event has completed.

        Looks up the completed group multisig store (cgms) for the given
        prefixer/number pair. If a digest is provided it is compared against the
        stored digest to verify the event matches.

        Args:
            prefixer (Prefixer): Identifier prefix of the event to check.
            number (Number): Sequence number of the event to check.
            diger (Diger, optional): Digest of the event to verify against the stored
                value. If provided and the digests do not match, a ValidationError is
                raised.

        Returns:
            bool: True if the event has completed, False otherwise.

        Raises:
            ValidationError: If diger is provided and does not match the stored digest.
        """
        cdiger = self.hby.db.cgms.get(keys=(prefixer.qb64, number.qb64))
        if not cdiger:
            return False
        else:
            if diger and (cdiger.qb64 != diger.qb64):
                raise ValidationError(f"invalid multisig protocol escrowed event {cdiger.qb64}-{diger.qb64}")

        return True

    def escrowDo(self, tymth, tock=1.0, **kwa):
        """Process escrows of group multisig identifiers waiting to be completed.

        Runs continuously, calling processEscrows on each iteration. The escrow
        processing pipeline covers three stages. First, the local signed event is sent
        to other participants and the coordinator waits for enough signatures to meet the
        signing threshold (gpse). Second, for delegated identifiers (dip/drt), the
        elected participant sends the fully signed event to the delegator while
        non-elected participants query witnesses for the delegator's anchor; both wait in
        gdee until delegation approval is confirmed. Third, once delegation is confirmed
        (or for non-delegated identifiers), the coordinator waits for a full complement
        of witness receipts (gpwe), with the elected participant submitting the event to
        witnesses and others polling for the receipted result.

        Args:
            tymth (function): Injected function wrapper closure returned by .tymen() of
                a Tymist instance. Calling tymth() returns the associated Tymist .tyme.
            tock (float): Injected initial tock value. Defaults to 1.0 to slow down
                processing.
        """
        # enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        while True:
            self.processEscrows()
            yield 0.5

    def processEscrows(self):
        """Process all group multisig event escrows."""
        self.processPartialSignedEscrow()
        self.processDelegateEscrow()
        self.processPartialWitnessEscrow()

    def processPartialSignedEscrow(self):
        """Process escrow of partially signed multisig group KEL events.

        For each entry in the group partially signed escrow (gpse), checks whether the
        event has been accepted into the KEL. When it has, the entry is removed from
        gpse and the elected participant is determined as the member whose key holds the
        lowest signing index among current signers.

        For delegated establishment events (dip/drt), the elected participant sends the
        event to the delegator via swain while non-elected participants query the
        delegator's witnesses for the anchor; the entry is then moved to the delegate
        escrow (gdee). For non-delegated events, the elected participant enqueues the
        event for witness receipting via witDoer and the entry is moved to the partial
        witness escrow (gpwe).
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
                        if self.proxy:
                            self.witq.query(hab=self.proxy, pre=kever.delpre, anchor=anchor)
                        else:
                            self.witq.query(src=ghab.mhab.pre, pre=kever.delpre, anchor=anchor)

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
        """Process escrow of delegated group multisig identifiers awaiting delegator approval.

        For each entry in the group delegatee escrow (gdee), checks whether the delegator
        has anchored the delegation seal. The elected participant (key index 0) checks
        whether swain has completed delegation anchoring; on completion the digest is
        stored in cgms and the entry is removed from gdee. Non-elected participants
        search the delegator's KEL for a sealing event matching the anchor; on finding
        it, the authorizer event seal is recorded in aess, the entry is removed from
        gdee, and it is moved to the partial witness escrow (gpwe).
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
        """Process escrow of group multisig events awaiting a full complement of witness receipts.

        For each entry in the group partial witness escrow (gpwe), checks whether all
        expected witness receipts have been collected. When receipts are complete and
        the local participant is elected, a corresponding witness cue must also be
        present before the entry is considered finished; on completion the entry is
        removed from gpwe, the digest is written to cgms, and completion is logged.
        When receipts are still incomplete and the local participant is not elected, a
        receipt fetch request is enqueued via witDoer so the fully receipted event can
        be retrieved from the witnesses.
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
    """Handler for multisig coordination EXN messages.

    Receives routed /multisig/* exn messages and forwards them to a Multiplexor
    for further coordination.

    Attributes:
        resource (str): The route string this handler is registered for
            (e.g. ``"/multisig/icp"``).
        mux (Multiplexor): The multisig communication coordinator that will
            process the message.
    """

    def __init__(self, resource, mux):
        """Create a handler for a specific multisig exn route.

        Args:
            resource (str): The route string this handler is registered for
                (e.g. ``"/multisig/icp"``).
            mux (Multiplexor): Multisig communication coordinator that will
                process incoming messages.
        """
        self.resource = resource
        self.mux = mux

    def handle(self, serder, attachments=None):
        """Process a routed multisig exn message.

        Logs receipt of the message and forwards the serder to the Multiplexor.

        Args:
            serder (SerderKERI): Serder of the incoming /multisig/* exn message.
            attachments (list, optional): List of (pather, bytes) tuples representing
                CESR SAD-path attachments to the exn event.
        """
        logger.info("Notification for %s event SAID=%s", self.resource, serder.said)
        logger.debug("EXN Body=\n%s\n", serder.pretty())
        self.mux.add(serder=serder)


def loadHandlers(exc, mux):
    """Register handlers for the peer-to-peer distributed group multisig protocol.

    Registers a MultisigNotificationHandler with exc for each supported /multisig/*
    route: icp, rot, ixn, vcp, iss, rev, exn, and rpy.

    Args:
        exc (Exchanger): Peer-to-peer message router.
        mux (Multiplexor): Multisig communication coordinator passed to each handler.
    """
    exc.addHandler(MultisigNotificationHandler(resource="/multisig/icp", mux=mux))
    exc.addHandler(MultisigNotificationHandler(resource="/multisig/rot", mux=mux))
    exc.addHandler(MultisigNotificationHandler(resource="/multisig/ixn", mux=mux))
    exc.addHandler(MultisigNotificationHandler(resource="/multisig/vcp", mux=mux))
    exc.addHandler(MultisigNotificationHandler(resource="/multisig/iss", mux=mux))
    exc.addHandler(MultisigNotificationHandler(resource="/multisig/rev", mux=mux))
    exc.addHandler(MultisigNotificationHandler(resource="/multisig/exn", mux=mux))
    exc.addHandler(MultisigNotificationHandler(resource="/multisig/rpy", mux=mux))


def multisigInceptExn(hab, smids, rmids, icp, delegator=None):
    """Create a peer-to-peer exn message proposing a group multisig inception event.

    Args:
        hab (Hab): Habitat of the local multisig member AID used to endorse the message.
        smids (list): qb64 AIDs of members with signing authority.
        rmids (list): qb64 AIDs of members with rotation authority. Defaults to smids
            if None.
        icp (bytes): Serialized inception event with CESR streamed attachments.
        delegator (str, optional): qb64 AID of the delegator if the group multisig
            identifier is a delegated AID.

    Returns:
        tuple[Serder, bytes]: Serder of the exn message and its CESR attachments.
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

    # Create `exn` peer to peer message to notify other participants UI
    exn, end = exchange(route="/multisig/icp", modifiers=dict(),
                        payload=data, embeds=embeds, sender=hab.pre)
    ims = hab.endorse(serder=exn, last=False, pipelined=False)
    del ims[:exn.size]
    ims.extend(end)

    return exn, ims


def multisigRotateExn(ghab, smids, rmids, rot):
    """Create a peer-to-peer exn message proposing a group multisig rotation event.

    Args:
        ghab (GroupHab): Habitat of the group multisig AID used to endorse the message.
        smids (list): qb64 AIDs of members with signing authority.
        rmids (list): qb64 AIDs of members with rotation authority.
        rot (bytes): Serialized rotation event with CESR streamed attachments.

    Returns:
        tuple[Serder, bytes]: Serder of the exn message and its CESR attachments.
    """
    embeds = dict(
        rot=rot,
    )

    exn, end = exchange(route="/multisig/rot", modifiers=dict(),
                        payload=dict(gid=ghab.pre,
                                     smids=smids,
                                     rmids=rmids),
                        sender=ghab.mhab.pre,
                        embeds=embeds)
    ims = ghab.mhab.endorse(serder=exn, last=False, pipelined=False)
    atc = bytearray(ims[exn.size:])
    atc.extend(end)

    return exn, atc


def multisigInteractExn(ghab, aids, ixn):
    """Create a peer-to-peer exn message proposing a group multisig interaction event.

    Args:
        ghab (GroupHab): Group Hab used to endorse the message.
        aids (list): qb64 identifier prefixes of the signing members to include.
        ixn (bytes): Serialized interaction event with CESR streamed attachments.

    Returns:
        tuple[Serder, bytes]: Serder of the exn message and its CESR attachments.
    """

    embeds = dict(
        ixn=ixn,
    )

    exn, end = exchange(route="/multisig/ixn", modifiers=dict(),
                        payload=dict(gid=ghab.pre,
                                     smids=aids),
                        sender=ghab.mhab.pre,
                        embeds=embeds)
    ims = ghab.mhab.endorse(serder=exn, last=False, pipelined=False)
    atc = bytearray(ims[exn.size:])
    atc.extend(end)

    return exn, atc


def multisigRegistryInceptExn(ghab, usage, vcp, anc):
    """Create a peer-to-peer exn message proposing a credential registry inception from a
    group multisig identifier.

    Args:
        ghab (GroupHab): Group Hab used to endorse the message.
        usage (str): Human-readable description of the intended use of the registry.
        vcp (bytes): Serialized credential registry inception event.
        anc (bytes): CESR stream of the serialized and signed KEL event anchoring the
            registry inception.

    Returns:
        tuple[Serder, bytes]: Serder of the exn message and its CESR attachments.
    """

    embeds = dict(
        vcp=vcp,
        anc=anc
    )

    exn, end = exchange(route="/multisig/vcp", payload={'gid': ghab.pre, 'usage': usage},
                        sender=ghab.mhab.pre, embeds=embeds)
    evt = ghab.mhab.endorse(serder=exn, last=False, pipelined=False)
    atc = bytearray(evt[exn.size:])
    atc.extend(end)

    return exn, atc


def multisigIssueExn(ghab, acdc, iss, anc):
    """Create a peer-to-peer exn message proposing a credential issuance from a group
    multisig identifier.

    Args:
        ghab (GroupHab): Group Hab used to endorse the message.
        acdc (bytes): Serialized credential (ACDC).
        iss (bytes): CESR stream of the serialized TEL issuance event.
        anc (bytes): CESR stream of the serialized and signed KEL event anchoring the
            issuance.

    Returns:
        tuple[Serder, bytes]: Serder of the exn message and its CESR attachments.
    """

    embeds = dict(
        acdc=acdc,
        iss=iss,
        anc=anc
    )

    exn, end = exchange(route="/multisig/iss", payload={'gid': ghab.pre},
                        sender=ghab.mhab.pre, embeds=embeds)
    evt = ghab.mhab.endorse(serder=exn, last=False, pipelined=False)
    atc = bytearray(evt[exn.size:])
    atc.extend(end)

    return exn, atc


def multisigRevokeExn(ghab, said, rev, anc):
    """Create a peer-to-peer exn message proposing a credential revocation from a group
    multisig identifier.

    Args:
        ghab (GroupHab): Group Hab used to endorse the message.
        said (str): qb64 SAID of the credential being revoked.
        rev (bytes): CESR stream of the serialized TEL revocation event.
        anc (bytes): CESR stream of the serialized and signed KEL event anchoring the
            revocation.

    Returns:
        tuple[Serder, bytes]: Serder of the exn message and its CESR attachments.
    """

    embeds = dict(
        rev=rev,
        anc=anc
    )

    exn, end = exchange(route="/multisig/rev", payload={'gid': ghab.pre, 'said': said},
                        sender=ghab.mhab.pre, embeds=embeds)
    evt = ghab.mhab.endorse(serder=exn, last=False, pipelined=False)
    atc = bytearray(evt[exn.size:])
    atc.extend(end)

    return exn, atc


def multisigRpyExn(ghab, rpy):
    """Create a peer-to-peer exn message proposing a reply event from a group multisig
    identifier.

    Args:
        ghab (GroupHab): Group Hab used to endorse the message.
        rpy (bytes): CESR stream of the serialized reply event with attachments.

    Returns:
        tuple[Serder, bytes]: Serder of the exn message and its CESR attachments.
    """

    embeds = dict(
        rpy=rpy
    )

    exn, end = exchange(route="/multisig/rpy", payload={'gid': ghab.pre},
                        sender=ghab.mhab.pre, embeds=embeds)
    evt = ghab.mhab.endorse(serder=exn, last=False, pipelined=False)
    atc = bytearray(evt[exn.size:])
    atc.extend(end)

    return exn, atc


def multisigExn(ghab, exn):
    """Create a peer-to-peer exn wrapper message forwarding a multisig-coordinated exchange
    message from a group multisig identifier.

    Args:
        ghab (GroupHab): Group Hab used to endorse the wrapper message.
        exn (bytes): CESR stream of the serialized exchange message with signatures.

    Returns:
        tuple[Serder, bytes]: Serder of the wrapper exn message and its CESR attachments.
    """
    embeds = dict(
        exn=exn
    )

    wexn, end = exchange(route="/multisig/exn", payload={'gid': ghab.pre}, sender=ghab.mhab.pre,
                         embeds=embeds)
    evt = ghab.mhab.endorse(serder=wexn, last=False, pipelined=False)
    atc = bytearray(evt[wexn.size:])
    atc.extend(end)

    return wexn, atc


def getEscrowedEvent(db, pre, sn):
    """Retrieve a KEL event from escrow or the KEL and assemble it with its attachments.

    Looks up the event digest first in the partially signed escrow (pses) and falls back
    to the KEL (kels). Assembles the raw event bytes, the controller indexed signature
    counter and signers, and (if present) a seal source couple for delegated events.

    Args:
        db: LMDB database environment (Baser) providing event and escrow access.
        pre (str): qb64 identifier prefix of the event.
        sn (int): Sequence number of the event.

    Returns:
        bytearray: CESR stream containing the event, signature counter, signatures, and
            any seal source couples.
    """
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
    """Coordinates peer-to-peer /multisig/* exn messages between group multisig participants.

    When a new /multisig/* exn message arrives, the Multiplexor associates the SAID of
    the embedded event section with the exn SAID and the sender prefix, giving each
    local participant visibility into which remote participants have submitted which
    proposals and whether they match the local participant's own submission.

    If the local participant has already approved the embedded events (i.e. has itself
    submitted an identical proposal), incoming embedded events are immediately parsed
    through the non-local parser so additional signatures are processed. Otherwise a
    notification is queued for human consumption.

    Attributes:
        hby (Habery): Database environment for local Habs.
        rtr (Router): Routes reply rpy messages.
        rvy (Revery): Processes reply rpy messages.
        exc (Exchanger): Processor and router for peer-to-peer exn messages.
        kvy (Kevery): Processes KEL events from non-local sources.
        psr (Parser): Parses CESR streams containing KEL, reply, and exn messages.
        notifier (Notifier): Stores notices for human consumption.
    """

    def __init__(self, hby, notifier):
        """Create a Multiplexor for a local database and Hab set.

        Args:
            hby (Habery): Database environment for local Habs.
            notifier (Notifier): Stores notices for human consumption.
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

    def add(self, serder):
        """Process an incoming /multisig/* exn message.

        Validates that the local participant is a legitimate member of the group
        referenced by the message, then records the exn SAID and sender prefix against
        the SAID of the embedded event section in the database.

        If no participant has previously submitted this proposal and the sender is not
        the local participant, a notification is queued. If the sender is not the local
        participant but the local participant has already approved an identical proposal,
        the embedded events are extracted from the stored exn and parsed immediately so
        any additional signatures are incorporated. If neither condition holds, a second
        notification is queued prompting the local participant to review and approve.

        Args:
            serder (SerderKERI): The incoming /multisig/* exn message to process.

        Raises:
            ValueError: If the local participant is not a valid member of the referenced
                group, or if the route is not a recognised /multisig/* route.
        """
        ked = serder.ked
        if 'e' not in ked:  # No embedded events
            return

        embed = ked['e']
        esaid = embed['d']
        sender = ked['i']
        route = ked['r']
        payload = ked['a']

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
                exn, paths = cloneMessage(self.hby, said=serder.said)
                e = exn.ked['e']
                ims = bytearray()

                # Loop through all the embedded events, extract the attachments for those events...
                for key, val in e.items():
                    if not isinstance(val, dict):
                        continue

                    sadder = Sadder(ked=val)
                    ims.extend(sadder.raw)
                    if key in paths:
                        atc = paths[key]
                        ims.extend(atc)

                # ... and parse
                self.psr.parse(ims=ims, local=True)

            else:
                # Should we prod the user with another submission if we haven't already approved it?
                route = ked['r']
                data = dict(
                    r=route,
                    d=serder.said,
                    e=embed['d']
                )

                self.notifier.add(attrs=data)

    def get(self, esaid):
        """Retrieve all exn messages associated with a given embedded event section SAID.

        Args:
            esaid (str): qb64 SAID of the embedded event section to look up.

        Returns:
            list[dict]: List of dicts, each containing an ``exn`` key holding the ked of
                the exn message and a ``paths`` key holding attachment paths decoded to
                str and keyed by embedded event label.
        """
        digers = self.hby.db.meids.get(keys=(esaid,))

        exns = []
        for diger in digers:
            exn, paths = cloneMessage(hby=self.hby, said=diger.qb64)
            exns.append(dict(
                exn=exn.ked,
                paths={k: path.decode("utf-8") for k, path in paths.items()},
            ))

        return exns

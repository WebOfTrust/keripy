# -*- encoding: utf-8 -*-
"""
KERI
keri.app.grouping module

module for enveloping and forwarding KERI message
"""

from hio.base import doing
from hio.help import decking

from .. import kering, core
from .. import help
from ..app import delegating, agenting
from ..core import coring, routing, eventing, parsing, serdering, indexing
from ..db import dbing
from ..db.dbing import snKey
from ..peer import exchanging

logger = help.ogler.getLogger()


class Counselor(doing.DoDoer):

    def __init__(self, hby, swain=None, proxy=None, **kwa):

        self.hby = hby
        self.swain = swain if swain is not None else delegating.Anchorer(hby=self.hby)
        self.proxy = proxy
        self.witDoer = agenting.Receiptor(hby=self.hby)
        self.witq = agenting.WitnessInquisitor(hby=hby)

        doers = [self.swain, self.witq, self.witDoer, doing.doify(self.escrowDo)]

        super(Counselor, self).__init__(doers=doers, **kwa)

    def start(self, ghab, prefixer, seqner, saider):
        """ Begin processing of escrowed group multisig identifier

        Escrow identifier for multisigs, witness receipts and delegation anchor

        Parameters:

            ghab (Hab): group Habitat
            prefixer (Prefixer): prefixer of group identifier
            seqner (Seqner): seqner of event of group identifier
            saider (Saider): saider of event of group identifier

        """
        print(f"Waiting for other signatures for {prefixer.qb64}:{seqner.sn}...")
        return self.hby.db.gpse.add(keys=(prefixer.qb64,), val=(seqner, saider))

    def complete(self, prefixer, seqner, saider=None):
        """ Check for completed multsig protocol for the specific event

        Parameters:
            prefixer (Prefixer): qb64 identifier prefix of event to check
            seqner (Seqner): sequence number of event to check
            saider (Saider): optional digest of event to verify

        Returns:

        """
        csaider = self.hby.db.cgms.get(keys=(prefixer.qb64, seqner.qb64))
        if not csaider:
            return False
        else:
            if saider and (csaider.qb64 != saider.qb64):
                raise kering.ValidationError(f"invalid multisig protocol escrowed event {csaider.qb64}-{saider.qb64}")

        return True

    def escrowDo(self, tymth, tock=1.0):
        """ Process escrows of group multisig identifiers waiting to be compeleted.

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
        self.processPartialSignedEscrow()
        self.processDelegateEscrow()
        self.processPartialWitnessEscrow()

    def processPartialSignedEscrow(self):
        """
        Process escrow of partially signed multisig group KEL events.  Message
        processing will send this local controllers signature to all other participants
        then this escrow waits for signatures from all other participants

        """
        for (pre,), (seqner, saider) in self.hby.db.gpse.getItemIter():  # group partially signed escrow
            snkey = dbing.snKey(pre, seqner.sn)
            sdig = self.hby.db.getKeLast(key=snkey)
            if sdig:
                self.hby.db.gpse.rem(keys=(pre,))
                ghab = self.hby.habs[pre]
                kever = ghab.kever
                keys = [verfer.qb64 for verfer in kever.verfers]
                sigs = self.hby.db.getSigs(dbing.dgKey(pre, bytes(sdig)))
                if not sigs:  # otherwise its a list of sigs
                    continue

                sigers = [indexing.Siger(qb64b=bytes(sig)) for sig in sigs]
                windex = min([siger.index for siger in sigers])

                # True if Elected to perform delegation and witnessing
                witered = ghab.mhab.kever.verfers[0].qb64 == keys[windex]

                if kever.delegated and kever.ilk in (coring.Ilks.dip, coring.Ilks.drt):
                    # We are a delegated identifier, must wait for delegator approval for dip and drt
                    if witered:  # We are elected to perform delegation and witnessing messaging
                        logger.info(f"We are the witnesser, sending {pre} to delegator")
                        self.swain.delegation(pre=pre, sn=seqner.sn)
                    else:
                        anchor = dict(i=pre, s=seqner.snh, d=saider.qb64)
                        if self.proxy:
                            self.witq.query(hab=self.proxy, pre=kever.delpre, anchor=anchor)
                        else:
                            self.witq.query(src=ghab.mhab.pre, pre=kever.delpre, anchor=anchor)

                    logger.info("Waiting for delegation approval...")
                    self.hby.db.gdee.add(keys=(pre,), val=(seqner, saider))
                else:  # Non-delegation, move on to witnessing
                    if witered:  # We are elected witnesser, send off event to witnesses
                        logger.info(f"We are the fully signed witnesser {seqner.sn}, sending to witnesses")
                        self.witDoer.msgs.append(dict(pre=pre, sn=seqner.sn))

                    # Move to escrow waiting for witness receipts
                    logger.info(f"Waiting for fully signed witness receipts for {seqner.sn}")
                    self.hby.db.gpwe.add(keys=(pre,), val=(seqner, saider))

    def processDelegateEscrow(self):
        """
        Process escrow of delegate group multisig identifiers that are
        waiting for delegator approval of a recent establishment event.

        """
        for (pre,), (seqner, saider) in self.hby.db.gdee.getItemIter():  # group delegatee escrow
            anchor = dict(i=pre, s=seqner.snh, d=saider.qb64)
            ghab = self.hby.habs[pre]
            kever = ghab.kevers[pre]

            keys = [verfer.qb64 for verfer in kever.verfers]
            witer = ghab.mhab.kever.verfers[0].qb64 == keys[0]  # We are elected to perform delegation and witnessing

            if witer:  # We are elected witnesser, We've already done out part in Boatswain, we are done.
                if self.swain.complete(prefixer=kever.prefixer, seqner=coring.Seqner(sn=kever.sn)):
                    self.hby.db.gdee.rem(keys=(pre,))
                    logger.info(f"Delegation approval for {pre} received.")

                    self.hby.db.cgms.put(keys=(pre, seqner.qb64), val=saider)

            else:  # Not witnesser, we need to look for the anchor and then wait for receipts
                if serder := self.hby.db.fetchAllSealingEventByEventSeal(kever.delpre,
                                                                         seal=anchor):
                    aseq = coring.Seqner(sn=serder.sn)
                    couple = aseq.qb64b + serder.saidb
                    dgkey = dbing.dgKey(pre, saider.qb64b)
                    self.hby.db.setAes(dgkey, couple)  # authorizer event seal (delegator/issuer)
                    self.hby.db.gdee.rem(keys=(pre,))
                    logger.info(f"Delegation approval for {pre} received.")

                    # Move to escrow waiting for witness receipts
                    logger.info(f"Waiting for witness receipts for {pre}")
                    self.hby.db.gdee.rem(keys=(pre,))
                    self.hby.db.gpwe.add(keys=(pre,), val=(seqner, saider))

    def processPartialWitnessEscrow(self):
        """
        Process escrow of group multisig events that do not have a full compliment of receipts
        from witnesses yet.  When receipting is complete, remove from escrow and cue up a message
        that the event is complete.

        """
        for (pre,), (seqner, saider) in self.hby.db.gpwe.getItemIter():  # group partial witness escrow
            kever = self.hby.kevers[pre]
            dgkey = dbing.dgKey(pre, saider.qb64)

            # Load all the witness receipts we have so far
            wigs = self.hby.db.getWigs(dgkey)
            ghab = self.hby.habs[pre]
            keys = [verfer.qb64 for verfer in kever.verfers]
            witer = ghab.mhab.kever.verfers[0].qb64 == keys[0]
            if len(wigs) == len(kever.wits):  # We have all of them, this event is finished
                if witer and len(kever.wits) > 0:
                    witnessed = False
                    for cue in self.witDoer.cues:
                        if cue["pre"] == ghab.pre and cue["sn"] == seqner.sn:
                            witnessed = True
                    if not witnessed:
                        continue
                logger.info(f"Witness receipts complete, {pre} confirmed.")
                self.hby.db.gpwe.rem(keys=(pre,))
                self.hby.db.cgms.put(keys=(pre, seqner.qb64), val=saider)
            elif not witer:
                self.witDoer.gets.append(dict(pre=pre, sn=seqner.sn))


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

    def handle(self, serder, attachments=None):
        """  Do route specific processsing of multisig exn messages

        Parameters:
            serder (Serder): Serder of the exn multisig message
            attachments (list): list of tuples of pather, CESR SAD path attachments to the exn event

        """
        self.mux.add(serder=serder)


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


def multisigInceptExn(hab, smids, rmids, icp, delegator=None):
    """

    Args:
        hab (Hab): habitat of local multisig member AID
        smids (list): list of qb64 AIDs of members with signing authority
        rmids (list): list of qb64 AIDs of members with rotation authority
        icp (bytes): serialized inception event with CESR streamed attachments
        delegator (str): qb64 AID of Delegator is group multisig is a delegated AID

    Returns:
        tuple: (Serder, bytes): Serder of exn message and CESR attachments

    """
    rmids = rmids if rmids is not None else smids
    serder = serdering.SerderKERI(raw=icp)
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
    exn, end = exchanging.exchange(route="/multisig/icp", modifiers=dict(),
                                   payload=data, embeds=embeds, sender=hab.pre)
    ims = hab.endorse(serder=exn, last=False, pipelined=False)
    del ims[:exn.size]
    ims.extend(end)

    return exn, ims


def multisigRotateExn(ghab, smids, rmids, rot):
    """

    Args:
        ghab (GroupHab): habitat of group multisig AID
        smids (list): list of qb64 AIDs of members with signing authority
        rmids (list): list of qb64 AIDs of members with rotation authority
        rot (bytes): serialized rotation event with CESR streamed attachments

    Returns:
        tuple: (Serder, bytes): Serder of exn message and CESR attachments

    """
    embeds = dict(
        rot=rot,
    )

    exn, end = exchanging.exchange(route="/multisig/rot", modifiers=dict(),
                                   payload=dict(gid=ghab.pre,
                                                smids=smids,
                                                rmids=rmids), sender=ghab.mhab.pre,
                                   embeds=embeds)
    ims = ghab.mhab.endorse(serder=exn, last=False, pipelined=False)
    atc = bytearray(ims[exn.size:])
    atc.extend(end)

    return exn, atc


def multisigInteractExn(ghab, aids, ixn):
    """ Create a peer to peer message to propose a multisig group interaction event

    Parameters:
        ghab (GroupHab): group Hab to endorse the message
        aids (list): qb64 identifier prefixes to include in the interaction event
        ixn (bytes): serialized interaction event with CESR streamed attachments

    Returns:
        tuple: (Serder, bytes): Serder of exn message and CESR attachments
    """

    embeds = dict(
        ixn=ixn,
    )

    exn, end = exchanging.exchange(route="/multisig/ixn", modifiers=dict(),
                                   payload=dict(gid=ghab.pre,
                                                smids=aids), sender=ghab.mhab.pre,
                                   embeds=embeds)
    ims = ghab.mhab.endorse(serder=exn, last=False, pipelined=False)
    atc = bytearray(ims[exn.size:])
    atc.extend(end)

    return exn, atc


def multisigRegistryInceptExn(ghab, usage, vcp, anc):
    """ Create a peer to peer message to propose a credential registry inception from a multisig group identifier

    Either rot or ixn are required but not both

    Parameters:
        ghab (GroupHab): identifier Hab for ensorsing the message to send
        usage (str): human readable reason for creating the credential registry
        vcp (bytes): serialized Credentials registry inception event
        anc (bytes): CESR stream of serialized and signed event anchoring registry inception event

    Returns:
        tuple: (Serder, bytes): Serder of exn message and CESR attachments

    """

    embeds = dict(
        vcp=vcp,
        anc=anc
    )

    exn, end = exchanging.exchange(route="/multisig/vcp", payload={'gid': ghab.pre, 'usage': usage},
                                   sender=ghab.mhab.pre, embeds=embeds)
    evt = ghab.mhab.endorse(serder=exn, last=False, pipelined=False)
    atc = bytearray(evt[exn.size:])
    atc.extend(end)

    return exn, atc


def multisigIssueExn(ghab, acdc, iss, anc):
    """ Create a peer to peer message to propose a credential creation from a multisig group identifier

    Either rot or ixn are required but not both

    Parameters:
        ghab (GroupHab): identifier Hab for ensorsing the message to send
        acdc (bytes): serialized Credential
        iss (bytes): CESR stream of serialized and TEL issuance event
        anc (bytes): CESR stream of serialized and signed anchoring event anchoring creation

    Returns:
        tuple: (Serder, bytes): Serder of exn message and CESR attachments

    """

    embeds = dict(
        acdc=acdc,
        iss=iss,
        anc=anc
    )

    exn, end = exchanging.exchange(route="/multisig/iss", payload={'gid': ghab.pre},
                                   sender=ghab.mhab.pre, embeds=embeds)
    evt = ghab.mhab.endorse(serder=exn, last=False, pipelined=False)
    atc = bytearray(evt[exn.size:])
    atc.extend(end)

    return exn, atc


def multisigRevokeExn(ghab, said, rev, anc):
    """ Create a peer to peer message to propose a credential revocation from a multisig group identifier

    Either rot or ixn are required but not both

    Parameters:
        ghab (GroupHab): identifier Hab for ensorsing the message to send
        said (str): qb64 SAID of credential being revoked
        rev (bytes): CESR stream of serialized and TEL revocation event
        anc (bytes): CESR stream of serialized and signed anchoring event anchoring revocation

    Returns:
        tuple: (Serder, bytes): Serder of exn message and CESR attachments

    """

    embeds = dict(
        rev=rev,
        anc=anc
    )

    exn, end = exchanging.exchange(route="/multisig/rev", payload={'gid': ghab.pre, 'said': said},
                                   sender=ghab.mhab.pre, embeds=embeds)
    evt = ghab.mhab.endorse(serder=exn, last=False, pipelined=False)
    atc = bytearray(evt[exn.size:])
    atc.extend(end)

    return exn, atc


def multisigRpyExn(ghab, rpy):
    """ Create a peer to peer message to propose a credential revocation from a multisig group identifier

    Either rot or ixn are required but not both

    Parameters:
        ghab (GroupHab): identifier Hab for ensorsing the message to send
        rpy (bytes): CESR stream of serialized and reply event

    Returns:
        tuple: (Serder, bytes): Serder of exn message and CESR attachments

    """

    embeds = dict(
        rpy=rpy
    )

    exn, end = exchanging.exchange(route="/multisig/rpy", payload={'gid': ghab.pre},
                                   sender=ghab.mhab.pre, embeds=embeds)
    evt = ghab.mhab.endorse(serder=exn, last=False, pipelined=False)
    atc = bytearray(evt[exn.size:])
    atc.extend(end)

    return exn, atc


def multisigExn(ghab, exn):
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

    wexn, end = exchanging.exchange(route="/multisig/exn", payload={'gid': ghab.pre}, sender=ghab.mhab.pre,
                                    embeds=embeds)
    evt = ghab.mhab.endorse(serder=wexn, last=False, pipelined=False)
    atc = bytearray(evt[wexn.size:])
    atc.extend(end)

    return wexn, atc


def getEscrowedEvent(db, pre, sn):
    key = snKey(pre, sn)
    dig = db.getPseLast(key)
    if dig is None:
        dig = db.getKeLast(key)

    dig = bytes(dig)
    key = dbing.dgKey(pre, dig)  # digest key
    msg = db.getEvt(key)
    serder = serdering.SerderKERI(raw=bytes(msg))

    sigs = []
    for sig in db.getSigsIter(key):
        sigs.append(indexing.Siger(qb64b=bytes(sig)))

    couple = db.getAes(key)

    msg = bytearray()
    msg.extend(serder.raw)
    msg.extend(core.Counter(core.Codens.ControllerIdxSigs,
                            count=len(sigs), gvrsn=kering.Vrsn_1_0).qb64b)  # attach cnt
    for sig in sigs:
        msg.extend(sig.qb64b)  # attach sig

    if couple is not None:
        msg.extend(core.Counter(core.Codens.SealSourceCouples,
                                count=1, gvrsn=kering.Vrsn_1_0).qb64b)
        msg.extend(couple)

    return msg


class Multiplexor:
    """ Multiplexor (mux) is responsible for coordinating peer-to-peer messages between group multisig participants

    When new messages arrive the Mux will associate the SAID of the embedded messages with the exn message said
    as well as the sender.  This will allow the controller of the participant in the group multisig to have knowledge
    of who has sent what messages and whether they match.  In addition, if the controller of the local participant
    has already approved the messages embedded in this exn, the messages will be passed thru a non-local parser.

    Attributes:
        hby (habbing.Habery): database environment for local Habs
        rtr (routing.Router): routes reply 'rpy' messages
        rvy (routing.Revery): factory that processes reply 'rpy' messages
        exc (exchanging.Exchanger): processor and router for peer-to-peer msgs
        kvy (eventing.Kevery): factory for local processing of local event msgs
        psr (parsing.Parser):  parses local messages for .kvy .rvy
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
        self.rtr = routing.Router()
        self.rvy = routing.Revery(db=self.hby.db, rtr=self.rtr)
        self.exc = exchanging.Exchanger(hby=self.hby, handlers=[])
        self.kvy = eventing.Kevery(db=self.hby.db, lax=False, local=False, rvy=self.rvy)
        self.kvy.registerReplyRoutes(router=self.rtr)
        self.psr = parsing.Parser(framed=True, kvy=self.kvy, rvy=self.rvy, exc=self.exc)

        self.notifier = notifier

    def add(self, serder):
        """ Process /multisig message by associating the exn with the SAID of the embedded event section

        Adds the exn message contained in `serder` to the set of messages received for a given set of embedded
        events.  Ensures this is a /multisig message with the correct properties and then stores the SAID of the
        exn message and the prefix of the sender associated with the SAID of the embedded event section.  Also
        sends the controller of the local participant a notice.

        This method will extract and parse the embedded events if the local participant has already approved the
        events so that any addition signatures can be processed.

        Parameters:
            serder (serdering.SerderKERI): peer-to-peer exn "/multisig" message to coordinate from other participants

        Returns:

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

        self.hby.db.meids.add(keys=(esaid,), val=coring.Saider(qb64=serder.said))
        self.hby.db.maids.add(keys=(esaid,), val=coring.Prefixer(qb64=serder.pre))

        submitters = self.hby.db.maids.get(keys=(esaid,))
        if sender not in self.hby.habs:  # We are not sending this one, need to parse if already approved

            # If we've already submitted an identical payload, parse this one because we've approved it
            approved = any([True for sub in submitters if sub.qb64 in self.hby.kevers])
            if approved:
                # Clone exn from database, ensuring it is stored with valid signatures
                exn, paths = exchanging.cloneMessage(self.hby, said=serder.said)
                e = exn.ked['e']
                ims = bytearray()

                # Loop through all the embedded events, extract the attachments for those events...
                for key, val in e.items():
                    if not isinstance(val, dict):
                        continue

                    sadder = coring.Sadder(ked=val)
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
        saiders = self.hby.db.meids.get(keys=(esaid,))

        exns = []
        for saider in saiders:
            exn, paths = exchanging.cloneMessage(hby=self.hby, said=saider.qb64)
            exns.append(dict(
                exn=exn.ked,
                paths={k: path.decode("utf-8") for k, path in paths.items()},
            ))

        return exns


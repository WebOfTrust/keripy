# -*- encoding: utf-8 -*-
"""
KERI
keri.app.grouping module

module for enveloping and forwarding KERI message
"""

from hio.base import doing
from hio.help import decking

from .. import kering
from .. import help
from ..app import delegating, agenting
from ..core import coring
from ..db import dbing
from ..db.dbing import snKey
from ..peer import exchanging
from ..vc import proving

logger = help.ogler.getLogger()


class Counselor(doing.DoDoer):

    def __init__(self, hby, swain=None, proxy=None, **kwa):

        self.hby = hby
        self.swain = swain if swain is not None else delegating.Boatswain(hby=self.hby)
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
            seqner (Seqner): seqner of inception event of group identifier
            saider (Saider): saider of inception event of group identifier

        """
        evt = ghab.makeOwnEvent(sn=seqner.sn, allowPartiallySigned=True)
        serder = coring.Serder(raw=evt)
        del evt[:serder.size]

        print(f"Waiting for other signatures for {serder.pre}:{seqner.sn}...")
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
           4. If delegated, wait for delegator's anchor
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

                sigers = [coring.Siger(qb64b=bytes(sig)) for sig in sigs]
                windex = min([siger.index for siger in sigers])

                # True if Elected to perform delegation and witnessing
                witered = ghab.mhab.kever.verfers[0].qb64 == keys[windex]

                if kever.delegated and kever.ilk in (coring.Ilks.dip, coring.Ilks.drt):
                    # We are a delegated identifier, must wait for delegator approval for dip and drt
                    if witered:  # We are elected to perform delegation and witnessing messaging
                        print(f"We are the witnesser, sending {pre} to delegator")
                        self.swain.delegation(pre=pre, sn=seqner.sn)
                    else:
                        anchor = dict(i=pre, s=seqner.snh, d=saider.qb64)
                        if self.proxy:
                            self.witq.query(hab=self.proxy, pre=kever.delegator, anchor=anchor)
                        else:
                            self.witq.query(src=ghab.mhab.pre, pre=kever.delegator, anchor=anchor)

                    print("Waiting for delegation approval...")
                    self.hby.db.gdee.add(keys=(pre,), val=(seqner, saider))
                else:  # Non-delegation, move on to witnessing
                    if witered:  # We are elected witnesser, send off event to witnesses
                        print(f"We are the fully signed witnesser {seqner.sn}, sending to witnesses")
                        self.witDoer.msgs.append(dict(pre=pre, sn=seqner.sn))

                    # Move to escrow waiting for witness receipts
                    print(f"Waiting for fully signed witness receipts for {seqner.sn}")
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
                    print(f"Delegation approval for {pre} received.")

                    self.hby.db.cgms.put(keys=(pre, seqner.qb64), val=saider)

            else:  # Not witnesser, we need to look for the anchor and then wait for receipts
                if serder := self.hby.db.findAnchoringEvent(kever.delegator, anchor=anchor):
                    aseq = coring.Seqner(sn=serder.sn)
                    couple = aseq.qb64b + serder.saidb
                    dgkey = dbing.dgKey(pre, saider.qb64b)
                    self.hby.db.setAes(dgkey, couple)  # authorizer event seal (delegator/issuer)
                    self.hby.db.gdee.rem(keys=(pre,))
                    print(f"Delegation approval for {pre} received.")

                    # Move to escrow waiting for witness receipts
                    print(f"Waiting for witness receipts for {pre}")
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
                print(f"Witness receipts complete, {pre} confirmed.")
                self.hby.db.gpwe.rem(keys=(pre,))
                self.hby.db.cgms.put(keys=(pre, seqner.qb64), val=saider)
            elif not witer:
                self.witDoer.gets.append(dict(pre=pre, sn=seqner.sn))


class MultisigNotificationHandler(doing.Doer):
    """
    Handler for multisig coordination EXN messages

    """
    persist = True

    def __init__(self, resource, notifier, **kwargs):
        self.resource = resource
        self.notifier = notifier
        self.msgs = decking.Deck()
        self.cues = decking.Deck()

        super(MultisigNotificationHandler, self).__init__(**kwargs)

    def recur(self, tyme):
        if self.msgs:
            msg = self.msgs.popleft()
            serder = msg["serder"]

            data = dict(
                r=self.resource,
                d=serder.said
            )

            self.notifier.add(attrs=data)

        return False


def loadHandlers(hby, exc, notifier):
    """ Load handlers for the peer-to-peer distributed group multisig protocol

    Parameters:
        hby (Habery): Database and keystore for environment
        exc (Exchanger): Peer-to-peer message router
        notifier (Notifier): Database for storing mailbox messages

    """
    exc.addHandler(MultisigNotificationHandler(resource="/multisig/icp", hby=hby, notifier=notifier))
    exc.addHandler(MultisigNotificationHandler(resource="/multisig/rot", hby=hby, notifier=notifier))
    exc.addHandler(MultisigNotificationHandler(resource="/multisig/ixn", hby=hby, notifier=notifier))
    exc.addHandler(MultisigNotificationHandler(resource="/multisig/vcp", hby=hby, notifier=notifier))
    exc.addHandler(MultisigNotificationHandler(resource="/multisig/iss", hby=hby, notifier=notifier))
    exc.addHandler(MultisigNotificationHandler(resource="/multisig/rvk", hby=hby, notifier=notifier))


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
    data = dict(
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
        ghab (Hab): group Hab to endorse the message
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
                                                aids=aids), sender=ghab.mhab.pre,
                                   embeds=embeds)
    ims = ghab.mhab.endorse(serder=exn, last=False, pipelined=False)
    atc = bytearray(ims[exn.size:])
    atc.extend(end)

    return exn, atc


def multisigRegistryInceptExn(hab, recipient, vcp, ixn, rot):
    """ Create a peer to peer message to propose a credential issuance from a multisig group identifier

    Either rot or ixn are required but not both

    Parameters:
        hab (Hab): identifier Hab for ensorsing the message to send
        recipient (str): qb64 AID to send this message t0
        vcp (bytes): serialized Credentials registry inception event
        ixn (bytes): CESR stream of serialized and signed interaction event anchoring registry inception event
        rot (bytes): CESR stream of serialized and signed rotation event anchoring registry inception event

    Returns:
        tuple: (Serder, bytes): Serder of exn message and CESR attachments

    """

    embeds = dict(
        vcp=vcp,
    )

    if rot is not None:
        embeds["rot"] = rot
    elif ixn is not None:
        embeds['ixn'] = ixn

    exn, end = exchanging.exchange(route="/multisig/vcp", payload={}, sender=hab.pre, recipient=recipient,
                                   embeds=embeds)
    evt = hab.mhab.endorse(serder=exn, last=False, pipelined=False)
    atc = bytearray(evt[exn.size:])
    atc.extend(end)

    return exn, atc


def multisigIssueExn(hab, recipient, acdc, iss, ixn=None, rot=None):
    """ Create a peer to peer message to propose a credential issuance from a multisig group identifier

    Either rot or ixn are required but not both

    Parameters:
        hab (Hab): identifier Hab for ensorsing the message to send
        recipient (str): qb64 AID to send this message t0
        acdc (bytes): CESR stream of serialized Creder instance of the issued credential, with signatures
        iss (bytes): serialized Credential issuance event
        ixn (bytes): CESR stream of serialized and signed interaction event anchoring credential issuance event
        rot (bytes): CESR stream of serialized and signed rotation event anchoring credential issuance event

    Returns:
        tuple: (Serder, bytes): Serder of exn message and CESR attachments

    """
    embeds = dict(
        acdc=acdc,
        iss=iss,
    )

    if rot is not None:
        embeds["rot"] = rot
    elif ixn is not None:
        embeds['ixn'] = ixn

    exn, end = exchanging.exchange(route="/multisig/iss", payload={}, sender=hab.pre, recipient=recipient,
                                   embeds=embeds)
    evt = hab.mhab.endorse(serder=exn, last=False, pipelined=False)
    atc = bytearray(evt[exn.size:])
    atc.extend(end)

    return exn, atc


def getEscrowedEvent(db, pre, sn):
    key = snKey(pre, sn)
    dig = db.getPseLast(key)
    if dig is None:
        dig = db.getKeLast(key)

    dig = bytes(dig)
    key = dbing.dgKey(pre, dig)  # digest key
    msg = db.getEvt(key)
    serder = coring.Serder(raw=bytes(msg))

    sigs = []
    for sig in db.getSigsIter(key):
        sigs.append(coring.Siger(qb64b=bytes(sig)))

    couple = db.getAes(key)

    msg = bytearray()
    msg.extend(serder.raw)
    msg.extend(coring.Counter(code=coring.CtrDex.ControllerIdxSigs,
                              count=len(sigs)).qb64b)  # attach cnt
    for sig in sigs:
        msg.extend(sig.qb64b)  # attach sig

    if couple is not None:
        msg.extend(coring.Counter(code=coring.CtrDex.SealSourceCouples,
                                  count=1).qb64b)
        msg.extend(couple)

    return msg

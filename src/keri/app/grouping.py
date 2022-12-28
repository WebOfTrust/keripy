# -*- encoding: utf-8 -*-
"""
KERI
keri.app.grouping module

module for enveloping and forwarding KERI message
"""
import json
from ordered_set import OrderedSet as oset

from hio import help
from hio.base import doing
from hio.help import decking

from keri import kering
from keri.app import forwarding, delegating, agenting
from keri.core import coring
from keri.db import dbing, basing
from keri.db.dbing import snKey
from keri.help import helping
from keri.peer import exchanging
from keri.vc import proving

logger = help.ogler.getLogger()


class Counselor(doing.DoDoer):

    def __init__(self, hby, **kwa):

        self.hby = hby
        self.postman = forwarding.Postman(hby=hby)
        self.swain = delegating.Boatswain(hby=self.hby)
        self.witDoer = agenting.WitnessReceiptor(hby=self.hby)
        self.witq = agenting.WitnessInquisitor(hby=hby)

        doers = [self.postman, self.swain, self.witq, self.witDoer, doing.doify(self.escrowDo)]

        super(Counselor, self).__init__(doers=doers, **kwa)

    def start(self, prefixer, seqner, saider, mid, smids, rmids=None):
        """ Begin processing of escrowed group multisig identifier

        Escrow identifier for multisigs, witness receipts and delegation anchor

        Parameters:

            prefixer (Prefixer): prefixer of group identifier
            seqner (Seqner): seqner of inception event of group identifier
            saider (Saider): saider of inception event of group identifier
            mid (str): group member (local) identifier prefix qb64
            smids (list): group signing member ids qb64 (multisig group)
            rmids (list | None): group rotating member ids qb64 (multisig group)


        """
        evt = getEscrowedEvent(db=self.hby.db, pre=prefixer.qb64, sn=seqner.sn)
        serder = coring.Serder(raw=evt)
        del evt[:serder.size]

        others = list(oset(smids + (rmids or [])))

        others.remove(mid)  # don't send to self

        print(f"Sending multisig event to {len(others)} other participants")
        for recpt in others:
            self.postman.send(src=mid, dest=recpt, topic="multisig", serder=serder, attachment=evt)

        print(f"Waiting for other signatures for {seqner.sn}...")
        return self.hby.db.gpse.add(keys=(prefixer.qb64,), val=(seqner, saider))


    def rotate(self, ghab, smids, *, rmids=None, isith=None, nsith=None,
               toad=None, cuts=None, adds=None, data=None):
        """ Begin processing of escrowed group multisig identifier

        Escrow identifier for multisigs, witness receipts and delegation anchor

        Parameters:
            ghab (Hab): group identifier Hab
            smids (list): group signing member identifier prefixes qb64
            smids (list): group rotating member identifier prefixes qb64
            isith (Optional[int,str]) currentsigning threshold as int or str hex
                 or list of str weights
            nsith (Optional[int,str])next signing threshold as int or str hex
                 or list of str weights
            toad (int) or str hex of witness threshold after cuts and adds
            cuts (list) of qb64 pre of witnesses to be removed from witness list
            adds (list) of qb64 pre of witnesses to be added to witness list
            data (list) of dicts of committed data such as seals

        ToDo: NRR
        Add midxs for each group member identifier or just the local member
        for mhab.pre
        Then store these with rotationRecord to be used by .processPartialAidEscrow()


        """
        mid = ghab.mhab.pre
        smids = smids if smids is not None else ghab.smids
        rmids = rmids if rmids is not None else ghab.rmids
        both = list(oset(smids + (rmids or [])))

        if mid not in both:
            raise kering.ConfigurationError(f"local identifier {mid} not elected"
                                            f" to participate in rotation: {both}")

        kever = ghab.kever

        # Get local next key and see if we are in current group next keys
        pkever = ghab.mhab.kever
        pndig = pkever.digers[0].qb64

        rec = basing.RotateRecord(sn=kever.sn+1, isith=isith, nsith=nsith,
                                  toad=toad, cuts=cuts, adds=adds,
                                  data=data, date=helping.nowIso8601(),
                                  smids=smids, rmids=rmids)

        if pndig in kever.digs:  # local already participate in last event, rotate
            ghab.mhab.rotate()
            print(f"Rotating local identifier, waiting for witness receipts")
            self.witDoer.msgs.append(dict(pre=ghab.mhab.pre, sn=ghab.mhab.kever.sn))
            return self.hby.db.glwe.put(keys=(ghab.pre,), val=rec)

        else: # XXXX no unit test ever reaches here
            rot = ghab.mhab.makeOwnEvent(pkever.lastEst.s)  # grab latest est evt
            others = list(both)
            others.remove(mid)
            serder = coring.Serder(raw=rot)
            del rot[:serder.size]

            print(f"Sending local rotation event to {others} other participants")
            for recpt in others:
                self.postman.send(src=mid, dest=recpt, topic="multisig", serder=serder, attachment=rot)

            return self.hby.db.gpae.put(keys=(ghab.pre,), val=rec)

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
        self.processLocalWitnessEscrow()
        self.processPartialAidEscrow()
        self.processPartialSignedEscrow()
        self.processDelegateEscrow()
        self.processPartialWitnessEscrow()

    def processLocalWitnessEscrow(self):
        """
        Process escrow of group multisig events that do not have a full compliment of receipts
        from witnesses yet.  When receipting is complete, remove from escrow and cue up a message
        that the event is complete.

        """
        for (pre,), rec in self.hby.db.glwe.getItemIter():  # group partial witness escrow
            ghab = self.hby.habs[pre]
            mid = ghab.mhab.pre
            pkever = ghab.mhab.kever
            dgkey = dbing.dgKey(mid, pkever.serder.saidb)

            # Load all the witness receipts we have so far
            wigs = self.hby.db.getWigs(dgkey)
            if len(wigs) == len(pkever.wits):  # We have all of them, this event is finished
                self.hby.db.glwe.rem(keys=(pre,))

                rot = self.hby.db.cloneEvtMsg(mid, pkever.sn, pkever.serder.said)  # grab latest est evt

                others = list(rec.smids)
                others.remove(mid)
                serder = coring.Serder(raw=rot)
                del rot[:serder.size]

                print(f"Sending local rotation event to {len(others)} other participants")
                for recpt in others:
                    self.postman.send(src=mid, dest=recpt, topic="multisig", serder=serder, attachment=rot)

                return self.hby.db.gpae.put(keys=(ghab.pre,), val=rec)

    def processPartialAidEscrow(self):
        """
        Process escrow of group multisig rotate requests missing rotations from other participants.  Message
        processing will send this local controllers rotation event to all other participants
        then this escrow waits for rotations from all other participants

        ToDo: NRR
        rec includes the dual indices for current and next for new rotation
        add database for each group hab to store for each local hab the reference
        to the event used in by local hab to provided current and/or next keys
        to latest est event. This reference is new seal that includes not just
        reference (sn, said, of event but also the crt and nxt index used by the
        group hab est event for the local habe est event keys (in either both current
        next of group habe est event.)

        Logic to determin if current local hab kever is ok to use is based on
        if latest prior est event in database exposed a its current for the local hab
        if so then the local hab must rotate and the sn must be at least one greater
        if current key was not exposed then the lhab does not need to be rotated and the
        unexposed next key can be reused in the new rotation event.

        ToDo: NRR
        Need to fix this logic to be for new rotation rules
        need to use both rec.smids and rec.rmids
        both = list(oset(smids + (rmids or [])))

        """
        # ignore saider because it is not relevant yet
        for (pre,), rec in self.hby.db.gpae.getItemIter():  # group partially aid escrow
            ghab = self.hby.habs[pre]  # group hab Hab instance
            gkever = ghab.kever  # group hab's Kever instance key state

            merfers = []  # local verfers of group signing keys
            indices = []  # weights of the local signers who have already rotated
            migers = list(gkever.digers)  # local participants next digers
            for aid in rec.smids:
                pkever = self.hby.kevers[aid]
                idx = ghab.smids.index(aid)
                if pkever.digers[0].qb64 != gkever.digers[idx].qb64:
                    indices.append(idx)
                    merfers.append(pkever.verfers[0])
                    migers[idx] = pkever.digers[0]

            if not gkever.ntholder.satisfy(indices):
                continue

            if gkever.tholder.weighted and rec.isith is None:
                isith = [gkever.ntholder.sith[idx] for idx in indices]
            else:
                isith = rec.isith

            nsith = rec.nsith if rec.nsith is not None else gkever.ntholder.sith
            rot = ghab.rotate(isith=isith, nsith=nsith,
                              toad=rec.toad, cuts=rec.cuts, adds=rec.adds, data=rec.data,
                              merfers=merfers, migers=migers)
            serder = coring.Serder(raw=rot)
            del rot[:serder.size]

            others = list(rec.smids)
            others.remove(ghab.mhab.pre)
            print(f"Sending rotation event to {len(others)} other participants")
            for recpt in others:
                self.postman.send(src=ghab.mhab.pre, dest=recpt, topic="multisig", serder=serder, attachment=rot)

            print("Waiting for other signatures...")
            self.hby.db.gpae.rem((pre,))
            return self.hby.db.gpse.add(keys=(ghab.pre,), val=(coring.Seqner(sn=serder.sn), serder.saider))

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
                sraw = self.hby.db.getEvt(key=dbing.dgKey(pre=pre, dig=bytes(sdig)))

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
                        self.swain.msgs.append(dict(pre=pre, sn=seqner.sn))
                    else:
                        anchor = dict(i=pre, s=seqner.snh, d=saider.qb64)
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

            if serder := self.hby.db.findAnchoringEvent(kever.delegator, anchor=anchor):
                aseq = coring.Seqner(sn=serder.sn)
                couple = aseq.qb64b + serder.saidb
                dgkey = dbing.dgKey(pre, saider.qb64b)
                self.hby.db.setAes(dgkey, couple)  # authorizer event seal (delegator/issuer)
                self.hby.db.gdee.rem(keys=(pre,))
                print(f"Delegation approval for {pre} received.")

                if witer:  # We are elected witnesser, send off event to witnesses
                    print(f"We are the witnesser, sending {pre} to witnesses")
                    self.witDoer.msgs.append(dict(pre=pre, sn=seqner.sn))

                # Move to escrow waiting for witness receipts
                print(f"Waiting for witness receipts for {pre}")
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
            if len(wigs) == len(kever.wits):  # We have all of them, this event is finished
                ghab = self.hby.habs[pre]
                keys = [verfer.qb64 for verfer in kever.verfers]
                witer = ghab.mhab.kever.verfers[0].qb64 == keys[0]
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

    def pendingEvents(self, pre):
        """ Return information about any pending events for a given AID

        Parameters:
            pre (str): qb64 identifier of distributed multisig AID

        Returns:
            Prefixer, Saider: prefixer of identifier and saider of the event (if available)

        """
        key = (pre,)
        evts = []
        if (rec := self.hby.db.gpae.get(keys=key)) is not None:  # RotateRecord
            data = dict(
                aids=rec.smids,
                sn=rec.sn,
                isith=rec.isith,
                nsith=rec.nsith,
                timestamp=rec.date,
                toad=rec.toad,
                cuts=rec.cuts,
                adds=rec.adds,
                data=rec.data
            )
            evts.append(data)
        if (rec := self.hby.db.glwe.get(keys=key)) is not None:  # RotateRecord
            data = dict(
                aids=rec.smids,
                sn=rec.sn,
                isith=rec.isith,
                nsith=rec.nsith,
                timestamp=rec.date,
                toad=rec.toad,
                cuts=rec.cuts,
                adds=rec.adds,
                data=rec.data
            )
            evts.append(data)

        return evts


def loadHandlers(hby, exc, notifier):
    """ Load handlers for the peer-to-peer distributed group multisig protocol

    Parameters:
        hby (Habery): Database and keystore for environment
        exc (Exchanger): Peer-to-peer message router
        notifier (Notifier): Database for storing mailbox messages

    """
    incept = MultisigInceptHandler(hby=hby, notifier=notifier)
    exc.addHandler(incept)
    rotate = MultisigRotateHandler(hby=hby, notifier=notifier)
    exc.addHandler(rotate)
    interact = MultisigInteractHandler(hby=hby, notifier=notifier)
    exc.addHandler(interact)
    issue = MultisigIssueHandler(notifier=notifier)
    exc.addHandler(issue)


class MultisigInceptHandler(doing.DoDoer):
    """
    Handler for multisig group inception notification EXN messages

    """
    resource = "/multisig/icp"
    persist = True

    def __init__(self, hby, notifier, **kwa):
        """

        Parameters:
            mbx (Mailboxer) of format str names accepted for offers
            cues (decking.Deck) of outbound cue messages from handler

        """
        self.hby = hby
        self.notifier = notifier
        self.msgs = decking.Deck()
        self.cues = decking.Deck()

        super(MultisigInceptHandler, self).__init__(**kwa)

    def do(self, tymth, tock=0.0, **opts):
        """

        Handle incoming messages by parsing and verifying the credential and storing it in the wallet

        Parameters:
            payload is dict representing the body of a multisig/incept message
            pre is qb64 identifier prefix of sender
            sigers is list of Sigers representing the sigs on the /credential/issue message
            verfers is list of Verfers of the keys used to sign the message

        """
        self.wind(tymth)
        self.tock = tock
        yield self.tock

        while True:
            while self.msgs:
                msg = self.msgs.popleft()

                if "pre" not in msg:
                    logger.error(f"invalid incept message, missing pre.  evt: {msg}")
                    continue

                prefixer = msg["pre"]
                if "payload" not in msg:
                    logger.error(f"invalid incept message, missing payload.  evt: {msg}")
                    continue

                pay = msg["payload"]
                if "aids" not in pay or "ked" not in pay:
                    logger.error(f"invalid incept payload, aids and ked are required.  payload: {pay}")
                    continue

                src = prefixer.qb64
                aids = pay["aids"]

                hab = None
                for aid in aids:
                    if aid in self.hby.habs:
                        hab = self.hby.habs[aid]

                if hab is None:
                    logger.error(f"invalid incept message, no local event in aids: {pay}")
                    continue

                if src not in pay["aids"] or src not in hab.kevers:
                    logger.error(f"invalid incept message, source not knows or not part of group.  evt: {msg}")
                    continue

                data = dict(
                    r='/multisig/icp/init',
                    src=src,
                    aids=aids,
                    ked=pay["ked"]
                )
                self.notifier.add(attrs=data)

                yield
            yield


def multisigInceptExn(hab, aids, ked, delegator=None):
    data = dict(
        aids=aids,
        ked=ked
    )

    if delegator is not None:
        data |= dict(delegator=delegator)

    # Create `exn` peer to peer message to notify other participants UI
    exn = exchanging.exchange(route=MultisigInceptHandler.resource, modifiers=dict(),
                              payload=data)
    ims = hab.endorse(serder=exn, last=True, pipelined=False)
    del ims[:exn.size]

    return exn, ims


class MultisigRotateHandler(doing.DoDoer):
    """
    Handler for multisig group inception notification EXN messages

    """
    resource = "/multisig/rot"

    def __init__(self, hby, notifier, **kwa):
        """

        Parameters:
            mbx (Mailboxer) of format str names accepted for offers
            controller (str) qb64 identity prefix of controller
            cues (decking.Deck) of outbound cue messages from handler

        """
        self.hby = hby
        self.notifier = notifier
        self.msgs = decking.Deck()
        self.cues = decking.Deck()

        super(MultisigRotateHandler, self).__init__(**kwa)

    def do(self, tymth, tock=0.0, **opts):
        """ Process incoming notifications for a group rotation

        Handle incoming messages by parsing and verifiying the credential and storing it in the wallet

        Parameters:
            payload is dict representing the body of a multisig/incept message
            pre is qb64 identifier prefix of sender
            sigers is list of Sigers representing the sigs on the /credential/issue message
            verfers is list of Verfers of the keys used to sign the message

        ToDo: NRR
        fix to use both ghab.smids and ghab.rmids

        """
        self.wind(tymth)
        self.tock = tock
        yield self.tock

        while True:
            while self.msgs:
                msg = self.msgs.popleft()

                if "pre" not in msg:
                    logger.error(f"invalid rotation message, missing pre.  evt: {msg}")
                    continue

                prefixer = msg["pre"]
                if "payload" not in msg:
                    logger.error(f"invalid rotation message, missing payload.  evt: {msg}")
                    continue

                pay = msg["payload"]
                if "aids" not in pay or "gid" not in pay:
                    logger.error(f"invalid rotation payload, aids and gid are required.  payload: {pay}")
                    continue

                src = prefixer.qb64
                aids = pay["aids"]
                gid = pay["gid"]

                ghab = self.hby.habs[gid]
                if ghab is None:
                    logger.error(f"invalid rotate message, not a local group: {pay}")
                    continue

                if src not in ghab.smids or src not in ghab.kevers:
                    logger.error(f"invalid incept message, source not knows or not part of group.  evt: {msg}")
                    continue

                data = dict(
                    r='/multisig/rot',
                    src=src,
                    aids=aids,
                )
                data["i"] = ghab.pre
                data["toad"] = pay["toad"] if "toad" in pay else None
                data["wits"] = pay["wits"] if "wits" in pay else []
                data["adds"] = pay["adds"] if "adds" in pay else []
                data["cuts"] = pay["cuts"] if "cuts" in pay else []
                data["isith"] = pay["isith"] if "isith" in pay else None
                data["data"] = pay["data"] if "data" in pay else None

                self.notifier.add(attrs=data)

                yield

            yield


def multisigRotateExn(ghab, aids, isith, toad, cuts, adds, data):
    exn = exchanging.exchange(route=MultisigRotateHandler.resource, modifiers=dict(),
                              payload=dict(gid=ghab.pre,
                                           aids=aids,
                                           isith=isith,
                                           toad=toad,
                                           cuts=list(cuts),
                                           adds=list(adds),
                                           data=data)
                              )
    ims = ghab.mhab.endorse(serder=exn, last=True, pipelined=False)
    atc = bytearray(ims[exn.size:])

    return exn, atc


class MultisigInteractHandler(doing.DoDoer):
    """
    Handler for multisig group inception notification EXN messages

    """
    resource = "/multisig/ixn"

    def __init__(self, hby, notifier, **kwa):
        """

        Parameters:
            mbx (Mailboxer) of format str names accepted for offers
            cues (decking.Deck) of outbound cue messages from handler

        """
        self.hby = hby
        self.notifier = notifier
        self.msgs = decking.Deck()
        self.cues = decking.Deck()

        super(MultisigInteractHandler, self).__init__(**kwa)

    def do(self, tymth, tock=0.0, **opts):
        """ Process incoming notifications for a group interaction events

        Handle incoming messages by storing a message in the mailbox of the controller

        Parameters:
            payload is dict representing the body of a multisig/ixn message
            pre is qb64 identifier prefix of sender

        ToDo: NRR
        fix to use both ghab.smids and ghab.rmids

        """
        self.wind(tymth)
        self.tock = tock
        yield self.tock

        while True:
            while self.msgs:
                msg = self.msgs.popleft()

                if "pre" not in msg:
                    logger.error(f"invalid rotation message, missing pre.  evt: {msg}")
                    continue

                prefixer = msg["pre"]
                if "payload" not in msg:
                    logger.error(f"invalid rotation message, missing payload.  evt: {msg}")
                    continue

                pay = msg["payload"]
                if "aids" not in pay or "gid" not in pay:
                    logger.error(f"invalid rotation payload, aids and gid are required.  payload: {pay}")
                    continue

                src = prefixer.qb64
                aids = pay["aids"]
                gid = pay["gid"]

                ghab = self.hby.habs[gid]
                if ghab is None:
                    logger.error(f"invalid rotate message, not a local group: {pay}")
                    continue

                if src not in ghab.smids or src not in ghab.kevers:
                    logger.error(f"invalid incept message, source not knows or not part of group.  evt: {msg}")
                    continue

                data = dict(
                    r='/multisig/ixn',
                    src=src,
                    gid=gid,
                    aids=aids,
                )
                data["data"] = pay["data"] if "data" in pay else None

                self.notifier.add(data)
                yield
            yield


def multisigInteractExn(ghab, aids, data):
    """ Create a peer to peer message to propose a multisig group interaction event

    Parameters:
        ghab (Hab): group Hab to endorse the message
        aids (list): qb64 identifier prefixes to include in the interaction event
        data (list): data to anchor in the interaction event

    Returns:
        Serder: Serder of exn message to send
        butearray: attachment signatures
    """

    exn = exchanging.exchange(route=MultisigInteractHandler.resource, modifiers=dict(),
                              payload=dict(gid=ghab.pre,
                                           aids=aids,
                                           data=data)
                              )
    ims = ghab.mhab.endorse(serder=exn, last=True, pipelined=False)
    atc = bytearray(ims[exn.size:])

    return exn, atc


class MultisigIssueHandler(doing.DoDoer):
    """
    Handler for multisig group issuance notification EXN messages

    """
    resource = "/multisig/issue"

    def __init__(self, notifier, **kwa):
        """

        Parameters:
            mbx (Mailboxer) of format str names accepted for offers
            controller (str) qb64 identity prefix of controller
            cues (decking.Deck) of outbound cue messages from handler

        """
        self.notifier = notifier
        self.msgs = decking.Deck()
        self.cues = decking.Deck()

        super(MultisigIssueHandler, self).__init__(**kwa)

    def do(self, tymth, tock=0.0, **opts):
        """

        Handle incoming messages by parsing and verifiying the credential and storing it in the wallet

        Parameters:
            payload is dict representing the body of a multisig/incept message
            pre is qb64 identifier prefix of sender
            sigers is list of Sigers representing the sigs on the /credential/issue message
            verfers is list of Verfers of the keys used to sign the message

        """
        self.wind(tymth)
        self.tock = tock
        yield self.tock

        while True:
            while self.msgs:
                msg = self.msgs.popleft()
                pl = msg["payload"]

                try:
                    creder = proving.Creder(ked=pl)
                    data = dict(
                        r="/multisig/issue",
                        ked=creder.ked
                    )

                    self.notifier.add(attrs=data)

                except ValueError as ex:
                    logger.error(f"unable to process multisig credential issue proposal {pl}: {ex}")
                yield
            yield


def multisigIssueExn(hab, creder):
    """ Create a peer to peer message to propose a credential issuance from a multisig group identifier

    Parameters:
        hab (Hab): identifier Hab for ensorsing the message to send
        creder (Creder): Creder instance of the issued credential

    Returns:
        Serder: Serder of exn message to send
        butearray: attachment signatures

    """
    exn = exchanging.exchange(route="/multisig/issue", payload=creder.ked)
    evt = hab.mhab.endorse(serder=exn, last=True, pipelined=False)
    atc = bytearray(evt[exn.size:])

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

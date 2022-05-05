# -*- encoding: utf-8 -*-
"""
KERI
keri.app.grouping module

module for enveloping and forwarding KERI message
"""
import json

from hio import help
from hio.base import doing
from hio.help import decking

from keri import kering
from keri.app import forwarding, delegating, agenting
from keri.core import coring
from keri.db import dbing, basing
from keri.db.dbing import snKey
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

    def start(self, aids, pid, prefixer, seqner, saider):
        """ Begin processing of escrowed group multisig identifier

        Escrow identifier for multisigs, witness receipts and delegation anchor

        Parameters:
            aids (list): qb64 identifier prefixes of participants
            pid (str): qb64 identifier prefix of local participant
            prefixer (Prefixer): prefixer of group identifier
            seqner (Seqner): seqner of inception event of group identifier
            saider (Saider): saider of inception event of group identifier


        """
        evt = getEscrowedEvent(db=self.hby.db, pre=prefixer.qb64, sn=seqner.sn)
        serder = coring.Serder(raw=evt)
        del evt[:serder.size]

        others = list(aids)
        others.remove(pid)

        print(f"Sending multisig event to {len(aids) - 1} other participants")
        for recpt in others:
            self.postman.send(src=pid, dest=recpt, topic="multisig", serder=serder, attachment=evt)

        print(f"Waiting for other signatures for {seqner.sn}...")
        return self.hby.db.gpse.add(keys=(prefixer.qb64,), val=(seqner, saider))

    def rotate(self, ghab, aids, sith, toad, cuts=None, adds=None, data=None):
        """ Begin processing of escrowed group multisig identifier

        Escrow identifier for multisigs, witness receipts and delegation anchor

        Parameters:
            ghab (Hab): group identifier Hab
            aids (list): qb64 identifier prefixes of participants
            sith (Optional[int,str])next signing threshold as int or str hex or list of str weights
            toad (int) or str hex of witness threshold after cuts and adds
            cuts (list) of qb64 pre of witnesses to be removed from witness list
            adds (list) of qb64 pre of witnesses to be added to witness list
            data (list) of dicts of committed data such as seals

        """
        aids = aids if aids is not None else ghab.aids
        pid = ghab.phab.pre

        if pid not in aids:
            raise kering.ConfigurationError(f"local identifier {pid} not elected to participate in rotation: {aids}")

        kever = ghab.kever

        # Get local next key and see if we are in current group next keys
        pkever = ghab.phab.kever
        pnkey = pkever.nexter.digs[0]

        rec = basing.RotateRecord(aids=aids, sith=sith, toad=toad, cuts=cuts, adds=adds, data=data)
        if pnkey in kever.nexter.digs:  # local already participate in last event, rotate
            ghab.phab.rotate()
            print(f"Rotating local identifier, waiting for witness receipts")
            self.witDoer.msgs.append(dict(pre=ghab.phab.pre, sn=ghab.phab.kever.sn))
            return self.hby.db.glwe.put(keys=(ghab.pre,), val=rec)

        else:
            rot = ghab.phab.makeOwnEvent(pkever.lastEst.sn)  # grab latest est evt

            others = list(aids)
            others.remove(pid)
            serder = coring.Serder(raw=rot)
            del rot[:serder.size]

            print(f"Sending local rotation event to {len(aids) - 1} other participants")
            for recpt in others:
                self.postman.send(src=pid, dest=recpt, topic="multisig", serder=serder, attachment=rot)

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
            pid = ghab.phab.pre
            pkever = ghab.phab.kever
            dgkey = dbing.dgKey(pid, pkever.serder.saidb)

            # Load all the witness receipts we have so far
            wigs = self.hby.db.getWigs(dgkey)
            if len(wigs) == len(pkever.wits):  # We have all of them, this event is finished
                self.hby.db.glwe.rem(keys=(pre,))

                rot = self.hby.db.cloneEvtMsg(pid, pkever.sn, pkever.serder.said)  # grab latest est evt

                others = list(rec.aids)
                others.remove(pid)
                serder = coring.Serder(raw=rot)
                del rot[:serder.size]

                print(f"Sending local rotation event to {len(others)} other participants")
                for recpt in others:
                    self.postman.send(src=pid, dest=recpt, topic="multisig", serder=serder, attachment=rot)

                return self.hby.db.gpae.put(keys=(ghab.pre,), val=rec)

    def processPartialAidEscrow(self):
        """
        Process escrow of group multisig rotate requests missing rotations from other participants.  Message
        processing will send this local controllers rotation event to all other participants
        then this escrow waits for rotations from all other participants

        """
        # ignore saider because it is not relevant yet
        for (pre,), rec in self.hby.db.gpae.getItemIter():  # group partially signed escrow
            ghab = self.hby.habs[pre]
            gkever = ghab.kever

            keys = []
            nkeys = gkever.nexter.digers
            for aid in rec.aids:
                pkever = self.hby.kevers[aid]
                idx = ghab.aids.index(aid)
                if pkever.nexter.digs[0] != gkever.nexter.digs[idx]:
                    keys.append(pkever.verfers[0])
                    nkeys[idx] = pkever.nexter.digers[0]
                else:
                    break

            if len(keys) != len(rec.aids):
                continue

            rot = ghab.rotate(sith=rec.sith, toad=rec.toad, cuts=rec.cuts, adds=rec.adds, data=rec.data,
                              mskeys=keys, msdigers=nkeys)
            serder = coring.Serder(raw=rot)
            del rot[:serder.size]

            others = list(rec.aids)
            others.remove(ghab.phab.pre)
            print(f"Sending rotation event to {len(others)} other participants")
            for recpt in others:
                self.postman.send(src=ghab.phab.pre, dest=recpt, topic="multisig", serder=serder, attachment=rot)

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
                witer = ghab.phab.kever.verfers[0].qb64 == keys[0]  # Elected to perform delegation and witnessing

                if kever.delegated:  # We are a delegated identfier, must wait for delegator approval
                    if witer:  # We are elected to perform delegation and witnessing messaging
                        print("We are the witnesser, sending to delegator")
                        self.swain.msgs.append(dict(pre=pre, sn=seqner.sn))
                    else:
                        anchor = dict(i=pre, s=seqner.snh, d=saider.qb64)
                        self.witq.query(src=ghab.phab.pre, pre=kever.delegator, anchor=anchor)

                    # Move to escrow waiting for delegator approval
                    if witer:
                        # Send exn message for notification purposes
                        srdr = coring.Serder(raw=bytes(sraw))
                        exn, atc = delegating.delegateRequestExn(ghab.phab, delpre=kever.delegator, ked=srdr.ked)
                        self.postman.send(src=ghab.phab.pre, dest=kever.delegator, topic="delegate", serder=exn,
                                          attachment=atc)

                    print("Waiting for delegation approval...")
                    self.hby.db.gdee.add(keys=(pre,), val=(seqner, saider))
                else:  # Non-delegation, move on to witnessing
                    if witer:  # We are elected witnesser, send off event to witnesses
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
            witer = ghab.phab.kever.verfers[0].qb64 == keys[0]  # We are elected to perform delegation and witnessing

            if serder := self.hby.db.findAnchoringEvent(kever.delegator, anchor=anchor):
                aseq = coring.Seqner(sn=serder.sn)
                couple = aseq.qb64b + serder.saidb
                dgkey = dbing.dgKey(pre, saider.qb64b)
                self.hby.db.setAes(dgkey, couple)  # authorizer event seal (delegator/issuer)
                self.hby.db.gdee.rem(keys=(pre,))

                if witer:  # We are elected witnesser, send off event to witnesses
                    print("We are the witnesser, sending to witnesses")
                    self.witDoer.msgs.append(dict(pre=pre, sn=seqner.sn))

                # Move to escrow waiting for witness receipts
                print("Waiting for witness receipts")
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
                witer = ghab.phab.kever.verfers[0].qb64 == keys[0]
                if witer and len(kever.wits) > 0:
                    witnessed = False
                    for cue in self.witDoer.cues:
                        if cue["pre"] == ghab.pre and cue["sn"] == seqner.sn:
                            witnessed = True
                    if not witnessed:
                        continue

                self.hby.db.gpwe.rem(keys=(pre,))
                self.hby.db.cgms.put(keys=(pre, seqner.qb64), val=saider)


def loadHandlers(hby, exc, mbx, controller):
    """ Load handlers for the peer-to-peer distributed group multisig protocol

    Parameters:
        hby (Habery): Database and keystore for environment
        exc (Exchanger): Peer-to-peer message router
        mbx (Mailboxer): Database for storing mailbox messages
        controller (str): qb64 identifier prefix of controller

    """
    incept = MultisigInceptHandler(hby=hby, mbx=mbx, controller=controller)
    exc.addHandler(incept)
    rotate = MultisigRotateHandler(hby=hby, mbx=mbx, controller=controller)
    exc.addHandler(rotate)
    interact = MultisigInteractHandler(hby=hby, mbx=mbx, controller=controller)
    exc.addHandler(interact)
    issue = MultisigIssueHandler(controller=controller, mbx=mbx)
    exc.addHandler(issue)


class MultisigInceptHandler(doing.DoDoer):
    """
    Handler for multisig group inception notification EXN messages

    """
    resource = "/multisig/icp"

    def __init__(self, hby, mbx, controller, **kwa):
        """

        Parameters:
            mbx (Mailboxer) of format str names accepted for offers
            controller (str) qb64 identity prefix of controller
            cues (decking.Deck) of outbound cue messages from handler

        """
        self.controller = controller
        self.hby = hby
        self.mbx = mbx
        self.msgs = decking.Deck()
        self.cues = decking.Deck()

        super(MultisigInceptHandler, self).__init__(**kwa)

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
                    src=src,
                    r='/icp/init',
                    aids=aids,
                    ked=pay["ked"]
                )
                raw = json.dumps(data).encode("utf-8")

                if self.controller:
                    self.mbx.storeMsg(self.controller+"/multisig", raw)

                yield
            yield


def multisigInceptExn(hab, aids, ked):
    data = dict(
        aids=aids,
        ked=ked
    )

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

    def __init__(self, hby, mbx, controller, **kwa):
        """

        Parameters:
            mbx (Mailboxer) of format str names accepted for offers
            controller (str) qb64 identity prefix of controller
            cues (decking.Deck) of outbound cue messages from handler

        """
        self.controller = controller
        self.hby = hby
        self.mbx = mbx
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

                if src not in ghab.aids or src not in ghab.kevers:
                    logger.error(f"invalid incept message, source not knows or not part of group.  evt: {msg}")
                    continue

                data = dict(
                    src=src,
                    r='/rot',
                    aids=aids,
                )
                data["toad"] = pay["toad"] if "toad" in pay else None
                data["wits"] = pay["wits"] if "wits" in pay else []
                data["adds"] = pay["adds"] if "adds" in pay else []
                data["cuts"] = pay["cuts"] if "cuts" in pay else []
                data["isith"] = pay["isith"] if "isith" in pay else None
                data["data"] = pay["data"] if "data" in pay else None
                
                raw = json.dumps(data).encode("utf-8")

                if self.controller:
                    self.mbx.storeMsg(self.controller+"/multisig", raw)

                yield
            yield


def multisigRotateExn(ghab, aids, isith, toad, cuts, adds, data):

    exn = exchanging.exchange(route=MultisigRotateHandler.resource, modifiers=dict(),
                              payload=dict(gid=ghab.pre,
                                           aids=aids,
                                           sith=isith,
                                           toad=toad,
                                           cuts=list(cuts),
                                           adds=list(adds),
                                           data=data)
                              )
    ims = ghab.phab.endorse(serder=exn, last=True, pipelined=False)
    atc = bytearray(ims[exn.size:])

    return exn, atc


class MultisigInteractHandler(doing.DoDoer):
    """
    Handler for multisig group inception notification EXN messages

    """
    resource = "/multisig/ixn"

    def __init__(self, hby, mbx, controller, **kwa):
        """

        Parameters:
            mbx (Mailboxer) of format str names accepted for offers
            controller (str) qb64 identity prefix of controller
            cues (decking.Deck) of outbound cue messages from handler

        """
        self.controller = controller
        self.hby = hby
        self.mbx = mbx
        self.msgs = decking.Deck()
        self.cues = decking.Deck()

        super(MultisigInteractHandler, self).__init__(**kwa)

    def do(self, tymth, tock=0.0, **opts):
        """ Process incoming notifications for a group interaction events

        Handle incoming messages by storing a message in the mailbox of the controller

        Parameters:
            payload is dict representing the body of a multisig/ixn message
            pre is qb64 identifier prefix of sender

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

                if src not in ghab.aids or src not in ghab.kevers:
                    logger.error(f"invalid incept message, source not knows or not part of group.  evt: {msg}")
                    continue

                data = dict(
                    src=src,
                    r='/ixn',
                    aids=aids,
                )
                data["data"] = pay["data"] if "data" in pay else None

                raw = json.dumps(data).encode("utf-8")

                if self.controller:
                    self.mbx.storeMsg(self.controller+"/multisig", raw)

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
    ims = ghab.phab.endorse(serder=exn, last=True, pipelined=False)
    atc = bytearray(ims[exn.size:])

    return exn, atc


class MultisigIssueHandler(doing.DoDoer):
    """
    Handler for multisig group issuance notification EXN messages

    """
    resource = "/multisig/issue"

    def __init__(self, mbx, controller, **kwa):
        """

        Parameters:
            mbx (Mailboxer) of format str names accepted for offers
            controller (str) qb64 identity prefix of controller
            cues (decking.Deck) of outbound cue messages from handler

        """
        self.controller = controller
        self.mbx = mbx
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
                pl["r"] = "/issue"

                try:
                    creder = proving.Creder(ked=pl)
                    self.mbx.storeMsg(self.controller+"/multisig", creder.raw)
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
    evt = hab.phab.endorse(serder=exn, last=True, pipelined=False)
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

# -*- encoding: utf-8 -*-
"""
KERI
keri.app.grouping module

module for enveloping and forwarding KERI message
"""
import json

import sys
from hio import help
from hio.base import doing
from hio.help import decking

from keri import kering
from keri.app import forwarding, delegating, agenting
from keri.core import coring, eventing, parsing
from keri.db import dbing, basing
from keri.db.dbing import snKey

logger = help.ogler.getLogger()


class Counselor(doing.DoDoer):

    def __init__(self, hby, cues=None, **kwa):

        self.hby = hby
        self.postman = forwarding.Postman(hby=hby)
        self.swain = delegating.Boatswain(hby=self.hby)
        self.witDoer = agenting.WitnessReceiptor(hby=self.hby)
        self.witq = agenting.WitnessInquisitor(hby=hby)

        self.cues = cues if cues is not None else decking.Deck()

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

        print(f"Sending inception event to {len(aids) - 1} other participants")
        for recpt in others:
            self.postman.send(src=pid, dest=recpt, topic="multisig", serder=serder, attachment=evt)

        sys.stdout.write("Waiting for other signatures")
        sys.stdout.flush()
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
            yield self.tock

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

            sys.stdout.write("Waiting for other signatures")
            sys.stdout.flush()
            self.hby.db.gpae.rem((pre,))
            return self.hby.db.gpse.add(keys=(ghab.pre,), val=(coring.Seqner(sn=serder.sn), serder.saider))

    def processPartialSignedEscrow(self):
        """
        Process escrow of partially signed multisig group KEL events.  Message
        processing will send this local controllers signature to all other participants
        then this escrow waits for signatures from all other participants

        """
        for (pre,), (seqner, saider) in self.hby.db.gpse.getItemIter():  # group partially signed escrpw
            sys.stdout.write(".")
            sys.stdout.flush()
            snkey = dbing.snKey(pre, seqner.sn)
            evt = self.hby.db.getKeLast(key=snkey)
            if evt:
                print()
                self.hby.db.gpse.rem(keys=(pre, ))
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
                    print("Waiting for delegation approval...")
                    self.hby.db.gdee.add(keys=(pre,), val=(seqner, saider))
                else:  # Non-delegation, move on to witnessing
                    if witer:  # We are elected witnesser, send off event to witnesses
                        print("We are the witnesser, sending to witnesses")
                        self.witDoer.msgs.append(dict(pre=pre, sn=seqner.sn))

                    # Move to escrow waiting for witness receipts
                    print("Waiting for witness receipts")
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
                self.cues.append(dict(kin="complete", pre=pre, sn=seqner.sn, said=saider.qb64))


class MultisigInceptHandler(doing.DoDoer):
    """
    Handler for multisig group inception notification EXN messages

    """
    resource = "/multisig/incept"

    def __init__(self, hby, mbx, controller, cues=None, **kwa):
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
        self.cues = cues if cues is not None else decking.Deck()

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
                pl = msg["payload"]
                attachments = msg["attachments"]
                srdr = coring.Serder(ked=pl)
                raw = bytearray(srdr.raw)

                for path, atc in attachments:
                    if path.text == "-":
                        raw.extend(atc)

                kvy = eventing.Kevery(db=self.hby.db, lax=True, local=False)
                parsing.Parser().parseOne(ims=bytearray(raw), kvy=kvy)

                if self.controller:
                    self.mbx.storeMsg(self.controller+"/multisig", raw)

                # print(raw)

                yield
            yield


class MultisigIssueHandler(doing.DoDoer):
    """
    Handler for multisig group issuance notification EXN messages

    """
    resource = "/multisig/issue"

    def __init__(self, mbx, controller, cues=None, **kwa):
        """

        Parameters:
            mbx (Mailboxer) of format str names accepted for offers
            controller (str) qb64 identity prefix of controller
            cues (decking.Deck) of outbound cue messages from handler

        """
        self.controller = controller
        self.mbx = mbx
        self.msgs = decking.Deck()
        self.cues = cues if cues is not None else decking.Deck()

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
                raw = json.dumps(pl).encode("utf-8")
                self.mbx.storeMsg(self.controller+"/multisig", raw)

                yield
            yield


class MultisigEventHandler(doing.Doer):
    """
    Handler for multisig group rotation/interact notification EXN messages

    """

    resource = "/multisig/event"

    def __init__(self, hby, verifier, cues=None, **kwa):
        """

        Parameters:
            hab (Habitat) is environment of participant in multisig group
            controller (str) qb64 identity prefix of controller
            mbx (Mailboxer) of format str names accepted for offers
            cues (decking.Deck) of outbound cue messages from handler

        """
        self.hby = hby
        self.verifier = verifier
        self.msgs = decking.Deck()
        self.cues = cues if cues is not None else decking.Deck()

        self.kvy = eventing.Kevery(db=self.hby.db, lax=False, local=False)

        super(MultisigEventHandler, self).__init__(**kwa)

    def do(self, tymth, tock=0.0, **opts):
        """

        Handle incoming messages by parsing and verifiying the credential and storing it in the wallet

        Parameters:
            payload is dict representing the body of a /multisig/interact message
            pre is qb64 identifier prefix of sender
            sigers is list of Sigers representing the sigs on the /credential/issue message
            verfers is list of Verfers of the keys used to sign the message

        Payload:
            evt is bytes of ixn message from another participant
            reason is either a str expressing reason for interaction event or credential

        """
        yield self.tock

        while True:
            while self.msgs:
                msg = self.msgs.popleft()
                payload = msg["payload"]
                evt = payload["evt"].encode("utf-8")
                reason = payload["reason"]

                parsing.Parser().parse(bytearray(evt), kvy=self.kvy)
                if reason is not None:
                    craw = reason.encode("utf-8")
                    parsing.Parser().parse(ims=craw, vry=self.verifier)

                yield

            yield


def getEscrowedEvent(db, pre, sn):
    key = snKey(pre, sn)
    dig = db.getPseLast(key)
    if dig is None:
        return None

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

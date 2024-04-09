# -*- encoding: utf-8 -*-

import os

from keri import core
from keri.core import  eventing, parsing
from keri.core import MtrDex
from keri.core.coring import Seqner

from keri.core.eventing import (incept, rotate, interact, messagize, SealEvent, receipt)

from keri.app.keeping import Manager, openKS

from keri.db.dbing import dgKey, snKey
from keri.db.basing import  openDB


def test_direct_mode_with_manager():
    """
    Test direct mode with transferable validator event receipts

    """
    # manual process to generate a list of secrets
    # root = pysodium.randombytes(pysodium.crypto_pwhash_SALTBYTES)
    # secrets = generateSecrets(root=root, count=8)

    # Direct Mode initiated by coe is controller, val is validator
    # but goes both ways once initiated.

    # set of secrets  (seeds for private keys)
    coeSalt = core.Salter(raw=b'0123456789abcdea').qb64

    # set of secrets (seeds for private keys)
    valSalt = core.Salter(raw=b'1123456789abcdea').qb64


    with openDB(name="controller") as coeLogger, openDB(name="validator") as valLogger, \
         openKS(name="controller") as coeKpr, openKS(name="validator") as valKpr:
        # Init key pair manager
        coeMgr = Manager(ks=coeKpr, salt=coeSalt)
        coeVerfers, coeDigers = coeMgr.incept(icount=1, ncount=1)

        #  init Keverys
        coeKevery = eventing.Kevery(db=coeLogger)
        valKevery = eventing.Kevery(db=valLogger)

        coe_event_digs = []  # list of controller's own event log digs to verify against database
        val_event_digs = []  # list of validator's own event log digs to verify against database

        #  init sequence numbers for both controller and validator
        csn = cesn = 0  # sn and last establishment sn = esn
        vsn = vesn = 0  # sn and last establishment sn = esn

        # Controller Event 0  Inception Transferable (nxt digest not empty)
        coeSerder = incept(keys=[coeVerfers[0].qb64],
                           ndigs=[coeDigers[0].qb64],
                           code=MtrDex.Blake3_256)

        assert csn == int(coeSerder.ked["s"], 16) == 0
        coepre = coeSerder.ked["i"]

        coe_event_digs.append(coeSerder.said)
        # sign serialization
        sigers = coeMgr.sign(ser=coeSerder.raw, verfers=coeVerfers)

        #  create serialized message
        cmsg = messagize(coeSerder, sigers=sigers)

        # create own Controller Kever in  Controller's Kevery
        parsing.Parser().parseOne(ims=bytearray(cmsg), kvy=coeKevery)
        # coeKevery.processOne(ims=bytearray(cmsg))  # send copy of cmsg
        coeKever = coeKevery.kevers[coepre]
        assert coeKever.prefixer.qb64 == coepre

        # Validator Event 0  Inception Transferable (nxt digest not empty)
        # Init key pair manager
        valMgr = Manager(ks=valKpr, salt=valSalt)
        valVerfers, valDigers = valMgr.incept(icount=1, ncount=1)

        valSerder = incept(keys=[valVerfers[0].qb64],
                           ndigs=[valDigers[0].qb64],
                           code=MtrDex.Blake3_256)

        assert vsn == int(valSerder.ked["s"], 16) == 0
        valpre = valSerder.ked["i"]

        val_event_digs.append(valSerder.said)

        # sign serialization
        sigers = valMgr.sign(valSerder.raw, verfers=valVerfers)  # return Siger if index

        #  create serialized message
        vmsg = messagize(valSerder, sigers=sigers)

        # create own Validator Kever in  Validator's Kevery
        parsing.Parser().parseOne(ims=bytearray(vmsg), kvy=valKevery)
        # valKevery.processOne(ims=bytearray(vmsg))  # send copy of vmsg
        valKever = valKevery.kevers[valpre]
        assert valKever.prefixer.qb64 == valpre

        # simulate sending of controller's inception message to validator
        parsing.Parser().parse(ims=bytearray(cmsg), kvy=valKevery)
        # valKevery.process(ims=bytearray(cmsg))  # make copy of msg
        assert coepre in valKevery.kevers  # creates Kever for controller in validator's .kevers

        # create receipt of controller's inception
        # create seal of validator's last establishment event
        seal = SealEvent(i=valpre,
                         s="{:x}".format(valKever.lastEst.s),
                         d=valKever.lastEst.d)
        coeK = valKevery.kevers[coepre]  # lookup coeKever from validator's .kevers
        # create trans receipt by attaching siger to recipt msg
        reserder = receipt(pre=coeK.prefixer.qb64,
                           sn=coeK.sn,
                           said=coeK.serder.said)

        # sign controller's event not receipt
        # look up event to sign from validator's kever for coe
        coeIcpDig = bytes(valKevery.db.getKeLast(key=snKey(pre=coepre, sn=csn)))
        assert coeIcpDig == coeK.serder.saidb
        coeIcpRaw = bytes(valKevery.db.getEvt(key=dgKey(pre=coepre, dig=coeIcpDig)))

        #counter = Counter(CtrDex.ControllerIdxSigs)
        #assert counter.qb64 == '-AAB'
        sigers = valMgr.sign(ser=coeIcpRaw, verfers=valVerfers)  # return Siger if index

        # attach signatures
        rmsg = messagize(reserder, sigers=sigers, seal=seal)
        assert len(rmsg) == 353

        # process own validator receipt in validator's Kevery so have copy in own log
        # also server to validate receipt
        parsing.Parser().parseOne(ims=bytearray(rmsg), kvy=valKevery)

        # attach receipt message to existing message with validators inception message
        # simulate streaming. validator first sends it's inception event, then
        # sends a receipt to controller
        vmsg.extend(rmsg)

        # Simulate sending validator's inception event and receipt of
        # controller's inception message to controller
        parsing.Parser().parse(ims=vmsg, kvy=coeKevery)
        # coeKevery.process(ims=vmsg)  # controller process validator's inception and receipt

        # check if validator's Kever in controller's .kevers
        assert valpre in coeKevery.kevers
        #  check if receipt quadruple from validator in receipt database
        result = coeKevery.db.getVrcs(key=dgKey(pre=coeKever.prefixer.qb64,
                                                dig=coeKever.serder.said))
        assert bytes(result[0]) == (valKever.prefixer.qb64b +
                                    Seqner(sn=valKever.sn).qb64b +
                                    valKever.serder.saidb +
                                    sigers[0].qb64b)


        # create receipt to escrow use invalid digest and sequence number so not in controller's db
        fake = reserder.said  # some other digest
        reserder = receipt(pre=coeK.prefixer.qb64,
                           sn=10,
                           said=fake)
        # sign event not receipt
        sigers = valMgr.sign(ser=coeIcpRaw, verfers=valVerfers)  # return Siger if index
        # create receipt message
        vmsg = messagize(reserder, sigers=sigers, seal=seal)

        parsing.Parser().parse(ims=bytearray(vmsg), kvy=coeKevery)
        # coeKevery.process(ims=vmsg)  # controller process the escrow receipt from validator
        #  check if receipt quadruple in escrow database
        result = coeKevery.db.getVres(key=snKey(pre=coeKever.prefixer.qb64,
                                                   sn=10))
        assert bytes(result[0]) == (fake.encode("utf-8") +
                                    valKever.prefixer.qb64b +
                                    Seqner(sn=valKever.sn).qb64b +
                                    valKever.serder.saidb +
                                    sigers[0].qb64b)

        # Send receipt from controller to validator
        # create receipt of validator's inception
        # create seal of controller's last establishment event
        seal = SealEvent(i=coepre,
                         s="{:x}".format(coeKever.lastEst.s),
                         d=coeKever.lastEst.d)
        valK = coeKevery.kevers[valpre]  # lookup valKever from controller's .kevers
        # create trans receipt
        reserder = receipt(pre=valK.prefixer.qb64,
                           sn=valK.sn,
                           said=valK.serder.said, )
        # sign validator's event not receipt
        # look up event to sign from controller's kever for validator
        valIcpDig = bytes(coeKevery.db.getKeLast(key=snKey(pre=valpre, sn=vsn)))
        assert valIcpDig == valK.serder.saidb
        valIcpRaw = bytes(coeKevery.db.getEvt(key=dgKey(pre=valpre, dig=valIcpDig)))
        sigers = coeMgr.sign(ser=valIcpRaw, verfers=coeVerfers)  # return Siger if index
        # create receipt message
        cmsg = messagize(reserder, sigers=sigers, seal=seal)
        # controller process own receipt in own Kevery so have copy in own log
        parsing.Parser().parseOne(ims=bytearray(cmsg), kvy=coeKevery)
        # coeKevery.processOne(ims=bytearray(cmsg))  # make copy

        # Simulate sending controller's receipt of validator's inception message to validator
        parsing.Parser().parse(ims=cmsg, kvy=valKevery)
        # valKevery.process(ims=cmsg)  # controller process validator's inception and receipt

        #  check if receipt quadruple from controller in validator's receipt database
        result = valKevery.db.getVrcs(key=dgKey(pre=valKever.prefixer.qb64,
                                                dig=valKever.serder.said))
        assert bytes(result[0]) == (coeKever.prefixer.qb64b +
                                    Seqner(sn=coeKever.sn).qb64b +
                                    coeKever.serder.saidb +
                                    sigers[0].qb64b)

        # Controller Event 1 Rotation Transferable
        csn += 1
        cesn += 1
        assert csn == cesn == 1
        coeVerfers, coeDigers = coeMgr.rotate(pre=coeVerfers[0].qb64)
        coeSerder = rotate(pre=coeKever.prefixer.qb64,
                           keys=[coeVerfers[0].qb64],
                           dig=coeKever.serder.said,
                           ndigs=[coeDigers[0].qb64],
                           sn=csn)
        coe_event_digs.append(coeSerder.said)

        # sign serialization
        sigers = coeMgr.sign(coeSerder.raw, verfers=coeVerfers)  # returns sigers

        #  create serialized message
        cmsg = messagize(coeSerder, sigers=sigers)

        # update controller's key event verifier state
        parsing.Parser().parseOne(ims=bytearray(cmsg), kvy=coeKevery)
        # coeKevery.processOne(ims=bytearray(cmsg))  # make copy
        # verify controller's copy of controller's event stream is updated
        assert coeKever.sn == csn
        assert coeKever.serder.said == coeSerder.said

        # simulate send message from controller to validator
        parsing.Parser().parse(ims=cmsg, kvy=valKevery)
        # valKevery.process(ims=cmsg)
        # verify validator's copy of controller's event stream is updated
        assert coeK.sn == csn
        assert coeK.serder.said == coeSerder.said

        # create receipt of controller's rotation
        # create seal of validator's last establishment event
        seal = SealEvent(i=valpre,
                         s="{:x}".format(valKever.lastEst.s),
                         d=valKever.lastEst.d)
        # create validator receipt
        reserder = receipt(pre=coeK.prefixer.qb64,
                           sn=coeK.sn,
                           said=coeK.serder.said)
        # sign controller's event not receipt
        # look up event to sign from validator's kever for controller
        coeRotDig = bytes(valKevery.db.getKeLast(key=snKey(pre=coepre, sn=csn)))
        assert coeRotDig == coeK.serder.saidb
        coeRotRaw = bytes(valKevery.db.getEvt(key=dgKey(pre=coepre, dig=coeRotDig)))
        sigers = valMgr.sign(ser=coeRotRaw, verfers=valVerfers)
        # validator create receipt message
        vmsg = messagize(reserder, sigers=sigers, seal=seal)

        # validator process own receipt in own kevery so have copy in own log
        parsing.Parser().parseOne(ims=bytearray(vmsg), kvy=valKevery)
        # valKevery.processOne(ims=bytearray(vmsg))  # make copy

        # Simulate send to controller of validator's receipt of controller's rotation message
        parsing.Parser().parse(ims=vmsg, kvy=coeKevery)
        # coeKevery.process(ims=vmsg)  # controller process validator's incept and receipt

        # check if receipt quadruple from validator in receipt database
        result = coeKevery.db.getVrcs(key=dgKey(pre=coeKever.prefixer.qb64,
                                                dig=coeKever.serder.said))
        assert bytes(result[0]) == (valKever.prefixer.qb64b +
                                    Seqner(sn=valKever.sn).qb64b +
                                    valKever.serder.saidb +
                                    sigers[0].qb64b)

        # Next Event 2 Controller Interaction
        csn += 1  # do not increment esn
        assert csn == 2
        assert cesn == 1
        coeSerder = interact(pre=coeKever.prefixer.qb64,
                             dig=coeKever.serder.said,
                             sn=csn)
        coe_event_digs.append(coeSerder.said)

        # sign serialization
        sigers = coeMgr.sign(coeSerder.raw, verfers=coeVerfers)

        # create msg
        cmsg = messagize(coeSerder, sigers=sigers)

        # update controller's key event verifier state
        parsing.Parser().parseOne(ims=bytearray(cmsg), kvy=coeKevery)
        # coeKevery.processOne(ims=bytearray(cmsg))  # make copy
        # verify controller's copy of controller's event stream is updated
        assert coeKever.sn == csn
        assert coeKever.serder.said == coeSerder.said

        # simulate send message from controller to validator
        parsing.Parser().parse(ims=cmsg, kvy=valKevery)
        # valKevery.process(ims=cmsg)
        # verify validator's copy of controller's event stream is updated
        assert coeK.sn == csn
        assert coeK.serder.said == coeSerder.said

        # create receipt of controller's interaction
        # create seal of validator's last est event
        seal = SealEvent(i=valpre,
                         s="{:x}".format(valKever.lastEst.s),
                         d=valKever.lastEst.d)
        # create validator receipt
        reserder = receipt(pre=coeK.prefixer.qb64,
                           sn=coeK.sn,
                           said=coeK.serder.said)
        # sign controller's event not receipt
        # look up event to sign from validator's kever for controller
        coeIxnDig = bytes(valKevery.db.getKeLast(key=snKey(pre=coepre, sn=csn)))
        assert coeIxnDig == coeK.serder.saidb
        coeIxnRaw = bytes(valKevery.db.getEvt(key=dgKey(pre=coepre, dig=coeIxnDig)))
        sigers = valMgr.sign(ser=coeIxnRaw, verfers=valVerfers)
        # create receipt message
        vmsg = messagize(reserder, sigers=sigers, seal=seal)

        # validator process own receipt in own kevery so have copy in own log
        parsing.Parser().parseOne(ims=bytearray(vmsg), kvy=valKevery)
        # valKevery.processOne(ims=bytearray(vmsg))  # make copy

        # Simulate send to controller of validator's receipt of controller's rotation message
        parsing.Parser().parse(ims=bytearray(vmsg), kvy=coeKevery)
        # coeKevery.process(ims=vmsg)  # controller process validator's incept and receipt

        #  check if receipt quadruple from validator in receipt database
        result = coeKevery.db.getVrcs(key=dgKey(pre=coeKever.prefixer.qb64,
                                                dig=coeKever.serder.said))
        assert bytes(result[0]) == (valKever.prefixer.qb64b +
                                    Seqner(sn=valKever.sn).qb64b +
                                    valKever.serder.saidb +
                                    sigers[0].qb64b)


        #  verify final controller event state
        assert coeKever.sn == coeK.sn == csn

        db_digs = [bytes(v).decode("utf-8") for v in coeKever.db.getKelIter(coepre)]
        assert len(db_digs) == len(coe_event_digs) == csn + 1
        assert db_digs == coe_event_digs

        db_digs = [bytes(v).decode("utf-8") for v in valKever.db.getKelIter(coepre)]
        assert len(db_digs) == len(coe_event_digs) == csn + 1
        assert db_digs == coe_event_digs

        #  verify final validator event state
        assert valKever.sn == valK.sn == vsn

        db_digs = [bytes(v).decode("utf-8") for v in valKever.db.getKelIter(valpre)]
        assert len(db_digs) == len(val_event_digs) == vsn + 1
        assert db_digs == val_event_digs

        db_digs = [bytes(v).decode("utf-8") for v in coeKever.db.getKelIter(valpre)]
        assert len(db_digs) == len(val_event_digs) == vsn + 1
        assert db_digs == val_event_digs

    assert not os.path.exists(valKevery.db.path)
    assert not os.path.exists(coeKever.db.path)


if __name__ == "__main__":
    test_direct_mode_with_manager()

# -*- encoding: utf-8 -*-
"""
tests escrows in database primarily logic in Kevery and Kever from keri.core.eventing

"""
import os
import time
import datetime

import pytest

from keri.kering import Vrsn_1_0, Vrsn_2_0
from keri import help
from keri.help import helping

from keri import core, kering
from keri.core import coring, eventing, parsing

from keri.db import dbing, basing
from keri.app import keeping


logger = help.ogler.getLogger()


def test_partial_signed_escrow():
    """
    Test partially signed escrow

    """
    salt = core.Salter(raw=b'0123456789abcdef').qb64  # init wes Salter
    psr = parsing.Parser(version=Vrsn_1_0)

    # init event DB and keep DB
    with basing.openDB(name="edy") as db, keeping.openKS(name="edy") as ks:
        # Init key pair manager
        mgr = keeping.Manager(ks=ks, salt=salt)

        # Init Kevery with event DB
        kvy = eventing.Kevery(db=db)

        # create inception event with 3 keys each in incept and next sets
        # defaults are algo salty and rooted
        sith = ["1/2", "1/2", "1/2"]  #  2 of 3 but with weighted threshold
        nxtsith = ["1/2", "1/2", "1/2"]
        verfers, digers = mgr.incept(icount=3, ncount=3, stem='wes', temp=True)

        srdr = eventing.incept(keys=[verfer.qb64 for verfer in verfers],
                               isith=sith,
                               nsith=nxtsith,
                               ndigs=[diger.qb64 for diger in digers],
                               code=coring.MtrDex.Blake3_256)

        pre = srdr.ked["i"]

        mgr.move(old=verfers[0].qb64, new=pre)  # move key pair label to prefix

        sigers = mgr.sign(ser=srdr.raw, verfers=verfers)

        msg = bytearray(srdr.raw)
        counter = core.Counter(core.Codens.ControllerIdxSigs,
                               version=kering.Vrsn_1_0)
        msg.extend(counter.qb64b)
        msg.extend(sigers[0].qb64b)

        # apply msg to Kevery to process
        psr.parse(ims=bytearray(msg), kvy=kvy)
        # kvy.process(ims=bytearray(msg))  # process local copy of msg
        assert pre not in kvy.kevers  # event not accepted
        escrows = kvy.db.pses.getOn(keys=pre, on=int(srdr.ked["s"], 16))
        assert len(escrows) == 1
        assert escrows[0].encode("utf-8") == srdr.saidb  #  escrow entry for event

        # verify Kevery process is idempotent to previously escrowed events
        psr.parse(ims=bytearray(msg), kvy=kvy)
        # kvy.process(ims=bytearray(msg))  # process local copy of msg
        assert pre not in kvy.kevers  # event not accepted
        escrows = kvy.db.pses.getOn(keys=pre, on=int(srdr.ked["s"], 16))
        assert len(escrows) == 1
        assert escrows[0].encode("utf-8") == srdr.saidb  #  escrow entry for event

        time.sleep(0.001)
        # verify Kevery process partials escrow is idempotent to previously escrowed events
        # assuming not stale but nothing else has changed
        kvy.processEscrowPartialSigs()
        assert pre not in kvy.kevers  # event not accepted
        escrows = kvy.db.pses.getOn(keys=pre, on=int(srdr.ked["s"], 16))
        assert len(escrows) == 1
        assert escrows[0].encode("utf-8") == srdr.saidb  #  escrow entry for event

        # Send message again but with signature from other siger
        # send duplicate message with all three sigs
        counter = core.Counter(core.Codens.ControllerIdxSigs,
                                 version=kering.Vrsn_1_0)
        msg.extend(counter.qb64b)
        msg.extend(sigers[2].qb64b)
        # apply msg to Kevery to process
        psr.parse(ims=bytearray(msg), kvy=kvy)
        # kvy.process(ims=bytearray(msg))  # process local copy of msg
        assert pre in kvy.kevers  # event accepted
        escrows = kvy.db.pses.getOn(keys=pre, on=int(srdr.ked["s"], 16))
        assert len(escrows) == 1
        assert escrows[0].encode("utf-8") == srdr.saidb  #  escrow entry for event
        sigers = kvy.db.sigs.get(keys=(pre, srdr.said))  #  but sigs is more
        assert len(sigers) == 2

        # get DTS set by escrow date time stamp on event
        edater = kvy.db.dtss.get(keys=dbing.dgKey(pre, srdr.saidb))

        time.sleep(0.001)
        # verify Kevery process partials escrow now unescrows correctly given
        # two signatures and assuming not stale
        kvy.processEscrowPartialSigs()
        assert pre in kvy.kevers  # event now accepted via escrow
        kvr = kvy.kevers[pre]  # kever created so event was validated
        assert kvr.prefixer.qb64 == pre
        assert kvr.serder.said == srdr.said  # key state updated so event was validated
        # escrows now empty
        escrows = kvy.db.pses.getOn(keys=pre, on=int(srdr.ked["s"], 16))
        assert len(escrows) == 0

        # get DTS set by first seen event acceptance date time stamp
        adater = kvy.db.dtss.get(keys=dbing.dgKey(pre, srdr.saidb))
        # ensure accept time is later than escrow time, default timedelta is zero
        # assert (adater.datetime - edater.datetime) > datetime.timedelta()

        # send duplicate message with all three sigs
        # Re-sign to get all 3 original signatures
        allsigers = mgr.sign(ser=srdr.raw, verfers=verfers)
        msg = bytearray(srdr.raw)
        counter = core.Counter(core.Codens.ControllerIdxSigs,
                            count=len(allsigers), version=kering.Vrsn_1_0)
        msg.extend(counter.qb64b)
        for siger in allsigers:
            msg.extend(siger.qb64b)
        psr.parse(ims=bytearray(msg), kvy=kvy)
        # kvy.process(ims=bytearray(msg))  # process local copy of msg
        sigers = kvy.db.sigs.get(keys=(pre, srdr.said))
        assert len(sigers) == 3
        escrows = kvy.db.pses.getOn(keys=pre, on=int(srdr.ked["s"], 16))
        assert len(escrows) == 0  # escrow stays gone

        # get DTS after partial last sig should not change dts from first accepted
        pdater = kvy.db.dtss.get(keys=dbing.dgKey(pre, srdr.saidb))
        assert pdater.dts == adater.dts

        # get first seen
        fsdig = kvy.db.fels.getOn(keys=pre, on=0)
        assert fsdig == srdr.saidb.decode("utf-8")

        # create interaction event for
        srdr = eventing.interact(pre=kvr.prefixer.qb64,
                                 dig=kvr.serder.said,
                                 sn=kvr.sn+1,
                                 data=[])

        sigers = mgr.sign(ser=srdr.raw, verfers=kvr.verfers)

        msg = bytearray(srdr.raw)
        counter = core.Counter(core.Codens.ControllerIdxSigs, version=kering.Vrsn_1_0)
        msg.extend(counter.qb64b)
        msg.extend(sigers[1].qb64b)

        # apply msg to Kevery to process
        psr.parse(ims=bytearray(msg), kvy=kvy)
        # kvy.process(ims=bytearray(msg))  # process local copy of msg
        assert kvr.sn == 0  # key state not updated
        escrows = kvy.db.pses.getOn(keys=pre, on=int(srdr.ked["s"], 16))
        assert len(escrows) == 1
        assert escrows[0].encode("utf-8") == srdr.saidb  #  escrow entry for event

        # add another sig
        msg = bytearray(srdr.raw)
        counter = core.Counter(core.Codens.ControllerIdxSigs, version=kering.Vrsn_1_0)
        msg.extend(counter.qb64b)
        msg.extend(sigers[0].qb64b)

        # apply msg to Kevery to process
        psr.parse(ims=bytearray(msg), kvy=kvy)
        # kvy.process(ims=bytearray(msg))  # process local copy of msg
        assert kvr.sn == 0  # key state not updated
        escrows = kvy.db.pses.getOn(keys=pre, on=int(srdr.ked["s"], 16))
        assert len(escrows) == 1
        assert escrows[0].encode("utf-8") == srdr.saidb  #  escrow entry for event
        sigers = kvy.db.sigs.get(keys=(pre, srdr.said))  #  but sigs is more
        assert len(sigers) == 2

        # Process partials but stale escrow  despite two sigs set Timeout to 0
        kvy.TimeoutPSE = 0  # forces all escrows to be stale
        time.sleep(0.001)
        kvy.processEscrowPartialSigs()
        assert kvr.sn == 0  # key state not updated
        # escrows now empty
        escrows = kvy.db.pses.getOn(keys=pre, on=int(srdr.ked["s"], 16))
        assert len(escrows) == 0

        # Now reset timeout so not zero
        kvy.TimeoutPSE = 3600

        # resend events to load escrow
        msg = bytearray(srdr.raw)
        counter = core.Counter(core.Codens.ControllerIdxSigs, version=kering.Vrsn_1_0)
        msg.extend(counter.qb64b)
        msg.extend(sigers[1].qb64b)

        # apply msg to Kevery to process
        psr.parse(ims=bytearray(msg), kvy=kvy)
        # kvy.process(ims=bytearray(msg))  # process local copy of msg
        assert kvr.sn == 0  # key state not updated
        escrows = kvy.db.pses.getOn(keys=pre, on=int(srdr.ked["s"], 16))
        assert len(escrows) == 1
        assert escrows[0].encode("utf-8") == srdr.saidb  #  escrow entry for event

        # add another sig
        msg = bytearray(srdr.raw)
        counter = core.Counter(core.Codens.ControllerIdxSigs, version=kering.Vrsn_1_0)
        msg.extend(counter.qb64b)
        msg.extend(sigers[0].qb64b)

        # apply msg to Kevery to process
        psr.parse(ims=bytearray(msg), kvy=kvy)
        # kvy.process(ims=bytearray(msg))  # process local copy of msg
        assert kvr.sn == 0  # key state not updated
        escrows = kvy.db.pses.getOn(keys=pre, on=int(srdr.ked["s"], 16))
        assert len(escrows) == 1
        assert escrows[0].encode("utf-8") == srdr.saidb  #  escrow entry for event

        # get DTS set by escrow date time stamp on event
        edater = kvy.db.dtss.get(keys=dbing.dgKey(pre, srdr.saidb))

        time.sleep(0.001)
        # Process partials but now escrow not stale
        kvy.processEscrowPartialSigs()
        assert kvr.serder.said == srdr.said  # key state updated so event was validated
        assert kvr.sn == 1  # key state successfully updated
        escrows = kvy.db.pses.getOn(keys=pre, on=int(srdr.ked["s"], 16))
        assert len(escrows) == 0  # escrow gone

        # get DTS set by first seen event acceptance date time stamp
        adater = kvy.db.dtss.get(keys=dbing.dgKey(pre, srdr.saidb))
        # ensure accept time is later than escrow time, default timedelta is zero
        assert (adater.datetime - edater.datetime) > datetime.timedelta()

        # send duplicate message but add last sig
        msg = bytearray(srdr.raw)
        counter = core.Counter(core.Codens.ControllerIdxSigs, version=kering.Vrsn_1_0)
        msg.extend(counter.qb64b)
        msg.extend(sigers[1].qb64b)
        psr.parse(ims=bytearray(msg), kvy=kvy)
        # kvy.process(ims=bytearray(msg))  # process local copy of msg
        sigers = kvy.db.sigs.get(keys=(pre, srdr.said))  #  but sigs is more
        assert len(sigers) == 2
        escrows = kvy.db.pses.getOn(keys=pre, on=int(srdr.ked["s"], 16))
        assert len(escrows) == 0  # escrow stays gone

        # get DTS after partial last sig should not change dts from first accepted
        pdater = kvy.db.dtss.get(keys=dbing.dgKey(pre, srdr.saidb))
        assert pdater.dts == adater.dts

        # get first seen
        fsdig = kvy.db.fels.getOn(keys=pre, on=1)
        assert fsdig == srdr.saidb.decode("utf-8")

        # Create rotation event
        # get current keys as verfers and next digests as digers
        sith = nxtsith  # rotate so nxtsith is now current sith and need new nextsith
        #  2 of first 3 and 1 of last 2
        nxtsith = [["1/2", "1/2", "1/2"],["1/1", "1/1"]]
        verfers, digers = mgr.rotate(pre=pre, ncount=5, temp=True)

        srdr = eventing.rotate(pre=kvr.prefixer.qb64,
                               keys=[verfer.qb64 for verfer in verfers],
                               isith=sith,
                               dig=kvr.serder.said,
                               nsith=nxtsith,
                               ndigs=[diger.qb64 for diger in digers],
                               sn=kvr.sn+1,
                               data=[])

        sigers = mgr.sign(ser=srdr.raw, verfers=verfers)

        msg = bytearray(srdr.raw)
        counter = core.Counter(core.Codens.ControllerIdxSigs,
                                 count=len(sigers), version=kering.Vrsn_1_0)
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        # apply msg to Kevery
        psr.parse(ims=bytearray(msg), kvy=kvy)
        # kvy.process(ims=bytearray(msg))  # process local copy of msg
        assert kvr.serder.said == srdr.said  # key state updated so event was validated

        # Create rotation event
        # get current keys as verfers and next digests as digers
        sith = nxtsith  # rotate so nxtsith is now current sith and need new nextsith
        #  2 of first 3 and 1 of last 2
        nxtsith = [["1/2", "1/2", "1/2"],["1/1", "1/1"]]
        verfers, digers = mgr.rotate(pre=pre, ncount=5, temp=True)

        srdr = eventing.rotate(pre=kvr.prefixer.qb64,
                               keys=[verfer.qb64 for verfer in verfers],
                               isith=sith,
                               dig=kvr.serder.said,
                               nsith=nxtsith,
                               ndigs=[diger.qb64 for diger in digers],
                               sn=kvr.sn+1,
                               data=[])

        sigers = mgr.sign(ser=srdr.raw, verfers=verfers)

        msg = bytearray(srdr.raw)
        counter = core.Counter(core.Codens.ControllerIdxSigs, count=2,
                               version=kering.Vrsn_1_0)
        msg.extend(counter.qb64b)
        msg.extend(sigers[0].qb64b)
        msg.extend(sigers[3].qb64b)

        # apply msg to Kevery
        psr.parse(ims=bytearray(msg), kvy=kvy)
        # kvy.process(ims=bytearray(msg))  # process local copy of msg
        assert kvr.serder.said != srdr.said  # key state not updated

        time.sleep(0.001)
        # process escrow
        kvy.processEscrowPartialSigs()
        assert kvr.serder.said != srdr.said  # key state not updated

        msg = bytearray(srdr.raw)
        counter = core.Counter(core.Codens.ControllerIdxSigs, version=kering.Vrsn_1_0)
        msg.extend(counter.qb64b)
        msg.extend(sigers[1].qb64b)

        # apply msg to Kevery
        psr.parse(ims=bytearray(msg), kvy=kvy)
        # kvy.process(ims=bytearray(msg))  # process local copy of msg
        assert kvr.serder.said != srdr.said  # key state not updated

        # get DTS set by escrow date time stamp on event
        edater = kvy.db.dtss.get(keys=dbing.dgKey(pre, srdr.saidb))

        time.sleep(0.001)
        # process escrow
        kvy.processEscrowPartialSigs()
        assert kvr.serder.said == srdr.said  # key state updated

        # get DTS set by first seen event acceptance date time stamp
        adater = kvy.db.dtss.get(keys=dbing.dgKey(pre, srdr.saidb))
        # ensure accept time is later than escrow time, default timedelta is zero
        assert (adater.datetime - edater.datetime) > datetime.timedelta()

        # get first seen
        fsdig = kvy.db.fels.getOn(keys=pre, on=3)
        assert fsdig == srdr.saidb.decode("utf-8")

    assert not os.path.exists(ks.path)
    assert not os.path.exists(db.path)

    """End Test"""


def test_missing_delegator_escrow():
    """
    Test missing delegator escrow

    bod is the delegator
    del is the delegate
    wat is the watcher
    """

    bobSalt = core.Salter(raw=b'0123456789abcdef').qb64
    delSalt = core.Salter(raw=b'abcdef0123456789').qb64
    watSalt = core.Salter(raw=b'wxyzabcdefghijkl').qb64

    psr = parsing.Parser(version=Vrsn_1_0)

    with (basing.openDB(name="bob") as bobDB,
          keeping.openKS(name="bob") as bobKS,
          basing.openDB(name="del") as delDB,
          keeping.openKS(name="del") as delKS,
          basing.openDB(name="wat") as watDB, \
          keeping.openKS(name="wat") as watKS          ):

        # Init key pair managers
        bobMgr = keeping.Manager(ks=bobKS, salt=bobSalt)
        delMgr = keeping.Manager(ks=delKS, salt=delSalt)
        watMgr = keeping.Manager(ks=watKS, salt=watSalt)

        # Init Keverys
        bobKvy = eventing.Kevery(db=bobDB)
        delKvy = eventing.Kevery(db=delDB)
        watKvy = eventing.Kevery(db=watDB)

        # Setup Wat with own inception event
        verfers, digers = watMgr.incept(stem='wat', temp=True)  # algo default salty and rooted

        watSrdr = eventing.incept(keys=[verfer.qb64 for verfer in verfers],
                                  ndigs=[diger.qb64 for diger in digers],
                                  code=coring.MtrDex.Blake3_256)

        watPre = watSrdr.pre
        watMgr.move(old=verfers[0].qb64, new=watPre)  # move key pair label to prefix
        # Setup wat's prefixes so wat's KEL will be Kever.locallyOwned()
        watDB.prefixes.add(watPre)
        assert watPre in watDB.prefixes
        # setup wat's on kel
        sigers = watMgr.sign(ser=watSrdr.raw, verfers=verfers)
        msg = bytearray(watSrdr.raw)
        counter = core.Counter(core.Codens.ControllerIdxSigs,
                                 count=len(sigers), version=kering.Vrsn_1_0)
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)
        watIcpMsg = msg  # save for later

        # apply msg to wats's Kevery
        psr.parse(ims=bytearray(watIcpMsg), kvy=watKvy, local=True)
        watK = watKvy.kevers[watPre]
        assert watK.prefixer.qb64 == watPre
        assert watK.serder.said == watSrdr.said

        # Setup Bob with own inception event
        verfers, digers = bobMgr.incept(stem='bob', temp=True) # algo default salty and rooted
        bobSrdr = eventing.incept(keys=[verfer.qb64 for verfer in verfers],
                                  ndigs=[diger.qb64 for diger in digers],
                                  code=coring.MtrDex.Blake3_256)

        bobPre = bobSrdr.pre
        bobMgr.move(old=verfers[0].qb64, new=bobPre)  # move key pair label to prefix
        # Setup Bob's prefixes so bob's KEL will be Kever.locallyOwned() and
        # Del's KEL will be Kever.locallyDelegated()
        bobDB.prefixes.add(bobPre)
        assert bobPre in bobDB.prefixes

        sigers = bobMgr.sign(ser=bobSrdr.raw, verfers=verfers)
        msg = bytearray(bobSrdr.raw)
        counter = core.Counter(core.Codens.ControllerIdxSigs,
                                 count=len(sigers), version=kering.Vrsn_1_0)
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        bobIcpMsg = msg  # save for later

        # apply msg to bob's Kevery
        psr.parse(ims=bytearray(bobIcpMsg), kvy=bobKvy, local=True)
        bobK = bobKvy.kevers[bobPre]
        assert bobK.prefixer.qb64 == bobPre
        assert bobK.serder.said == bobSrdr.said
        assert bobK.sn == 0

        # apply msg to del's Kevery so he knows about the AID
        psr.parse(ims=bytearray(bobIcpMsg), kvy=delKvy, local=True)
        assert bobK.prefixer.qb64 in delKvy.kevers
        delBobK = bobKvy.kevers[bobPre]  # bobs kever in dels kevery
        assert delBobK.sn == 0

        # Setup Del's inception event assuming that Bob's next event will be
        # an ixn delegating event
        verfers, digers = delMgr.incept(stem='del', temp=True)  # algo default salty and rooted
        delSrdr = eventing.delcept(keys=[verfer.qb64 for verfer in verfers],
                                   delpre=bobPre,
                                   ndigs=[diger.qb64 for diger in digers])

        delPre = delSrdr.pre
        delMgr.move(old=verfers[0].qb64, new=delPre)  # move key pair label to prefix
        # Setup Del's prefixes so Del's KEL will be Kever.locallyOwned()
        delDB.prefixes.add(delPre)
        assert delPre in delDB.prefixes

        # Now create delegating event for Bob
        seal = eventing.SealEvent(i=delPre,
                                  s=delSrdr.ked["s"],
                                  d=delSrdr.said)
        bobSrdr = eventing.interact(pre=bobK.prefixer.qb64,
                                    dig=bobK.serder.said,
                                    sn=bobK.sn+1,
                                    data=[seal._asdict()])

        sigers = bobMgr.sign(ser=bobSrdr.raw, verfers=bobK.verfers)

        msg = bytearray(bobSrdr.raw)
        counter = core.Counter(core.Codens.ControllerIdxSigs,
                                 count=len(sigers), version=kering.Vrsn_1_0)
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)
        bobIxnMsg1 = msg  # delegating event with attachments

        # apply msg to bob's Kevery
        psr.parse(ims=bytearray(bobIxnMsg1), kvy=bobKvy, local=True)
        assert bobK.serder.said == bobSrdr.said  # key state updated so event was validated
        assert bobK.sn == 1

        # now create Del's delegated inception event msg
        sigers = delMgr.sign(ser=delSrdr.raw, verfers=verfers)

        msg = bytearray(delSrdr.raw)
        counter = core.Counter(core.Codens.ControllerIdxSigs,
                                 count=len(sigers), version=kering.Vrsn_1_0)
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)
        counter = core.Counter(core.Codens.SealSourceCouples,
                                     count=1, version=kering.Vrsn_1_0)
        msg.extend(counter.qb64b)
        seqner = coring.Seqner(sn=bobK.sn)
        msg.extend(seqner.qb64b)
        msg.extend(bobSrdr.saidb)
        delIcpMsg = msg

        # apply Del's delegated inception event message to bob's Kevery
        # because the attachment includes valid source seal then the Delegables
        # escrow is bypassed and is validated and shows up in AES
        psr.parse(ims=bytearray(delIcpMsg), kvy=bobKvy, local=True)
        # bobKvy.process(ims=bytearray(msg))  # process local copy of msg
        assert delPre in bobKvy.kevers  # successfully validated
        bobDelK = bobKvy.kevers[delPre]  # delK in bobs kevery
        assert bobDelK.delegated
        assert bobDelK.serder.said == delSrdr.said  # key state updated so event was validated
        result = bobKvy.db.aess.get(keys=(delPre, delSrdr.said))
        assert result is not None
        rseqner, rsaider = result
        assert rseqner.qb64b == seqner.qb64b
        assert rsaider.qb64b == bobSrdr.saidb

        # apply Del's inception msg to Del's Kevery
        # Because locallyOwned by delegate event does not validate delegation
        # and ignores the attached source seal
        psr.parse(ims=bytearray(delIcpMsg), kvy=delKvy, local=True)
        assert delPre in delKvy.kevers
        delK = delKvy.kevers[delPre]
        # no AES entry for del's own delegated event when locallyOwned
        assert not delKvy.db.aess.get(keys=(delPre, delSrdr.said))

        # apply Del's delegated inception event message to wats's Kevery as remote
        # because the attachment includes valid source seal but wat does not
        # yet have Bob's delegating event entry. The event goes into partial
        # delegated event escrow
        psr.parse(ims=bytearray(delIcpMsg), kvy=watKvy, local=False)
        assert not bobPre in watKvy.kevers
        assert not delPre in watKvy.kevers
        escrows = watKvy.db.pdes.getOn(keys=delPre, on=delSrdr.sn)
        assert len(escrows) == 1
        assert escrows[0] == delSrdr.said  # escrow entry for event

        # Now apply Bob's incept to wat's kvy and process escrow
        psr.parse(ims=bytearray(bobIcpMsg), kvy=watKvy, local=False)
        assert bobPre in watKvy.kevers
        watBobK = watKvy.kevers[bobPre]
        assert watBobK.sn == 0
        watKvy.processEscrows()
        assert not delPre in watKvy.kevers
        escrows = watKvy.db.pdes.getOn(keys=delPre, on=delSrdr.sn)
        assert len(escrows) == 1
        assert escrows[0] == delSrdr.said  # escrow entry for event

        # Now apply Bob's ixn to wat's kvy and process escrow
        psr.parse(ims=bytearray(bobIxnMsg1), kvy=watKvy, local=False)
        watKvy.processEscrows()
        escrows = watKvy.db.pdes.getOn(keys=delPre, on=delSrdr.sn)
        assert len(escrows) == 0
        assert watBobK.sn == 1

        assert delPre in watKvy.kevers  # successfully validated
        watDelK = watKvy.kevers[delPre]  # delK in wats kevery
        assert watDelK.delegated
        assert watDelK.serder.said == delSrdr.said  # key state updated so event was validated
        result = watKvy.db.aess.get(keys=(delPre, delSrdr.said))
        assert result is not None
        rseqner, rsaider = result
        assert rseqner.qb64b == seqner.qb64b
        assert rsaider.qb64b == bobSrdr.saidb


        # Setup Del rotation event
        verfers, digers = delMgr.rotate(pre=delPre, temp=True)

        delSrdr = eventing.deltate(pre=bobDelK.prefixer.qb64,
                                   keys=[verfer.qb64 for verfer in verfers],
                                   dig=bobDelK.serder.said,
                                   sn=bobDelK.sn+1,
                                   ndigs=[diger.qb64 for diger in digers])

        # Now create delegating interaction event
        seal = eventing.SealEvent(i=bobDelK.prefixer.qb64,
                                  s=delSrdr.ked["s"],
                                  d=delSrdr.said)
        bobSrdr = eventing.interact(pre=bobK.prefixer.qb64,
                                    dig=bobK.serder.said,
                                    sn=bobK.sn+1,
                                    data=[seal._asdict()])

        sigers = bobMgr.sign(ser=bobSrdr.raw, verfers=bobK.verfers)

        msg = bytearray(bobSrdr.raw)
        counter = core.Counter(core.Codens.ControllerIdxSigs,
                                 count=len(sigers), version=kering.Vrsn_1_0)
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        bobIxnMsg2 = msg

        # apply bobs IXN msg to bob's Kevery
        psr.parse(ims=bytearray(bobIxnMsg2), kvy=bobKvy, local=True)
        assert bobK.serder.said == bobSrdr.said  # key state updated so event was validated
        assert bobK.sn == 2

        # apply msg to del's Kevery
        psr.parse(ims=bytearray(bobIxnMsg2), kvy=delKvy, local=True)
        assert delBobK.serder.said == bobSrdr.said
        assert delBobK.sn == 2

        # apply msg to wat's Kevery
        psr.parse(ims=bytearray(bobIxnMsg2), kvy=watKvy, local=True)
        assert watBobK.serder.said == bobSrdr.said
        assert watBobK.sn == 2

        # now create msg from Del's delegated rotation event
        sigers = delMgr.sign(ser=delSrdr.raw, verfers=verfers)
        msg = bytearray(delSrdr.raw)
        counter = core.Counter(core.Codens.ControllerIdxSigs,
                                 count=len(sigers), version=kering.Vrsn_1_0)
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)
        counter = core.Counter(core.Codens.SealSourceCouples,
                                     count=1, version=kering.Vrsn_1_0)
        msg.extend(counter.qb64b)
        seqner = coring.Seqner(sn=bobK.sn)
        msg.extend(seqner.qb64b)
        msg.extend(bobSrdr.saidb)

        delRotMsg = msg

        # apply Del's delegated Rotation event message to del's Kevery
        psr.parse(ims=bytearray(delRotMsg), kvy=delKvy, local=True)
        assert delK.delegated
        assert delK.serder.said == delSrdr.said
        assert not delKvy.db.aess.get(keys=(delPre, delSrdr.said))

        # apply Del's delegated Rotation event message to bob's Kevery
        psr.parse(ims=bytearray(delRotMsg), kvy=bobKvy, local=True)
        assert bobDelK.delegated
        assert bobDelK.serder.said == delSrdr.said  # key state updated so event was validated
        result = bobKvy.db.aess.get(keys=(delPre, delSrdr.said))
        assert result is not None
        rseqner, rsaider = result
        assert rseqner.qb64b == seqner.qb64b
        assert rsaider.qb64b == bobSrdr.saidb

        # apply Del's delegated Rotation event message to wats's Kevery
        psr.parse(ims=bytearray(delRotMsg), kvy=watKvy, local=True)
        assert watDelK.delegated
        assert watDelK.serder.said == delSrdr.said  # key state updated so event was validated
        result = watKvy.db.aess.get(keys=(delPre, delSrdr.said))
        assert result is not None
        rseqner, rsaider = result
        assert rseqner.qb64b == seqner.qb64b
        assert rsaider.qb64b == bobSrdr.saidb



    assert not os.path.exists(delKS.path)
    assert not os.path.exists(delDB.path)
    assert not os.path.exists(bobKS.path)
    assert not os.path.exists(bobDB.path)

    """End Test"""


def test_misfit_escrow():
    """
    Test misfit escrow

    """
    salt = core.Salter(raw=b'0123456789abcdef').qb64
    psr = parsing.Parser(version=Vrsn_1_0)

    # init event DB and keep DB
    with basing.openDB(name="misfit", temp=True) as db, keeping.openKS(name="misfit") as ks:
        # Init key pair manager
        mgr = keeping.Manager(ks=ks, salt=salt)

        # Init Kevery with event DB
        kvy = eventing.Kevery(db=db)

        # Create inception event for a locally owned AID
        verfers, digers = mgr.incept(stem='mis', temp=True)
        srdr = eventing.incept(keys=[verfer.qb64 for verfer in verfers],
                               ndigs=[diger.qb64 for diger in digers],
                               code=coring.MtrDex.Blake3_256)

        pre = srdr.pre
        mgr.move(old=verfers[0].qb64, new=pre)  # move key pair label to prefix

        # Mark prefix as locally owned so Kever.locallyOwned() is True
        db.prefixes.add(pre)
        assert pre in db.prefixes

        sigers = mgr.sign(ser=srdr.raw, verfers=verfers)
        msg = bytearray(srdr.raw)
        counter = core.Counter(core.Codens.ControllerIdxSigs,
                               count=len(sigers), version=kering.Vrsn_1_0)
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        # Apply inception as local so event is accepted and Kever exists
        psr.parse(ims=bytearray(msg), kvy=kvy, local=True)
        assert pre in kvy.kevers
        kever = kvy.kevers[pre]

        # Build a valid interaction event for the same AID
        srdr2 = eventing.interact(pre=kever.prefixer.qb64,
                                  dig=kever.serder.said,
                                  sn=kever.sn + 1,
                                  data=[])

        sigers2 = mgr.sign(ser=srdr2.raw, verfers=kever.verfers)
        msg2 = bytearray(srdr2.raw)
        counter = core.Counter(core.Codens.ControllerIdxSigs,
                               count=len(sigers2), version=kering.Vrsn_1_0)
        msg2.extend(counter.qb64b)
        for siger in sigers2:
            msg2.extend(siger.qb64b)

        # Parse the second event as non-local; this should trigger misfit escrow.
        # Parser swallows ValidationError subclasses (including MisfitEventSourceError),
        # so we assert via escrow side effects instead of expecting the exception.
        psr.parse(ims=bytearray(msg2), kvy=kvy, local=False)

        dgkey = dbing.dgKey(srdr2.preb, srdr2.saidb)

        # Misfit index contains the event SAID
        assert db.misfits.cnt(keys=(srdr2.pre, srdr2.snh)) == 1
        misfit_vals = db.misfits.get(keys=(srdr2.pre, srdr2.snh))
        assert misfit_vals == [srdr2.said]

        # Event and signatures are stored in common escrow DBs
        stored = db.evts.get(keys=(srdr2.preb, srdr2.saidb))
        assert stored is not None
        assert stored.saidb == srdr2.saidb

        sigs = db.sigs.get(keys=(srdr2.preb, srdr2.saidb))
        assert sigs is not None
        assert [siger.qb64b for siger in sigs] == [siger.qb64b for siger in sigers2]

        # Datetime stamp and event source record are stored
        dater = db.dtss.get(keys=dgkey)
        assert dater is not None

        esr = db.esrs.get(keys=dgkey)
        assert esr is not None
        assert not esr.local


def test_misfit_escrow_delegated():
    """
    Test misfit escrow for a delegated event with attached source seal.

    Remote (local=False) delegated inception for a delegate whose delegator
    is local should be escrowed as a misfit and recorded in .udes.
    """
    salt = core.Salter(raw=b'fedcba9876543210').qb64
    psr = parsing.Parser(version=Vrsn_1_0)

    with basing.openDB(name="misfit-del", temp=True) as db, keeping.openKS(name="misfit-del") as ks:
        mgr = keeping.Manager(ks=ks, salt=salt)
        kvy = eventing.Kevery(db=db)

        # Create a local delegator AID and mark it as local
        delg_verfers, delg_digers = mgr.incept(stem='delg', temp=True)
        delg_srdr = eventing.incept(keys=[verfer.qb64 for verfer in delg_verfers],
                                    ndigs=[diger.qb64 for diger in delg_digers],
                                    code=coring.MtrDex.Blake3_256)
        delg_pre = delg_srdr.pre
        mgr.move(old=delg_verfers[0].qb64, new=delg_pre)
        db.prefixes.add(delg_pre)
        assert delg_pre in db.prefixes

        # Create delegated inception event (dip) for a new delegatee AID
        del_verfers, del_digers = mgr.incept(stem='del', temp=True)
        dip_srdr = eventing.delcept(keys=[verfer.qb64 for verfer in del_verfers],
                                    delpre=delg_pre,
                                    ndigs=[diger.qb64 for diger in del_digers])
        del_pre = dip_srdr.pre
        mgr.move(old=del_verfers[0].qb64, new=del_pre)

        # Build message: delegated inception with controller sigs and a source seal
        sigers = mgr.sign(ser=dip_srdr.raw, verfers=del_verfers)
        msg = bytearray(dip_srdr.raw)
        counter = core.Counter(core.Codens.ControllerIdxSigs,
                               count=len(sigers), version=kering.Vrsn_1_0)
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        # Attach a SealSourceCouples group for the delegator event
        seqner = coring.Seqner(sn=0)
        saider = coring.Saider(qb64=delg_srdr.said)
        counter = core.Counter(core.Codens.SealSourceCouples,
                               count=1, version=kering.Vrsn_1_0)
        msg.extend(counter.qb64b)
        msg.extend(seqner.qb64b)
        msg.extend(saider.qb64b)

        # Parse as non-local; this should trigger delegated misfit escrow.
        # Parser swallows ValidationError subclasses (including MisfitEventSourceError),
        # so we assert via escrow side effects instead of expecting the exception.
        psr.parse(ims=bytearray(msg), kvy=kvy, local=False)

        dgkey = dbing.dgKey(dip_srdr.preb, dip_srdr.saidb)

        # Misfit index entry for delegated event
        assert db.misfits.cnt(keys=(dip_srdr.pre, dip_srdr.snh)) == 1

        # Event and signatures stored
        stored = db.evts.get(keys=(dip_srdr.preb, dip_srdr.saidb))
        assert stored is not None
        assert stored.saidb == dip_srdr.saidb

        sigs = db.sigs.get(keys=(dip_srdr.preb, dip_srdr.saidb))
        assert sigs is not None
        assert [siger.qb64b for siger in sigs] == [siger.qb64b for siger in sigers]

        # .udes contains (Number, Saider) tuple for the delegated misfit
        uval = db.udes.get(keys=dgkey)
        assert uval is not None
        num, src = uval
        assert isinstance(num, coring.Number)
        assert num.num == seqner.sn
        assert src.qb64 == delg_srdr.said

    """End Test"""


def test_misfit_escrow_valSigsWigsDel():
    """
    Unit-style test that calls Kever.valSigsWigsDel with local=False for a
    locally owned AID to trigger misfit escrow.
    """
    salt = core.Salter(raw=b'1234567890abcdef').qb64

    with basing.openDB(name="misfit-unit", temp=True) as db, keeping.openKS(name="misfit-unit") as ks:
        mgr = keeping.Manager(ks=ks, salt=salt)
        kvy = eventing.Kevery(db=db)

        # Create and accept a local inception event
        verfers, digers = mgr.incept(stem='unit', temp=True)
        srdr = eventing.incept(keys=[verfer.qb64 for verfer in verfers],
                               ndigs=[diger.qb64 for diger in digers],
                               code=coring.MtrDex.Blake3_256)
        pre = srdr.pre
        mgr.move(old=verfers[0].qb64, new=pre)
        db.prefixes.add(pre)
        assert pre in db.prefixes

        sigers = mgr.sign(ser=srdr.raw, verfers=verfers)
        msg = bytearray(srdr.raw)
        counter = core.Counter(core.Codens.ControllerIdxSigs,
                               count=len(sigers), version=kering.Vrsn_1_0)
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        psr = parsing.Parser(version=Vrsn_1_0)
        psr.parse(ims=bytearray(msg), kvy=kvy, local=True)
        assert pre in kvy.kevers
        kever = kvy.kevers[pre]

        # Build a valid interaction event and its signatures
        ixn = eventing.interact(pre=kever.prefixer.qb64,
                                dig=kever.serder.said,
                                sn=kever.sn + 1,
                                data=[])
        ixn_sigers = mgr.sign(ser=ixn.raw, verfers=kever.verfers)

        tholder = kever.tholder
        toader = kever.toader
        wits = kever.wits
        wigers = []

        # Call valSigsWigsDel directly with local=False to force misfit escrow
        with pytest.raises(kering.MisfitEventSourceError):
            kever.valSigsWigsDel(serder=ixn,
                                 sigers=ixn_sigers,
                                 verfers=kever.verfers,
                                 tholder=tholder,
                                 wigers=wigers,
                                 toader=toader,
                                 wits=wits,
                                 delnum=None,
                                 deldiger=None,
                                 eager=False,
                                 local=False)

        dgkey = dbing.dgKey(ixn.preb, ixn.saidb)

        # Misfit and common escrow DBs should have been updated
        assert db.misfits.cnt(keys=(ixn.pre, ixn.snh)) == 1
        assert db.evts.get(keys=(ixn.preb, ixn.saidb)) is not None
        assert db.sigs.get(keys=(ixn.preb, ixn.saidb)) is not None
        assert db.dtss.get(keys=dgkey) is not None
        esr = db.esrs.get(keys=dgkey)
        assert esr is not None
        assert not esr.local


def test_misfit_escrow_kevery():
    """
    Kevery-level test that calls Kevery.escrowMFEvent directly and asserts that
    misfit escrow side effects are written to the DB (misfits, evts, sigs, dtss,
    esrs, and .udes for delegated-like metadata).
    """
    salt = core.Salter(raw=b'abcdef0123456789').qb64

    with basing.openDB(name="misfit-kvy", temp=True) as db, keeping.openKS(name="misfit-kvy") as ks:
        mgr = keeping.Manager(ks=ks, salt=salt)
        kvy = eventing.Kevery(db=db)

        # Create a simple inception event and its signatures
        verfers, digers = mgr.incept(stem='kvy', temp=True)
        srdr = eventing.incept(keys=[verfer.qb64 for verfer in verfers],
                               ndigs=[diger.qb64 for diger in digers],
                               code=coring.MtrDex.Blake3_256)

        sigers = mgr.sign(ser=srdr.raw, verfers=verfers)

        # Delegation-like seal metadata for .udes: use sn=0 and the event's own digest
        delnum = coring.Number(num=0)
        diger = coring.Diger(qb64=srdr.said)

        # Call Kevery.escrowMFEvent directly with local=False to simulate a misfit
        kvy.escrowMFEvent(serder=srdr,
                          sigers=sigers,
                          wigers=None,
                          delnum=delnum,
                          diger=diger,
                          local=False)

        dgkey = dbing.dgKey(srdr.preb, srdr.saidb)

        # Misfit index is populated
        assert db.misfits.cnt(keys=(srdr.pre, srdr.snh)) == 1
        misfit_vals = db.misfits.get(keys=(srdr.pre, srdr.snh))
        assert misfit_vals == [srdr.said]

        # Core escrow tables populated
        stored = db.evts.get(keys=(srdr.preb, srdr.saidb))
        assert stored is not None
        assert stored.saidb == srdr.saidb

        sigs = db.sigs.get(keys=dgkey)
        assert sigs is not None
        assert [siger.qb64b for siger in sigs] == [siger.qb64b for siger in sigers]

        dater = db.dtss.get(keys=dgkey)
        assert dater is not None

        esr = db.esrs.get(keys=dgkey)
        assert esr is not None
        assert not esr.local

        # .udes contains the (Number, Diger) tuple written by Kevery.escrowMFEvent
        uval = db.udes.get(keys=dgkey)
        assert uval is not None
        num, src = uval
        assert isinstance(num, coring.Number)
        assert num.num == delnum.num
        assert src.qb64 == diger.qb64


def test_delegated_partial_signed_escrow_udes():
    """
    Test delegated partial-signature escrow writes (Number, Diger) into .udes.

    We create a delegated inception (dip) with a SealSourceCouples attachment
    referencing a local delegator event but deliberately under-sign it so that
    it is escrowed via Kever.escrowPSEvent (PSE escrow), not accepted.
    """
    salt = core.Salter(raw=b'567890abcdef1234').qb64
    psr = parsing.Parser(version=Vrsn_1_0)

    with basing.openDB(name="pse-del", temp=True) as db, keeping.openKS(name="pse-del") as ks:
        mgr = keeping.Manager(ks=ks, salt=salt)
        kvy = eventing.Kevery(db=db)

        # Create a local delegator AID and mark it as local
        delg_verfers, delg_digers = mgr.incept(stem='pse-delg', temp=True)
        delg_srdr = eventing.incept(keys=[verfer.qb64 for verfer in delg_verfers],
                                    ndigs=[diger.qb64 for diger in delg_digers],
                                    code=coring.MtrDex.Blake3_256)
        delg_pre = delg_srdr.pre
        mgr.move(old=delg_verfers[0].qb64, new=delg_pre)
        db.prefixes.add(delg_pre)
        assert delg_pre in db.prefixes

        # Accept delegator inception locally so its KEL exists
        sigers_delg = mgr.sign(ser=delg_srdr.raw, verfers=delg_verfers)
        msg = bytearray(delg_srdr.raw)
        counter = core.Counter(core.Codens.ControllerIdxSigs,
                               count=len(sigers_delg), version=kering.Vrsn_1_0)
        msg.extend(counter.qb64b)
        for siger in sigers_delg:
            msg.extend(siger.qb64b)
        psr.parse(ims=bytearray(msg), kvy=kvy, local=True)
        assert delg_pre in kvy.kevers
        delg_kever = kvy.kevers[delg_pre]

        # Create delegated inception event (dip) for a new delegatee AID, with multi-sig threshold
        del_verfers, del_digers = mgr.incept(icount=2, ncount=2, stem='pse-del', temp=True)
        dip_srdr = eventing.delcept(keys=[verfer.qb64 for verfer in del_verfers],
                                    delpre=delg_pre,
                                    isith='2',
                                    nsith='2',
                                    ndigs=[diger.qb64 for diger in del_digers])
        del_pre = dip_srdr.pre
        mgr.move(old=del_verfers[0].qb64, new=del_pre)

        # Build message: delegated inception with only one controller sig (under-signed)
        sigers = mgr.sign(ser=dip_srdr.raw, verfers=del_verfers)
        assert len(sigers) >= 2
        msg = bytearray(dip_srdr.raw)
        counter = core.Counter(core.Codens.ControllerIdxSigs,
                               count=1, version=kering.Vrsn_1_0)
        msg.extend(counter.qb64b)
        msg.extend(sigers[0].qb64b)

        # Attach a SealSourceCouples group for the delegator event
        seqner = coring.Seqner(sn=delg_kever.sn)
        saider = coring.Saider(qb64=delg_srdr.said)
        counter = core.Counter(core.Codens.SealSourceCouples,
                               count=1, version=kering.Vrsn_1_0)
        msg.extend(counter.qb64b)
        msg.extend(seqner.qb64b)
        msg.extend(saider.qb64b)

        # Parse as local; this should not be a misfit but a partial-signature escrow.
        # Parser swallows MissingSignatureError, so assert via escrow side effects.
        psr.parse(ims=bytearray(msg), kvy=kvy, local=True)

        dgkey = dbing.dgKey(dip_srdr.preb, dip_srdr.saidb)

        # PSE index contains the event SAID
        escrows = db.pses.getOn(keys=dip_srdr.pre, on=dip_srdr.sn)
        assert len(escrows) == 1
        assert escrows[0].encode("utf-8") == dip_srdr.saidb

        # .udes contains (Number, Saider) tuple for the delegated PSE escrow
        uval = db.udes.get(keys=dgkey)
        assert uval is not None
        num, src = uval
        assert isinstance(num, coring.Number)
        assert num.num == seqner.sn
        assert src.qb64 == delg_srdr.said


def test_out_of_order_escrow():
    """
    Test out of order escrow

    """
    salt = core.Salter(raw=b'0123456789abcdef').qb64  # init wes Salter
    psr = parsing.Parser(version=Vrsn_1_0)

    # init event DB and keep DB
    with basing.openDB(name="edy", temp=True) as db, keeping.openKS(name="edy") as ks:
        # Init key pair manager
        mgr = keeping.Manager(ks=ks, salt=salt)

        # Init Kevery with event DB
        kvy = eventing.Kevery(db=db)

        # create inception event with 3 keys each in incept and next sets
        # defaults are algo salty and rooted
        sith = ["1/2", "1/2", "1/2"]  #  2 of 3 but with weighted threshold
        nxtsith = ["1/2", "1/2", "1/2"]
        verfers, digers = mgr.incept(icount=3, ncount=3, stem='wes', temp=True)

        srdr = eventing.incept(keys=[verfer.qb64 for verfer in verfers],
                               isith=sith,
                               nsith=nxtsith,
                               ndigs=[diger.qb64 for diger in digers],
                               code=coring.MtrDex.Blake3_256)

        pre = srdr.ked["i"]
        icpdig = srdr.said

        mgr.move(old=verfers[0].qb64, new=pre)  # move key pair label to prefix

        sigers = mgr.sign(ser=srdr.raw, verfers=verfers)

        msg = bytearray(srdr.raw)
        counter = core.Counter(core.Codens.ControllerIdxSigs,
                                 count=len(sigers), version=kering.Vrsn_1_0)
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        icpmsg = bytearray(msg)  # save copy for later

        # create interaction event
        srdr = eventing.interact(pre=pre, dig=icpdig, sn=1, data=[])
        ixndig = srdr.said
        sigers = mgr.sign(ser=srdr.raw, verfers=verfers)

        ixnRawmsg = bytearray(srdr.raw)
        counter = core.Counter(core.Codens.ControllerIdxSigs,
                                 count=len(sigers), version=kering.Vrsn_1_0)
        ixnRawmsg.extend(counter.qb64b)
        for siger in sigers:
            ixnRawmsg.extend(siger.qb64b)

        ixnmsg = bytearray(ixnRawmsg)  # save copy for later

        # Create rotation event
        # get current keys as verfers and next digests as digers
        sith = nxtsith  # rotate so nxtsith is now current sith and need new nextsith
        #  2 of first 3 and 1 of last 2
        nxtsith = [["1/2", "1/2", "1/2"],["1/1", "1/1"]]
        verfers, digers = mgr.rotate(pre=pre, ncount=5, temp=True)

        srdr = eventing.rotate(pre=pre,
                               keys=[verfer.qb64 for verfer in verfers],
                               isith=sith,
                               dig=ixndig,
                               nsith=nxtsith,
                               ndigs=[diger.qb64 for diger in digers],
                               sn=2,
                               data=[])

        rotdig = srdr.said

        sigers = mgr.sign(ser=srdr.raw, verfers=verfers)

        msg = bytearray(srdr.raw)
        counter = core.Counter(core.Codens.ControllerIdxSigs,
                                 count=len(sigers), version=kering.Vrsn_1_0)
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        rotmsg = bytearray(msg)  # save copy for later

        # apply rotation msg to Kevery to process
        psr.parse(ims=bytearray(rotmsg), kvy=kvy)
        # kvy.process(ims=bytearray(rotmsg))  # process local copy of msg
        assert pre not in kvy.kevers  # event not accepted
        escrows = kvy.db.ooes.getOn(keys=pre, on=2)
        assert len(escrows) == 1
        assert escrows[0] == rotdig  #  escrow entry for event

        # verify Kevery process is idempotent to previously escrowed events
        psr.parse(ims=bytearray(rotmsg), kvy=kvy)
        # kvy.process(ims=bytearray(rotmsg))  # process local copy of msg
        assert pre not in kvy.kevers  # event not accepted
        escrows = kvy.db.ooes.getOn(keys=pre, on=2)
        assert len(escrows) == 1
        assert escrows[0] == rotdig #  escrow entry for event

        # verify Kevery process out of order escrow is idempotent to previously escrowed events
        # assuming not stale but nothing else has changed
        kvy.processEscrowOutOfOrders()
        assert pre not in kvy.kevers  # event not accepted
        escrows = kvy.db.ooes.getOn(keys=pre, on=2)
        assert len(escrows) == 1
        assert escrows[0] == rotdig   #  escrow entry for event

        # apply ixn msg to Kevery to process
        psr.parse(ims=bytearray(ixnmsg), kvy=kvy)
        # kvy.process(ims=bytearray(ixnmsg))  # process local copy of msg
        assert pre not in kvy.kevers  # event not accepted
        escrows = kvy.db.ooes.getOn(keys=pre, on=1)
        # assert len(escrows) == 1
        assert escrows[0] == ixndig   #  escrow entry for event

        # verify Kevery process is idempotent to previously escrowed events
        psr.parse(ims=bytearray(ixnmsg), kvy=kvy)
        # kvy.process(ims=bytearray(ixnmsg))  # process local copy of msg
        assert pre not in kvy.kevers  # event not accepted
        escrows = kvy.db.ooes.getOn(keys=pre, on=1)
        assert len(escrows) == 1     
        assert escrows[0] == ixndig #  escrow entry for event

        # verify Kevery process out of order escrow is idempotent to previously escrowed events
        # assuming not stale but nothing else has changed
        kvy.processEscrowOutOfOrders()
        assert pre not in kvy.kevers  # event not accepted
        escrows = kvy.db.ooes.getOn(keys=pre, on=1)
        assert len(escrows) == 1
        assert escrows[0] == ixndig    #  escrow entry for event

        # Process partials but stale escrow  set Timeout to 0
        kvy.TimeoutOOE = 0  # forces all escrows to be stale
        time.sleep(0.001)
        kvy.processEscrowOutOfOrders()
        assert pre not in kvy.kevers  # key state not updated
        escrows = kvy.db.ooes.getOn(keys=pre, on=1)
        assert len(escrows) == 0  # escrow gone
        escrows = kvy.db.ooes.getOn(keys=pre, on=2)
        assert len(escrows) == 0

        # Now reset timeout so not zero and rsend events to reload escrow
        kvy.TimeoutOOE = 3600
        
        # re-apply rotation msg to Kevery to process
        psr.parse(ims=bytearray(rotmsg), kvy=kvy)
        # kvy.process(ims=bytearray(rotmsg))  # process local copy of msg
        assert pre not in kvy.kevers  # event not accepted
        escrows = kvy.db.ooes.getOn(keys=pre, on=2)
        assert len(escrows) == 1
        assert escrows[0] == rotdig  #  escrow entry for event

        # re-apply ixn msg to Kevery to process
        psr.parse(ims=bytearray(ixnmsg), kvy=kvy)
        # kvy.process(ims=bytearray(ixnmsg))  # process local copy of msg
        assert pre not in kvy.kevers  # event not accepted
        escrows = kvy.db.ooes.getOn(keys=pre, on=1)
        assert len(escrows) == 1
        assert escrows[0] == ixndig  #  escrow entry for event
        # re-apply inception msg to Kevery to process
        psr.parse(ims=bytearray(icpmsg), kvy=kvy)
        # kvy.process(ims=bytearray(icpmsg))  # process local copy of msg
        assert pre in kvy.kevers  # event accepted
        kvr = kvy.kevers[pre]
        assert kvr.serder.said == icpdig  # key state updated so event was validated
        assert kvr.sn == 0  # key state successfully updated
        # verify escrows not changed
        escrows = kvy.db.ooes.getOn(keys=pre, on=2)
        assert len(escrows) == 1
        assert escrows[0] == rotdig  #  escrow entry for event
        escrows = kvy.db.ooes.getOn(keys=pre, on=1)
        assert len(escrows) == 1
        assert escrows[0] == ixndig  #  escrow entry for event

        # Process out of order escrow
        # assuming not stale but nothing else has changed
        kvy.processEscrowOutOfOrders()
        assert kvr.serder.said == rotdig  # key state updated so event was validated
        assert kvr.sn == 2  # key state successfully updated
        escrows = kvy.db.ooes.getOn(keys=pre, on=1)
        assert len(escrows) == 0  # escrow gone
        escrows = kvy.db.ooes.getOn(keys=pre, on=2)
        assert len(escrows) == 0


    assert not os.path.exists(ks.path)
    assert not os.path.exists(db.path)

    """End Test"""


def test_ooes_missing_db_entries_escrow_cleanup():
    """
    Test missing records (evt, sigs, dts) of out of
    order escrow cleanup 
    """

    salt = core.Salter(raw=b'0123456789abcdef').qb64
    psr = parsing.Parser(version=Vrsn_1_0)

    with basing.openDB(name="edy") as db, keeping.openKS(name="edy") as ks:
        mgr = keeping.Manager(ks=ks, salt=salt)
        kvy = eventing.Kevery(db=db)

        # create a simple 1-key inception 
        verfers, digers = mgr.incept(icount=1, ncount=1, stem='A', temp=True)

        icp = eventing.incept(
            keys=[verfers[0].qb64],
            isith="1",
            nsith="1",
            ndigs=[digers[0].qb64],
            code=coring.MtrDex.Blake3_256,
        )
        pre = icp.ked["i"]
        icpdig = icp.said
        mgr.move(old=verfers[0].qb64, new=pre)

        sigers = mgr.sign(ser=icp.raw, verfers=verfers)
        msg = bytearray(icp.raw)
        counter = core.Counter(core.Codens.ControllerIdxSigs,
                                count=len(sigers), version=kering.Vrsn_1_0)
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)
        icpmsg = msg

        # valid interaction event
        ixn = eventing.interact(pre=pre, dig=icpdig, sn=1, data=[])
        ixndig = ixn.said

        sigers = mgr.sign(ser=ixn.raw, verfers=verfers)
        msg = bytearray(ixn.raw)
        counter = core.Counter(core.Codens.ControllerIdxSigs,
                                count=len(sigers), version=kering.Vrsn_1_0)
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)
        ixnmsg = msg

        # apply interaction first → goes to OOES 
        psr.parse(ims=bytearray(ixnmsg), kvy=kvy)
        assert db.ooes.getOn(keys=pre, on=1) == [ixndig]

        # find dgkey for this escrowed event
        dgkey = dbing.dgKey(pre, ixndig)

        # missing DTS → OOES must remove entry
        db.dtss.rem(keys=dgkey)
        kvy.processEscrowOutOfOrders()
        assert db.ooes.getOn(keys=pre, on=1) == []  # cleaned up

        # reload interaction event into OOES
        psr.parse(ims=bytearray(ixnmsg), kvy=kvy)
        assert db.ooes.getOn(keys=pre, on=1) == [ixndig]

        # missing EVT → OOES must remove entry
        assert db.evts.rem(keys=(pre, ixndig)) == True
        kvy.processEscrowOutOfOrders()
        assert db.ooes.getOn(keys=pre, on=1) == []  # cleaned up

        # reload interaction event into OOES
        psr.parse(ims=bytearray(ixnmsg), kvy=kvy)
        assert db.ooes.getOn(keys=pre, on=1) == [ixndig]

        # missing SIGS → OOES must remove entry
        db.sigs.rem(keys=dgkey)
        kvy.processEscrowOutOfOrders()
        assert db.ooes.getOn(keys=pre, on=1) == []  # cleaned up

        # reload interaction event into OOES
        psr.parse(ims=bytearray(ixnmsg), kvy=kvy)
        assert db.ooes.getOn(keys=pre, on=1) == [ixndig]

        # apply inception msg
        psr.parse(ims=bytearray(icpmsg), kvy=kvy)
        assert pre in kvy.kevers
        kvr = kvy.kevers[pre]
        assert kvr.serder.said == icpdig
        assert kvr.sn == 0

        # process OOES
        kvy.processEscrowOutOfOrders()
        assert kvr.serder.said == ixndig  # key state updated so event was validated
        assert kvr.sn == 1  # key state successfully updated
        escrows = db.ooes.getOn(keys=pre, on=1)
        assert len(escrows) == 0

    """End Test"""


def test_unverified_receipt_escrow():
    """
    Test unverified receipt escrow

    """
    salt = core.Salter(raw=b'0123456789abcdef').qb64  # init Salter
    psr = parsing.Parser(version=Vrsn_1_0)

    # init event DB and keep DB
    with basing.openDB(name="edy") as db, keeping.openKS(name="edy") as ks:
        # Init key pair manager
        mgr = keeping.Manager(ks=ks, salt=salt)

        # Init Kevery with event DB
        kvy = eventing.Kevery(db=db)

        # create witness identifiers
        verfers, digers = mgr.incept(ncount=0, stem="wit0",
                                         transferable=False, temp=True)
        wit0Verfer = verfers[0]
        wit0pre = wit0Verfer.qb64

        verfers, digers = mgr.incept(ncount=0, stem="wit1",
                                         transferable=False, temp=True)
        wit1Verfer = verfers[0]
        wit1pre = wit1Verfer.qb64

        assert wit1pre != wit0pre
        assert wit1pre <  wit0pre  # means wit1 escrow will get serviced first

        # create inception event with 3 keys each in incept and next sets
        # defaults are algo salty and rooted
        sith = ["1/2", "1/2", "1/2"]  #  2 of 3 but with weighted threshold
        nxtsith = ["1/2", "1/2", "1/2"]
        verfers, digers = mgr.incept(icount=3, ncount=3, stem='edy', temp=True)

        srdr = eventing.incept(keys=[verfer.qb64 for verfer in verfers],
                               isith=sith,
                               nsith=nxtsith,
                               ndigs=[diger.qb64 for diger in digers],
                               code=coring.MtrDex.Blake3_256)

        pre = srdr.ked["i"]
        icpdig = srdr.said

        mgr.move(old=verfers[0].qb64, new=pre)  # move key pair label to prefix

        sigers = mgr.sign(ser=srdr.raw, verfers=verfers)

        msg = bytearray(srdr.raw)
        counter = core.Counter(core.Codens.ControllerIdxSigs,
                                 count=len(sigers), version=kering.Vrsn_1_0)
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        icpmsg = msg

        # create receipt(s) of inception message
        reserder = eventing.receipt(pre=pre, sn=0, said=srdr.said)
        # sign event not receipt with wit0
        wit0Cigar = mgr.sign(ser=srdr.raw, verfers=[wit0Verfer], indexed=False)[0]  # returns Cigar unindexed
        wit1Cigar = mgr.sign(ser=srdr.raw, verfers=[wit1Verfer], indexed=False)[0]  # returns Cigar unindexed

        recnt = core.Counter(core.Codens.NonTransReceiptCouples, count=2,
                             version=kering.Vrsn_1_0)

        msg = bytearray()
        msg.extend(reserder.raw)
        msg.extend(recnt.qb64b)
        msg.extend(wit0pre.encode("utf-8"))
        msg.extend(wit0Cigar.qb64b)
        msg.extend(wit1pre.encode("utf-8"))
        msg.extend(wit1Cigar.qb64b)

        rcticpmsg = msg

        # Process receipt by kvy
        psr.parse(ims=bytearray(rcticpmsg), kvy=kvy)
        # kvy.process(ims=bytearray(rcticpmsg))  # process local copy of msg
        assert pre not in kvy.kevers  # no events yet for pre
        escrows = kvy.db.ures.get(keys=(pre, coring.Number(num=0, code=coring.NumDex.Huge).qb64))  # so escrowed receipts
        assert len(escrows) == 2
        diger, prefixer, cigar = escrows[0]
        assert diger.qb64 == srdr.said
        assert prefixer.qb64 == wit0pre
        assert cigar.qb64 == wit0Cigar.qb64
        diger, prefixer, cigar = escrows[1]
        assert diger.qb64 == srdr.said
        assert prefixer.qb64 == wit1pre
        assert cigar.qb64 == wit1Cigar.qb64

        # create interaction event
        srdr = eventing.interact(pre=pre, dig=icpdig, sn=1, data=[])
        ixndig = srdr.said
        sigers = mgr.sign(ser=srdr.raw, verfers=verfers)

        msg = bytearray(srdr.raw)
        counter = core.Counter(core.Codens.ControllerIdxSigs,
                                 count=len(sigers), version=kering.Vrsn_1_0)
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        ixnmsg = msg

        # create receipt(s) of interaction message
        reserder = eventing.receipt(pre=pre, sn=1, said=srdr.said)
        # sign event not receipt with wit0
        wit0Cigar = mgr.sign(ser=srdr.raw, verfers=[wit0Verfer], indexed=False)[0]  # returns Cigar unindexed
        wit1Cigar = mgr.sign(ser=srdr.raw, verfers=[wit1Verfer], indexed=False)[0]  # returns Cigar unindexed

        recnt = core.Counter(core.Codens.NonTransReceiptCouples, count=2,
                             version=kering.Vrsn_1_0)

        msg = bytearray()
        msg.extend(reserder.raw)
        msg.extend(recnt.qb64b)
        msg.extend(wit0pre.encode("utf-8"))
        msg.extend(wit0Cigar.qb64b)
        msg.extend(wit1pre.encode("utf-8"))
        msg.extend(wit1Cigar.qb64b)

        rctixnmsg = msg

        # Process receipt by kvy
        psr.parse(ims=bytearray(rctixnmsg), kvy=kvy)
        # kvy.process(ims=bytearray(rctixnmsg))  # process local copy of msg
        assert pre not in kvy.kevers  # no events yet for pre
        escrows = kvy.db.ures.get(keys=(pre, coring.Number(num=1, code=coring.NumDex.Huge).qb64))  # so escrowed receipts
        assert len(escrows) == 2
        diger, prefixer, cigar = escrows[0]
        assert diger.qb64 == srdr.said
        assert prefixer.qb64 == wit0pre
        assert cigar.qb64 == wit0Cigar.qb64
        diger, prefixer, cigar = escrows[1]
        assert diger.qb64 == srdr.said
        assert prefixer.qb64 == wit1pre
        assert cigar.qb64 == wit1Cigar.qb64

        # Create rotation event
        # get current keys as verfers and next digests as digers
        verfers, digers = mgr.rotate(pre=pre, ncount=5, temp=True)
        sith = nxtsith  # rotate so nxtsith is now current sith and need new nextsith
        #  2 of first 3 and 1 of last 2
        nxtsith = [["1/2", "1/2", "1/2"],["1/1", "1/1"]]

        srdr = eventing.rotate(pre=pre,
                               keys=[verfer.qb64 for verfer in verfers],
                               isith=sith,
                               dig=ixndig,
                               nsith=nxtsith,
                               ndigs=[diger.qb64 for diger in digers],
                               sn=2,
                               data=[])

        rotdig = srdr.said

        sigers = mgr.sign(ser=srdr.raw, verfers=verfers)

        msg = bytearray(srdr.raw)
        counter = core.Counter(core.Codens.ControllerIdxSigs,
                                 count=len(sigers), version=kering.Vrsn_1_0)
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        rotmsg = msg

        # create receipt(s) of rotation message
        reserder = eventing.receipt(pre=pre, sn=2, said=srdr.said)
        # sign event not receipt with wit0
        wit0Cigar = mgr.sign(ser=srdr.raw, verfers=[wit0Verfer], indexed=False)[0]  # returns Cigar unindexed
        wit1Cigar = mgr.sign(ser=srdr.raw, verfers=[wit1Verfer], indexed=False)[0]  # returns Cigar unindexed

        recnt = core.Counter(core.Codens.NonTransReceiptCouples, count=2,
                             version=kering.Vrsn_1_0)

        msg = bytearray()
        msg.extend(reserder.raw)
        msg.extend(recnt.qb64b)
        msg.extend(wit0pre.encode("utf-8"))
        msg.extend(wit0Cigar.qb64b)
        msg.extend(wit1pre.encode("utf-8"))
        msg.extend(wit1Cigar.qb64b)

        rctrotmsg = msg

        # Process receipt by kvy
        psr.parse(ims=bytearray(rctrotmsg), kvy=kvy)
        assert pre not in kvy.kevers  # no events yet for pre
        escrows = kvy.db.ures.get(keys=(pre, coring.Number(num=2, code=coring.NumDex.Huge).qb64))  # so escrowed receipts
        assert len(escrows) == 2
        diger, prefixer, cigar = escrows[0]
        assert diger.qb64 == srdr.said
        assert prefixer.qb64 == wit0pre
        assert cigar.qb64 == wit0Cigar.qb64
        diger, prefixer, cigar = escrows[1]
        assert diger.qb64 == srdr.said
        assert prefixer.qb64 == wit1pre
        assert cigar.qb64 == wit1Cigar.qb64

        # Process out of unverified but stale escrow  set Timeout to 0
        kvy.TimeoutURE = 0  # forces all escrows to be stale
        time.sleep(0.001)
        kvy.processEscrowUnverNonTrans()
        assert pre not in kvy.kevers  # key state not updated
        # check escrows removed
        kvy.db.ures.get(keys=(pre, coring.Number(num=0, code=coring.NumDex.Huge).qb64))
        kvy.db.ures.get(keys=(pre, coring.Number(num=1, code=coring.NumDex.Huge).qb64))
        kvy.db.ures.get(keys=(pre, coring.Number(num=2, code=coring.NumDex.Huge).qb64))

        # Now reset timeout so not zero and resend receipts to reload escrow
        kvy.TimeoutURE = 3600

        # Process receipt by kvy
        psr.parse(ims=bytearray(rcticpmsg), kvy=kvy)
        # kvy.process(ims=bytearray(rcticpmsg))  # process local copy of msg
        psr.parse(ims=bytearray(rctixnmsg), kvy=kvy)
        # kvy.process(ims=bytearray(rctixnmsg))  # process local copy of msg
        psr.parse(ims=bytearray(rctrotmsg), kvy=kvy)
        # kvy.process(ims=bytearray(rctrotmsg))  # process local copy of msg
        assert pre not in kvy.kevers  # no events yet for pre
        # assert Ure escrows are back
        kvy.db.ures.get(keys=(pre, coring.Number(num=0, code=coring.NumDex.Huge).qb64))
        kvy.db.ures.get(keys=(pre, coring.Number(num=1, code=coring.NumDex.Huge).qb64))
        kvy.db.ures.get(keys=(pre, coring.Number(num=2, code=coring.NumDex.Huge).qb64))

        # apply inception msg to Kevery to process
        psr.parse(ims=bytearray(icpmsg), kvy=kvy)
        # kvy.process(ims=bytearray(icpmsg))  # process local copy of msg
        assert pre in kvy.kevers  # event accepted
        kvr = kvy.kevers[pre]
        assert kvr.serder.said == icpdig  # key state updated so event was validated
        assert kvr.sn == 0  # key state successfully updated

        # apply ixn msg to Kevery to process
        psr.parse(ims=bytearray(ixnmsg), kvy=kvy)
        # kvy.process(ims=bytearray(ixnmsg))  # process local copy of msg
        assert kvr.serder.said == ixndig  # key state updated so event was validated
        assert kvr.sn == 1  # key state successfully updated

        # apply rotation msg to Kevery to process
        psr.parse(ims=bytearray(rotmsg), kvy=kvy)
        # kvy.process(ims=bytearray(rotmsg))  # process local copy of msg
        assert kvr.serder.said == rotdig  # key state updated so event was validated
        assert kvr.sn == 2  # key state successfully updated

        # assert Ure escrows have not changed
        assert len(kvy.db.ures.get(keys=(pre, coring.Number(num=0, code=coring.NumDex.Huge).qb64))) == 2
        assert len(kvy.db.ures.get(keys=(pre, coring.Number(num=1, code=coring.NumDex.Huge).qb64))) == 2
        assert len(kvy.db.ures.get(keys=(pre, coring.Number(num=2, code=coring.NumDex.Huge).qb64))) == 2

        # verify Kevery process unverified receipt escrow i
        # assuming not stale but nothing else has changed
        kvy.processEscrowUnverNonTrans()
        # check escrows removed
        assert len(kvy.db.ures.get(keys=(pre, coring.Number(num=0, code=coring.NumDex.Huge).qb64))) == 0
        assert len(kvy.db.ures.get(keys=(pre, coring.Number(num=1, code=coring.NumDex.Huge).qb64))) == 0
        assert len(kvy.db.ures.get(keys=(pre, coring.Number(num=2, code=coring.NumDex.Huge).qb64))) == 0

        # verify receipts from db in insertion order
        receipts = kvy.db.rcts.get(keys=dbing.dgKey(pre, icpdig))
        assert len(receipts) == 2
        # receipts[0] should be wit0 (inserted first), receipts[1] should be wit1 (inserted second)
        rctPrefixer0, rctCigar0 = receipts[0]
        assert rctPrefixer0.qb64 == wit0pre
        rctPrefixer1, rctCigar1 = receipts[1]
        assert rctPrefixer1.qb64 == wit1pre
        
        receipts = kvy.db.rcts.get(keys=dbing.dgKey(pre, ixndig))
        assert len(receipts) == 2
        rctPrefixer0, rctCigar0 = receipts[0]
        assert rctPrefixer0.qb64 == wit0pre
        rctPrefixer1, rctCigar1 = receipts[1]
        assert rctPrefixer1.qb64 == wit1pre
        
        receipts = kvy.db.rcts.get(keys=dbing.dgKey(pre, rotdig))
        assert len(receipts) == 2
        rctPrefixer0, rctCigar0 = receipts[0]
        assert rctPrefixer0.qb64 == wit0pre
        rctPrefixer1, rctCigar1 = receipts[1]
        assert rctPrefixer1.qb64 == wit1pre

    assert not os.path.exists(ks.path)
    assert not os.path.exists(db.path)

    """End Test"""


def test_unverified_trans_receipt_escrow():
    """
    Test unverified transferable receipt escrow

    """
    salt = core.Salter(raw=b'0123456789abcdef').qb64  # init Salter
    psr = parsing.Parser(version=Vrsn_1_0)

    # init event DB and keep DB
    with basing.openDB(name="edy") as db, keeping.openKS(name="edy") as ks:
        # Init key pair manager
        mgr = keeping.Manager(ks=ks, salt=salt)

        # Init Kevery with event DB
        kvy = eventing.Kevery(db=db)


        # create inception event with 3 keys each in incept and next sets
        # defaults are algo salty and rooted
        sith = ["1/2", "1/2", "1/2"]  #  2 of 3 but with weighted threshold
        nxtsith = ["1/2", "1/2", "1/2"]
        verfers, digers = mgr.incept(icount=3, ncount=3, stem='edy', temp=True)

        srdr = eventing.incept(keys=[verfer.qb64 for verfer in verfers],
                               isith=sith,
                               nsith=nxtsith,
                               ndigs=[diger.qb64 for diger in digers],
                               code=coring.MtrDex.Blake3_256)

        pre = srdr.ked["i"]
        icpdig = srdr.said

        mgr.move(old=verfers[0].qb64, new=pre)  # move key pair label to prefix

        sigers = mgr.sign(ser=srdr.raw, verfers=verfers)

        msg = bytearray(srdr.raw)
        counter = core.Counter(core.Codens.ControllerIdxSigs,
                                 count=len(sigers), version=kering.Vrsn_1_0)
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        icpmsg = msg

        # create receipter (validator) inception keys 2 of 3
        rverfers, rdigers = mgr.incept(icount=3, ncount=3, stem='ray', temp=True)
        rsith = '2'

        # create recepter's inception event
        rsrdr = eventing.incept(keys=[verfer.qb64 for verfer in rverfers],
                                isith=rsith,
                                nsith=rsith,
                                ndigs=[diger.qb64 for diger in rdigers],
                                code=coring.MtrDex.Blake3_256)

        rpre = rsrdr.ked["i"]
        ricpdig = rsrdr.said

        mgr.move(old=rverfers[0].qb64, new=rpre)  # move receipter key pair label to prefix

        rsigers = mgr.sign(ser=rsrdr.raw, verfers=rverfers)

        msg = bytearray(rsrdr.raw)
        counter = core.Counter(core.Codens.ControllerIdxSigs,
                                 count=len(rsigers), version=kering.Vrsn_1_0)
        msg.extend(counter.qb64b)
        for siger in rsigers:
            msg.extend(siger.qb64b)

        ricpmsg = msg


        # create transferable receipt of inception message
        seal = eventing.SealEvent(i=rpre,
                                  s=rsrdr.ked["s"],
                                  d=rsrdr.said)
        reserder = eventing.receipt(pre=pre, sn=0, said=icpdig)
        # sign event not receipt
        resigers = mgr.sign(ser=srdr.raw, verfers=rverfers)
        rcticpmsg = eventing.messagize(serder=reserder, sigers=resigers, seal=seal)

        # Process receipt by kvy
        psr.parse(ims=bytearray(rcticpmsg), kvy=kvy)
        # kvy.process(ims=bytearray(rcticpmsg))  # process local copy of msg
        assert pre not in kvy.kevers  # no events yet for pre  (receipted)
        assert rpre not in kvy.kevers  # no events yet for rpre (receipter)

        escrows = kvy.db.vres.get(dbing.snKey(pre, 0))  # so escrowed receipts
        assert len(escrows) == 3
        diger, sprefixer, snumber, sdiger, siger = eventing.deTransReceiptQuintuple(escrows[0])
        assert diger.qb64 == srdr.said
        assert sprefixer.qb64 == rpre
        assert snumber.sn == 0
        assert sdiger.qb64 == rsrdr.said
        assert siger.qb64 == resigers[0].qb64


        # create interaction event
        srdr = eventing.interact(pre=pre, dig=icpdig, sn=1, data=[])
        ixndig = srdr.said
        sigers = mgr.sign(ser=srdr.raw, verfers=verfers)

        msg = bytearray(srdr.raw)
        counter = core.Counter(core.Codens.ControllerIdxSigs,
                                 count=len(sigers), version=kering.Vrsn_1_0)
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        ixnmsg = msg

        # Create rotation event of receipter
        # get current keys as verfers and next digests as digers
        rverfers, rdigers = mgr.rotate(pre=rpre, ncount=3, temp=True)

        rsrdr = eventing.rotate(pre=rpre,
                                keys=[verfer.qb64 for verfer in rverfers],
                                isith=rsith,
                                dig=ricpdig,
                                nsith=rsith,
                                ndigs=[diger.qb64 for diger in rdigers],
                                sn=1,
                                data=[])

        rrotdig = rsrdr.said

        rsigers = mgr.sign(ser=rsrdr.raw, verfers=rverfers)

        msg = bytearray(rsrdr.raw)
        counter = core.Counter(core.Codens.ControllerIdxSigs,
                                 count=len(rsigers), version=kering.Vrsn_1_0)
        msg.extend(counter.qb64b)
        for siger in rsigers:
            msg.extend(siger.qb64b)

        rrotmsg = msg

        # create receipt(s) of interaction message with receipter rotation message
        # create chit receipt(s) of interaction message
        seal = eventing.SealEvent(i=rpre,
                                  s=rsrdr.ked["s"],
                                  d=rsrdr.said)
        reserder = eventing.receipt(pre=pre, sn=1, said=ixndig)
        # sign event not receipt
        resigers = mgr.sign(ser=srdr.raw, verfers=rverfers)
        rctixnmsg = eventing.messagize(serder=reserder, sigers=resigers, seal=seal)

        # Process receipt by kvy
        psr.parse(ims=bytearray(rctixnmsg), kvy=kvy)
        # kvy.process(ims=bytearray(rctixnmsg))  # process local copy of msg
        assert pre not in kvy.kevers  # no events yet for pre
        assert rpre not in kvy.kevers  # no events yet for rpre (receipter)

        escrows = kvy.db.vres.get(dbing.snKey(pre, 1))  # so escrowed receipts
        assert len(escrows) == 3
        diger, sprefixer, snumber, sdiger, siger = eventing.deTransReceiptQuintuple(escrows[0])
        assert diger.qb64 == srdr.said
        assert sprefixer.qb64 == rpre
        assert snumber.sn == 1
        assert sdiger.qb64 == rsrdr.said
        assert siger.qb64 == resigers[0].qb64

        # Create rotation event or receipted
        # get current keys as verfers and next digests as digers
        sith = nxtsith  # rotate so nxtsith is now current sith and need new nextsith
        #  2 of first 3 and 1 of last 2
        nxtsith = [["1/2", "1/2", "1/2"],["1/1", "1/1"]]
        verfers, digers = mgr.rotate(pre=pre, ncount=5, temp=True)

        srdr = eventing.rotate(pre=pre,
                               keys=[verfer.qb64 for verfer in verfers],
                               isith=sith,
                               dig=ixndig,
                               nsith=nxtsith,
                               ndigs=[diger.qb64 for diger in digers],
                               sn=2,
                               data=[])

        rotdig = srdr.said

        sigers = mgr.sign(ser=srdr.raw, verfers=verfers)

        msg = bytearray(srdr.raw)
        counter = core.Counter(core.Codens.ControllerIdxSigs,
                                 count=len(sigers), version=kering.Vrsn_1_0)
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        rotmsg = msg

        # create receipt(s) of rotation message with rotation message of receipter
        # create chit receipt(s) of interaction message
        seal = eventing.SealEvent(i=rpre,
                                  s=rsrdr.ked["s"],
                                  d=rsrdr.said)
        reserder = eventing.receipt(pre=pre, sn=2, said=rotdig)
        # sign event not receipt
        resigers = mgr.sign(ser=srdr.raw, verfers=rverfers)
        rctrotmsg = eventing.messagize(serder=reserder, sigers=resigers, seal=seal)

        # Process receipt by kvy
        psr.parse(ims=bytearray(rctrotmsg), kvy=kvy)
        # kvy.process(ims=bytearray(rctrotmsg))  # process local copy of msg
        assert pre not in kvy.kevers  # no events yet for pre
        assert rpre not in kvy.kevers  # no events yet for rpre (receipter)

        escrows = kvy.db.vres.get(dbing.snKey(pre, 2))  # so escrowed receipts
        assert len(escrows) == 3
        diger, sprefixer, snumber, sdiger, siger = eventing.deTransReceiptQuintuple(escrows[0])
        assert diger.qb64 == srdr.said
        assert sprefixer.qb64 == rpre
        assert snumber.sn == 1
        assert sdiger.qb64 == rsrdr.said
        assert siger.qb64 == resigers[0].qb64

        # Process out of unverified but stale escrow  set Timeout to 0
        kvy.TimeoutVRE = 0  # forces all escrows to be stale
        time.sleep(0.001)
        kvy.processEscrowUnverTrans()
        assert pre not in kvy.kevers  # key state not updated
        assert rpre not in kvy.kevers  # key state not updated for receipter
        # check escrows removed
        assert len(kvy.db.vres.get(dbing.snKey(pre, 0))) == 0
        assert len(kvy.db.vres.get(dbing.snKey(pre, 1))) == 0
        assert len(kvy.db.vres.get(dbing.snKey(pre, 2))) == 0

        # Now reset timeout so not zero and resend receipts to reload escrow
        kvy.TimeoutVRE = 3600

        # Process receipt by kvy
        psr.parse(ims=bytearray(rcticpmsg), kvy=kvy)
        # kvy.process(ims=bytearray(rcticpmsg))  # process local copy of msg
        psr.parse(ims=bytearray(rctixnmsg), kvy=kvy)
        # kvy.process(ims=bytearray(rctixnmsg))  # process local copy of msg
        psr.parse(ims=bytearray(rctrotmsg), kvy=kvy)
        # kvy.process(ims=bytearray(rctrotmsg))  # process local copy of msg
        assert pre not in kvy.kevers  # no events yet for pre
        assert rpre not in kvy.kevers  # no events yet for rpre (receipter)
        # check escrows are back
        assert len(kvy.db.vres.get(dbing.snKey(pre, 0))) == 3
        assert len(kvy.db.vres.get(dbing.snKey(pre, 1))) == 3
        assert len(kvy.db.vres.get(dbing.snKey(pre, 2))) == 3

        # apply inception msg to Kevery to process
        psr.parse(ims=bytearray(icpmsg), kvy=kvy)
        # kvy.process(ims=bytearray(icpmsg))  # process local copy of msg
        assert pre in kvy.kevers  # event accepted
        kvr = kvy.kevers[pre]
        assert kvr.serder.said == icpdig  # key state updated so event was validated
        assert kvr.sn == 0  # key state successfully updated

        # apply ixn msg to Kevery to process
        psr.parse(ims=bytearray(ixnmsg), kvy=kvy)
        # kvy.process(ims=bytearray(ixnmsg))  # process local copy of msg
        assert kvr.serder.said == ixndig  # key state updated so event was validated
        assert kvr.sn == 1  # key state successfully updated

        # apply rotation msg to Kevery to process
        psr.parse(ims=bytearray(rotmsg), kvy=kvy)
        # kvy.process(ims=bytearray(rotmsg))  # process local copy of msg
        assert kvr.serder.said == rotdig  # key state updated so event was validated
        assert kvr.sn == 2  # key state successfully updated

        # check escrows have not changed
        assert len(kvy.db.vres.get(dbing.snKey(pre, 0))) == 3
        assert len(kvy.db.vres.get(dbing.snKey(pre, 1))) == 3
        assert len(kvy.db.vres.get(dbing.snKey(pre, 2))) == 3

        # verify Kevery process unverified trans receipt escrow
        kvy.processEscrowUnverTrans()
        # check escrows have not changed because no receipter events
        assert len(kvy.db.vres.get(dbing.snKey(pre, 0))) == 3
        assert len(kvy.db.vres.get(dbing.snKey(pre, 1))) == 3
        assert len(kvy.db.vres.get(dbing.snKey(pre, 2))) == 3

        # apply inception msg of receipter to Kevery to process
        psr.parse(ims=bytearray(ricpmsg), kvy=kvy)
        # kvy.process(ims=bytearray(ricpmsg))  # process local copy of msg
        assert rpre in kvy.kevers  # rpre (receipter) accepted
        rkvr = kvy.kevers[rpre]
        assert rkvr.serder.said == ricpdig  # key state updated so event was validated
        assert rkvr.sn == 0  # key state successfully updated

        # verify Kevery process unverified trans receipt escrow
        kvy.processEscrowUnverTrans()
        # check escrows have changed for receipts by receipter inception
        assert len(kvy.db.vres.get(dbing.snKey(pre, 0))) == 0
        assert len(kvy.db.vres.get(dbing.snKey(pre, 1))) == 3
        assert len(kvy.db.vres.get(dbing.snKey(pre, 2))) == 3

        # apply rotation msg of receipter to Kevery to process
        psr.parse(ims=bytearray(rrotmsg), kvy=kvy)
        # kvy.process(ims=bytearray(rrotmsg))  # process local copy of msg
        assert rkvr.serder.said == rrotdig  # key state updated so event was validated
        assert rkvr.sn == 1  # key state successfully updated

        # verify Kevery process unverified trans receipt escrow
        kvy.processEscrowUnverTrans()
        # check escrows have changed for receipts by receipter inception
        assert len(kvy.db.vres.get(dbing.snKey(pre, 0))) == 0
        assert len(kvy.db.vres.get(dbing.snKey(pre, 1))) == 0
        assert len(kvy.db.vres.get(dbing.snKey(pre, 2))) == 0

        # verify receipts
        receipts = kvy.db.vrcs.get(keys=dbing.dgKey(pre, icpdig))
        assert len(receipts) == 3
        rctPrefixer, rctNumber, rctDiger, rctSiger = receipts[0]
        assert rctPrefixer.qb64 == rpre
        assert rctNumber.sn == 0
        assert rctDiger.qb64 == ricpdig

        receipts = kvy.db.vrcs.get(keys=dbing.dgKey(pre, ixndig))
        assert len(receipts) == 3
        rctPrefixer, rctNumber, rctDiger, rctSiger = receipts[0]
        assert rctPrefixer.qb64 == rpre
        assert rctNumber.sn == 1
        assert rctDiger.qb64 == rrotdig

        receipts = kvy.db.vrcs.get(keys=dbing.dgKey(pre, rotdig))
        assert len(receipts) == 3
        rctPrefixer, rctNumber, rctDiger, rctSiger = receipts[0]
        assert rctPrefixer.qb64 == rpre
        assert rctNumber.sn == 1
        assert rctDiger.qb64 == rrotdig

    assert not os.path.exists(ks.path)
    assert not os.path.exists(db.path)

    """End Test"""


if __name__ == "__main__":
    #test_unverified_receipt_escrow()
    test_missing_delegator_escrow()


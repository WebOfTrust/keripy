# -*- encoding: utf-8 -*-
"""
tests escrows in database primarily logic in Kevery and Kever from keri.core.eventing

"""
import os
import time
import datetime

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
        escrows = kvy.db.getPses(dbing.snKey(pre, int(srdr.ked["s"], 16)))
        assert len(escrows) == 1
        assert escrows[0] == srdr.saidb  #  escrow entry for event

        # verify Kevery process is idempotent to previously escrowed events
        psr.parse(ims=bytearray(msg), kvy=kvy)
        # kvy.process(ims=bytearray(msg))  # process local copy of msg
        assert pre not in kvy.kevers  # event not accepted
        escrows = kvy.db.getPses(dbing.snKey(pre, int(srdr.ked["s"], 16)))
        assert len(escrows) == 1
        assert escrows[0] == srdr.saidb  #  escrow entry for event

        time.sleep(0.001)
        # verify Kevery process partials escrow is idempotent to previously escrowed events
        # assuming not stale but nothing else has changed
        kvy.processEscrowPartialSigs()
        assert pre not in kvy.kevers  # event not accepted
        escrows = kvy.db.getPses(dbing.snKey(pre, int(srdr.ked["s"], 16)))
        assert len(escrows) == 1
        assert escrows[0] == srdr.saidb  #  escrow entry for event

        # Send message again but with signature from other siger
        msg = bytearray(srdr.raw)
        counter = core.Counter(core.Codens.ControllerIdxSigs,
                                 version=kering.Vrsn_1_0)
        msg.extend(counter.qb64b)
        msg.extend(sigers[2].qb64b)
        # apply msg to Kevery to process
        psr.parse(ims=bytearray(msg), kvy=kvy)
        # kvy.process(ims=bytearray(msg))  # process local copy of msg
        assert pre not in kvy.kevers  # event not accepted
        escrows = kvy.db.getPses(dbing.snKey(pre, int(srdr.ked["s"], 16)))
        assert len(escrows) == 1
        assert escrows[0] == srdr.saidb  #  escrow entry for event
        sigs = kvy.db.getSigs(dbing.dgKey(pre, srdr.said))  #  but sigs is more
        assert len(sigs) == 2

        # get DTS set by escrow date time stamp on event
        edtsb = bytes(kvy.db.getDts(dbing.dgKey(pre, srdr.saidb)))

        time.sleep(0.001)
        # verify Kevery process partials escrow now unescrows correctly given
        # two signatures and assuming not stale
        kvy.processEscrowPartialSigs()
        assert pre in kvy.kevers  # event now accepted via escrow
        kvr = kvy.kevers[pre]  # kever created so event was validated
        assert kvr.prefixer.qb64 == pre
        assert kvr.serder.said == srdr.said  # key state updated so event was validated
        # escrows now empty
        escrows = kvy.db.getPses(dbing.snKey(pre, int(srdr.ked["s"], 16)))
        assert len(escrows) == 0

        # get DTS set by first seen event acceptance date time stamp
        adtsb = bytes(kvy.db.getDts(dbing.dgKey(pre, srdr.saidb)))
        # ensure accept time is later than escrow time, default timedelta is zero
        assert (helping.fromIso8601(adtsb) - helping.fromIso8601(edtsb)) > datetime.timedelta()

        # send duplicate message with all three sigs
        msg = bytearray(srdr.raw)
        counter = core.Counter(core.Codens.ControllerIdxSigs,
                                 count=len(sigers), version=kering.Vrsn_1_0)
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)
        psr.parse(ims=bytearray(msg), kvy=kvy)
        # kvy.process(ims=bytearray(msg))  # process local copy of msg
        sigs = kvy.db.getSigs(dbing.dgKey(pre, srdr.said))
        assert len(sigs) == 3
        escrows = kvy.db.getPses(dbing.snKey(pre, int(srdr.ked["s"], 16)))
        assert len(escrows) == 0  # escrow stays gone

        # get DTS after partial last sig should not change dts from first accepted
        pdtsb = bytes(kvy.db.getDts(dbing.dgKey(pre, srdr.saidb)))
        assert pdtsb == adtsb

        # get first seen
        fsdig = kvy.db.getFe(dbing.fnKey(pre, 0))
        assert fsdig == srdr.saidb

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
        escrows = kvy.db.getPses(dbing.snKey(pre, int(srdr.ked["s"], 16)))
        assert len(escrows) == 1
        assert escrows[0] == srdr.saidb  #  escrow entry for event

        # add another sig
        msg = bytearray(srdr.raw)
        counter = core.Counter(core.Codens.ControllerIdxSigs, version=kering.Vrsn_1_0)
        msg.extend(counter.qb64b)
        msg.extend(sigers[0].qb64b)

        # apply msg to Kevery to process
        psr.parse(ims=bytearray(msg), kvy=kvy)
        # kvy.process(ims=bytearray(msg))  # process local copy of msg
        assert kvr.sn == 0  # key state not updated
        escrows = kvy.db.getPses(dbing.snKey(pre, int(srdr.ked["s"], 16)))
        assert len(escrows) == 1
        assert escrows[0] == srdr.saidb  #  escrow entry for event
        sigs = kvy.db.getSigs(dbing.dgKey(pre, srdr.said))  #  but sigs is more
        assert len(sigs) == 2

        # Process partials but stale escrow  despite two sigs set Timeout to 0
        kvy.TimeoutPSE = 0  # forces all escrows to be stale
        time.sleep(0.001)
        kvy.processEscrowPartialSigs()
        assert kvr.sn == 0  # key state not updated
        # escrows now empty
        escrows = kvy.db.getPses(dbing.snKey(pre, int(srdr.ked["s"], 16)))
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
        escrows = kvy.db.getPses(dbing.snKey(pre, int(srdr.ked["s"], 16)))
        assert len(escrows) == 1
        assert escrows[0] == srdr.saidb  #  escrow entry for event

        # add another sig
        msg = bytearray(srdr.raw)
        counter = core.Counter(core.Codens.ControllerIdxSigs, version=kering.Vrsn_1_0)
        msg.extend(counter.qb64b)
        msg.extend(sigers[0].qb64b)

        # apply msg to Kevery to process
        psr.parse(ims=bytearray(msg), kvy=kvy)
        # kvy.process(ims=bytearray(msg))  # process local copy of msg
        assert kvr.sn == 0  # key state not updated
        escrows = kvy.db.getPses(dbing.snKey(pre, int(srdr.ked["s"], 16)))
        assert len(escrows) == 1
        assert escrows[0] == srdr.saidb  #  escrow entry for event

        # get DTS set by escrow date time stamp on event
        edtsb = bytes(kvy.db.getDts(dbing.dgKey(pre, srdr.saidb)))

        time.sleep(0.001)
        # Process partials but now escrow not stale
        kvy.processEscrowPartialSigs()
        assert kvr.serder.said == srdr.said  # key state updated so event was validated
        assert kvr.sn == 1  # key state successfully updated
        escrows = kvy.db.getPses(dbing.snKey(pre, int(srdr.ked["s"], 16)))
        assert len(escrows) == 0  # escrow gone

        # get DTS set by first seen event acceptance date time stamp
        adtsb = bytes(kvy.db.getDts(dbing.dgKey(pre, srdr.saidb)))
        # ensure accept time is later than escrow time, default timedelta is zero
        assert (helping.fromIso8601(adtsb) - helping.fromIso8601(edtsb)) > datetime.timedelta()

        # send duplicate message but add last sig
        msg = bytearray(srdr.raw)
        counter = core.Counter(core.Codens.ControllerIdxSigs, version=kering.Vrsn_1_0)
        msg.extend(counter.qb64b)
        msg.extend(sigers[2].qb64b)
        psr.parse(ims=bytearray(msg), kvy=kvy)
        # kvy.process(ims=bytearray(msg))  # process local copy of msg
        sigs = kvy.db.getSigs(dbing.dgKey(pre, srdr.said))  #  but sigs is more
        assert len(sigs) == 3
        escrows = kvy.db.getPses(dbing.snKey(pre, int(srdr.ked["s"], 16)))
        assert len(escrows) == 0  # escrow stays gone

        # get DTS after partial last sig should not change dts from first accepted
        pdtsb = bytes(kvy.db.getDts(dbing.dgKey(pre, srdr.saidb)))
        assert pdtsb == adtsb

        # get first seen
        fsdig = kvy.db.getFe(dbing.fnKey(pre, 1))
        assert fsdig == srdr.saidb

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
        edtsb = bytes(kvy.db.getDts(dbing.dgKey(pre, srdr.saidb)))

        time.sleep(0.001)
        # process escrow
        kvy.processEscrowPartialSigs()
        assert kvr.serder.said == srdr.said  # key state updated

        # get DTS set by first seen event acceptance date time stamp
        adtsb = bytes(kvy.db.getDts(dbing.dgKey(pre, srdr.saidb)))
        # ensure accept time is later than escrow time, default timedelta is zero
        assert (helping.fromIso8601(adtsb) - helping.fromIso8601(edtsb)) > datetime.timedelta()

        # get first seen
        fsdig = kvy.db.getFe(dbing.fnKey(pre, 3))
        assert fsdig == srdr.saidb

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
        couple = bobKvy.db.getAes(dbing.dgKey(delPre, delSrdr.said))
        assert couple == seqner.qb64b + bobSrdr.saidb

        # apply Del's inception msg to Del's Kevery
        # Because locallyOwned by delegate event does not validate delegation
        # and ignores the attached source seal
        psr.parse(ims=bytearray(delIcpMsg), kvy=delKvy, local=True)
        assert delPre in delKvy.kevers
        delK = delKvy.kevers[delPre]
        # no AES entry for del's own delegated event when locallyOwned
        assert not delKvy.db.getAes(dbing.dgKey(delPre, delSrdr.said))

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
        couple = watKvy.db.getAes(dbing.dgKey(delPre, delSrdr.said))
        assert couple == seqner.qb64b + bobSrdr.saidb


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
        assert not delKvy.db.getAes(dbing.dgKey(delPre, delSrdr.said))

        # apply Del's delegated Rotation event message to bob's Kevery
        psr.parse(ims=bytearray(delRotMsg), kvy=bobKvy, local=True)
        assert bobDelK.delegated
        assert bobDelK.serder.said == delSrdr.said  # key state updated so event was validated
        couple = bobKvy.db.getAes(dbing.dgKey(delPre, delSrdr.said))
        assert couple == seqner.qb64b + bobSrdr.saidb

        # apply Del's delegated Rotation event message to wats's Kevery
        psr.parse(ims=bytearray(delRotMsg), kvy=watKvy, local=True)
        assert watDelK.delegated
        assert watDelK.serder.said == delSrdr.said  # key state updated so event was validated
        couple = watKvy.db.getAes(dbing.dgKey(delPre, delSrdr.said))
        assert couple == seqner.qb64b + bobSrdr.saidb



    assert not os.path.exists(delKS.path)
    assert not os.path.exists(delDB.path)
    assert not os.path.exists(bobKS.path)
    assert not os.path.exists(bobDB.path)

    """End Test"""


def test_misfit_escrow():
    """
    Test misfit escrow

    """
    salt = core.Salter(raw=b'0123456789abcdef').qb64  # init wes Salter

    # stub for now

    """End Test"""



def test_out_of_order_escrow():
    """
    Test out of order escrow

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

        msg = bytearray(srdr.raw)
        counter = core.Counter(core.Codens.ControllerIdxSigs,
                                 count=len(sigers), version=kering.Vrsn_1_0)
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        ixnmsg = bytearray(msg)  # save copy for later

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
        escrows = kvy.db.getOoes(dbing.snKey(pre, 2))
        assert len(escrows) == 1
        assert escrows[0] == rotdig.encode("utf-8")  #  escrow entry for event

        # verify Kevery process is idempotent to previously escrowed events
        psr.parse(ims=bytearray(rotmsg), kvy=kvy)
        # kvy.process(ims=bytearray(rotmsg))  # process local copy of msg
        assert pre not in kvy.kevers  # event not accepted
        escrows = kvy.db.getOoes(dbing.snKey(pre, 2))
        assert len(escrows) == 1
        assert escrows[0] == rotdig.encode("utf-8")  #  escrow entry for event

        # verify Kevery process out of order escrow is idempotent to previously escrowed events
        # assuming not stale but nothing else has changed
        kvy.processEscrowOutOfOrders()
        assert pre not in kvy.kevers  # event not accepted
        escrows = kvy.db.getOoes(dbing.snKey(pre, 2))
        assert len(escrows) == 1
        assert escrows[0] == rotdig.encode("utf-8")   #  escrow entry for event

        # apply ixn msg to Kevery to process
        psr.parse(ims=bytearray(ixnmsg), kvy=kvy)
        # kvy.process(ims=bytearray(ixnmsg))  # process local copy of msg
        assert pre not in kvy.kevers  # event not accepted
        escrows = kvy.db.getOoes(dbing.snKey(pre, 1))
        assert len(escrows) == 1
        assert escrows[0] == ixndig.encode("utf-8")  #  escrow entry for event

        # verify Kevery process is idempotent to previously escrowed events
        psr.parse(ims=bytearray(ixnmsg), kvy=kvy)
        # kvy.process(ims=bytearray(ixnmsg))  # process local copy of msg
        assert pre not in kvy.kevers  # event not accepted
        escrows = kvy.db.getOoes(dbing.snKey(pre, 1))
        assert len(escrows) == 1
        assert escrows[0] == ixndig.encode("utf-8")  #  escrow entry for event

        # verify Kevery process out of order escrow is idempotent to previously escrowed events
        # assuming not stale but nothing else has changed
        kvy.processEscrowOutOfOrders()
        assert pre not in kvy.kevers  # event not accepted
        escrows = kvy.db.getOoes(dbing.snKey(pre, 1))
        assert len(escrows) == 1
        assert escrows[0] == ixndig.encode("utf-8")    #  escrow entry for event

        # Process partials but stale escrow  set Timeout to 0
        kvy.TimeoutOOE = 0  # forces all escrows to be stale
        time.sleep(0.001)
        kvy.processEscrowOutOfOrders()
        assert pre not in kvy.kevers  # key state not updated
        escrows = kvy.db.getOoes(dbing.snKey(pre, 1))
        assert len(escrows) == 0  # escrow gone
        escrows = kvy.db.getOoes(dbing.snKey(pre, 2))
        assert len(escrows) == 0

        # Now reset timeout so not zero and rsend events to reload escrow
        kvy.TimeoutOOE = 3600

        # re-apply rotation msg to Kevery to process
        psr.parse(ims=bytearray(rotmsg), kvy=kvy)
        # kvy.process(ims=bytearray(rotmsg))  # process local copy of msg
        assert pre not in kvy.kevers  # event not accepted
        escrows = kvy.db.getOoes(dbing.snKey(pre, 2))
        assert len(escrows) == 1
        assert escrows[0] == rotdig.encode("utf-8")  #  escrow entry for event

        # re-apply ixn msg to Kevery to process
        psr.parse(ims=bytearray(ixnmsg), kvy=kvy)
        # kvy.process(ims=bytearray(ixnmsg))  # process local copy of msg
        assert pre not in kvy.kevers  # event not accepted
        escrows = kvy.db.getOoes(dbing.snKey(pre, 1))
        assert len(escrows) == 1
        assert escrows[0] == ixndig.encode("utf-8")  #  escrow entry for event

        # re-apply inception msg to Kevery to process
        psr.parse(ims=bytearray(icpmsg), kvy=kvy)
        # kvy.process(ims=bytearray(icpmsg))  # process local copy of msg
        assert pre in kvy.kevers  # event accepted
        kvr = kvy.kevers[pre]
        assert kvr.serder.said == icpdig  # key state updated so event was validated
        assert kvr.sn == 0  # key state successfully updated
        # verify escrows not changed
        escrows = kvy.db.getOoes(dbing.snKey(pre, 2))
        assert len(escrows) == 1
        assert escrows[0] == rotdig.encode("utf-8")  #  escrow entry for event
        escrows = kvy.db.getOoes(dbing.snKey(pre, 1))
        assert len(escrows) == 1
        assert escrows[0] == ixndig.encode("utf-8")  #  escrow entry for event

        # Process out of order escrow
        # assuming not stale but nothing else has changed
        kvy.processEscrowOutOfOrders()
        assert kvr.serder.said == rotdig  # key state updated so event was validated
        assert kvr.sn == 2  # key state successfully updated
        escrows = kvy.db.getOoes(dbing.snKey(pre, 1))
        assert len(escrows) == 0  # escrow gone
        escrows = kvy.db.getOoes(dbing.snKey(pre, 2))
        assert len(escrows) == 0


    assert not os.path.exists(ks.path)
    assert not os.path.exists(db.path)

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
        escrows = kvy.db.getUres(dbing.snKey(pre, 0))  # so escrowed receipts
        assert len(escrows) == 2
        diger, prefixer, cigar = eventing.deReceiptTriple(escrows[0])
        assert diger.qb64 == srdr.said
        assert prefixer.qb64 == wit0pre
        assert cigar.qb64 == wit0Cigar.qb64
        diger, prefixer, cigar = eventing.deReceiptTriple(escrows[1])
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
        escrows = kvy.db.getUres(dbing.snKey(pre, 1))  # so escrowed receipts
        assert len(escrows) == 2
        diger, prefixer, cigar = eventing.deReceiptTriple(escrows[0])
        assert diger.qb64 == srdr.said
        assert prefixer.qb64 == wit0pre
        assert cigar.qb64 == wit0Cigar.qb64
        diger, prefixer, cigar = eventing.deReceiptTriple(escrows[1])
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
        escrows = kvy.db.getUres(dbing.snKey(pre, 2))  # so escrowed receipts
        assert len(escrows) == 2
        diger, prefixer, cigar = eventing.deReceiptTriple(escrows[0])
        assert diger.qb64 == srdr.said
        assert prefixer.qb64 == wit0pre
        assert cigar.qb64 == wit0Cigar.qb64
        diger, prefixer, cigar = eventing.deReceiptTriple(escrows[1])
        assert diger.qb64 == srdr.said
        assert prefixer.qb64 == wit1pre
        assert cigar.qb64 == wit1Cigar.qb64

        # Process out of unverified but stale escrow  set Timeout to 0
        kvy.TimeoutURE = 0  # forces all escrows to be stale
        time.sleep(0.001)
        kvy.processEscrowUnverNonTrans()
        assert pre not in kvy.kevers  # key state not updated
        # check escrows removed
        assert len(kvy.db.getUres(dbing.snKey(pre, 0))) == 0
        assert len(kvy.db.getUres(dbing.snKey(pre, 1))) == 0
        assert len(kvy.db.getUres(dbing.snKey(pre, 2))) == 0

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
        assert len(kvy.db.getUres(dbing.snKey(pre, 0))) == 2
        assert len(kvy.db.getUres(dbing.snKey(pre, 1))) == 2
        assert len(kvy.db.getUres(dbing.snKey(pre, 2))) == 2

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
        assert len(kvy.db.getUres(dbing.snKey(pre, 0))) == 2
        assert len(kvy.db.getUres(dbing.snKey(pre, 1))) == 2
        assert len(kvy.db.getUres(dbing.snKey(pre, 2))) == 2

        # verify Kevery process unverified receipt escrow i
        # assuming not stale but nothing else has changed
        kvy.processEscrowUnverNonTrans()
        # check escrows removed
        assert len(kvy.db.getUres(dbing.snKey(pre, 0))) == 0
        assert len(kvy.db.getUres(dbing.snKey(pre, 1))) == 0
        assert len(kvy.db.getUres(dbing.snKey(pre, 2))) == 0

        # verify receipts from db which changes order if wit1 < wit2
        receipts = kvy.db.getRcts(dbing.dgKey(pre, icpdig))
        assert len(receipts) == 2
        rctPrefixer, rctCigar = eventing.deReceiptCouple(receipts[0])
        assert rctPrefixer.qb64 == wit1pre
        rctPrefixer, rctCigar = eventing.deReceiptCouple(receipts[1])
        assert rctPrefixer.qb64 == wit0pre
        receipts = kvy.db.getRcts(dbing.dgKey(pre, ixndig))
        assert len(receipts) == 2
        rctPrefixer, rctCigar = eventing.deReceiptCouple(receipts[0])
        assert rctPrefixer.qb64 == wit1pre
        rctPrefixer, rctCigar = eventing.deReceiptCouple(receipts[1])
        assert rctPrefixer.qb64 == wit0pre
        receipts = kvy.db.getRcts(dbing.dgKey(pre, rotdig))
        assert len(receipts) == 2
        rctPrefixer, rctCigar = eventing.deReceiptCouple(receipts[0])
        assert rctPrefixer.qb64 == wit1pre
        rctPrefixer, rctCigar = eventing.deReceiptCouple(receipts[1])
        assert rctPrefixer.qb64 == wit0pre


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

        escrows = kvy.db.getVres(dbing.snKey(pre, 0))  # so escrowed receipts
        assert len(escrows) == 3
        diger, sprefixer, sseqner, sdiger, siger = eventing.deTransReceiptQuintuple(escrows[0])
        assert diger.qb64 == srdr.said
        assert sprefixer.qb64 == rpre
        assert sseqner.sn == 0
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

        escrows = kvy.db.getVres(dbing.snKey(pre, 1))  # so escrowed receipts
        assert len(escrows) == 3
        diger, sprefixer, sseqner, sdiger, siger = eventing.deTransReceiptQuintuple(escrows[0])
        assert diger.qb64 == srdr.said
        assert sprefixer.qb64 == rpre
        assert sseqner.sn == 1
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

        escrows = kvy.db.getVres(dbing.snKey(pre, 2))  # so escrowed receipts
        assert len(escrows) == 3
        diger, sprefixer, sseqner, sdiger, siger = eventing.deTransReceiptQuintuple(escrows[0])
        assert diger.qb64 == srdr.said
        assert sprefixer.qb64 == rpre
        assert sseqner.sn == 1
        assert sdiger.qb64 == rsrdr.said
        assert siger.qb64 == resigers[0].qb64

        # Process out of unverified but stale escrow  set Timeout to 0
        kvy.TimeoutVRE = 0  # forces all escrows to be stale
        time.sleep(0.001)
        kvy.processEscrowUnverTrans()
        assert pre not in kvy.kevers  # key state not updated
        assert rpre not in kvy.kevers  # key state not updated for receipter
        # check escrows removed
        assert len(kvy.db.getVres(dbing.snKey(pre, 0))) == 0
        assert len(kvy.db.getVres(dbing.snKey(pre, 1))) == 0
        assert len(kvy.db.getVres(dbing.snKey(pre, 2))) == 0

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
        assert len(kvy.db.getVres(dbing.snKey(pre, 0))) == 3
        assert len(kvy.db.getVres(dbing.snKey(pre, 1))) == 3
        assert len(kvy.db.getVres(dbing.snKey(pre, 2))) == 3

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
        assert len(kvy.db.getVres(dbing.snKey(pre, 0))) == 3
        assert len(kvy.db.getVres(dbing.snKey(pre, 1))) == 3
        assert len(kvy.db.getVres(dbing.snKey(pre, 2))) == 3

        # verify Kevery process unverified trans receipt escrow
        kvy.processEscrowUnverTrans()
        # check escrows have not changed because no receipter events
        assert len(kvy.db.getVres(dbing.snKey(pre, 0))) == 3
        assert len(kvy.db.getVres(dbing.snKey(pre, 1))) == 3
        assert len(kvy.db.getVres(dbing.snKey(pre, 2))) == 3

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
        assert len(kvy.db.getVres(dbing.snKey(pre, 0))) == 0
        assert len(kvy.db.getVres(dbing.snKey(pre, 1))) == 3
        assert len(kvy.db.getVres(dbing.snKey(pre, 2))) == 3

        # apply rotation msg of receipter to Kevery to process
        psr.parse(ims=bytearray(rrotmsg), kvy=kvy)
        # kvy.process(ims=bytearray(rrotmsg))  # process local copy of msg
        assert rkvr.serder.said == rrotdig  # key state updated so event was validated
        assert rkvr.sn == 1  # key state successfully updated

        # verify Kevery process unverified trans receipt escrow
        kvy.processEscrowUnverTrans()
        # check escrows have changed for receipts by receipter inception
        assert len(kvy.db.getVres(dbing.snKey(pre, 0))) == 0
        assert len(kvy.db.getVres(dbing.snKey(pre, 1))) == 0
        assert len(kvy.db.getVres(dbing.snKey(pre, 2))) == 0

        # verify receipts
        receipts = kvy.db.getVrcs(dbing.dgKey(pre, icpdig))
        assert len(receipts) == 3
        rctPrefixer, rctSeqner, rctDiger, rctSiger = eventing.deTransReceiptQuadruple(receipts[0])
        assert rctPrefixer.qb64 == rpre
        assert rctSeqner.sn == 0
        assert rctDiger.qb64 == ricpdig

        receipts = kvy.db.getVrcs(dbing.dgKey(pre, ixndig))
        assert len(receipts) == 3
        rctPrefixer, rctSeqner, rctDiger, rctSiger = eventing.deTransReceiptQuadruple(receipts[0])
        assert rctPrefixer.qb64 == rpre
        assert rctSeqner.sn == 1
        assert rctDiger.qb64 == rrotdig

        receipts = kvy.db.getVrcs(dbing.dgKey(pre, rotdig))
        assert len(receipts) == 3
        rctPrefixer, rctSeqner, rctDiger, rctSiger = eventing.deTransReceiptQuadruple(receipts[0])
        assert rctPrefixer.qb64 == rpre
        assert rctSeqner.sn == 1
        assert rctDiger.qb64 == rrotdig

    assert not os.path.exists(ks.path)
    assert not os.path.exists(db.path)

    """End Test"""


if __name__ == "__main__":
    #test_unverified_receipt_escrow()
    test_missing_delegator_escrow()


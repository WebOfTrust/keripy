# -*- encoding: utf-8 -*-
"""
tests escrows in database primarily logic in Kevery and Kever from keri.core.eventing

"""
import os
import time
import pytest

from keri import kering
from keri.help import ogling
from keri.db import dbing
from keri.base import keeping
from keri.core import coring
from keri.core import eventing

blogger, flogger = ogling.ogler.getLoggers()


def test_partial_signed_escrow():
    """
    Test partially signed escrow

    """
    salt = coring.Salter(raw=b'0123456789abcdef').qb64  # init wes Salter

    # init event DB and keep DB
    with dbing.openDB(name="edy") as db, keeping.openKeep(name="edy") as kpr:
        # Init key pair manager
        mgr = keeping.Manager(keeper=kpr, salt=salt)

        # Init Kevery with event DB
        kvy = eventing.Kevery(baser=db)

        # create inception event with 3 keys each in incept and next sets
        # defaults are algo salty and rooted
        verfers, digers = mgr.incept(icount=3, ncount=3, stem='wes', temp=True)
        sith = ["1/2", "1/2", "1/2"]  #  2 of 3 but with weighted threshold
        nxtsith = ["1/2", "1/2", "1/2"]

        srdr = eventing.incept(keys=[verfer.qb64 for verfer in verfers],
                                  sith=sith,
                                 nxt=coring.Nexter(sith=nxtsith,
                                                   digs=[diger.qb64 for diger in digers]).qb64,
                                 code=coring.CryOneDex.Blake3_256)

        pre = srdr.ked["i"]

        mgr.move(old=verfers[0].qb64, new=pre)  # move key pair label to prefix

        sigers = mgr.sign(ser=srdr.raw, verfers=verfers)

        msg = bytearray(srdr.raw)
        counter = coring.SigCounter(count=1)
        msg.extend(counter.qb64b)
        msg.extend(sigers[0].qb64b)

        # apply msg to Kevery to process
        kvy.processAll(ims=bytearray(msg))  # process local copy of msg
        assert pre not in kvy.kevers  # event not accepted
        escrows = kvy.baser.getPses(dbing.snKey(pre, int(srdr.ked["s"], 16)))
        assert len(escrows) == 1
        assert escrows[0] == srdr.digb  #  escrow entry for event

        # verify Kevery process is idempotent to previously escrowed events
        kvy.processAll(ims=bytearray(msg))  # process local copy of msg
        assert pre not in kvy.kevers  # event not accepted
        escrows = kvy.baser.getPses(dbing.snKey(pre, int(srdr.ked["s"], 16)))
        assert len(escrows) == 1
        assert escrows[0] == srdr.digb  #  escrow entry for event

        # verify Kevery process partials escrow is idempotent to previously escrowed events
        # assuming not stale but nothing else has changed
        kvy.processPartials()
        assert pre not in kvy.kevers  # event not accepted
        escrows = kvy.baser.getPses(dbing.snKey(pre, int(srdr.ked["s"], 16)))
        assert len(escrows) == 1
        assert escrows[0] == srdr.digb  #  escrow entry for event

        # Send message again but with signature from other siger
        msg = bytearray(srdr.raw)
        counter = coring.SigCounter(count=1)
        msg.extend(counter.qb64b)
        msg.extend(sigers[2].qb64b)
        # apply msg to Kevery to process
        kvy.processAll(ims=bytearray(msg))  # process local copy of msg
        assert pre not in kvy.kevers  # event not accepted
        escrows = kvy.baser.getPses(dbing.snKey(pre, int(srdr.ked["s"], 16)))
        assert len(escrows) == 1
        assert escrows[0] == srdr.digb  #  escrow entry for event
        sigs = kvy.baser.getSigs(dbing.dgKey(pre, srdr.dig))  #  but sigs is more
        assert len(sigs) == 2

        # verify Kevery process partials escrow now unescrows correctly given
        # two signatures and assuming not stale
        kvy.processPartials()
        assert pre in kvy.kevers  # event now accepted via escrow
        kvr = kvy.kevers[pre]  # kever created so event was validated
        assert kvr.prefixer.qb64 == pre
        assert kvr.serder.dig == srdr.dig  # key state updated so event was validated
        # escrows now empty
        escrows = kvy.baser.getPses(dbing.snKey(pre, int(srdr.ked["s"], 16)))
        assert len(escrows) == 0

        # send duplicate message with all three sigs
        msg = bytearray(srdr.raw)
        counter = coring.SigCounter(count=len(sigers))
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)
        kvy.processAll(ims=bytearray(msg))  # process local copy of msg
        sigs = kvy.baser.getSigs(dbing.dgKey(pre, srdr.dig))
        assert len(sigs) == 3
        escrows = kvy.baser.getPses(dbing.snKey(pre, int(srdr.ked["s"], 16)))
        assert len(escrows) == 0  # escrow stays gone

        # create interaction event for
        srdr = eventing.interact(pre=kvr.prefixer.qb64,
                                    dig=kvr.serder.diger.qb64,
                                    sn=kvr.sn+1,
                                    data=[])

        sigers = mgr.sign(ser=srdr.raw, verfers=kvr.verfers)

        msg = bytearray(srdr.raw)
        counter = coring.SigCounter(count=1)
        msg.extend(counter.qb64b)
        msg.extend(sigers[1].qb64b)

        # apply msg to Kevery to process
        kvy.processAll(ims=bytearray(msg))  # process local copy of msg
        assert kvr.sn == 0  # key state not updated
        escrows = kvy.baser.getPses(dbing.snKey(pre, int(srdr.ked["s"], 16)))
        assert len(escrows) == 1
        assert escrows[0] == srdr.digb  #  escrow entry for event

        # add another sig
        msg = bytearray(srdr.raw)
        counter = coring.SigCounter(count=1)
        msg.extend(counter.qb64b)
        msg.extend(sigers[0].qb64b)

        # apply msg to Kevery to process
        kvy.processAll(ims=bytearray(msg))  # process local copy of msg
        assert kvr.sn == 0  # key state not updated
        escrows = kvy.baser.getPses(dbing.snKey(pre, int(srdr.ked["s"], 16)))
        assert len(escrows) == 1
        assert escrows[0] == srdr.digb  #  escrow entry for event
        sigs = kvy.baser.getSigs(dbing.dgKey(pre, srdr.dig))  #  but sigs is more
        assert len(sigs) == 2

        # Process partials but stale escrow  despite two sigs set Timeout to 0
        kvy.TimeoutPSE = 0  # forces all escrows to be stale
        time.sleep(0.001)
        kvy.processPartials()
        assert kvr.sn == 0  # key state not updated
        # escrows now empty
        escrows = kvy.baser.getPses(dbing.snKey(pre, int(srdr.ked["s"], 16)))
        assert len(escrows) == 0

        # Now reset timeout so not zero
        kvy.TimeoutPSE = 3600

        # resend events to load escrow
        msg = bytearray(srdr.raw)
        counter = coring.SigCounter(count=1)
        msg.extend(counter.qb64b)
        msg.extend(sigers[1].qb64b)

        # apply msg to Kevery to process
        kvy.processAll(ims=bytearray(msg))  # process local copy of msg
        assert kvr.sn == 0  # key state not updated
        escrows = kvy.baser.getPses(dbing.snKey(pre, int(srdr.ked["s"], 16)))
        assert len(escrows) == 1
        assert escrows[0] == srdr.digb  #  escrow entry for event

        # add another sig
        msg = bytearray(srdr.raw)
        counter = coring.SigCounter(count=1)
        msg.extend(counter.qb64b)
        msg.extend(sigers[0].qb64b)

        # apply msg to Kevery to process
        kvy.processAll(ims=bytearray(msg))  # process local copy of msg
        assert kvr.sn == 0  # key state not updated
        escrows = kvy.baser.getPses(dbing.snKey(pre, int(srdr.ked["s"], 16)))
        assert len(escrows) == 1
        assert escrows[0] == srdr.digb  #  escrow entry for event

        # Process partials but now escrow not stale
        kvy.processPartials()
        assert kvr.serder.dig == srdr.dig  # key state updated so event was validated
        assert kvr.sn == 1  # key state successfully updated
        escrows = kvy.baser.getPses(dbing.snKey(pre, int(srdr.ked["s"], 16)))
        assert len(escrows) == 0  # escrow gone

        # send duplicate message but add last sig
        msg = bytearray(srdr.raw)
        counter = coring.SigCounter(count=1)
        msg.extend(counter.qb64b)
        msg.extend(sigers[2].qb64b)
        kvy.processAll(ims=bytearray(msg))  # process local copy of msg
        sigs = kvy.baser.getSigs(dbing.dgKey(pre, srdr.dig))  #  but sigs is more
        assert len(sigs) == 3
        escrows = kvy.baser.getPses(dbing.snKey(pre, int(srdr.ked["s"], 16)))
        assert len(escrows) == 0  # escrow stays gone

        # Create rotation event
        # get current keys as verfers and next digests as digers
        verfers, digers = mgr.rotate(pre=pre, count=5, temp=True)
        sith = nxtsith  # rotate so nxtsith is now current sith and need new nextsith
        #  2 of first 3 and 1 of last 2
        nxtsith = [["1/2", "1/2", "1/2"],["1/1", "1/1"]]

        srdr = eventing.rotate(pre=kvr.prefixer.qb64,
                                  keys=[verfer.qb64 for verfer in verfers],
                                  sith=sith,
                                  dig=kvr.serder.diger.qb64,
                                  nxt=coring.Nexter(sith=nxtsith,
                                                    digs=[diger.qb64 for diger in digers]).qb64,
                                  sn=kvr.sn+1,
                                  data=[])

        sigers = mgr.sign(ser=srdr.raw, verfers=verfers)

        msg = bytearray(srdr.raw)
        counter = coring.SigCounter(count=len(sigers))
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        # apply msg to Kevery
        kvy.processAll(ims=bytearray(msg))  # process local copy of msg
        assert kvr.serder.dig == srdr.dig  # key state updated so event was validated

        # Create rotation event
        # get current keys as verfers and next digests as digers
        verfers, digers = mgr.rotate(pre=pre, count=5, temp=True)
        sith = nxtsith  # rotate so nxtsith is now current sith and need new nextsith
        #  2 of first 3 and 1 of last 2
        nxtsith = [["1/2", "1/2", "1/2"],["1/1", "1/1"]]

        srdr = eventing.rotate(pre=kvr.prefixer.qb64,
                                  keys=[verfer.qb64 for verfer in verfers],
                                  sith=sith,
                                  dig=kvr.serder.diger.qb64,
                                  nxt=coring.Nexter(sith=nxtsith,
                                                    digs=[diger.qb64 for diger in digers]).qb64,
                                  sn=kvr.sn+1,
                                  data=[])

        sigers = mgr.sign(ser=srdr.raw, verfers=verfers)

        msg = bytearray(srdr.raw)
        counter = coring.SigCounter(count=2)
        msg.extend(counter.qb64b)
        msg.extend(sigers[0].qb64b)
        msg.extend(sigers[3].qb64b)

        # apply msg to Kevery
        kvy.processAll(ims=bytearray(msg))  # process local copy of msg
        assert kvr.serder.diger.qb64 != srdr.dig  # key state not updated

        # process escrow
        kvy.processPartials()
        assert kvr.serder.diger.qb64 != srdr.dig  # key state not updated

        msg = bytearray(srdr.raw)
        counter = coring.SigCounter(count=1)
        msg.extend(counter.qb64b)
        msg.extend(sigers[1].qb64b)

        # apply msg to Kevery
        kvy.processAll(ims=bytearray(msg))  # process local copy of msg
        assert kvr.serder.diger.qb64 != srdr.dig  # key state not updated

        # process escrow
        kvy.processPartials()
        assert kvr.serder.diger.qb64 == srdr.dig  # key state updated

    assert not os.path.exists(kpr.path)
    assert not os.path.exists(db.path)

    """End Test"""


def test_missing_delegator_escrow():
    """
    Test missing delegator escrow
    """
    # bob is the delegator del is bob's delegate

    bobSalt = coring.Salter(raw=b'0123456789abcdef').qb64
    delSalt = coring.Salter(raw=b'abcdef0123456789').qb64

    with dbing.openDB(name="bob") as bobDB, \
          keeping.openKeep(name="bob") as bobKp, \
          dbing.openDB(name="del") as delDB, \
          keeping.openKeep(name="del") as delKp:

        # Init key pair managers
        bobMgr = keeping.Manager(keeper=bobKp, salt=bobSalt)
        delMgr = keeping.Manager(keeper=delKp, salt=delSalt)

        # Init Keverys
        bobKvy = eventing.Kevery(baser=bobDB)
        delKvy = eventing.Kevery(baser=delDB)

        # Setup Bob by creating inception event
        verfers, digers = bobMgr.incept(stem='bob', temp=True) # algo default salty and rooted
        bobSrdr = eventing.incept(keys=[verfer.qb64 for verfer in verfers],
                                 nxt=coring.Nexter(digs=[diger.qb64 for diger in digers]).qb64,
                                 code=coring.CryOneDex.Blake3_256)

        bobPre = bobSrdr.ked["i"]

        bobMgr.move(old=verfers[0].qb64, new=bobPre)  # move key pair label to prefix

        sigers = bobMgr.sign(ser=bobSrdr.raw, verfers=verfers)

        msg = bytearray(bobSrdr.raw)
        counter = coring.SigCounter(count=len(sigers))
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        bobIcpMsg = msg  # save for later

        # apply msg to bob's Kevery
        bobKvy.processAll(ims=bytearray(msg))  # process local copy of msg
        bobK = bobKvy.kevers[bobPre]
        assert bobK.prefixer.qb64 == bobPre
        assert bobK.serder.diger.qb64 == bobSrdr.dig


        # Setup Del's inception event assuming that Bob's next event will be an ixn delegating event
        verfers, digers = delMgr.incept(stem='del', temp=True) # algo default salty and rooted

        seal = eventing.SealLocation(i=bobK.prefixer.qb64,
                                     s="{:x}".format(bobK.sn+1),
                                     t=coring.Ilks.ixn,
                                     p=bobK.serder.diger.qb64)

        delSrdr = eventing.delcept(keys=[verfer.qb64 for verfer in verfers],
                                   seal=seal,
                                   nxt=coring.Nexter(digs=[diger.qb64 for diger in digers]).qb64)

        delPre = delSrdr.ked["i"]

        delMgr.move(old=verfers[0].qb64, new=delPre)  # move key pair label to prefix

        # Now create delegating event
        seal = eventing.SealEvent(i=delPre,
                                  s=delSrdr.ked["s"],
                                  d=delSrdr.dig)
        bobSrdr = eventing.interact(pre=bobK.prefixer.qb64,
                                    dig=bobK.serder.diger.qb64,
                                    sn=bobK.sn+1,
                                    data=[seal._asdict()])

        sigers = bobMgr.sign(ser=bobSrdr.raw, verfers=bobK.verfers)

        msg = bytearray(bobSrdr.raw)
        counter = coring.SigCounter(count=len(sigers))
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        bobIxnMsg = msg

        # apply msg to bob's Kevery
        bobKvy.processAll(ims=bytearray(msg))  # process local copy of msg
        assert bobK.serder.diger.qb64 == bobSrdr.dig  # key state updated so event was validated

        # now create msg with Del's delegated inception event
        sigers = delMgr.sign(ser=delSrdr.raw, verfers=verfers)

        msg = bytearray(delSrdr.raw)
        counter = coring.SigCounter(count=len(sigers))
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)


        # apply Del's delegated inception event message to bob's Kevery
        bobKvy.processAll(ims=bytearray(msg))  # process local copy of msg
        assert delPre in bobKvy.kevers  # successfully validated
        delKbobKvy = bobKvy.kevers[delPre]  # delK in bobs kevery
        assert delKbobKvy.delegated
        assert delKbobKvy.serder.diger.qb64 == delSrdr.dig  # key state updated so event was validated


        # apply Del's inception msg to Del's Kevery
        # Dels event will fail but will add to its escrow
        delKvy.processAll(ims=bytearray(msg))  # process remote copy of msg
        assert delPre not in delKvy.kevers
        assert bobPre not in delKvy.kevers
        escrows = delKvy.baser.getPses(dbing.snKey(delPre, int(delSrdr.ked["s"], 16)))
        assert len(escrows) == 1
        assert escrows[0] == delSrdr.digb  #  escrow entry for event

        # verify Kevery process partials escrow is idempotent to previously escrowed events
        # assuming not stale but nothing else has changed
        delKvy.processPartials()
        assert delPre not in delKvy.kevers
        assert bobPre not in delKvy.kevers
        escrows = delKvy.baser.getPses(dbing.snKey(delPre, int(delSrdr.ked["s"], 16)))
        assert len(escrows) == 1
        assert escrows[0] == delSrdr.digb  #  escrow entry for event

        # apply Bob's inception to Dels' Kvy
        delKvy.processAll(ims=bytearray(bobIcpMsg))  # process remote copy of msg
        assert bobPre in delKvy.kevers  # mssage accepted
        delKvy.processPartials()  # process escrow
        assert delPre not in delKvy.kevers
        escrows = delKvy.baser.getPses(dbing.snKey(delPre, int(delSrdr.ked["s"], 16)))
        assert len(escrows) == 1
        assert escrows[0] == delSrdr.digb  #  escrow entry for event

        # apply Bob's delegating interaction to Dels' Kvy
        delKvy.processAll(ims=bytearray(bobIxnMsg))  # process remote copy of msg
        delKvy.processPartials()  # process escrows
        assert delPre in delKvy.kevers  # event removed from escrow
        assert delKvy.kevers[delPre].serder.diger.qb64 == delSrdr.dig
        escrows = delKvy.baser.getPses(dbing.snKey(delPre, int(delSrdr.ked["s"], 16)))
        assert len(escrows) == 0

        # Setup Del rotation event assuming that Bob's next event will be an ixn delegating event
        verfers, digers = delMgr.rotate(pre=delPre, temp=True)

        seal = eventing.SealLocation(i=bobK.prefixer.qb64,
                                     s="{:x}".format(bobK.sn+1),
                                     t=coring.Ilks.ixn,
                                     p=bobK.serder.diger.qb64)

        delSrdr = eventing.deltate(pre=delKbobKvy.prefixer.qb64,
                                   keys=[verfer.qb64 for verfer in verfers],
                                   dig=delKbobKvy.serder.diger.qb64,
                                   seal=seal,
                                   sn=delKbobKvy.sn+1,
                                   nxt=coring.Nexter(digs=[diger.qb64 for diger in digers]).qb64)

        # Now create delegating rotation event
        seal = eventing.SealEvent(i=delKbobKvy.prefixer.qb64,
                                  s=delSrdr.ked["s"],
                                  d=delSrdr.dig)
        bobSrdr = eventing.interact(pre=bobK.prefixer.qb64,
                                    dig=bobK.serder.diger.qb64,
                                    sn=bobK.sn+1,
                                    data=[seal._asdict()])

        sigers = bobMgr.sign(ser=bobSrdr.raw, verfers=bobK.verfers)

        msg = bytearray(bobSrdr.raw)
        counter = coring.SigCounter(count=len(sigers))
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        # apply msg to bob's Kevery
        bobKvy.processAll(ims=bytearray(msg))  # process local copy of msg
        assert bobK.serder.diger.qb64 == bobSrdr.dig  # key state updated so event was validated

        # apply msg to del's Kevery
        delKvy.processAll(ims=bytearray(msg))  # process remote copy of msg
        assert delKvy.kevers[bobPre].serder.diger.qb64 == bobSrdr.dig

        # now create msg from Del's delegated rotation event
        sigers = delMgr.sign(ser=delSrdr.raw, verfers=verfers)

        msg = bytearray(delSrdr.raw)
        counter = coring.SigCounter(count=len(sigers))
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        # apply Del's delegated inception event message to bob's Kevery
        bobKvy.processAll(ims=bytearray(msg))  # process local copy of msg
        assert delKbobKvy.delegated
        assert delKbobKvy.serder.diger.qb64 == delSrdr.dig  # key state updated so event was validated

        # apply msg to del's Kevery
        delKvy.processAll(ims=bytearray(msg))  # process remote copy of msg
        assert delKvy.kevers[delPre].serder.diger.qb64 == delSrdr.dig

    assert not os.path.exists(delKp.path)
    assert not os.path.exists(delDB.path)
    assert not os.path.exists(bobKp.path)
    assert not os.path.exists(bobDB.path)

    """End Test"""



if __name__ == "__main__":
    test_partial_signed_escrow()


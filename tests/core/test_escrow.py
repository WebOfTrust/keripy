# -*- encoding: utf-8 -*-
"""
tests escrows in database primarily logic in Kevery and Kever from keri.core.eventing

"""
import os

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
        # counter = coring.SigCounter(count=len(sigers))
        #for siger in sigers:
            #msg.extend(siger.qb64b)
        # add only one signature so creates partial sig escrow
        counter = coring.SigCounter(count=1)
        msg.extend(counter.qb64b)
        msg.extend(sigers[0].qb64b)

        # apply msg to Kevery
        kvy.processAll(ims=bytearray(msg))  # process local copy of msg
        assert pre not in kvy.kevers  # event not accepted
        escrows = kvy.baser.getPses(dbing.snKey(pre, int(srdr.ked["s"], 16)))
        assert len(escrows) == 1
        assert escrows[0] == srdr.digb  #  escrow entry for event

        # verify process is idempotent to escrowed events
        kvy.processAll(ims=bytearray(msg))  # process local copy of msg
        assert pre not in kvy.kevers  # event not accepted
        escrows = kvy.baser.getPses(dbing.snKey(pre, int(srdr.ked["s"], 16)))
        assert len(escrows) == 1
        assert escrows[0] == srdr.digb  #  escrow entry for event


        # apply msg to Kevery
        kvy.processAll(ims=bytearray(msg))  # process local copy of msg
        kvr = kvy.kevers[pre]  # kever created so event was validated
        assert kvr.prefixer.qb64 == pre
        assert kvr.serder.diger.qb64 == srdr.dig  # key state updated so event was validated

        # create interaction event for
        srdr = eventing.interact(pre=kvr.prefixer.qb64,
                                    dig=kvr.serder.diger.qb64,
                                    sn=kvr.sn+1,
                                    data=[])

        sigers = mgr.sign(ser=srdr.raw, verfers=kvr.verfers)

        msg = bytearray(srdr.raw)
        counter = coring.SigCounter(count=len(sigers))
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)


        # apply msg to Kevery
        kvy.processAll(ims=bytearray(msg))  # process local copy of msg
        assert kvr.serder.diger.qb64 == srdr.dig  # key state updated so event was validated

        # Create rotation event for
        # get current keys as verfers and next digests as digers
        verfers, digers = mgr.rotate(pre=pre, count=3, temp=True)
        nxtsith = ["1/2", "1/2", "1/2"]  #  2 of 3 but with weighted threshold

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
        assert kvr.serder.diger.qb64 == srdr.dig  # key state updated so event was validated

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
        assert kvr.serder.diger.qb64 == srdr.dig  # key state updated so event was validated

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
        assert kvr.serder.diger.qb64 == srdr.dig  # key state updated so event was validated


    assert not os.path.exists(kpr.path)
    assert not os.path.exists(db.path)

    """End Test"""


if __name__ == "__main__":
    test_partial_signed_escrow()


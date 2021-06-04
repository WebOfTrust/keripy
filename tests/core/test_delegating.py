# -*- encoding: utf-8 -*-
"""
tests delegation primaily from keri.core.eventing

"""
import os

import pytest

from keri import kering
from keri import help
from keri.db import dbing, basing
from keri.app import keeping
from keri.core import coring
from keri.core import eventing

logger = help.ogler.getLogger()


def test_delegation():
    """
    Test creation and validation of delegated identifer prefixes and events

    """
    # bob is the delegator del is bob's delegate

    bobSalt = coring.Salter(raw=b'0123456789abcdef').qb64
    delSalt = coring.Salter(raw=b'abcdef0123456789').qb64

    with basing.openDB(name="bob") as bobDB, \
          keeping.openKS(name="bob") as bobKS, \
          basing.openDB(name="del") as delDB, \
          keeping.openKS(name="del") as delKS:

        # Init key pair managers
        bobMgr = keeping.Manager(keeper=bobKS, salt=bobSalt)
        delMgr = keeping.Manager(keeper=delKS, salt=delSalt)

        # Init Keverys
        bobKvy = eventing.Kevery(db=bobDB)
        delKvy = eventing.Kevery(db=delDB)

        # Setup Bob by creating inception event
        verfers, digers, cst, nst = bobMgr.incept(stem='bob', temp=True) # algo default salty and rooted
        bobSrdr = eventing.incept(keys=[verfer.qb64 for verfer in verfers],
                                 nxt=coring.Nexter(digs=[diger.qb64 for diger in digers]).qb64,
                                 code=coring.MtrDex.Blake3_256)

        bob = bobSrdr.ked["i"]
        assert bob == 'Eta8KLf1zrE5n-HZpgRAnDmxLASZdXEiU9u6aahqR8TI'

        bobMgr.move(old=verfers[0].qb64, new=bob)  # move key pair label to prefix

        sigers = bobMgr.sign(ser=bobSrdr.raw, verfers=verfers)

        msg = bytearray(bobSrdr.raw)
        counter = coring.Counter(code=coring.CtrDex.ControllerIdxSigs, count=len(sigers))
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        assert msg == (b'{"v":"KERI10JSON0000ed_","i":"Eta8KLf1zrE5n-HZpgRAnDmxLASZdXEiU9'
                    b'u6aahqR8TI","s":"0","t":"icp","kt":"1","k":["DqI2cOZ06RwGNwCovYU'
                    b'WExmdKU983IasmUKMmZflvWdQ"],"n":"E7FuL3Z_KBgt_QAwuZi1lUFNC69wvyH'
                    b'SxnMFUsKjZHss","bt":"0","b":[],"c":[],"a":[]}-AABAAp8S6RgfLwdCEi'
                    b'z0jL9cXaDwTJF6MLuKyXp7EfJtrp2myOikOJVUB-w9UGZc1Y8dnURxhXPSca-ZEU'
                    b'AV73XOaAw')

        # apply msg to bob's Kevery
        eventing.Parser().process(ims=bytearray(msg), kvy=bobKvy)
        # bobKvy.process(ims=bytearray(msg))  # process local copy of msg
        bobK = bobKvy.kevers[bob]
        assert bobK.prefixer.qb64 == bob
        assert bobK.serder.diger.qb64 == bobSrdr.dig
        assert bobK.serder.diger.qb64 == 'E1-QL0TCdsBTRaKoakLjFhjSlELK60Vv8WdRaG6zMnTM'

        # apply msg to del's Kevery
        eventing.Parser().process(ims=bytearray(msg), kvy=delKvy)
        # delKvy.process(ims=bytearray(msg))  # process remote copy of msg
        assert bob in delKvy.kevers

        # Setup Del's inception event assuming that Bob's next event will be an ixn delegating event
        verfers, digers, cst, nst = delMgr.incept(stem='del', temp=True) # algo default salty and rooted


        delSrdr = eventing.delcept(keys=[verfer.qb64 for verfer in verfers],
                                   delpre=bobK.prefixer.qb64,
                                   nxt=coring.Nexter(digs=[diger.qb64 for diger in digers]).qb64)

        delPre = delSrdr.ked["i"]
        assert delPre == 'E-9tsnVcfUyXVQyBPGfntoL-xexf4Cldt_EPzHis2W4U'

        delMgr.move(old=verfers[0].qb64, new=delPre)  # move key pair label to prefix
        assert delSrdr.dig == 'E1x1JOub6oEQkxAxTNFu1Pma6y-lrbprNsaILHJHoPmY'


        # Now create delegating event
        seal = eventing.SealEvent(i=delPre,
                                  s=delSrdr.ked["s"],
                                  d=delSrdr.dig)
        bobSrdr = eventing.interact(pre=bobK.prefixer.qb64,
                                    dig=bobK.serder.diger.qb64,
                                    sn=bobK.sn+1,
                                    data=[seal._asdict()])

        assert bobSrdr.dig == 'E3fUycq1G-P1K1pL2OhvY6ZU-9otSa3hXiCcrxuhjyII'

        sigers = bobMgr.sign(ser=bobSrdr.raw, verfers=bobK.verfers)
        msg = bytearray(bobSrdr.raw)
        counter = coring.Counter(code=coring.CtrDex.ControllerIdxSigs,
                                 count=len(sigers))
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        assert msg == (b'{"v":"KERI10JSON000107_","i":"Eta8KLf1zrE5n-HZpgRAnDmxLASZdXEiU9'
                        b'u6aahqR8TI","s":"1","t":"ixn","p":"E1-QL0TCdsBTRaKoakLjFhjSlELK6'
                        b'0Vv8WdRaG6zMnTM","a":[{"i":"E-9tsnVcfUyXVQyBPGfntoL-xexf4Cldt_EP'
                        b'zHis2W4U","s":"0","d":"E1x1JOub6oEQkxAxTNFu1Pma6y-lrbprNsaILHJHo'
                        b'PmY"}]}-AABAAROVSK0qK2gqlr_OUsnHNW_ksCyLVmRaysRne2dI5dweECGIy3_Z'
                        b'uFHyOofiDRt5tRE09PlS0uZdot6byFNr-AA')

        # apply msg to bob's Kevery
        eventing.Parser().process(ims=bytearray(msg), kvy=bobKvy)
        # bobKvy.process(ims=bytearray(msg))  # process local copy of msg
        assert bobK.serder.diger.qb64 == bobSrdr.dig  # key state updated so event was validated

        # apply msg to del's Kevery
        eventing.Parser().process(ims=bytearray(msg), kvy=delKvy)
        # delKvy.process(ims=bytearray(msg))  # process remote copy of msg
        assert delKvy.kevers[bob].serder.diger.qb64 == bobSrdr.dig

        # now create msg with Del's delegated inception event
        sigers = delMgr.sign(ser=delSrdr.raw, verfers=verfers)

        #seal = eventing.SealSource(s="{:x}".format(bobK.sn+1),
                                   #d=bobSrdr.diger.qb64)

        msg = bytearray(delSrdr.raw)
        counter = coring.Counter(code=coring.CtrDex.ControllerIdxSigs,
                                 count=len(sigers))
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)
        counter = coring.Counter(code=coring.CtrDex.SealSourceCouples,
                                     count=1)
        msg.extend(counter.qb64b)
        seqner = coring.Seqner(sn=bobK.sn)
        msg.extend(seqner.qb64b)
        msg.extend(bobSrdr.diger.qb64b)

        assert msg == (b'{"v":"KERI10JSON000121_","i":"E-9tsnVcfUyXVQyBPGfntoL-xexf4Cldt_'
                        b'EPzHis2W4U","s":"0","t":"dip","kt":"1","k":["DuK1x8ydpucu3480Jpd'
                        b'1XBfjnCwb3dZ3x5b1CJmuUphA"],"n":"EWWkjZkZDXF74O2bOQ4H5hu4nXDlKg2'
                        b'm4CBEBkUxibiU","bt":"0","b":[],"c":[],"a":[],"di":"Eta8KLf1zrE5n'
                        b'-HZpgRAnDmxLASZdXEiU9u6aahqR8TI"}-AABAA2_8Guj0Gf2JoNTq7hOs4u6eOO'
                        b'WhENALJWDfLxkVcS2uLh753FjtyE80lpeS3to1C9yvENyMnyN4q96ehA4exDA-GA'
                        b'B0AAAAAAAAAAAAAAAAAAAAAAQE3fUycq1G-P1K1pL2OhvY6ZU-9otSa3hXiCcrxu'
                        b'hjyII')

        # apply Del's delegated inception event message to Del's own Kevery
        eventing.Parser().process(ims=bytearray(msg), kvy=delKvy)
        # delKvy.process(ims=bytearray(msg))  # process remote copy of msg
        assert delPre in delKvy.kevers
        delK = delKvy.kevers[delPre]
        assert delK.delegated
        assert delK.serder.diger.qb64 == delSrdr.dig
        couple = delKvy.db.getAes(dbing.dgKey(delPre, delSrdr.dig))
        assert couple == seqner.qb64b + bobSrdr.diger.qb64b

        # apply Del's delegated inception event message to bob's Kevery
        eventing.Parser().process(ims=bytearray(msg), kvy=bobKvy)
        # bobKvy.process(ims=bytearray(msg))  # process local copy of msg
        assert delPre in bobKvy.kevers  # successfully validated
        bobDelK = bobKvy.kevers[delPre]
        assert bobDelK.delegated
        assert bobDelK.serder.diger.qb64 == delSrdr.dig  # key state updated so event was validated
        couple = bobKvy.db.getAes(dbing.dgKey(delPre, delSrdr.dig))
        assert couple == seqner.qb64b + bobSrdr.diger.qb64b

        # Setup Del rotation event assuming that Bob's next event will be an ixn delegating event
        verfers, digers, cst, nst = delMgr.rotate(pre=delPre, temp=True)

        delSrdr = eventing.deltate(pre=bobDelK.prefixer.qb64,
                                   keys=[verfer.qb64 for verfer in verfers],
                                   dig=bobDelK.serder.diger.qb64,
                                   sn=bobDelK.sn+1,
                                   nxt=coring.Nexter(digs=[diger.qb64 for diger in digers]).qb64)

        assert delSrdr.dig == 'EPjLBcb4pp-3PGvSi_fTvLvsqUqFoJ0CVCHvIFfu93Xc'

        # Now create delegating interaction event
        seal = eventing.SealEvent(i=bobDelK.prefixer.qb64,
                                  s=delSrdr.ked["s"],
                                  d=delSrdr.dig)
        bobSrdr = eventing.interact(pre=bobK.prefixer.qb64,
                                    dig=bobK.serder.diger.qb64,
                                    sn=bobK.sn+1,
                                    data=[seal._asdict()])

        sigers = bobMgr.sign(ser=bobSrdr.raw, verfers=bobK.verfers)

        msg = bytearray(bobSrdr.raw)
        counter = coring.Counter(code=coring.CtrDex.ControllerIdxSigs,
                                 count=len(sigers))
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        assert msg == bytearray(b'{"v":"KERI10JSON000107_","i":"Eta8KLf1zrE5n-HZpgRAnDmxLASZdXEiU9'
                                b'u6aahqR8TI","s":"2","t":"ixn","p":"E3fUycq1G-P1K1pL2OhvY6ZU-9otS'
                                b'a3hXiCcrxuhjyII","a":[{"i":"E-9tsnVcfUyXVQyBPGfntoL-xexf4Cldt_EP'
                                b'zHis2W4U","s":"1","d":"EPjLBcb4pp-3PGvSi_fTvLvsqUqFoJ0CVCHvIFfu9'
                                b'3Xc"}]}-AABAAclMVE-bkIn-wPiAqfgR384nWmslQHQvmo2o3xQvd_4Bt6bflc4B'
                                b'AmfBa03KgrDVqmB7qG2VXQbOHevkzOgRdDA')

        # apply msg to bob's Kevery
        eventing.Parser().process(ims=bytearray(msg), kvy=bobKvy)
        # bobKvy.process(ims=bytearray(msg))  # process local copy of msg
        assert bobK.serder.diger.qb64 == bobSrdr.dig  # key state updated so event was validated

        # apply msg to del's Kevery
        eventing.Parser().process(ims=bytearray(msg), kvy=delKvy)
        # delKvy.process(ims=bytearray(msg))  # process remote copy of msg
        assert delKvy.kevers[bob].serder.diger.qb64 == bobSrdr.dig

        # now create msg from Del's delegated rotation event
        sigers = delMgr.sign(ser=delSrdr.raw, verfers=verfers)

        msg = bytearray(delSrdr.raw)
        counter = coring.Counter(code=coring.CtrDex.ControllerIdxSigs,
                                 count=len(sigers))
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)
        counter = coring.Counter(code=coring.CtrDex.SealSourceCouples,
                                     count=1)
        msg.extend(counter.qb64b)
        seqner = coring.Seqner(sn=bobK.sn)
        msg.extend(seqner.qb64b)
        msg.extend(bobSrdr.diger.qb64b)


        assert msg == (b'{"v":"KERI10JSON000122_","i":"E-9tsnVcfUyXVQyBPGfntoL-xexf4Cldt_'
                       b'EPzHis2W4U","s":"1","t":"drt","p":"E1x1JOub6oEQkxAxTNFu1Pma6y-lr'
                       b'bprNsaILHJHoPmY","kt":"1","k":["DTf6QZWoet154o9wvzeMuNhLQRr8JaAU'
                       b'eiC6wjB_4_08"],"n":"E8kyiXDfkE7idwWnAZQjHbUZMz-kd_yIMH0miptIFFPo'
                       b'","bt":"0","br":[],"ba":[],"a":[]}-AABAAAVUMNfOl9Fcqx-C3fAYnaxvs'
                       b'iJJO3zG6rP0FQ2WVp__hMEaprrQbJL6-Esnny3U5zvMOqbso17rvecTwmVIwDw-G'
                       b'AB0AAAAAAAAAAAAAAAAAAAAAAgEbOI0OIIFv2VV5bmeSq1pwCn-6b2k6TdWcCbJH'
                       b'E6Ly7o')


        # apply msg to del's Kevery
        eventing.Parser().process(ims=bytearray(msg), kvy=delKvy)
        # delKvy.process(ims=bytearray(msg))  # process remote copy of msg
        assert bobDelK.delegated
        assert delK.serder.diger.qb64 == delSrdr.dig
        couple = delKvy.db.getAes(dbing.dgKey(delPre, delSrdr.dig))
        assert couple == seqner.qb64b + bobSrdr.diger.qb64b

        # apply Del's delegated inception event message to bob's Kevery
        eventing.Parser().process(ims=bytearray(msg), kvy=bobKvy)
        # bobKvy.process(ims=bytearray(msg))  # process local copy of msg
        assert bobDelK.delegated
        assert bobDelK.serder.diger.qb64 == delSrdr.dig  # key state updated so event was validated
        couple = delKvy.db.getAes(dbing.dgKey(delPre, delSrdr.dig))
        assert couple == seqner.qb64b + bobSrdr.diger.qb64b

        # test replay
        msgs = bytearray()
        for msg in delKvy.db.clonePreIter(pre=delPre, fn=0):
            msgs.extend(msg)
        assert len(msgs) == 1043
        assert couple in msgs



    assert not os.path.exists(delKS.path)
    assert not os.path.exists(delDB.path)
    assert not os.path.exists(bobKS.path)
    assert not os.path.exists(bobDB.path)

    """End Test"""


if __name__ == "__main__":
    test_delegation()

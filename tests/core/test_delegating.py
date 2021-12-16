# -*- encoding: utf-8 -*-
"""
tests delegation primaily from keri.core.eventing

"""
import os

from keri import help
from keri.app import keeping
from keri.core import coring, eventing, parsing
from keri.db import dbing, basing

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
        bobMgr = keeping.Manager(ks=bobKS, salt=bobSalt)
        delMgr = keeping.Manager(ks=delKS, salt=delSalt)

        # Init Keverys
        bobKvy = eventing.Kevery(db=bobDB)
        delKvy = eventing.Kevery(db=delDB)

        # Setup Bob by creating inception event
        verfers, digers, cst, nst = bobMgr.incept(stem='bob', temp=True)  # algo default salty and rooted
        bobSrdr = eventing.incept(keys=[verfer.qb64 for verfer in verfers],
                                  nxt=coring.Nexter(digs=[diger.qb64 for diger in digers]).qb64,
                                  code=coring.MtrDex.Blake3_256)

        bob = bobSrdr.ked["i"]
        assert bob == 'Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8'

        bobMgr.move(old=verfers[0].qb64, new=bob)  # move key pair label to prefix

        sigers = bobMgr.sign(ser=bobSrdr.raw, verfers=verfers)

        msg = bytearray(bobSrdr.raw)
        counter = coring.Counter(code=coring.CtrDex.ControllerIdxSigs, count=len(sigers))
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        assert msg == (b'{"v":"KERI10JSON000120_","t":"icp","d":"ExlxAnFCuDpC2jUsbG_j4j2c'
                       b'w24IEwXPJjVHo9avJlu4","i":"Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEG'
                       b'dpPVWV8","s":"0","kt":"1","k":["DqI2cOZ06RwGNwCovYUWExmdKU983Ias'
                       b'mUKMmZflvWdQ"],"n":"E7FuL3Z_KBgt_QAwuZi1lUFNC69wvyHSxnMFUsKjZHss'
                       b'","bt":"0","b":[],"c":[],"a":[]}-AABAApyNjPzGKfc9j2A6YjNfCaaVvLQ'
                       b'-iOMD2kHGaJpfwd_GrWzDyD3fFB8EHk2WWSm5Xerl6Rbfnj0ezlHinO_fQBw')

        # apply msg to bob's Kevery
        parsing.Parser().parse(ims=bytearray(msg), kvy=bobKvy)
        # bobKvy.process(ims=bytearray(msg))  # process local copy of msg
        bobK = bobKvy.kevers[bob]
        assert bobK.prefixer.qb64 == bob
        assert bobK.serder.diger.qb64 == bobSrdr.dig
        assert bobK.serder.diger.qb64 == 'ExlxAnFCuDpC2jUsbG_j4j2cw24IEwXPJjVHo9avJlu4'

        # apply msg to del's Kevery
        parsing.Parser().parse(ims=bytearray(msg), kvy=delKvy)
        # delKvy.process(ims=bytearray(msg))  # process remote copy of msg
        assert bob in delKvy.kevers

        # Setup Del's inception event assuming that Bob's next event will be an ixn delegating event
        verfers, digers, cst, nst = delMgr.incept(stem='del', temp=True)  # algo default salty and rooted

        delSrdr = eventing.delcept(keys=[verfer.qb64 for verfer in verfers],
                                   delpre=bobK.prefixer.qb64,
                                   nxt=coring.Nexter(digs=[diger.qb64 for diger in digers]).qb64)

        delPre = delSrdr.ked["i"]
        assert delPre == 'Er4bHXd4piEtsQat1mquwsNZXItvuoj_auCUyICmwyXI'

        delMgr.move(old=verfers[0].qb64, new=delPre)  # move key pair label to prefix
        assert delSrdr.dig == 'EICQDlgWNjlshgzphFMk8tMgz2HcWC4efN-ayxxmrGzw'

        # Now create delegating event
        seal = eventing.SealEvent(i=delPre,
                                  s=delSrdr.ked["s"],
                                  d=delSrdr.dig)
        bobSrdr = eventing.interact(pre=bobK.prefixer.qb64,
                                    dig=bobK.serder.diger.qb64,
                                    sn=bobK.sn + 1,
                                    data=[seal._asdict()])

        assert bobSrdr.dig == 'EdQYAzAnChP63I-Yahu9iBh0vltE8wVUXb1NiTz0GnwE'

        sigers = bobMgr.sign(ser=bobSrdr.raw, verfers=bobK.verfers)
        msg = bytearray(bobSrdr.raw)
        counter = coring.Counter(code=coring.CtrDex.ControllerIdxSigs,
                                 count=len(sigers))
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        assert msg == (b'{"v":"KERI10JSON00013a_","t":"ixn","d":"EdQYAzAnChP63I-Yahu9iBh0'
                  b'vltE8wVUXb1NiTz0GnwE","i":"Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEG'
                  b'dpPVWV8","s":"1","p":"ExlxAnFCuDpC2jUsbG_j4j2cw24IEwXPJjVHo9avJl'
                  b'u4","a":[{"i":"Er4bHXd4piEtsQat1mquwsNZXItvuoj_auCUyICmwyXI","s"'
                  b':"0","d":"EICQDlgWNjlshgzphFMk8tMgz2HcWC4efN-ayxxmrGzw"}]}-AABAA'
                  b'4Ur8pBV5KlvXHuojFsdsE5JSHO2rw_kaf_ku2TsVzidTi9ZgzgJiaK4-wBgWaZH-'
                  b'PsuSvpYfnVvOi6wXmy_tBA')

        # apply msg to bob's Kevery
        parsing.Parser().parse(ims=bytearray(msg), kvy=bobKvy)
        # bobKvy.process(ims=bytearray(msg))  # process local copy of msg
        assert bobK.serder.diger.qb64 == bobSrdr.dig  # key state updated so event was validated

        # apply msg to del's Kevery
        parsing.Parser().parse(ims=bytearray(msg), kvy=delKvy)
        # delKvy.process(ims=bytearray(msg))  # process remote copy of msg
        assert delKvy.kevers[bob].serder.diger.qb64 == bobSrdr.dig

        # now create msg with Del's delegated inception event
        sigers = delMgr.sign(ser=delSrdr.raw, verfers=verfers)

        # seal = eventing.SealSource(s="{:x}".format(bobK.sn+1),
        # d=bobSrdr.diger.qb64)

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

        assert msg == (b'{"v":"KERI10JSON000154_","t":"dip","d":"EICQDlgWNjlshgzphFMk8tMg'
                  b'z2HcWC4efN-ayxxmrGzw","i":"Er4bHXd4piEtsQat1mquwsNZXItvuoj_auCUy'
                  b'ICmwyXI","s":"0","kt":"1","k":["DuK1x8ydpucu3480Jpd1XBfjnCwb3dZ3'
                  b'x5b1CJmuUphA"],"n":"EWWkjZkZDXF74O2bOQ4H5hu4nXDlKg2m4CBEBkUxibiU'
                  b'","bt":"0","b":[],"c":[],"a":[],"di":"Et78eYkh8A3H9w6Q87EC5Ociji'
                  b'VEJT8KyNtEGdpPVWV8"}-AABAA3S8XBk2G8CDI2v6xFAuXmDFsMxA2rjLhWD40HR'
                  b'UVbMcdmmy72PxpDuBokFN_fMclbq2Ffch_I4r_f7D4FOrfBQ-GAB0AAAAAAAAAAA'
                  b'AAAAAAAAAAAQEdQYAzAnChP63I-Yahu9iBh0vltE8wVUXb1NiTz0GnwE')

        # apply Del's delegated inception event message to Del's own Kevery
        parsing.Parser().parse(ims=bytearray(msg), kvy=delKvy)
        # delKvy.process(ims=bytearray(msg))  # process remote copy of msg
        assert delPre in delKvy.kevers
        delK = delKvy.kevers[delPre]
        assert delK.delegated
        assert delK.serder.diger.qb64 == delSrdr.dig
        couple = delKvy.db.getAes(dbing.dgKey(delPre, delSrdr.dig))
        assert couple == seqner.qb64b + bobSrdr.diger.qb64b

        # apply Del's delegated inception event message to bob's Kevery
        parsing.Parser().parse(ims=bytearray(msg), kvy=bobKvy)
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
                                   sn=bobDelK.sn + 1,
                                   nxt=coring.Nexter(digs=[diger.qb64 for diger in digers]).qb64)

        assert delSrdr.dig == 'ExoKrLr3T2Dtng9RkIwod6FtavVe7gp4AmLdc45kz1Tc'

        # Now create delegating interaction event
        seal = eventing.SealEvent(i=bobDelK.prefixer.qb64,
                                  s=delSrdr.ked["s"],
                                  d=delSrdr.dig)
        bobSrdr = eventing.interact(pre=bobK.prefixer.qb64,
                                    dig=bobK.serder.diger.qb64,
                                    sn=bobK.sn + 1,
                                    data=[seal._asdict()])

        sigers = bobMgr.sign(ser=bobSrdr.raw, verfers=bobK.verfers)

        msg = bytearray(bobSrdr.raw)
        counter = coring.Counter(code=coring.CtrDex.ControllerIdxSigs,
                                 count=len(sigers))
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        assert msg == bytearray(b'{"v":"KERI10JSON00013a_","t":"ixn","d":"EQoPloS1vGdHesMoF1AtSn8Y'
                  b'oGFPFq0uyp5-lM8SZ-BU","i":"Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEG'
                  b'dpPVWV8","s":"2","p":"EdQYAzAnChP63I-Yahu9iBh0vltE8wVUXb1NiTz0Gn'
                  b'wE","a":[{"i":"Er4bHXd4piEtsQat1mquwsNZXItvuoj_auCUyICmwyXI","s"'
                  b':"1","d":"ExoKrLr3T2Dtng9RkIwod6FtavVe7gp4AmLdc45kz1Tc"}]}-AABAA'
                  b'GwOzjptvmpBdNq0flVB8YKVB-8VD3YmHDLlsqD3hTjjCaDUgutDeJYIePXnDeySd'
                  b'QAjBpFaJPIT9ISYr-B42Bw')

        # apply msg to bob's Kevery
        parsing.Parser().parse(ims=bytearray(msg), kvy=bobKvy)
        # bobKvy.process(ims=bytearray(msg))  # process local copy of msg
        assert bobK.serder.diger.qb64 == bobSrdr.dig  # key state updated so event was validated

        # apply msg to del's Kevery
        parsing.Parser().parse(ims=bytearray(msg), kvy=delKvy)
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

        assert msg == (b'{"v":"KERI10JSON000155_","t":"drt","d":"ExoKrLr3T2Dtng9RkIwod6Ft'
                  b'avVe7gp4AmLdc45kz1Tc","i":"Er4bHXd4piEtsQat1mquwsNZXItvuoj_auCUy'
                  b'ICmwyXI","s":"1","p":"EICQDlgWNjlshgzphFMk8tMgz2HcWC4efN-ayxxmrG'
                  b'zw","kt":"1","k":["DTf6QZWoet154o9wvzeMuNhLQRr8JaAUeiC6wjB_4_08"'
                  b'],"n":"E8kyiXDfkE7idwWnAZQjHbUZMz-kd_yIMH0miptIFFPo","bt":"0","b'
                  b'r":[],"ba":[],"a":[]}-AABAA50YsNHYYsJ7Y5UmbQ8eAkXsTlr376r-fPhyoK'
                  b'OpSSZgfBPnWZ7RVPY7H2OIozmSZbmsoYfFM0pWqI338IaI2Dg-GAB0AAAAAAAAAA'
                  b'AAAAAAAAAAAAgEQoPloS1vGdHesMoF1AtSn8YoGFPFq0uyp5-lM8SZ-BU')

        # apply msg to del's Kevery
        parsing.Parser().parse(ims=bytearray(msg), kvy=delKvy)
        # delKvy.process(ims=bytearray(msg))  # process remote copy of msg
        assert bobDelK.delegated
        assert delK.serder.diger.qb64 == delSrdr.dig
        couple = delKvy.db.getAes(dbing.dgKey(delPre, delSrdr.dig))
        assert couple == seqner.qb64b + bobSrdr.diger.qb64b

        # apply Del's delegated inception event message to bob's Kevery
        parsing.Parser().parse(ims=bytearray(msg), kvy=bobKvy)
        # bobKvy.process(ims=bytearray(msg))  # process local copy of msg
        assert bobDelK.delegated
        assert bobDelK.serder.diger.qb64 == delSrdr.dig  # key state updated so event was validated
        couple = delKvy.db.getAes(dbing.dgKey(delPre, delSrdr.dig))
        assert couple == seqner.qb64b + bobSrdr.diger.qb64b

        # test replay
        msgs = bytearray()
        for msg in delKvy.db.clonePreIter(pre=delPre, fn=0):
            msgs.extend(msg)
        assert len(msgs) == 1145
        assert couple in msgs

    assert not os.path.exists(delKS.path)
    assert not os.path.exists(delDB.path)
    assert not os.path.exists(bobKS.path)
    assert not os.path.exists(bobDB.path)

    """End Test"""


if __name__ == "__main__":
    test_delegation()

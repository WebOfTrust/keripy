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

        assert msg == (b'{"v":"KERI10JSON000120_","t":"icp","d":"Et78eYkh8A3H9w6Q87EC5Oci'
                       b'jiVEJT8KyNtEGdpPVWV8","i":"Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEG'
                       b'dpPVWV8","s":"0","kt":"1","k":["DqI2cOZ06RwGNwCovYUWExmdKU983Ias'
                       b'mUKMmZflvWdQ"],"n":"E7FuL3Z_KBgt_QAwuZi1lUFNC69wvyHSxnMFUsKjZHss'
                       b'","bt":"0","b":[],"c":[],"a":[]}-AABAAJEloPu7b4z8v1455StEJ1b7dMI'
                       b'z-P0tKJ_GBBCxQA8JEg0gm8qbS4TWGiHikLoZ2GtLA58l9dzIa2x_otJhoDA')

        # apply msg to bob's Kevery
        parsing.Parser().parse(ims=bytearray(msg), kvy=bobKvy)
        # bobKvy.process(ims=bytearray(msg))  # process local copy of msg
        bobK = bobKvy.kevers[bob]
        assert bobK.prefixer.qb64 == bob
        assert bobK.serder.saider.qb64 == bobSrdr.said
        assert bobK.serder.saider.qb64 == 'Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8'

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
        assert delSrdr.said == 'Er4bHXd4piEtsQat1mquwsNZXItvuoj_auCUyICmwyXI'

        # Now create delegating event
        seal = eventing.SealEvent(i=delPre,
                                  s=delSrdr.ked["s"],
                                  d=delSrdr.said)
        bobSrdr = eventing.interact(pre=bobK.prefixer.qb64,
                                    dig=bobK.serder.saider.qb64,
                                    sn=bobK.sn + 1,
                                    data=[seal._asdict()])

        assert bobSrdr.said == 'E1_-icBrwC_HhxyFwsQLV6hZEbApOc_McGUjhLONpQuc'

        sigers = bobMgr.sign(ser=bobSrdr.raw, verfers=bobK.verfers)
        msg = bytearray(bobSrdr.raw)
        counter = coring.Counter(code=coring.CtrDex.ControllerIdxSigs,
                                 count=len(sigers))
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        assert msg == (b'{"v":"KERI10JSON00013a_","t":"ixn","d":"E1_-icBrwC_HhxyFwsQLV6hZ'
                       b'EbApOc_McGUjhLONpQuc","i":"Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEG'
                       b'dpPVWV8","s":"1","p":"Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVW'
                       b'V8","a":[{"i":"Er4bHXd4piEtsQat1mquwsNZXItvuoj_auCUyICmwyXI","s"'
                       b':"0","d":"Er4bHXd4piEtsQat1mquwsNZXItvuoj_auCUyICmwyXI"}]}-AABAA'
                       b'6h5mD5stIwO_rwV9apMuhHXjxrKp2ATa35u-H6DM2X-BKo5NkJ1khzBdHo-VLQ6Z'
                       b'w_yajj2Ul_WOL8pFSk_ZDg')

        # apply msg to bob's Kevery
        parsing.Parser().parse(ims=bytearray(msg), kvy=bobKvy)
        # bobKvy.process(ims=bytearray(msg))  # process local copy of msg
        assert bobK.serder.saider.qb64 == bobSrdr.said  # key state updated so event was validated

        # apply msg to del's Kevery
        parsing.Parser().parse(ims=bytearray(msg), kvy=delKvy)
        # delKvy.process(ims=bytearray(msg))  # process remote copy of msg
        assert delKvy.kevers[bob].serder.saider.qb64 == bobSrdr.said

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
        msg.extend(bobSrdr.saider.qb64b)

        assert msg == (b'{"v":"KERI10JSON000154_","t":"dip","d":"Er4bHXd4piEtsQat1mquwsNZ'
                       b'XItvuoj_auCUyICmwyXI","i":"Er4bHXd4piEtsQat1mquwsNZXItvuoj_auCUy'
                       b'ICmwyXI","s":"0","kt":"1","k":["DuK1x8ydpucu3480Jpd1XBfjnCwb3dZ3'
                       b'x5b1CJmuUphA"],"n":"EWWkjZkZDXF74O2bOQ4H5hu4nXDlKg2m4CBEBkUxibiU'
                       b'","bt":"0","b":[],"c":[],"a":[],"di":"Et78eYkh8A3H9w6Q87EC5Ociji'
                       b'VEJT8KyNtEGdpPVWV8"}-AABAA_zcT2-86Zll3FG-hwoQiVuFiT0X28Ft0t4fZGN'
                       b'FISgtZjH2DCrBGoceko604NDZ0QF0Z3bSgEkN_y0lBafD_Bw-GAB0AAAAAAAAAAA'
                       b'AAAAAAAAAAAQE1_-icBrwC_HhxyFwsQLV6hZEbApOc_McGUjhLONpQuc')

        # apply Del's delegated inception event message to Del's own Kevery
        parsing.Parser().parse(ims=bytearray(msg), kvy=delKvy)
        # delKvy.process(ims=bytearray(msg))  # process remote copy of msg
        assert delPre in delKvy.kevers
        delK = delKvy.kevers[delPre]
        assert delK.delegated
        assert delK.serder.saider.qb64 == delSrdr.said
        couple = delKvy.db.getAes(dbing.dgKey(delPre, delSrdr.said))
        assert couple == seqner.qb64b + bobSrdr.saider.qb64b

        # apply Del's delegated inception event message to bob's Kevery
        parsing.Parser().parse(ims=bytearray(msg), kvy=bobKvy)
        # bobKvy.process(ims=bytearray(msg))  # process local copy of msg
        assert delPre in bobKvy.kevers  # successfully validated
        bobDelK = bobKvy.kevers[delPre]
        assert bobDelK.delegated
        assert bobDelK.serder.saider.qb64 == delSrdr.said  # key state updated so event was validated
        couple = bobKvy.db.getAes(dbing.dgKey(delPre, delSrdr.said))
        assert couple == seqner.qb64b + bobSrdr.saider.qb64b

        # Setup Del rotation event assuming that Bob's next event will be an ixn delegating event
        verfers, digers, cst, nst = delMgr.rotate(pre=delPre, temp=True)

        delSrdr = eventing.deltate(pre=bobDelK.prefixer.qb64,
                                   keys=[verfer.qb64 for verfer in verfers],
                                   dig=bobDelK.serder.saider.qb64,
                                   sn=bobDelK.sn + 1,
                                   nxt=coring.Nexter(digs=[diger.qb64 for diger in digers]).qb64)

        assert delSrdr.said == 'ELEnIYF_rAsluR9TI_jh5Dizq61dCXjos22AGN0hiVjw'

        # Now create delegating interaction event
        seal = eventing.SealEvent(i=bobDelK.prefixer.qb64,
                                  s=delSrdr.ked["s"],
                                  d=delSrdr.said)
        bobSrdr = eventing.interact(pre=bobK.prefixer.qb64,
                                    dig=bobK.serder.saider.qb64,
                                    sn=bobK.sn + 1,
                                    data=[seal._asdict()])

        sigers = bobMgr.sign(ser=bobSrdr.raw, verfers=bobK.verfers)

        msg = bytearray(bobSrdr.raw)
        counter = coring.Counter(code=coring.CtrDex.ControllerIdxSigs,
                                 count=len(sigers))
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        assert msg == bytearray(b'{"v":"KERI10JSON00013a_","t":"ixn","d":"Eq-MPVuYTPXNUlQSHKfnPhiV'
                                b'3rWo7hkkLa7ui67OIG68","i":"Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEG'
                                b'dpPVWV8","s":"2","p":"E1_-icBrwC_HhxyFwsQLV6hZEbApOc_McGUjhLONpQ'
                                b'uc","a":[{"i":"Er4bHXd4piEtsQat1mquwsNZXItvuoj_auCUyICmwyXI","s"'
                                b':"1","d":"ELEnIYF_rAsluR9TI_jh5Dizq61dCXjos22AGN0hiVjw"}]}-AABAA'
                                b'-QDEYYQCDtosLkziTAaWTu3mfVdFUxa8tytwQVohRwBJEhefCIaCDIbFhrrEn17K'
                                b'MwGoOJKBrJ7Da4WqeWbtAA')

        # apply msg to bob's Kevery
        parsing.Parser().parse(ims=bytearray(msg), kvy=bobKvy)
        # bobKvy.process(ims=bytearray(msg))  # process local copy of msg
        assert bobK.serder.saider.qb64 == bobSrdr.said  # key state updated so event was validated

        # apply msg to del's Kevery
        parsing.Parser().parse(ims=bytearray(msg), kvy=delKvy)
        # delKvy.process(ims=bytearray(msg))  # process remote copy of msg
        assert delKvy.kevers[bob].serder.saider.qb64 == bobSrdr.said

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
        msg.extend(bobSrdr.saider.qb64b)

        assert msg == (b'{"v":"KERI10JSON000155_","t":"drt","d":"ELEnIYF_rAsluR9TI_jh5Diz'
                       b'q61dCXjos22AGN0hiVjw","i":"Er4bHXd4piEtsQat1mquwsNZXItvuoj_auCUy'
                       b'ICmwyXI","s":"1","p":"Er4bHXd4piEtsQat1mquwsNZXItvuoj_auCUyICmwy'
                       b'XI","kt":"1","k":["DTf6QZWoet154o9wvzeMuNhLQRr8JaAUeiC6wjB_4_08"'
                       b'],"n":"E8kyiXDfkE7idwWnAZQjHbUZMz-kd_yIMH0miptIFFPo","bt":"0","b'
                       b'r":[],"ba":[],"a":[]}-AABAAer7S2mRuHlXxmJxy6E5lgdBmh3eeKd2Tnkyiv'
                       b'HlEw83Xhq98h6RBjXRDc_S0Z-TrLUS2u-6FnIkP_yYsOeH0Dg-GAB0AAAAAAAAAA'
                       b'AAAAAAAAAAAAgEq-MPVuYTPXNUlQSHKfnPhiV3rWo7hkkLa7ui67OIG68')

        # apply msg to del's Kevery
        parsing.Parser().parse(ims=bytearray(msg), kvy=delKvy)
        # delKvy.process(ims=bytearray(msg))  # process remote copy of msg
        assert bobDelK.delegated
        assert delK.serder.saider.qb64 == delSrdr.said
        couple = delKvy.db.getAes(dbing.dgKey(delPre, delSrdr.said))
        assert couple == seqner.qb64b + bobSrdr.saider.qb64b

        # apply Del's delegated inception event message to bob's Kevery
        parsing.Parser().parse(ims=bytearray(msg), kvy=bobKvy)
        # bobKvy.process(ims=bytearray(msg))  # process local copy of msg
        assert bobDelK.delegated
        assert bobDelK.serder.saider.qb64 == delSrdr.said  # key state updated so event was validated
        couple = delKvy.db.getAes(dbing.dgKey(delPre, delSrdr.said))
        assert couple == seqner.qb64b + bobSrdr.saider.qb64b

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

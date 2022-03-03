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
                                  nkeys=[diger.qb64 for diger in digers],
                                  code=coring.MtrDex.Blake3_256)

        bob = bobSrdr.ked["i"]
        assert bob == 'E7YbTIkWWyNwOxZQTTnrs6qn8jFbu2A8zftQ33JYQFQ0'

        bobMgr.move(old=verfers[0].qb64, new=bob)  # move key pair label to prefix

        sigers = bobMgr.sign(ser=bobSrdr.raw, verfers=verfers)

        msg = bytearray(bobSrdr.raw)
        counter = coring.Counter(code=coring.CtrDex.ControllerIdxSigs, count=len(sigers))
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        assert msg == (b'{"v":"KERI10JSON00012b_","t":"icp","d":"E7YbTIkWWyNwOxZQTTnrs6qn'
                       b'8jFbu2A8zftQ33JYQFQ0","i":"E7YbTIkWWyNwOxZQTTnrs6qn8jFbu2A8zftQ3'
                       b'3JYQFQ0","s":"0","kt":"1","k":["DqI2cOZ06RwGNwCovYUWExmdKU983Ias'
                       b'mUKMmZflvWdQ"],"nt":"1","n":["EOmBSdblll8qB4324PEmETrFN-DhElyZ0B'
                       b'cBH1q1qukw"],"bt":"0","b":[],"c":[],"a":[]}-AABAAotHSmS5LuCg2LXw'
                       b'landbAs3MFR0yTC5BbE2iSW_35U2qA0hP9gp66G--mHhiFmfHEIbBKrs3tjcc8yS'
                       b'vYcpiBg')

        # apply msg to bob's Kevery
        parsing.Parser().parse(ims=bytearray(msg), kvy=bobKvy)
        # bobKvy.process(ims=bytearray(msg))  # process local copy of msg
        bobK = bobKvy.kevers[bob]
        assert bobK.prefixer.qb64 == bob
        assert bobK.serder.saider.qb64 == bobSrdr.said
        assert bobK.serder.saider.qb64 == 'E7YbTIkWWyNwOxZQTTnrs6qn8jFbu2A8zftQ33JYQFQ0'

        # apply msg to del's Kevery
        parsing.Parser().parse(ims=bytearray(msg), kvy=delKvy)
        # delKvy.process(ims=bytearray(msg))  # process remote copy of msg
        assert bob in delKvy.kevers

        # Setup Del's inception event assuming that Bob's next event will be an ixn delegating event
        verfers, digers, cst, nst = delMgr.incept(stem='del', temp=True)  # algo default salty and rooted

        delSrdr = eventing.delcept(keys=[verfer.qb64 for verfer in verfers],
                                   delpre=bobK.prefixer.qb64,
                                   nkeys=[diger.qb64 for diger in digers])

        delPre = delSrdr.ked["i"]
        assert delPre == 'ESVGDRnpHMCAESkvj2bxKGAmMloX6K6vxfcmBLTOCM0A'

        delMgr.move(old=verfers[0].qb64, new=delPre)  # move key pair label to prefix
        assert delSrdr.said == 'ESVGDRnpHMCAESkvj2bxKGAmMloX6K6vxfcmBLTOCM0A'

        # Now create delegating event
        seal = eventing.SealEvent(i=delPre,
                                  s=delSrdr.ked["s"],
                                  d=delSrdr.said)
        bobSrdr = eventing.interact(pre=bobK.prefixer.qb64,
                                    dig=bobK.serder.saider.qb64,
                                    sn=bobK.sn + 1,
                                    data=[seal._asdict()])

        assert bobSrdr.said == 'E4ncGiiaG9wbKMHrACX9iPxb7fMSSeBSnngBNIRoZ2_A'

        sigers = bobMgr.sign(ser=bobSrdr.raw, verfers=bobK.verfers)
        msg = bytearray(bobSrdr.raw)
        counter = coring.Counter(code=coring.CtrDex.ControllerIdxSigs,
                                 count=len(sigers))
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        assert msg == (b'{"v":"KERI10JSON00013a_","t":"ixn","d":"E4ncGiiaG9wbKMHrACX9iPxb'
                       b'7fMSSeBSnngBNIRoZ2_A","i":"E7YbTIkWWyNwOxZQTTnrs6qn8jFbu2A8zftQ3'
                       b'3JYQFQ0","s":"1","p":"E7YbTIkWWyNwOxZQTTnrs6qn8jFbu2A8zftQ33JYQF'
                       b'Q0","a":[{"i":"ESVGDRnpHMCAESkvj2bxKGAmMloX6K6vxfcmBLTOCM0A","s"'
                       b':"0","d":"ESVGDRnpHMCAESkvj2bxKGAmMloX6K6vxfcmBLTOCM0A"}]}-AABAA'
                       b'Rpc88hIeWV9Z2IvzDl7dRHP-g1-EOYZLiDKyjNZB9PDSeGcNTj_SUXgWIVNdssPL'
                       b'7ajYvglbvxRwIU8teoFHCA')

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

        assert msg == (b'{"v":"KERI10JSON00015f_","t":"dip","d":"ESVGDRnpHMCAESkvj2bxKGAm'
                       b'MloX6K6vxfcmBLTOCM0A","i":"ESVGDRnpHMCAESkvj2bxKGAmMloX6K6vxfcmB'
                       b'LTOCM0A","s":"0","kt":"1","k":["DuK1x8ydpucu3480Jpd1XBfjnCwb3dZ3'
                       b'x5b1CJmuUphA"],"nt":"1","n":["Ej1L6zmDszZ8GmBdYGeUYmAwoT90h3Dt9k'
                       b'RAS90nRyqI"],"bt":"0","b":[],"c":[],"a":[],"di":"E7YbTIkWWyNwOxZ'
                       b'QTTnrs6qn8jFbu2A8zftQ33JYQFQ0"}-AABAAbb1dks4dZCRcibL74840WKKtk9w'
                       b'sdMLLlmNFkjb1s7hBfevCqpN8nkZaewQFZu5QWR-rbZtN-Y8DDQ8lh_1WDA-GAB0'
                       b'AAAAAAAAAAAAAAAAAAAAAAQE4ncGiiaG9wbKMHrACX9iPxb7fMSSeBSnngBNIRoZ'
                       b'2_A')

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
                                   nkeys=[diger.qb64 for diger in digers])

        assert delSrdr.said == 'EnjU4Rc4YtHFV7ezc6FbmXWNdT4QGE2sTtl-yaGXH-ag'

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

        assert msg == bytearray(b'{"v":"KERI10JSON00013a_","t":"ixn","d":"EAh9mAkWlONIqJPdhMFQ4a9j'
                                b'x4nZWz7JW6wLp9T2YFqk","i":"E7YbTIkWWyNwOxZQTTnrs6qn8jFbu2A8zftQ3'
                                b'3JYQFQ0","s":"2","p":"E4ncGiiaG9wbKMHrACX9iPxb7fMSSeBSnngBNIRoZ2'
                                b'_A","a":[{"i":"ESVGDRnpHMCAESkvj2bxKGAmMloX6K6vxfcmBLTOCM0A","s"'
                                b':"1","d":"EnjU4Rc4YtHFV7ezc6FbmXWNdT4QGE2sTtl-yaGXH-ag"}]}-AABAA'
                                b'EGO3wl32as1yxubkrY19x_BwntHVl7jAXHhUpFEPkkpkBxA9lbIG_vhe6-gm-GT6'
                                b'pwKg_pfPDr7pWTZ5sgR5AQ')

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

        assert msg ==(b'{"v":"KERI10JSON000160_","t":"drt","d":"EnjU4Rc4YtHFV7ezc6FbmXWN'
                      b'dT4QGE2sTtl-yaGXH-ag","i":"ESVGDRnpHMCAESkvj2bxKGAmMloX6K6vxfcmB'
                      b'LTOCM0A","s":"1","p":"ESVGDRnpHMCAESkvj2bxKGAmMloX6K6vxfcmBLTOCM'
                      b'0A","kt":"1","k":["DTf6QZWoet154o9wvzeMuNhLQRr8JaAUeiC6wjB_4_08"'
                      b'],"nt":"1","n":["EJHd79BFLgnljYhhWP2wmc6RD3A12oHDJhkixwNe2sH0"],'
                      b'"bt":"0","br":[],"ba":[],"a":[]}-AABAA9-6k6bExTqgFDG8akEA7ifbMPx'
                      b'sWDe0ttdAXpm3HiYdjfTlY5-vUcDZ1e6RHs6xLADNiNhmKHAuRQW8nmFyPBw-GAB'
                      b'0AAAAAAAAAAAAAAAAAAAAAAgEAh9mAkWlONIqJPdhMFQ4a9jx4nZWz7JW6wLp9T2'
                      b'YFqk')

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
        assert len(msgs) == 1167
        assert couple in msgs

    assert not os.path.exists(delKS.path)
    assert not os.path.exists(delDB.path)
    assert not os.path.exists(bobKS.path)
    assert not os.path.exists(bobDB.path)

    """End Test"""


if __name__ == "__main__":
    test_delegation()

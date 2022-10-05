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

    with (basing.openDB(name="bob") as bobDB, \
            keeping.openKS(name="bob") as bobKS, \
            basing.openDB(name="del") as delDB, \
            keeping.openKS(name="del") as delKS):

        # Init key pair managers
        bobMgr = keeping.Manager(ks=bobKS, salt=bobSalt)
        delMgr = keeping.Manager(ks=delKS, salt=delSalt)

        # Init Keverys
        bobKvy = eventing.Kevery(db=bobDB)
        delKvy = eventing.Kevery(db=delDB)

        # Setup Bob by creating inception event
        verfers, digers, cst, nst = bobMgr.incept(stem='bob', temp=True)  # algo default salty and rooted
        bobSrdr = eventing.incept(keys=[verfer.qb64 for verfer in verfers],
                                  ndigs=[diger.qb64 for diger in digers],
                                  code=coring.MtrDex.Blake3_256)

        bob = bobSrdr.ked["i"]
        assert bob == 'EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH'

        bobMgr.move(old=verfers[0].qb64, new=bob)  # move key pair label to prefix

        sigers = bobMgr.sign(ser=bobSrdr.raw, verfers=verfers)

        msg = bytearray(bobSrdr.raw)
        counter = coring.Counter(code=coring.CtrDex.ControllerIdxSigs, count=len(sigers))
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        assert msg == (b'{"v":"KERI10JSON00012b_","t":"icp","d":"EA_SbBUZYwqLVlAAn14d6QUB'
                    b'QCSReJlZ755JqTgmRhXH","i":"EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755Jq'
                    b'TgmRhXH","s":"0","kt":"1","k":["DKiNnDmdOkcBjcAqL2FFhMZnSlPfNyGr'
                    b'JlCjJmX5b1nU"],"nt":"1","n":["EMP7Lg6BtehOYZt2RwOqXLNfMUiUllejAp'
                    b'8G_5EiANXR"],"bt":"0","b":[],"c":[],"a":[]}-AABAAArkDBeflIAo4kBs'
                    b'Knc754XHJvdLnf04iq-noTFEJkbv2MeIGZtx6lIfJPmRSEmFMUkFW4otRrMeBGQ0'
                    b'-nlhHEE')

        # apply msg to bob's Kevery
        parsing.Parser().parse(ims=bytearray(msg), kvy=bobKvy)
        # bobKvy.process(ims=bytearray(msg))  # process local copy of msg
        bobK = bobKvy.kevers[bob]
        assert bobK.prefixer.qb64 == bob
        assert bobK.serder.saider.qb64 == bobSrdr.said
        assert bobK.serder.saider.qb64 == 'EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH'

        # apply msg to del's Kevery
        parsing.Parser().parse(ims=bytearray(msg), kvy=delKvy)
        # delKvy.process(ims=bytearray(msg))  # process remote copy of msg
        assert bob in delKvy.kevers

        # Setup Del's inception event assuming that Bob's next event will be an ixn delegating event
        verfers, digers, cst, nst = delMgr.incept(stem='del', temp=True)  # algo default salty and rooted

        delSrdr = eventing.delcept(keys=[verfer.qb64 for verfer in verfers],
                                   delpre=bobK.prefixer.qb64,
                                   ndigs=[diger.qb64 for diger in digers])

        delPre = delSrdr.ked["i"]
        assert delPre == 'EHng2fV42DdKb5TLMIs6bbjFkPNmIdQ5mSFn6BTnySJj'

        delMgr.move(old=verfers[0].qb64, new=delPre)  # move key pair label to prefix
        assert delSrdr.said == 'EHng2fV42DdKb5TLMIs6bbjFkPNmIdQ5mSFn6BTnySJj'

        # Now create delegating event
        seal = eventing.SealEvent(i=delPre,
                                  s=delSrdr.ked["s"],
                                  d=delSrdr.said)
        bobSrdr = eventing.interact(pre=bobK.prefixer.qb64,
                                    dig=bobK.serder.saider.qb64,
                                    sn=bobK.sn + 1,
                                    data=[seal._asdict()])

        assert bobSrdr.said == 'EJtQndkvwnMpVGE5oVVbLWSCm-jLviGw1AOOkzBvNwsS'

        sigers = bobMgr.sign(ser=bobSrdr.raw, verfers=bobK.verfers)
        msg = bytearray(bobSrdr.raw)
        counter = coring.Counter(code=coring.CtrDex.ControllerIdxSigs,
                                 count=len(sigers))
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        assert msg == (b'{"v":"KERI10JSON00013a_","t":"ixn","d":"EJtQndkvwnMpVGE5oVVbLWSC'
                    b'm-jLviGw1AOOkzBvNwsS","i":"EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755Jq'
                    b'TgmRhXH","s":"1","p":"EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRh'
                    b'XH","a":[{"i":"EHng2fV42DdKb5TLMIs6bbjFkPNmIdQ5mSFn6BTnySJj","s"'
                    b':"0","d":"EHng2fV42DdKb5TLMIs6bbjFkPNmIdQ5mSFn6BTnySJj"}]}-AABAA'
                    b'DFmoctrQkBbm47vuk7ejMbQ1y5vKD0Nfo8cqzbETZAlEPdbgVRSFta1-Bpv0y1Ri'
                    b'DrCxa_0IOp906gYqDPXIwG')

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

        assert msg == (b'{"v":"KERI10JSON00015f_","t":"dip","d":"EHng2fV42DdKb5TLMIs6bbjF'
                    b'kPNmIdQ5mSFn6BTnySJj","i":"EHng2fV42DdKb5TLMIs6bbjFkPNmIdQ5mSFn6'
                    b'BTnySJj","s":"0","kt":"1","k":["DLitcfMnabnLt-PNCaXdVwX45wsG93Wd'
                    b'8eW9QiZrlKYQ"],"nt":"1","n":["EDjXvWdaNJx7pAIr72Va6JhHxc7Pf4ScYJ'
                    b'G496ky8lK8"],"bt":"0","b":[],"c":[],"a":[],"di":"EA_SbBUZYwqLVlA'
                    b'An14d6QUBQCSReJlZ755JqTgmRhXH"}-AABAABv6Q3s-1Tif-ksrx7ul9OKyOL_Z'
                    b'PHHp6lB9He4n6kswjm9VvHXzWB3O7RS2OQNWhx8bd3ycg9bWRPRrcKADoYC-GAB0'
                    b'AAAAAAAAAAAAAAAAAAAAAABEJtQndkvwnMpVGE5oVVbLWSCm-jLviGw1AOOkzBvN'
                    b'wsS')


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
                                   ndigs=[diger.qb64 for diger in digers])

        assert delSrdr.said == 'EM5fj7YtOQYH3iLyWJr6HZVVxrY5t46LRL2vkNpdnPi0'

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

        assert msg == (b'{"v":"KERI10JSON00013a_","t":"ixn","d":"EJaPTWDiWvay8voiJkbxkvoa'
                    b'buUf_1a22yk9tVdRiMVs","i":"EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755Jq'
                    b'TgmRhXH","s":"2","p":"EJtQndkvwnMpVGE5oVVbLWSCm-jLviGw1AOOkzBvNw'
                    b'sS","a":[{"i":"EHng2fV42DdKb5TLMIs6bbjFkPNmIdQ5mSFn6BTnySJj","s"'
                    b':"1","d":"EM5fj7YtOQYH3iLyWJr6HZVVxrY5t46LRL2vkNpdnPi0"}]}-AABAA'
                    b'C8htl4epY7F5QBjro00VdfisxZMZWRXfe6xX_nVfS5gOsv8HOkzUKYMsvAVG4TJg'
                    b'7n1u44IyfsiKrB2R_UeUIK')

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

        assert msg ==(b'{"v":"KERI10JSON000160_","t":"drt","d":"EM5fj7YtOQYH3iLyWJr6HZVV'
                    b'xrY5t46LRL2vkNpdnPi0","i":"EHng2fV42DdKb5TLMIs6bbjFkPNmIdQ5mSFn6'
                    b'BTnySJj","s":"1","p":"EHng2fV42DdKb5TLMIs6bbjFkPNmIdQ5mSFn6BTnyS'
                    b'Jj","kt":"1","k":["DE3-kGVqHrdeeKPcL83jLjYS0Ea_CWgFHogusIwf-P9P"'
                    b'],"nt":"1","n":["EMj2mWvNvn6w9BbGUADX1AU3vn7idcUffZIaCvAsibru"],'
                    b'"bt":"0","br":[],"ba":[],"a":[]}-AABAAB_x-9_FTWr-OW_xXBN5pUkFNqL'
                    b'pAqTTQC02sPysnP0WmBFHb8NWvog9F-o279AfpPcLMxktypg1Fz7EQFYCuwC-GAB'
                    b'0AAAAAAAAAAAAAAAAAAAAAACEJaPTWDiWvay8voiJkbxkvoabuUf_1a22yk9tVdR'
                    b'iMVs')

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

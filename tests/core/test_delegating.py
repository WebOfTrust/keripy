# -*- encoding: utf-8 -*-
"""
tests delegation primaily from keri.core.eventing

"""
import os

from keri import help
from keri.app import keeping, habbing
from keri.core import coring, eventing, parsing
from keri.db import dbing, basing

logger = help.ogler.getLogger()


def test_delegation():
    """
    Test creation and validation of delegated identifier prefixes and events

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
        verfers, digers = bobMgr.incept(stem='bob', temp=True)  # algo default salty and rooted
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
        assert bobK.serder.said == bobSrdr.said
        assert bobK.serder.said == 'EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH'

        # apply msg to del's Kevery
        parsing.Parser().parse(ims=bytearray(msg), kvy=delKvy)
        # delKvy.process(ims=bytearray(msg))  # process remote copy of msg
        assert bob in delKvy.kevers

        # Setup Del's inception event assuming that Bob's next event will be an ixn delegating event
        verfers, digers = delMgr.incept(stem='del', temp=True)  # algo default salty and rooted

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
                                    dig=bobK.serder.said,
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
        assert bobK.serder.said == bobSrdr.said  # key state updated so event was validated

        # apply msg to del's Kevery
        parsing.Parser().parse(ims=bytearray(msg), kvy=delKvy)
        # delKvy.process(ims=bytearray(msg))  # process remote copy of msg
        assert delKvy.kevers[bob].serder.said == bobSrdr.said

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
        msg.extend(bobSrdr.saidb)

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
        assert delK.serder.said == delSrdr.said
        couple = delKvy.db.getAes(dbing.dgKey(delPre, delSrdr.said))
        assert couple == seqner.qb64b + bobSrdr.saidb

        # apply Del's delegated inception event message to bob's Kevery
        parsing.Parser().parse(ims=bytearray(msg), kvy=bobKvy)
        # bobKvy.process(ims=bytearray(msg))  # process local copy of msg
        assert delPre in bobKvy.kevers  # successfully validated
        bobDelK = bobKvy.kevers[delPre]
        assert bobDelK.delegated
        assert bobDelK.serder.said == delSrdr.said  # key state updated so event was validated
        couple = bobKvy.db.getAes(dbing.dgKey(delPre, delSrdr.said))
        assert couple == seqner.qb64b + bobSrdr.saidb

        # Setup Del rotation event assuming that Bob's next event will be an ixn delegating event
        verfers, digers = delMgr.rotate(pre=delPre, temp=True)

        delSrdr = eventing.deltate(pre=bobDelK.prefixer.qb64,
                                   keys=[verfer.qb64 for verfer in verfers],
                                   dig=bobDelK.serder.said,
                                   sn=bobDelK.sn + 1,
                                   ndigs=[diger.qb64 for diger in digers])

        assert delSrdr.said == 'EM5fj7YtOQYH3iLyWJr6HZVVxrY5t46LRL2vkNpdnPi0'

        # Now create delegating interaction event
        seal = eventing.SealEvent(i=bobDelK.prefixer.qb64,
                                  s=delSrdr.ked["s"],
                                  d=delSrdr.said)
        bobSrdr = eventing.interact(pre=bobK.prefixer.qb64,
                                    dig=bobK.serder.said,
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
        assert bobK.serder.said == bobSrdr.said  # key state updated so event was validated

        # apply msg to del's Kevery
        parsing.Parser().parse(ims=bytearray(msg), kvy=delKvy)
        # delKvy.process(ims=bytearray(msg))  # process remote copy of msg
        assert delKvy.kevers[bob].serder.said == bobSrdr.said

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
        msg.extend(bobSrdr.saidb)

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
        assert delK.serder.said == delSrdr.said
        couple = delKvy.db.getAes(dbing.dgKey(delPre, delSrdr.said))
        assert couple == seqner.qb64b + bobSrdr.saidb

        # apply Del's delegated inception event message to bob's Kevery
        parsing.Parser().parse(ims=bytearray(msg), kvy=bobKvy)
        # bobKvy.process(ims=bytearray(msg))  # process local copy of msg
        assert bobDelK.delegated
        assert bobDelK.serder.said == delSrdr.said  # key state updated so event was validated
        couple = delKvy.db.getAes(dbing.dgKey(delPre, delSrdr.said))
        assert couple == seqner.qb64b + bobSrdr.saidb

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

def test_delegation_supersede():
    """
    Test superseding delegation rules

    Three level delegation
    top is at top or root level with witness wop. top is not delegated
    mid is at mid level with witness wid. mid is delegatred from top
    bot is at bottom level with wintess wot. bot is delegated from mid


    def test_load_event(mockHelpingNowUTC):
    with habbing.openHby(name="tor", base="test") as torHby, \
         habbing.openHby(name="wil", base="test") as wilHby, \
         habbing.openHby(name="wan", base="test") as wanHby, \
         habbing.openHby(name="tee", base="test") as teeHby:



        # Create Wan the witness
        wanHab = wanHby.makeHab(name="wan", transferable=False)
        assert wanHab.pre == "BAbSj3jfaeJbpuqg0WtvHw31UoRZOnN_RZQYBwbAqteP"
        msg = wanHab.makeOwnEvent(sn=0)
        parsing.Parser().parse(ims=msg, kvy=torKvy)

        # Create Wil the witness, we'll use him later
        wilHab = wilHby.makeHab(name="wil", transferable=False)

        # Create Tor the delegaTOR and pass to witness Wan
        torHab = torHby.makeHab(name="tor", icount=1, isith='1', ncount=1, nsith='1', wits=[wanHab.pre], toad=1)
        assert torHab.pre == "EBOVJXs0trI76PRfvJB2fsZ56PrtyR6HrUT9LOBra8VP"
        torIcp = torHab.makeOwnEvent(sn=0)

        wanKvy = Kevery(db=wanHby.db, lax=False, local=False)  # remote events
        torKvy = Kevery(db=torHby.db, lax=False, local=False)  # remote events


    """
    topSalt = coring.Salter(raw=b'0123456789abcdef').qb64
    wopSalt = coring.Salter(raw=b'0123456789abcdef').qb64
    midSalt = coring.Salter(raw=b'abcdef0123456789').qb64
    widSalt = coring.Salter(raw=b'abcdef0123456789').qb64
    botSalt = coring.Salter(raw=b'zyxwvutsrponmlkj').qb64
    wotSalt = coring.Salter(raw=b'zyxwvutsrponmlkj').qb64

    with (habbing.openHby(name="top", base="test", salt=topSalt) as topHby,
            habbing.openHby(name="wop", base="test", salt=wopSalt) as wopHby,
            habbing.openHby(name="mid", base="test", salt=midSalt) as midHby,
            habbing.openHby(name="wid", base="test", salt=widSalt) as widHby,
            habbing.openHby(name="bot", base="test", salt=botSalt) as botHby,
            habbing.openHby(name="wot", base="test", salt=wotSalt) as wotHby):

        # Create witness wop and controller top
        wopHab = wopHby.makeHab(name="wop", transferable=False)  # witness nontrans
        # makehab also enters inception event into its own kel.
        # Otherwise failed make raises exception ConfigurationError
        assert wopHab.pre == 'BIDO3FhB5smF6WsTJkRRAao_wEttcbsBnDCmfQ4_f1b_'
        wopRemKvy = eventing.Kevery(db=wopHby.db, lax=False, local=False)  # for remote events

        topHab = topHby.makeHab(name="top", icount=1, isith='1',  # single sig
                                ncount=1, nsith='1', # single next
                                wits=[wopHab.pre], toad=1)   # one witness
        # makehab also enters inception event into its own kel
        # Otherwise failed make raises exception ConfigurationError
        assert topHab.pre == 'EJcCaHg3AtW_gRzpaz6Pw03Yv49is2IJDRwYE7ey91KE'
        topRemKvy = eventing.Kevery(db=topHby.db, lax=False, local=False)  # for remote events

        # be witness to controller's inception
        # first make inception
        stream = topHab.makeOwnInception()
        assert stream == (b'{"v":"KERI10JSON000159_","t":"icp","d":"EJcCaHg3AtW_gRzpaz6Pw03Y'
                        b'v49is2IJDRwYE7ey91KE","i":"EJcCaHg3AtW_gRzpaz6Pw03Yv49is2IJDRwYE'
                        b'7ey91KE","s":"0","kt":"1","k":["DPJVPYS9efLUHDOqxwG6pxISZSRACgNf'
                        b'uZm7qK7DzQKD"],"nt":"1","n":["EN8AnwKGnCOAyP2FRXuQMyMjbRsDjRpDd_'
                        b'_ZK2KuL0ID"],"bt":"1","b":["BIDO3FhB5smF6WsTJkRRAao_wEttcbsBnDCm'
                        b'fQ4_f1b_"],"c":[],"a":[]}-AABAADPMCL6P4DYi3qvgR4v1UcrCYMjnmRx-xJ'
                        b'meOfA8b8gdHZxZvVgpgLrAxFYwSEAtdhGT8LOPdGpTqxWSocCmXkH')

        # add test fail process as remote since since witness of controller

        # first process as local since witness
        wopHab.psr.parse(ims=stream)  # now have controller's inception in  db
        assert topHab.pre in wopHab.kevers  # success

        serder = wopHab.kevers[topHab.pre].serder
        # generate witness receipt and process
        receipt = wopHab.witness(serder=serder)  # now has fully witnessd controller icp
        count = wopHab.db.cntWigs(dbing.dgKey(topHab.pre, serder.said))
        assert count >= 1

        assert receipt == (b'{"v":"KERI10JSON000091_","t":"rct","d":"EJcCaHg3AtW_gRzpaz6Pw03Y'
                    b'v49is2IJDRwYE7ey91KE","i":"EJcCaHg3AtW_gRzpaz6Pw03Yv49is2IJDRwYE'
                    b'7ey91KE","s":"0"}-VAX-BABAACf4sllk4USRirj3xNlnFgDcbWHsAi6kOigNHr'
                    b'Ddbde06NhDELtWTeJOcz7T_rru_rpd6Uov4IN_0rthtMbxgcI')

        # add test fail process as remote since own witness

        # process receipt as local since own witness receipt.
        topHab.psr.parse(ims=receipt)  # now top has fully witnessed icp.
        count = topHab.db.cntWigs(dbing.dgKey(topHab.pre, serder.said))
        assert count >= 1

        # Create witness wid and delegated controller mid
        widHab = widHby.makeHab(name="wid", transferable=False)  # witness nontrans
        # makehab also enters inception event into its own kel.
        # Otherwise failed make raises exception ConfigurationError
        assert widHab.pre == 'BCI95exU-RepxQ0HmGcp7USLMCPxrXKzMc1DXqfRnikP'
        widRemKvy = eventing.Kevery(db=widHby.db, lax=False, local=False)  # for remote events

        midHab = midHby.makeHab(name="mid", icount=1, isith='1',  # single sig
                                ncount=1, nsith='1', # single next
                                wits=[widHab.pre], toad=1,   # one witness
                                delpre=topHab.pre)  # delegated
        # makehab also enters inception event into its own kel
        # Otherwise failed make raises exception ConfigurationError
        assert midHab.pre == 'EEaTQhI7QGM-usOJtpKM9L0yQjGiBYJC3tq905aC8am4'
        assert midHab.delpre == topHab.pre
        midRemKvy = eventing.Kevery(db=midHby.db, lax=False, local=False)  # for remote events

        # be witness to controller's inception.
        # first  make inception
        stream = midHab.makeOwnInception()

        # add test fail process as remote since since witness of controller

        #first process as local since witness
        widHab.psr.parse(ims=stream)  # now have controller's inception in db
        assert midHab.pre in widHab.kevers  # success

        serder = widHab.kevers[midHab.pre].serder
        # generate witness receipt and process
        receipt = widHab.witness(serder=serder)  # now has fully witnessed controller icp
        count = widHab.db.cntWigs(dbing.dgKey(midHab.pre, serder.said))
        assert count >= 1

        # add test fail process as remote since own witness

        # top process wop receipt as local since own witness receipt.
        midHab.psr.parse(ims=receipt)  # now top has fully witnessed icp.
        count = midHab.db.cntWigs(dbing.dgKey(midHab.pre, serder.said))
        assert count >= 1

        # Create witness wot and controller bot
        wotHab = widHby.makeHab(name="wot", transferable=False)  # witness nontrans
        # makehab also enters inception event into its own kel.
        # Otherwise failed make raises exception ConfigurationError
        assert wotHab.pre == 'BDChA_O6twrlHcXKf7xu1xYee__nZxDbBa0W_XznpLQH'
        wotRemKvy = eventing.Kevery(db=wotHby.db, lax=False, local=False)  # for remote events

        botHab = botHby.makeHab(name="bot", icount=1, isith='1',  # single sig
                                ncount=1, nsith='1', # single next
                                wits=[wotHab.pre], toad=1,  # one witness
                                delpre=midHab.pre)  # delegated
        # makehab also enters inception event into its own kel
        # Otherwise failed make raises exception ConfigurationError
        assert botHab.pre == 'EPtHqQJwlEj2sM0e2WslvwSsAsxAflmn7JIabs-LBqJC'
        assert botHab.delpre == midHab.pre
        botRemKvy = eventing.Kevery(db=botHby.db, lax=False, local=False)  # for remote events

        # be witness to controller's inception.
        # first  make inception
        stream = botHab.makeOwnInception()

        # add test fail process as remote since since witness of controller

        #first process as local since witness
        wotHab.psr.parse(ims=stream)  # now have controller inception in  db
        assert botHab.pre in wotHab.kevers  # success

        serder = wotHab.kevers[botHab.pre].serder
        # generate witness receipt and process
        receipt = wotHab.witness(serder=serder)  # now has fully witnessed controller icp
        count = wotHab.db.cntWigs(dbing.dgKey(botHab.pre, serder.said))
        assert count >= 1

        # add test fail process as remote since own witness

        # top process wop receipt as local since own witness receipt.
        botHab.psr.parse(ims=receipt)  # now top has fully witnessed icp.
        count = botHab.db.cntWigs(dbing.dgKey(botHab.pre, serder.said))
        assert count >= 1



        """End Test"""





    with (basing.openDB(name="bob") as bobDB,
            keeping.openKS(name="bob") as bobKS,
            basing.openDB(name="del") as delDB,
            keeping.openKS(name="del") as delKS):

        # Init key pair managers
        bobMgr = keeping.Manager(ks=bobKS, salt=topSalt)
        delMgr = keeping.Manager(ks=delKS, salt=midSalt)

        # Init Keverys
        bobKvy = eventing.Kevery(db=bobDB)
        delKvy = eventing.Kevery(db=delDB)

        # Setup Bob by creating inception event
        verfers, digers = bobMgr.incept(stem='bob', temp=True)  # algo default salty and rooted
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
        assert bobK.serder.said == bobSrdr.said
        assert bobK.serder.said == 'EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH'

        # apply msg to del's Kevery
        parsing.Parser().parse(ims=bytearray(msg), kvy=delKvy)
        # delKvy.process(ims=bytearray(msg))  # process remote copy of msg
        assert bob in delKvy.kevers

        # Setup Del's inception event assuming that Bob's next event will be an ixn delegating event
        verfers, digers = delMgr.incept(stem='del', temp=True)  # algo default salty and rooted

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
                                    dig=bobK.serder.said,
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
        assert bobK.serder.said == bobSrdr.said  # key state updated so event was validated

        # apply msg to del's Kevery
        parsing.Parser().parse(ims=bytearray(msg), kvy=delKvy)
        # delKvy.process(ims=bytearray(msg))  # process remote copy of msg
        assert delKvy.kevers[bob].serder.said == bobSrdr.said

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
        msg.extend(bobSrdr.saidb)

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
        assert delK.serder.said == delSrdr.said
        couple = delKvy.db.getAes(dbing.dgKey(delPre, delSrdr.said))
        assert couple == seqner.qb64b + bobSrdr.saidb

        # apply Del's delegated inception event message to bob's Kevery
        parsing.Parser().parse(ims=bytearray(msg), kvy=bobKvy)
        # bobKvy.process(ims=bytearray(msg))  # process local copy of msg
        assert delPre in bobKvy.kevers  # successfully validated
        bobDelK = bobKvy.kevers[delPre]
        assert bobDelK.delegated
        assert bobDelK.serder.said == delSrdr.said  # key state updated so event was validated
        couple = bobKvy.db.getAes(dbing.dgKey(delPre, delSrdr.said))
        assert couple == seqner.qb64b + bobSrdr.saidb

        # Setup Del rotation event assuming that Bob's next event will be an ixn delegating event
        verfers, digers = delMgr.rotate(pre=delPre, temp=True)

        delSrdr = eventing.deltate(pre=bobDelK.prefixer.qb64,
                                   keys=[verfer.qb64 for verfer in verfers],
                                   dig=bobDelK.serder.said,
                                   sn=bobDelK.sn + 1,
                                   ndigs=[diger.qb64 for diger in digers])

        assert delSrdr.said == 'EM5fj7YtOQYH3iLyWJr6HZVVxrY5t46LRL2vkNpdnPi0'

        # Now create delegating interaction event
        seal = eventing.SealEvent(i=bobDelK.prefixer.qb64,
                                  s=delSrdr.ked["s"],
                                  d=delSrdr.said)
        bobSrdr = eventing.interact(pre=bobK.prefixer.qb64,
                                    dig=bobK.serder.said,
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
        assert bobK.serder.said == bobSrdr.said  # key state updated so event was validated

        # apply msg to del's Kevery
        parsing.Parser().parse(ims=bytearray(msg), kvy=delKvy)
        # delKvy.process(ims=bytearray(msg))  # process remote copy of msg
        assert delKvy.kevers[bob].serder.said == bobSrdr.said

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
        msg.extend(bobSrdr.saidb)

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
        assert delK.serder.said == delSrdr.said
        couple = delKvy.db.getAes(dbing.dgKey(delPre, delSrdr.said))
        assert couple == seqner.qb64b + bobSrdr.saidb

        # apply Del's delegated inception event message to bob's Kevery
        parsing.Parser().parse(ims=bytearray(msg), kvy=bobKvy)
        # bobKvy.process(ims=bytearray(msg))  # process local copy of msg
        assert bobDelK.delegated
        assert bobDelK.serder.said == delSrdr.said  # key state updated so event was validated
        couple = delKvy.db.getAes(dbing.dgKey(delPre, delSrdr.said))
        assert couple == seqner.qb64b + bobSrdr.saidb

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
    test_delegation_supersede()

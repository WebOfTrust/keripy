# -*- encoding: utf-8 -*-
"""
tests delegation primaily from keri.core.eventing

"""
import os

from keri import help

from keri import kering, core
from keri.core import coring, eventing, parsing, serdering
from keri.core.eventing import MissingDelegableApprovalError
import pytest

from keri.app import keeping, habbing

from keri.db import dbing, basing
from keri.db.dbing import snKey

logger = help.ogler.getLogger()


def test_delegation():
    """
    Test creation and validation of delegated identifier prefixes and events

    """
    # bob is the delegator del is bob's delegate

    bobSalt = core.Salter(raw=b'0123456789abcdef').qb64
    delSalt = core.Salter(raw=b'abcdef0123456789').qb64

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
        counter = core.Counter(core.Codens.ControllerIdxSigs, count=len(sigers),
                               gvrsn=kering.Vrsn_1_0)
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
        counter = core.Counter(core.Codens.ControllerIdxSigs, count=len(sigers),
                               gvrsn=kering.Vrsn_1_0)
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
        counter = core.Counter(core.Codens.ControllerIdxSigs, count=len(sigers),
                               gvrsn=kering.Vrsn_1_0)
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)
        counter = core.Counter(core.Codens.SealSourceCouples, count=1,
                               gvrsn=kering.Vrsn_1_0)
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
        counter = core.Counter(core.Codens.ControllerIdxSigs, count=len(sigers),
                               gvrsn=kering.Vrsn_1_0)
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
        counter = core.Counter(core.Codens.ControllerIdxSigs, count=len(sigers),
                               gvrsn=kering.Vrsn_1_0)
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)
        counter = core.Counter(core.Codens.SealSourceCouples, count=1,
                               gvrsn=kering.Vrsn_1_0)
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
    topSalt = core.Salter(raw=b'0123456789abcdef').qb64
    wopSalt = core.Salter(raw=b'0123456789abcdef').qb64
    midSalt = core.Salter(raw=b'abcdef0123456789').qb64
    widSalt = core.Salter(raw=b'abcdef0123456789').qb64
    botSalt = core.Salter(raw=b'zyxwvutsrponmlkj').qb64
    wotSalt = core.Salter(raw=b'zyxwvutsrponmlkj').qb64

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

    # This needs to be fixedup to actually test delegating superseding recovery
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
        counter = core.Counter(core.Codens.ControllerIdxSigs, count=len(sigers),
                               gvrsn=kering.Vrsn_1_0)
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
        counter = core.Counter(core.Codens.ControllerIdxSigs, count=len(sigers),
                               gvrsn=kering.Vrsn_1_0)
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
        counter = core.Counter(core.Codens.ControllerIdxSigs, count=len(sigers),
                               gvrsn=kering.Vrsn_1_0)
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)
        counter = core.Counter(core.Codens.SealSourceCouples, count=1,
                               gvrsn=kering.Vrsn_1_0)
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
        counter = core.Counter(core.Codens.ControllerIdxSigs, count=len(sigers),
                               gvrsn=kering.Vrsn_1_0)
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
        counter = core.Counter(core.Codens.ControllerIdxSigs, count=len(sigers),
                               gvrsn=kering.Vrsn_1_0)
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)
        counter = core.Counter(core.Codens.SealSourceCouples, count=1,
                               gvrsn=kering.Vrsn_1_0)
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


def test_delegables_escrow():
    gateSalt = core.Salter(raw=b'0123456789abcdef').qb64
    torSalt = core.Salter(raw=b'0123456789defabc').raw

    with habbing.openHby(name="delegate", temp=True, salt=gateSalt) as gateHby, \
            habbing.openHab(name="delegator", temp=True, salt=torSalt) as (torHby, torHab):

        gateHab = gateHby.makeHab(name="repTest", transferable=True, delpre=torHab.pre)
        assert gateHab.pre == "EFqw1EgGdd2B6MgNLJaNO13_JoQpxAtasIjySDzGm9pd"

        gateIcp = gateHab.makeOwnEvent(sn=0)
        torKvy = eventing.Kevery(db=torHab.db, lax=False, local=False)
        parsing.Parser().parse(ims=bytearray(gateIcp), kvy=torKvy, local=True)
        assert gateHab.pre not in torKvy.kevers
        assert len(torHab.db.delegables.get(keys=snKey(gateHab.kever.serder.preb, gateHab.kever.serder.sn))) == 1
        # Exercise the MissingDelegableApprovalError case
        torKvy.processEscrowDelegables()

        # Now create delegating interaction event
        seal = eventing.SealEvent(i=gateHab.pre,
                                  s="0",
                                  d=gateHab.pre)
        ixn = torHab.interact(data=[seal._asdict()])
        assert ixn == (b'{"v":"KERI10JSON00013a_","t":"ixn","d":"EPUCIjCibL-VeT3n6PYIkbyP'
                       b'qpioIFT79NRqxboFv0Os","i":"EJTtW40aDl0aKDZ09v-o6uDz_VwLJGplp6WTI'
                       b'BGCoVog","s":"1","p":"EJTtW40aDl0aKDZ09v-o6uDz_VwLJGplp6WTIBGCoV'
                       b'og","a":[{"i":"EFqw1EgGdd2B6MgNLJaNO13_JoQpxAtasIjySDzGm9pd","s"'
                       b':"0","d":"EFqw1EgGdd2B6MgNLJaNO13_JoQpxAtasIjySDzGm9pd"}]}-AABAA'
                       b'BRR9HDRx_7KdWJ7uokLzREP3c1Hg7Grq5fwoGl_EXA-reR05aYPjDdZ4CIZTnqDo'
                       b'EN2hqNbHfq4zMaDlR8Ja4D')

        # Make sure that our anchoring ixn event is in our own KEL
        assert torHab.kever.sn == 1

        # Place the anchor seal in the database... this will be retrieved from the fully committed delegate event
        serder = torHab.kever.serder
        seqner = coring.Seqner(sn=serder.sn)
        couple = seqner.qb64b + serder.saidb
        dgkey = dbing.dgKey(gateHab.kever.prefixer.qb64b, gateHab.kever.serder.saidb)
        torHab.db.setAes(dgkey, couple)  # authorizer event seal (delegator/issuer)

        # delegate still not kevers
        assert gateHab.pre not in torKvy.kevers
        assert len(torHab.db.delegables.get(keys=snKey(gateHab.kever.serder.preb, gateHab.kever.serder.sn))) == 1

        # run the delegables escrow processor to make get delegate in our Kevers
        torKvy.processEscrowDelegables()
        assert len(torHab.db.delegables.get(keys=snKey(gateHab.kever.serder.preb, gateHab.kever.serder.sn))) == 0
        assert gateHab.pre in torKvy.kevers

def test_get_delegation_seal():
    """
    Test Kevery._getDelegationSeal:
    1. Seal found in AES
    2. Seal not in AES, dip event, delpre exists, seal found in KEL
    3. Seal not in AES, dip event, delpre is empty
    4. Seal not in AES, dip event, delpre exists, seal not found in KEL
    5. Seal not in AES, drt event, kever exists, delpre exists, seal found in KEL
    6. Seal not in AES, drt event, kever doesn't exist
    7. Seal not in AES, drt event, kever exists, delpre exists, seal not found in KEL
    8. Seal not in AES, event is neither dip nor drt
    """
    bobSalt = core.Salter(raw=b'0123456789abcdef').qb64
    delSalt = core.Salter(raw=b'abcdef0123456789').qb64

    with (basing.openDB(name="bob") as bobDB,
            keeping.openKS(name="bob") as bobKS,
            basing.openDB(name="del") as delDB,
            keeping.openKS(name="del") as delKS,
            keeping.openKS(name="fake") as fakeKS):

        # Init key pair managers
        bobMgr = keeping.Manager(ks=bobKS, salt=bobSalt)
        delMgr = keeping.Manager(ks=delKS, salt=delSalt)

        # Init Keverys
        bobKvy = eventing.Kevery(db=bobDB)
        delKvy = eventing.Kevery(db=delDB)

        # Setup Bob by creating inception event
        verfers, digers = bobMgr.incept(stem='bob', temp=True)
        bobSrdr = eventing.incept(keys=[verfer.qb64 for verfer in verfers],
                                  ndigs=[diger.qb64 for diger in digers],
                                  code=coring.MtrDex.Blake3_256)

        bob = bobSrdr.ked["i"]
        bobMgr.move(old=verfers[0].qb64, new=bob)

        sigers = bobMgr.sign(ser=bobSrdr.raw, verfers=verfers)
        msg = bytearray(bobSrdr.raw)
        counter = core.Counter(core.Codens.ControllerIdxSigs, count=len(sigers),
                               gvrsn=kering.Vrsn_1_0)
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        # apply msg to bob's Kevery
        parsing.Parser().parse(ims=bytearray(msg), kvy=bobKvy)
        bobK = bobKvy.kevers[bob]

        # Setup Del's delegated inception event
        verfers, digers = delMgr.incept(stem='del', temp=True)
        delSrdr = eventing.delcept(keys=[verfer.qb64 for verfer in verfers],
                                   delpre=bobK.prefixer.qb64,
                                   ndigs=[diger.qb64 for diger in digers])

        delPre = delSrdr.ked["i"]
        delMgr.move(old=verfers[0].qb64, new=delPre)

        # Create delegating event for Bob
        seal = eventing.SealEvent(i=delPre,
                                  s=delSrdr.ked["s"],
                                  d=delSrdr.said)
        bobIxnSrdr = eventing.interact(pre=bobK.prefixer.qb64,
                                      dig=bobK.serder.said,
                                      sn=bobK.sn + 1,
                                      data=[seal._asdict()])

        sigers = bobMgr.sign(ser=bobIxnSrdr.raw, verfers=bobK.verfers)
        msg = bytearray(bobIxnSrdr.raw)
        counter = core.Counter(core.Codens.ControllerIdxSigs, count=len(sigers),
                               gvrsn=kering.Vrsn_1_0)
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        # apply msg to bob's Kevery
        parsing.Parser().parse(ims=bytearray(msg), kvy=bobKvy)
        assert bobK.serder.said == bobIxnSrdr.said

        # Create Saider for the interaction event
        bobIxnSaider = coring.Saider(qb64=bobIxnSrdr.said)

        # Test 1: Seal found in AES
        dgkey = dbing.dgKey(delPre.encode("utf-8"), delSrdr.saidb)
        seqner = coring.Seqner(sn=bobK.sn)
        couple = seqner.qb64b + bobIxnSaider.qb64b
        bobKvy.db.setAes(dgkey, couple)

        result_seqner, result_saider = bobKvy._getDelegationSeal(eserder=delSrdr, dgkey=dgkey)
        assert result_seqner.sn == seqner.sn
        assert result_saider.qb64 == bobIxnSaider.qb64

        # Test 2: Seal not in AES, dip event, delpre exists, seal found in KEL
        # Remove from AES to test KEL lookup
        bobKvy.db.delAes(dgkey)
        # Seal should be found in KEL via fetchLastSealingEventByEventSeal
        result_seqner, result_saider = bobKvy._getDelegationSeal(eserder=delSrdr, dgkey=dgkey)
        assert result_seqner.sn == bobK.sn
        assert result_saider.qb64 == bobIxnSaider.qb64

        # Test 3: Seal not in AES, dip event, delpre is empty
        # Create a dip event with empty delpre by manually creating the sad dict
        # and then creating SerderKERI with verify=False
        tempDelSrdr = eventing.delcept(keys=[verfer.qb64 for verfer in verfers],
                                      delpre=bob,  # valid delpre for creation
                                      ndigs=[diger.qb64 for diger in digers])
        # Create a copy of the sad and set delpre to empty
        badSad = dict(tempDelSrdr.sad)
        badSad['di'] = ""  # set delpre to empty
        # Create SerderKERI from the modified sad with verify=False
        badDelSrdr = serdering.SerderKERI(sad=badSad, verify=False)
        badDgkey = dbing.dgKey(badDelSrdr.pre.encode("utf-8"), badDelSrdr.saidb)
        with pytest.raises(MissingDelegableApprovalError) as exc_info:
            bobKvy._getDelegationSeal(eserder=badDelSrdr, dgkey=badDgkey)
        assert "Empty or missing delegator" in str(exc_info.value)

        # Test 4: Seal not in AES, dip event, delpre exists, seal not found in KEL
        # Create a dip event with valid delpre but no seal in KEL
        # Use a different Manager with different salt and KS to create a different delegate prefix
        fakeSalt = core.Salter(raw=b'fakedelegate012345').qb64
        fakeMgr = keeping.Manager(ks=fakeKS, salt=fakeSalt)
        fakeVerfers, fakeDigers = fakeMgr.incept(stem='fake', temp=True)
        fakeDelSrdr = eventing.delcept(keys=[verfer.qb64 for verfer in fakeVerfers],
                                      delpre=bob,  # valid delpre
                                      ndigs=[diger.qb64 for diger in fakeDigers])
        fakeDgkey = dbing.dgKey(fakeDelSrdr.pre.encode("utf-8"), fakeDelSrdr.saidb)
        # Ensure no seal exists in KEL for this event (it's a different delegate)
        with pytest.raises(MissingDelegableApprovalError) as exc_info:
            bobKvy._getDelegationSeal(eserder=fakeDelSrdr, dgkey=fakeDgkey)
        assert "No delegation seal found for event" in str(exc_info.value)

        # Test 5: Seal not in AES, drt event, kever exists, delpre exists, seal found in KEL
        # First, create a valid dip event and process it so we have a kever
        sigers = delMgr.sign(ser=delSrdr.raw, verfers=verfers)
        msg = bytearray(delSrdr.raw)
        counter = core.Counter(core.Codens.ControllerIdxSigs, count=len(sigers),
                               gvrsn=kering.Vrsn_1_0)
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)
        counter = core.Counter(core.Codens.SealSourceCouples, count=1,
                               gvrsn=kering.Vrsn_1_0)
        msg.extend(counter.qb64b)
        seqner = coring.Seqner(sn=bobK.sn)
        msg.extend(seqner.qb64b)
        msg.extend(bobIxnSaider.qb64b)

        # Process the dip event so we have a kever for the delegate
        parsing.Parser().parse(ims=bytearray(msg), kvy=bobKvy)
        assert delPre in bobKvy.kevers
        delK = bobKvy.kevers[delPre]

        # Now create a drt event
        verfers, digers = delMgr.rotate(pre=delPre, temp=True)
        delRotSrdr = eventing.deltate(pre=delK.prefixer.qb64,
                                      keys=[verfer.qb64 for verfer in verfers],
                                      dig=delK.serder.said,
                                      sn=delK.sn + 1,
                                      ndigs=[diger.qb64 for diger in digers])

        # Create delegating interaction event for the rotation
        rotSeal = eventing.SealEvent(i=delPre,
                                     s=delRotSrdr.ked["s"],
                                     d=delRotSrdr.said)
        bobRotIxnSrdr = eventing.interact(pre=bobK.prefixer.qb64,
                                         dig=bobK.serder.said,
                                         sn=bobK.sn + 1,
                                         data=[rotSeal._asdict()])

        sigers = bobMgr.sign(ser=bobRotIxnSrdr.raw, verfers=bobK.verfers)
        msg = bytearray(bobRotIxnSrdr.raw)
        counter = core.Counter(core.Codens.ControllerIdxSigs, count=len(sigers),
                               gvrsn=kering.Vrsn_1_0)
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        # Process the delegated rotation event
        parsing.Parser().parse(ims=bytearray(msg), kvy=bobKvy)

        # Test KEL lookup for drt event
        bobRotIxnSaider = coring.Saider(qb64=bobRotIxnSrdr.said)
        drtDgkey = dbing.dgKey(delPre.encode("utf-8"), delRotSrdr.saidb)
        result_seqner, result_saider = bobKvy._getDelegationSeal(eserder=delRotSrdr, dgkey=drtDgkey)
        assert result_seqner.sn == bobK.sn
        assert result_saider.qb64 == bobRotIxnSaider.qb64

        # Test 6: Seal not in AES, drt event, kever doesn't exist
        # Create a drt event for a delegate we don't have a kever for
        # First create a valid delegate prefix by creating a dip event
        fakeVerfers, fakeDigers = fakeMgr.incept(stem='fake2', temp=True)
        fakeDipSrdr = eventing.delcept(keys=[verfer.qb64 for verfer in fakeVerfers],
                                      delpre=bob,
                                      ndigs=[diger.qb64 for diger in fakeDigers])
        fakeDelPre = fakeDipSrdr.pre  # valid prefix
        fakeMgr.move(old=fakeVerfers[0].qb64, new=fakeDelPre)  # move key to prefix
        # Now create a drt event for this delegate (but kever doesn't exist in bobKvy)
        fakeRotVerfers, fakeRotDigers = fakeMgr.rotate(pre=fakeDelPre, temp=True)
        fakeDrtSrdr = eventing.deltate(pre=fakeDelPre,
                                      keys=[verfer.qb64 for verfer in fakeRotVerfers],
                                      dig=fakeDipSrdr.said,  # use the dip said as prior
                                      sn=1,
                                      ndigs=[diger.qb64 for diger in fakeRotDigers])
        fakeDrtDgkey = dbing.dgKey(fakeDelPre.encode("utf-8"), fakeDrtSrdr.saidb)
        with pytest.raises(MissingDelegableApprovalError) as exc_info:
            bobKvy._getDelegationSeal(eserder=fakeDrtSrdr, dgkey=fakeDrtDgkey)
        assert "No kever found for delegated rotation event" in str(exc_info.value)

        # Test 7: Seal not in AES, drt event, kever exists, delpre exists, seal not found in KEL
        # Create a drt event with valid kever and delpre but no seal in KEL
        fakeRotSrdr = eventing.deltate(pre=delK.prefixer.qb64,
                                      keys=[verfer.qb64 for verfer in verfers],
                                      dig=delK.serder.said,
                                      sn=delK.sn + 2,  # different sn, so no seal
                                      ndigs=[diger.qb64 for diger in digers])
        fakeRotDgkey = dbing.dgKey(delPre.encode("utf-8"), fakeRotSrdr.saidb)
        with pytest.raises(MissingDelegableApprovalError) as exc_info:
            bobKvy._getDelegationSeal(eserder=fakeRotSrdr, dgkey=fakeRotDgkey)
        assert "No delegation seal found for event" in str(exc_info.value)

        # Test 8: Seal not in AES, event is neither dip nor drt
        # Create a regular icp event (not dip)
        icpVerfers, icpDigers = bobMgr.incept(stem='icp', temp=True)
        icpSrdr = eventing.incept(keys=[verfer.qb64 for verfer in icpVerfers],
                                  ndigs=[diger.qb64 for diger in icpDigers],
                                  code=coring.MtrDex.Blake3_256)
        icpDgkey = dbing.dgKey(icpSrdr.pre.encode("utf-8"), icpSrdr.saidb)
        with pytest.raises(MissingDelegableApprovalError) as exc_info:
            bobKvy._getDelegationSeal(eserder=icpSrdr, dgkey=icpDgkey)
        assert "No delegation seal found for event" in str(exc_info.value)

    assert not os.path.exists(delKS.path)
    assert not os.path.exists(delDB.path)
    assert not os.path.exists(bobKS.path)
    assert not os.path.exists(bobDB.path)

if __name__ == "__main__":
    test_delegation()
    test_delegation_supersede()


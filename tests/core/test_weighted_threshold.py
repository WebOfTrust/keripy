# -*- encoding: utf-8 -*-
"""
tests delegation primaily from keri.core.eventing

"""
import os

import pytest

from keri import help
from keri.db import dbing, basing
from keri.app import keeping
from keri.core import coring, eventing, parsing

logger = help.ogler.getLogger()


def test_weighted():
    """
    Test multisig with weighted threshold

    """
    wesSalt = coring.Salter(raw=b'0123456789abcdef').qb64  # init wes Salter

    # init event DB and keep DB
    with basing.openDB(name="wes") as wesDB, keeping.openKS(name="wes") as wesKS:
        # Init key pair manager
        wesMgr = keeping.Manager(ks=wesKS, salt=wesSalt)

        # Init Kevery with event DB
        wesKvy = eventing.Kevery(db=wesDB)

        # create inception event for Wes with 3 keys each in incept and next sets
        # defaults are algo salty and rooted
        sith = ["1/2", "1/2", "1/2"]  #  2 of 3 but with weighted threshold
        nxtsith = ["1/2", "1/2", "1/2"]
        verfers, digers, cst, nst = wesMgr.incept(icount=3, isith=sith,
                                               ncount=3, nsith=nxtsith,
                                               stem='wes', temp=True)
        assert cst == nst == sith

        wesSrdr = eventing.incept(keys=[verfer.qb64 for verfer in verfers],
                                  sith=sith,
                                 nxt=coring.Nexter(sith=nxtsith,
                                                   digs=[diger.qb64 for diger in digers]).qb64,
                                 code=coring.MtrDex.Blake3_256)

        wesPre = wesSrdr.ked["i"]

        wesMgr.move(old=verfers[0].qb64, new=wesPre)  # move key pair label to prefix

        sigers = wesMgr.sign(ser=wesSrdr.raw, verfers=verfers)

        msg = bytearray(wesSrdr.raw)
        counter = coring.Counter(coring.CtrDex.ControllerIdxSigs,
                                    count=len(sigers))
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        assert msg == bytearray(b'{"v":"KERI10JSON00015b_","i":"EX0WJtv6vc0IWzOqa92Pv9v9pgs1f0BfIV'
                                b'rSch648Zf0","s":"0","t":"icp","kt":["1/2","1/2","1/2"],"k":["DK4'
                                b'OJI8JOr6oEEUMeSF_X-SbKysfwpKwW-ho5KARvH5c","D1RZLgYke0GmfZm-CH8A'
                                b'sW4HoTU4m-2mFgu8kbwp8jQU","DBVwzum-jPfuUXUcHEWdplB4YcoL3BWGXK0TM'
                                b'oF_NeFU"],"n":"EhJGhyJQTpSlZ9oWfQT-lHNl1woMazLC42O89fRHocTI","bt'
                                b'":"0","b":[],"c":[],"a":[]}-AADAAKWMK8k4Po2A0rBrUBjBom73DfTCNg_b'
                                b'iwR-_LWm6DMHZHGDfCuOmEyR8sEdp7cPxhsavq4istIZ_QQ42yyUcDAABeTClYkN'
                                b'-yjbW3Kz3ot6MvAt5Se-jmcjhu-Cfsv4m_GKYgc_qwel1SbAcqF0TiY0EHFdjNKv'
                                b'Ikg3q19KlhSbuBgACA6QMnsnZuy66xrZVg3c84mTodZCEvOFrAIDQtm8jeXeCTg7'
                                b'yFauoQECZyNIlUnnxVHuk2_Fqi5xK_Lu9Pt76Aw')

        # apply msg to Wes's Kevery
        parsing.Parser().parse(ims=bytearray(msg), kvy=wesKvy)
        # wesKvy.process(ims=bytearray(msg))  # process local copy of msg
        wesK = wesKvy.kevers[wesPre]  # kever created so event was validated
        assert wesK.prefixer.qb64 == wesPre
        assert wesK.serder.diger.qb64 == wesSrdr.dig  # key state updated so event was validated

        # create interaction event for Wes
        wesSrdr = eventing.interact(pre=wesK.prefixer.qb64,
                                    dig=wesK.serder.diger.qb64,
                                    sn=wesK.sn+1,
                                    data=[])

        sigers = wesMgr.sign(ser=wesSrdr.raw, verfers=wesK.verfers)

        msg = bytearray(wesSrdr.raw)
        counter = coring.Counter(coring.CtrDex.ControllerIdxSigs,
                                    count=len(sigers))
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        assert msg == bytearray(b'{"v":"KERI10JSON000098_","i":"EX0WJtv6vc0IWzOqa92Pv9v9pgs1f0BfIV'
                                b'rSch648Zf0","s":"1","t":"ixn","p":"EInuqF20s1O0JhVJaOuKCZZDDyw6D'
                                b'YxATbiuC5Hv3WXs","a":[]}-AADAAmg8UoBCTlnENiySBpn6j7mR1w0gdkfC8Ai'
                                b'aYL5NCFfePp5ZK3CmnP7oQdj_ggiNp9FZNE0Q69A99wNK5FrwzDgABQZZunmJr2X'
                                b'3BYgX34-6SOpzkHZQS99ZL0tDsDyUIL7jZhD1e1203Fh6BnkDjzum2au2dGHJcIP'
                                b'giFGfDsrI5DwACwwYqqYYdEXeLpx_o6LTSKU-Fz_WF2gebP9Z72bZ75atg7_ZM3H'
                                b'g6hhztstGt8TthRQ0TJn6rkvatkbn6yzRjBw')

        # apply msg to wes's Kevery
        parsing.Parser().parse(ims=bytearray(msg), kvy=wesKvy)
        # wesKvy.process(ims=bytearray(msg))  # process local copy of msg
        assert wesK.serder.diger.qb64 == wesSrdr.dig  # key state updated so event was validated

        # Create rotation event for Wes
        # get current keys as verfers and next digests as digers
        nxtsith = ["1/2", "1/2", "1/2"]  #  2 of 3 but with weighted threshold
        verfers, digers, cst, nst = wesMgr.rotate(pre=wesPre, count=3, sith=nxtsith, temp=True)
        assert nst == nxtsith

        wesSrdr = eventing.rotate(pre=wesK.prefixer.qb64,
                                  keys=[verfer.qb64 for verfer in verfers],
                                  sith=sith,
                                  dig=wesK.serder.diger.qb64,
                                  nxt=coring.Nexter(sith=nxtsith,
                                                    digs=[diger.qb64 for diger in digers]).qb64,
                                  sn=wesK.sn+1,
                                  data=[])

        sigers = wesMgr.sign(ser=wesSrdr.raw, verfers=verfers)

        msg = bytearray(wesSrdr.raw)
        counter = coring.Counter(coring.CtrDex.ControllerIdxSigs,
                                    count=len(sigers))
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        assert bytearray(b'{"v":"KERI10JSON000190_","i":"EX0WJtv6vc0IWzOqa92Pv9v9pgs1f0BfIV'
                         b'rSch648Zf0","s":"2","t":"rot","p":"EznUtmH2XJF04dyqpUHLzwkNgwk6D'
                         b'jbDFbjXVI3UJLe0","kt":["1/2","1/2","1/2"],"k":["DeonYM2bKnAwp6VZ'
                         b'cuCXdX72kNFw56czlZ_Tc7XHHVGI","DQghKIy-2do9OkweSgazh3Ql1vCOt5bnc'
                         b'5QF8x50tRoU","DNAUn-5dxm6b8Njo01O0jlStMRCjo9FYQA2mfqFW1_JA"],"n"'
                         b':"EX5fxvjOg5VuDboWbqnTjTPpXa3nNIm99hlsB1EmhTo8","bt":"0","br":[]'
                         b',"ba":[],"a":[]}-AADAAahiASmZJY2KjXKRvVwdRSESmesNsfxUnOQ6buEk6S-'
                         b'4rxRdztde_6_CX2Q4MyUSErHMtmLhesrKjenPBairZAQABbnbZ3lOKcKCMmLYtpT'
                         b'hDEm-tRTsnEh_8loXpA6G3q1oJZNeVJphJjPm2HR0mX2ptC2DEt6p9i4GH1Y56HY'
                         b'TsAgACqF6e_29QkxgXvqDLEUnAIB_XJ7SUhDNpt3cYk6pF1-ULgrhGdZLS1h-c_V'
                         b'KpKITRx3ZTvme7sKbvr_NfR-0ECg')

        # apply msg to Wes's Kevery
        parsing.Parser().parse(ims=bytearray(msg), kvy=wesKvy)
        # wesKvy.process(ims=bytearray(msg))  # process local copy of msg
        assert wesK.serder.diger.qb64 == wesSrdr.dig  # key state updated so event was validated

        # Create rotation event for Wes
        # get current keys as verfers and next digests as digers
        sith = nxtsith  # rotate so nxtsith is now current sith and need new nextsith
        #  2 of first 3 and 1 of last 2
        nxtsith = [["1/2", "1/2", "1/2"],["1/1", "1/1"]]
        verfers, digers, cst, nst = wesMgr.rotate(pre=wesPre, count=5, sith=nxtsith, temp=True)
        assert cst == sith
        assert nst == nxtsith

        wesSrdr = eventing.rotate(pre=wesK.prefixer.qb64,
                                  keys=[verfer.qb64 for verfer in verfers],
                                  sith=sith,
                                  dig=wesK.serder.diger.qb64,
                                  nxt=coring.Nexter(sith=nxtsith,
                                                    digs=[diger.qb64 for diger in digers]).qb64,
                                  sn=wesK.sn+1,
                                  data=[])

        sigers = wesMgr.sign(ser=wesSrdr.raw, verfers=verfers)

        msg = bytearray(wesSrdr.raw)
        counter = coring.Counter(coring.CtrDex.ControllerIdxSigs,
                                    count=len(sigers))
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        assert msg == bytearray(b'{"v":"KERI10JSON000190_","i":"EX0WJtv6vc0IWzOqa92Pv9v9pgs1f0BfIV'
                                b'rSch648Zf0","s":"3","t":"rot","p":"EK1BTah7lTyaaol7sLdg9uObplAjP'
                                b'o_JOz1m4WPaLJBw","kt":["1/2","1/2","1/2"],"k":["D7WWKDLVwYxYMLAj'
                                b'DceIEs66xPMY4Afzx-RQw2x0mQzI","Dmg6Aah8qyKKDiQyNXTiO71QJwizjZfGM'
                                b'61BA-s0A5F4","DS3fhKpvPCDL5WmfN4_PkmJMMsSCdRTxG24OQuf_EmHQ"],"n"'
                                b':"EcM4iw7fElXWhad8V-za4Px7nBKjndxoh3XZRkohghKY","bt":"0","br":[]'
                                b',"ba":[],"a":[]}-AADAAl6FtC6Ynm8RAoa2utkIqJX5xW1ZxIkEH7I_MUCXL0p'
                                b'OUT8P0lCgPzn9dvmUagHbzZ4GIwOBqGI-lQJbeESnZBQAB_nJLQJTf9t1NJxNoP5'
                                b'gve9QEQbHFkn2aX6O78_bzOGUf01y8KSl-ugi0_B9-w0dk4J7gjYbv7RhG-TmFPE'
                                b'mEAAACEpJiOTGarwK4jWZ9ZKue05uYPDW5wp4HC8VIt6R93h7WHLqqLVH1m3n5jd'
                                b'AkiM4RFdhUqBwt-jKBfHQmVoBBCA')


        # apply msg to Wes's Kevery
        parsing.Parser().parse(ims=bytearray(msg), kvy=wesKvy)
        # wesKvy.process(ims=bytearray(msg))  # process local copy of msg
        assert wesK.serder.diger.qb64 == wesSrdr.dig  # key state updated so event was validated

        # Create rotation event for Wes
        # get current keys as verfers and next digests as digers
        sith = nxtsith  # rotate so nxtsith is now current sith and need new nextsith
        #  2 of first 3 and 1 of last 2
        nxtsith = [["1/2", "1/2", "1/2"],["1/1", "1/1"]]
        verfers, digers, cst, nst = wesMgr.rotate(pre=wesPre, count=5, sith=nxtsith, temp=True)
        assert cst == nst == nxtsith

        wesSrdr = eventing.rotate(pre=wesK.prefixer.qb64,
                                  keys=[verfer.qb64 for verfer in verfers],
                                  sith=sith,
                                  dig=wesK.serder.diger.qb64,
                                  nxt=coring.Nexter(sith=nxtsith,
                                                    digs=[diger.qb64 for diger in digers]).qb64,
                                  sn=wesK.sn+1,
                                  data=[])

        sigers = wesMgr.sign(ser=wesSrdr.raw, verfers=verfers)

        msg = bytearray(wesSrdr.raw)
        counter = coring.Counter(coring.CtrDex.ControllerIdxSigs,
                                    count=len(sigers))
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        assert msg == bytearray(b'{"v":"KERI10JSON0001fe_","i":"EX0WJtv6vc0IWzOqa92Pv9v9pgs1f0BfIV'
                                b'rSch648Zf0","s":"4","t":"rot","p":"EVfMO5GK8tg4KE8XCelX1s_TG_Hqr'
                                b'_kzb3ghIBYvzC6U","kt":[["1/2","1/2","1/2"],["1/1","1/1"]],"k":["'
                                b'DToUWoemnetqJoLFIqDI7lxIJEfF0W7xG5ZlqAseVUQc","Drz-IZjko61q-sPMD'
                                b'IW6n-0NGFubbXiZhzWZrO_BZ0Wc","DiGwL3hjQqiUgQlFPeA6kRR1EBXX0vSLm9'
                                b'b6QhPS8IkQ","Dxj5pcStgZ6CbQ2YktNaj8KLE_g9YAOZF6AL9fyLcWQw","DE5z'
                                b'r5eH8EUVQXyAaxWfQUWkGCId-QDCvvxMT77ibj2Q"],"n":"E3in3Z14va0kk4Wq'
                                b'd3vcCAojKNtQq7ZTrQaavR8x0yu4","bt":"0","br":[],"ba":[],"a":[]}-A'
                                b'AFAAdxx4UfoNYdXckLY9nSYvqYLJzvIRhixshBbqkQ6uwvqaVmwPqmvck0V9xl5x'
                                b'3ssVclasm8Ga3FTkcbmbV2jXDgABBWUhku-qDq8wYn5XMQuKzidAsA6bth8-EsCx'
                                b'9WwTIqWBR-AecW-3X1haAyJshqplDsS9MnZfVgmSHokwdLnRCQACp2tB0pFRv_C7'
                                b'nUXPf9rFKvlWUllrsY6Y1_F4bAOMvyCU-PES4HwyUQv3kQnLxEqnf0fbOYdHJNGo'
                                b'sXi-UqL9BAADW89YpsS5m3IASAtXvXEPez-0y11JRP8bAiUUBdIxGB9ms79jPZnQ'
                                b'tF3045byf3m0Dvi91Y9d4sh-xkzZ15v9DAAE6QR9qNXnHXLisg4Mbadav9AdMjS4'
                                b'uz6jNG1AL6UCa7P90Y53v1V6VRaOPu_RTWXcXYRGqA9BHJ2rLNYWJTJTBA')


        # apply msg to Wes's Kevery
        parsing.Parser().parse(ims=bytearray(msg), kvy=wesKvy)
        # wesKvy.process(ims=bytearray(msg))  # process local copy of msg
        assert wesK.serder.diger.qb64 == wesSrdr.dig  # key state updated so event was validated


    assert not os.path.exists(wesKS.path)
    assert not os.path.exists(wesDB.path)

    """End Test"""


if __name__ == "__main__":
    test_weighted()

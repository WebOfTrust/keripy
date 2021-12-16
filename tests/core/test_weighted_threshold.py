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
        sith = ["1/2", "1/2", "1/2"]  # 2 of 3 but with weighted threshold
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

        assert msg == bytearray(b'{"v":"KERI10JSON00018e_","t":"icp","d":"EZgXYINAQWXFpxAmWI9AwOwj'
                                b'VOYXzjyEE_-DdTfkEk8s","i":"EZgXYINAQWXFpxAmWI9AwOwjVOYXzjyEE_-Dd'
                                b'TfkEk8s","s":"0","kt":["1/2","1/2","1/2"],"k":["DK4OJI8JOr6oEEUM'
                                b'eSF_X-SbKysfwpKwW-ho5KARvH5c","D1RZLgYke0GmfZm-CH8AsW4HoTU4m-2mF'
                                b'gu8kbwp8jQU","DBVwzum-jPfuUXUcHEWdplB4YcoL3BWGXK0TMoF_NeFU"],"n"'
                                b':"EhJGhyJQTpSlZ9oWfQT-lHNl1woMazLC42O89fRHocTI","bt":"0","b":[],'
                                b'"c":[],"a":[]}-AADAAo74mzRNAT5WEVRYaUWs4apfEY9oblVL2MtNSORwsEVFN'
                                b'oyH8Vh_w_WC9TGfH-_zqN8dISIy102JtmBwllvHnBAABYQAmtsf2yhqi0zvF--TV'
                                b'Wp7kfzVRy3BQkTdYmJrfOZFnvp0kbXlG-PCXPO7OXbKM0ZLJ1Ga_qVJ_y-ERIMac'
                                b'CwACInxprKSzFp2-LNPn7eVAAc8z0XO0KbUE26vv_PXt5IMwyx6S5A1nCC4DQrv6'
                                b'bYHmmXP0YQpkOIm-tRHrPCOuDg')

        # apply msg to Wes's Kevery
        parsing.Parser().parse(ims=bytearray(msg), kvy=wesKvy)
        # wesKvy.process(ims=bytearray(msg))  # process local copy of msg
        wesK = wesKvy.kevers[wesPre]  # kever created so event was validated
        assert wesK.prefixer.qb64 == wesPre
        assert wesK.serder.saider.qb64 == wesSrdr.said  # key state updated so event was validated

        # create interaction event for Wes
        wesSrdr = eventing.interact(pre=wesK.prefixer.qb64,
                                    dig=wesK.serder.saider.qb64,
                                    sn=wesK.sn + 1,
                                    data=[])

        sigers = wesMgr.sign(ser=wesSrdr.raw, verfers=wesK.verfers)

        msg = bytearray(wesSrdr.raw)
        counter = coring.Counter(coring.CtrDex.ControllerIdxSigs,
                                 count=len(sigers))
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        assert msg == bytearray(b'{"v":"KERI10JSON0000cb_","t":"ixn","d":"E8LhfiGHj_YPjzZWu7xxMrla'
                                b'8Bz3Fn-L6tJFlQcgeA_0","i":"EZgXYINAQWXFpxAmWI9AwOwjVOYXzjyEE_-Dd'
                                b'TfkEk8s","s":"1","p":"EZgXYINAQWXFpxAmWI9AwOwjVOYXzjyEE_-DdTfkEk'
                                b'8s","a":[]}-AADAAvVH0h_W7QuioTt0OmcRgtZSksfQ7MOTYMd4Nc14rdJ9U6j1'
                                b'ycr06YCtuGTM-J34d0ADnG3f_0F3t3dX_lZacBQAB5LMjFgsQe_k-dxRgGcIBbEa'
                                b'30rPKkCOCNyqnjw56vl-V7RtOlAGIJ_KsyBrF0GD5vZp1NSGsmgTM5Ww36pqQAgA'
                                b'C077aW784R0cRErpzhndWsrbFs32lmhOdJ0QyAQ4MlKE0Li6dR20XtEoRLtGCcPo'
                                b'i6C188Gu1TwzmYOPlUjW2Bw')

        # apply msg to wes's Kevery
        parsing.Parser().parse(ims=bytearray(msg), kvy=wesKvy)
        # wesKvy.process(ims=bytearray(msg))  # process local copy of msg
        assert wesK.serder.saider.qb64 == wesSrdr.said  # key state updated so event was validated

        # Create rotation event for Wes
        # get current keys as verfers and next digests as digers
        nxtsith = ["1/2", "1/2", "1/2"]  # 2 of 3 but with weighted threshold
        verfers, digers, cst, nst = wesMgr.rotate(pre=wesPre, count=3, sith=nxtsith, temp=True)
        assert nst == nxtsith

        wesSrdr = eventing.rotate(pre=wesK.prefixer.qb64,
                                  keys=[verfer.qb64 for verfer in verfers],
                                  sith=sith,
                                  dig=wesK.serder.saider.qb64,
                                  nxt=coring.Nexter(sith=nxtsith,
                                                    digs=[diger.qb64 for diger in digers]).qb64,
                                  sn=wesK.sn + 1,
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
        assert wesK.serder.saider.qb64 == wesSrdr.said  # key state updated so event was validated

        # Create rotation event for Wes
        # get current keys as verfers and next digests as digers
        sith = nxtsith  # rotate so nxtsith is now current sith and need new nextsith
        #  2 of first 3 and 1 of last 2
        nxtsith = [["1/2", "1/2", "1/2"], ["1/1", "1/1"]]
        verfers, digers, cst, nst = wesMgr.rotate(pre=wesPre, count=5, sith=nxtsith, temp=True)
        assert cst == sith
        assert nst == nxtsith

        wesSrdr = eventing.rotate(pre=wesK.prefixer.qb64,
                                  keys=[verfer.qb64 for verfer in verfers],
                                  sith=sith,
                                  dig=wesK.serder.saider.qb64,
                                  nxt=coring.Nexter(sith=nxtsith,
                                                    digs=[diger.qb64 for diger in digers]).qb64,
                                  sn=wesK.sn + 1,
                                  data=[])

        sigers = wesMgr.sign(ser=wesSrdr.raw, verfers=verfers)

        msg = bytearray(wesSrdr.raw)
        counter = coring.Counter(coring.CtrDex.ControllerIdxSigs,
                                 count=len(sigers))
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        assert msg == bytearray(b'{"v":"KERI10JSON0001c3_","t":"rot","d":"Ebhb0Fnink_-r0JfJQIVr15G'
                                b'0Ew8upPjo94-cT3SzdlU","i":"EZgXYINAQWXFpxAmWI9AwOwjVOYXzjyEE_-Dd'
                                b'TfkEk8s","s":"3","p":"EzkHD4jwDn4EGqEvQtPnt6iWj0zwDCTj8zbM6tBCGH'
                                b'Ng","kt":["1/2","1/2","1/2"],"k":["D7WWKDLVwYxYMLAjDceIEs66xPMY4'
                                b'Afzx-RQw2x0mQzI","Dmg6Aah8qyKKDiQyNXTiO71QJwizjZfGM61BA-s0A5F4",'
                                b'"DS3fhKpvPCDL5WmfN4_PkmJMMsSCdRTxG24OQuf_EmHQ"],"n":"EcM4iw7fElX'
                                b'Whad8V-za4Px7nBKjndxoh3XZRkohghKY","bt":"0","br":[],"ba":[],"a":'
                                b'[]}-AADAAR0IDqMweOsLfeTDzXo6kPPjoBwAGJNRm9MuYNA07_ky8vNJ5d-0Fcln'
                                b'yHjnJcRN26DRIjyfVh5tAzgv9PuhIBAABiB2hbNyJ6oCKNSF4akuxF4fbuwVUsCn'
                                b'YhW9n9LjFxO8GCkcfKdeDllLkGjhMCCrTV_HI5-5SWQUvLlOGsxolAgAC9Yw0Kt_'
                                b'uYktLvZQIBq-eGNx7kJNvKxsedaOkY-j1yrjtfyOHEwY65JsQ7dG-anckc0KfhPC'
                                b'ld47DBRtVPSjLAQ')

        # apply msg to Wes's Kevery
        parsing.Parser().parse(ims=bytearray(msg), kvy=wesKvy)
        # wesKvy.process(ims=bytearray(msg))  # process local copy of msg
        assert wesK.serder.saider.qb64 == wesSrdr.said  # key state updated so event was validated

        # Create rotation event for Wes
        # get current keys as verfers and next digests as digers
        sith = nxtsith  # rotate so nxtsith is now current sith and need new nextsith
        #  2 of first 3 and 1 of last 2
        nxtsith = [["1/2", "1/2", "1/2"], ["1/1", "1/1"]]
        verfers, digers, cst, nst = wesMgr.rotate(pre=wesPre, count=5, sith=nxtsith, temp=True)
        assert cst == nst == nxtsith

        wesSrdr = eventing.rotate(pre=wesK.prefixer.qb64,
                                  keys=[verfer.qb64 for verfer in verfers],
                                  sith=sith,
                                  dig=wesK.serder.saider.qb64,
                                  nxt=coring.Nexter(sith=nxtsith,
                                                    digs=[diger.qb64 for diger in digers]).qb64,
                                  sn=wesK.sn + 1,
                                  data=[])

        sigers = wesMgr.sign(ser=wesSrdr.raw, verfers=verfers)

        msg = bytearray(wesSrdr.raw)
        counter = coring.Counter(coring.CtrDex.ControllerIdxSigs,
                                 count=len(sigers))
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        assert msg == bytearray(b'{"v":"KERI10JSON000231_","t":"rot","d":"EDK-dx1__PH_ZJXeZBfxVnod'
                                b'jUsaczSocKCNluEV6Cec","i":"EZgXYINAQWXFpxAmWI9AwOwjVOYXzjyEE_-Dd'
                                b'TfkEk8s","s":"4","p":"Ebhb0Fnink_-r0JfJQIVr15G0Ew8upPjo94-cT3Szd'
                                b'lU","kt":[["1/2","1/2","1/2"],["1/1","1/1"]],"k":["DToUWoemnetqJ'
                                b'oLFIqDI7lxIJEfF0W7xG5ZlqAseVUQc","Drz-IZjko61q-sPMDIW6n-0NGFubbX'
                                b'iZhzWZrO_BZ0Wc","DiGwL3hjQqiUgQlFPeA6kRR1EBXX0vSLm9b6QhPS8IkQ","'
                                b'Dxj5pcStgZ6CbQ2YktNaj8KLE_g9YAOZF6AL9fyLcWQw","DE5zr5eH8EUVQXyAa'
                                b'xWfQUWkGCId-QDCvvxMT77ibj2Q"],"n":"E3in3Z14va0kk4Wqd3vcCAojKNtQq'
                                b'7ZTrQaavR8x0yu4","bt":"0","br":[],"ba":[],"a":[]}-AAFAAt2EjEPyJO'
                                b'MqtUdrp2EaRenlwriXviQ0hJ4Wx0agCok1sU3QMFS5hRdwX_NEFca9OnKGVjOag6'
                                b'K_F4yOs1BiuDQABN30bxBTVoemwfv6bPMqi9aIBKAuqm5IjcXFpS6vdnSdcQiz5V'
                                b'Wb5DzpjhBztZyTiBbmxihl4tGyJ8xMTlIcmAwACq5YQaTJ45Smm2UwhyX5YLVkvx'
                                b'eJxt9oewmGAhOxyp-_tu0KAe2mehFHa6s9BlcqE-401mQh5EcniFbdHx3eAAQADR'
                                b'8Mtsn-7UKC-LjWq45-tKJfV8QVTaAXGiQsXye6DC7cf5iKQeUw7NXIcuxb-CXLL3'
                                b'AIMg3ZfhYy44-wW6pq6BgAEPtQg63EnWDfhwQjqgIlAHGupkeE_2hZhEp2Lcx0m5'
                                b'x4w0S6XqR9_Lx86RMnrzc3G9W3CJ_V5iEJhNQAqdTFqCw')

        # apply msg to Wes's Kevery
        parsing.Parser().parse(ims=bytearray(msg), kvy=wesKvy)
        # wesKvy.process(ims=bytearray(msg))  # process local copy of msg
        assert wesK.serder.saider.qb64 == wesSrdr.said  # key state updated so event was validated

    assert not os.path.exists(wesKS.path)
    assert not os.path.exists(wesDB.path)

    """End Test"""


if __name__ == "__main__":
    test_weighted()

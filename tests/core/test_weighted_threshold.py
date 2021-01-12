# -*- encoding: utf-8 -*-
"""
tests delegation primaily from keri.core.eventing

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


def test_weighted():
    """
    Test multisig with weighted threshold

    """
    wesSalt = coring.Salter(raw=b'0123456789abcdef').qb64  # init wes Salter

    # init event DB and keep DB
    with dbing.openDB(name="wes") as wesDB, keeping.openKeep(name="wes") as wesKp:
        # Init key pair manager
        wesMgr = keeping.Manager(keeper=wesKp, salt=wesSalt)

        # Init Kevery with event DB
        wesKvy = eventing.Kevery(baser=wesDB)

        # create inception event for Wes with 3 keys each in incept and next sets
        # defaults are algo salty and rooted
        verfers, digers = wesMgr.incept(icount=3, ncount=3, stem='wes', temp=True)
        sith = ["1/2", "1/2", "1/2"]  #  2 of 3 but with weighted threshold
        nxtsith = ["1/2", "1/2", "1/2"]

        wesSrdr = eventing.incept(keys=[verfer.qb64 for verfer in verfers],
                                  sith=sith,
                                 nxt=coring.Nexter(sith=nxtsith,
                                                   digs=[diger.qb64 for diger in digers]).qb64,
                                 code=coring.CryOneDex.Blake3_256)

        wesPre = wesSrdr.ked["i"]
        assert wesPre == 'EiLUP3YJQo2zKDL5R5L3yD7eHPrLo7cdlFQ9JP-x6bAA'

        wesMgr.move(old=verfers[0].qb64, new=wesPre)  # move key pair label to prefix

        sigers = wesMgr.sign(ser=wesSrdr.raw, verfers=verfers)

        msg = bytearray(wesSrdr.raw)
        counter = coring.SigCounter(count=len(sigers))
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        assert msg == bytearray(b'{"v":"KERI10JSON000154_","i":"EiLUP3YJQo2zKDL5R5L3yD7eHPrLo7cdlF'
                                b'Q9JP-x6bAA","s":"0","t":"icp","kt":["1/2","1/2","1/2"],"k":["DK4'
                                b'OJI8JOr6oEEUMeSF_X-SbKysfwpKwW-ho5KARvH5c","D1RZLgYke0GmfZm-CH8A'
                                b'sW4HoTU4m-2mFgu8kbwp8jQU","DBVwzum-jPfuUXUcHEWdplB4YcoL3BWGXK0TM'
                                b'oF_NeFU"],"n":"EhJGhyJQTpSlZ9oWfQT-lHNl1woMazLC42O89fRHocTI","wt'
                                b'":"0","w":[],"c":[]}-AADAAGapgdCsw7Ad0jiqd0HZI-pJMkWuse1tDamZ090'
                                b'jMFlI7-snmNZFq0KPKJbPkyG46MYYVaMsm7SeXoBdI7zD9DwABIciVlOQDtrPuPG'
                                b'lYSOhatNupNFvv_zG0Dgfpsg3gx4KzEG9FXNV0MbHX20pg48Mbmq9ZqJjN2yEJkp'
                                b'XJGbG2AgACTCbPvwZT341CZyDPTlYdMErfWJ4BLoMK4GInqvWTb53tKOMwewAzMj'
                                b'mbCgUmBgsmYgoTEJnHjP53_2Ddd_7VCA')

        # apply msg to Wes's Kevery
        wesKvy.processAll(ims=bytearray(msg))  # process local copy of msg
        wesK = wesKvy.kevers[wesPre]  # kever created so event was validated
        assert wesK.prefixer.qb64 == wesPre
        assert wesK.serder.diger.qb64 == wesSrdr.dig  # key state updated so event was validated
        assert wesK.serder.diger.qb64 == 'EFm137-l_G7WDTKNUmUXdcDkLlDN90cJeJ-NeIXWPhNU'

        # create interaction event for Wes
        wesSrdr = eventing.interact(pre=wesK.prefixer.qb64,
                                    dig=wesK.serder.diger.qb64,
                                    sn=wesK.sn+1,
                                    data=[])

        sigers = wesMgr.sign(ser=wesSrdr.raw, verfers=wesK.verfers)

        msg = bytearray(wesSrdr.raw)
        counter = coring.SigCounter(count=len(sigers))
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        assert msg == bytearray(b'{"v":"KERI10JSON000098_","i":"EiLUP3YJQo2zKDL5R5L3yD7eHPrLo7cdlF'
                                b'Q9JP-x6bAA","s":"1","t":"ixn","p":"EFm137-l_G7WDTKNUmUXdcDkLlDN9'
                                b'0cJeJ-NeIXWPhNU","a":[]}-AADAA1PVYniDwmHmutvL4BiUA7SXzPN-ibI2KJ1'
                                b'VjDMzwUf9_qlmPjTXf22vmJvNXkFoTFP-Pki3z9GtheyJBPHEDDgABODOMDScTLE'
                                b'2CXcQe95mDihb4k_w8Wu3BQP8Xm0gKuS493POlpuj23VBFRynZMU1HAhL2I1swZM'
                                b'Gt2XmnscEZDAACa0kZ1clbZvDSJYEcXdFlV65PN4Hb6cDcNkTX-pYO6TTHaZRy3a'
                                b'tURJonV558J2kTvVtB6E3RyTyL6qHAQ4ItAA')

        # apply msg to wes's Kevery
        wesKvy.processAll(ims=bytearray(msg))  # process local copy of msg
        assert wesK.serder.diger.qb64 == wesSrdr.dig  # key state updated so event was validated
        assert wesK.serder.diger.qb64 == 'ERTOyErK-hGJvld6G38CFN_I1MxaH9e_vaH1qz--KYtU'

        # Create rotation event for Wes
        # get current keys as verfers and next digests as digers
        verfers, digers = wesMgr.rotate(pre=wesPre, count=3, temp=True)
        nxtsith = ["1/2", "1/2", "1/2"]  #  2 of 3 but with weighted threshold

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
        counter = coring.SigCounter(count=len(sigers))
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        assert msg == bytearray(b'{"v":"KERI10JSON000190_","i":"EiLUP3YJQo2zKDL5R5L3yD7eHPrLo7cdlF'
                                b'Q9JP-x6bAA","s":"2","t":"rot","p":"ERTOyErK-hGJvld6G38CFN_I1MxaH'
                                b'9e_vaH1qz--KYtU","kt":["1/2","1/2","1/2"],"k":["DeonYM2bKnAwp6VZ'
                                b'cuCXdX72kNFw56czlZ_Tc7XHHVGI","DQghKIy-2do9OkweSgazh3Ql1vCOt5bnc'
                                b'5QF8x50tRoU","DNAUn-5dxm6b8Njo01O0jlStMRCjo9FYQA2mfqFW1_JA"],"n"'
                                b':"EX5fxvjOg5VuDboWbqnTjTPpXa3nNIm99hlsB1EmhTo8","wt":"0","wr":[]'
                                b',"wa":[],"a":[]}-AADAAZpGSRZmnNbcJDA1LZ1LoizGyjW_EscWWebJ3-c8cws'
                                b'v_u4p0RDEQRokxuyK7hSXIzI8ZTeUUHCsPvzUpfLNADQAB-QRmN2hfwqk1HYmxb5'
                                b'f4Rzsurxcv5fpSAuqDS7DFYUStcjl8zGXq7I9UkdN9fKz44gHCkhADIzzZc4LR5X'
                                b'CCCQACy70czPALNGqz-GdX4H90113zKto_P04NnMfPwp_E3wIlqM0YfXYy9NIJr7'
                                b'xugbHIsQajERM3blpUe1CllzjWBA')

        # apply msg to Wes's Kevery
        wesKvy.processAll(ims=bytearray(msg))  # process local copy of msg
        assert wesK.serder.diger.qb64 == wesSrdr.dig  # key state updated so event was validated
        assert wesK.serder.diger.qb64 == 'ETx4epYdzpME9yQKFhQ_PCE3a58vZgH6PJeJDq-ZgpC0'

        # Create rotation event for Wes
        # get current keys as verfers and next digests as digers
        verfers, digers = wesMgr.rotate(pre=wesPre, count=5, temp=True)
        sith = nxtsith  # rotate so nxtsith is now current sith and need new nextsith
        #  2 of first 3 and 1 of last 2
        nxtsith = [["1/2", "1/2", "1/2"],["1/1", "1/1"]]

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
        counter = coring.SigCounter(count=len(sigers))
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        assert msg == bytearray(b'{"v":"KERI10JSON000190_","i":"EiLUP3YJQo2zKDL5R5L3yD7eHPrLo7cdlF'
                                b'Q9JP-x6bAA","s":"3","t":"rot","p":"ETx4epYdzpME9yQKFhQ_PCE3a58vZ'
                                b'gH6PJeJDq-ZgpC0","kt":["1/2","1/2","1/2"],"k":["D7WWKDLVwYxYMLAj'
                                b'DceIEs66xPMY4Afzx-RQw2x0mQzI","Dmg6Aah8qyKKDiQyNXTiO71QJwizjZfGM'
                                b'61BA-s0A5F4","DS3fhKpvPCDL5WmfN4_PkmJMMsSCdRTxG24OQuf_EmHQ"],"n"'
                                b':"EcM4iw7fElXWhad8V-za4Px7nBKjndxoh3XZRkohghKY","wt":"0","wr":[]'
                                b',"wa":[],"a":[]}-AADAAWUGHldvgFs1_fFN_n5R-nDAWXwS8W2J_lAmQN-uy5B'
                                b'ZuZCkQ0nN1AyKZn57PFnXXFGN-DjHKd5U-RVRy23DzBQABQ0TEPseYhDCDPUf4mI'
                                b'sct1FECHF-fv18cDiupYLZoXiW3cNsFbpJA0hlumsC9vp-zopSkOxX3KNR41RnzI'
                                b'YYBQACS100r1L0Om-sN2ILrgHaZwhASCr0pkPk2-CWLpVGNDvuaBm25tVZAsWSL8'
                                b'Jq43GjrwqDu3yzSk7bTocgVQN7CA')

        # apply msg to Wes's Kevery
        wesKvy.processAll(ims=bytearray(msg))  # process local copy of msg
        assert wesK.serder.diger.qb64 == wesSrdr.dig  # key state updated so event was validated
        assert wesK.serder.diger.qb64 == 'EFJayD7ngsJTiNbFfyxZRhV_4XnrE_Z3VpTK2kUUZb4U'

        # Create rotation event for Wes
        # get current keys as verfers and next digests as digers
        verfers, digers = wesMgr.rotate(pre=wesPre, count=5, temp=True)
        sith = nxtsith  # rotate so nxtsith is now current sith and need new nextsith
        #  2 of first 3 and 1 of last 2
        nxtsith = [["1/2", "1/2", "1/2"],["1/1", "1/1"]]

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
        counter = coring.SigCounter(count=len(sigers))
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        assert msg == bytearray(b'{"v":"KERI10JSON0001fe_","i":"EiLUP3YJQo2zKDL5R5L3yD7eHPrLo7cdlF'
                                b'Q9JP-x6bAA","s":"4","t":"rot","p":"EFJayD7ngsJTiNbFfyxZRhV_4XnrE'
                                b'_Z3VpTK2kUUZb4U","kt":[["1/2","1/2","1/2"],["1/1","1/1"]],"k":["'
                                b'DToUWoemnetqJoLFIqDI7lxIJEfF0W7xG5ZlqAseVUQc","Drz-IZjko61q-sPMD'
                                b'IW6n-0NGFubbXiZhzWZrO_BZ0Wc","DiGwL3hjQqiUgQlFPeA6kRR1EBXX0vSLm9'
                                b'b6QhPS8IkQ","Dxj5pcStgZ6CbQ2YktNaj8KLE_g9YAOZF6AL9fyLcWQw","DE5z'
                                b'r5eH8EUVQXyAaxWfQUWkGCId-QDCvvxMT77ibj2Q"],"n":"E3in3Z14va0kk4Wq'
                                b'd3vcCAojKNtQq7ZTrQaavR8x0yu4","wt":"0","wr":[],"wa":[],"a":[]}-A'
                                b'AFAAxC_rkCi0QDswHoTC229WXAqV3v_drsQhaNjs1tAxMqy813o8onpAMp2KHC-p'
                                b'V-2-0t7WZf2xpPArvQtF7Yj9BAABu1mkYffvoo6wyFfZyb9LIikO7hKNWezyYkqA'
                                b'lgH0CTENqu2qyNfLeTjcHvK9WKsjkOH0dsfzQX-xsHR4CcCkCQAC4zA0VgJBdt9h'
                                b'zlIVhZbp4q2bMeYWFFqx_nQpDRAzepkA_6gz4AM9fB1CyaeKz1aGxhWgDoUwj4Vh'
                                b'qun0az62CAAD4n0Z0uQVaZ76WZa9suo1z-_PUUPbmLziBNWDffFXqvzrqZm9BG0n'
                                b'CD3HuAYOdvH7KXtOHcDGOk4wqksgzA1YAAAE292FFAQJDweKw_PKLngr-2iBeHrU'
                                b'Fu_rVJwIT2ddzjDKex9g7gsVcOgjmZtHce5mqFU5aUVWs1OAEHooC05zBA')

        # apply msg to Wes's Kevery
        wesKvy.processAll(ims=bytearray(msg))  # process local copy of msg
        assert wesK.serder.diger.qb64 == wesSrdr.dig  # key state updated so event was validated
        assert wesK.serder.diger.qb64 == 'EA0LlynpZE1kxSJIIGL9ipYnIfQMYdq2QzCGZVx-cR94'


    assert not os.path.exists(wesKp.path)
    assert not os.path.exists(wesDB.path)

    """End Test"""


if __name__ == "__main__":
    test_weighted()

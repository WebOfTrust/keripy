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

        assert msg == bytearray(b'{"v":"KERI10JSON00018e_","t":"icp","d":"EhutNfiLutnbeFiRKvrgH89r'
                                b'E8ZB8kOKDbG41eBscbj0","i":"EZgXYINAQWXFpxAmWI9AwOwjVOYXzjyEE_-Dd'
                                b'TfkEk8s","s":"0","kt":["1/2","1/2","1/2"],"k":["DK4OJI8JOr6oEEUM'
                                b'eSF_X-SbKysfwpKwW-ho5KARvH5c","D1RZLgYke0GmfZm-CH8AsW4HoTU4m-2mF'
                                b'gu8kbwp8jQU","DBVwzum-jPfuUXUcHEWdplB4YcoL3BWGXK0TMoF_NeFU"],"n"'
                                b':"EhJGhyJQTpSlZ9oWfQT-lHNl1woMazLC42O89fRHocTI","bt":"0","b":[],'
                                b'"c":[],"a":[]}-AADAADFwJfs95_k54FeDmMICHFuOXWOMZLxpqKTP2NtCkn9jb'
                                b'lcCxUGoOjPz8m51ghHnT-sinQgTit_5aKumm8wRfAwABzJyxlhJJUZUpbsDaPF6o'
                                b'VEsCKXg3XakhotYYattj9zrG6pYNy8ve0oMNxJCScQ6QmjcMQwDMGVSyHSAzccbg'
                                b'BgAChKA93JcrdoGqfmhLPoi6afrPzdMwNQU9OoCpDt_rNXeFOAhnSBE1OrZKz7rw'
                                b'1Q27ASmdxRzOvctcRsuE_3n8BQ')

        # apply msg to Wes's Kevery
        parsing.Parser().parse(ims=bytearray(msg), kvy=wesKvy)
        # wesKvy.process(ims=bytearray(msg))  # process local copy of msg
        wesK = wesKvy.kevers[wesPre]  # kever created so event was validated
        assert wesK.prefixer.qb64 == wesPre
        assert wesK.serder.diger.qb64 == wesSrdr.dig  # key state updated so event was validated

        # create interaction event for Wes
        wesSrdr = eventing.interact(pre=wesK.prefixer.qb64,
                                    dig=wesK.serder.diger.qb64,
                                    sn=wesK.sn + 1,
                                    data=[])

        sigers = wesMgr.sign(ser=wesSrdr.raw, verfers=wesK.verfers)

        msg = bytearray(wesSrdr.raw)
        counter = coring.Counter(coring.CtrDex.ControllerIdxSigs,
                                 count=len(sigers))
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        assert msg == bytearray(b'{"v":"KERI10JSON0000cb_","t":"ixn","d":"EFhOmk2_hyrfsuUu7xLtRBzV'
                                b'HdRPNuVHJl4SAbpZAPdE","i":"EZgXYINAQWXFpxAmWI9AwOwjVOYXzjyEE_-Dd'
                                b'TfkEk8s","s":"1","p":"EhutNfiLutnbeFiRKvrgH89rE8ZB8kOKDbG41eBscb'
                                b'j0","a":[]}-AADAAVgjqE2cDnVTIRves3_yQu1DwTt5oPyuowvXAXV4v21sF4g-'
                                b'mbUHawlbMDY1aq5I-yHW2nIFaSDjaHmm0GObGDQABD6dJ5yRKCCI3IZhnkb6r_-R'
                                b'A2XNtt0SjxlQkECyaVJfIR8LZ74GvLYsWyIyuknHyTiWpMzKSYpGpNC5VOqkiDgA'
                                b'C-XqDrlNExNrgeOFSR-Wys-ZZ1rStOYS_mcC_fLw9Xl_DRSpZx2PG2M3n_SuOysd'
                                b'z7OiIevj4OT0SWrjk3kvgBQ')

        # apply msg to wes's Kevery
        parsing.Parser().parse(ims=bytearray(msg), kvy=wesKvy)
        # wesKvy.process(ims=bytearray(msg))  # process local copy of msg
        assert wesK.serder.diger.qb64 == wesSrdr.dig  # key state updated so event was validated

        # Create rotation event for Wes
        # get current keys as verfers and next digests as digers
        nxtsith = ["1/2", "1/2", "1/2"]  # 2 of 3 but with weighted threshold
        verfers, digers, cst, nst = wesMgr.rotate(pre=wesPre, count=3, sith=nxtsith, temp=True)
        assert nst == nxtsith

        wesSrdr = eventing.rotate(pre=wesK.prefixer.qb64,
                                  keys=[verfer.qb64 for verfer in verfers],
                                  sith=sith,
                                  dig=wesK.serder.diger.qb64,
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
        assert wesK.serder.diger.qb64 == wesSrdr.dig  # key state updated so event was validated

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
                                  dig=wesK.serder.diger.qb64,
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

        assert msg == bytearray(b'{"v":"KERI10JSON0001c3_","t":"rot","d":"E0wXUK4nwf_03SoRfEbpo-KC'
                                b'4aKLSbx8ZgFfoIeF-T3c","i":"EZgXYINAQWXFpxAmWI9AwOwjVOYXzjyEE_-Dd'
                                b'TfkEk8s","s":"3","p":"E2hnTMwOVT3T2gAVtNG6H5i41yCAexv459kOsqEPEs'
                                b'D4","kt":["1/2","1/2","1/2"],"k":["D7WWKDLVwYxYMLAjDceIEs66xPMY4'
                                b'Afzx-RQw2x0mQzI","Dmg6Aah8qyKKDiQyNXTiO71QJwizjZfGM61BA-s0A5F4",'
                                b'"DS3fhKpvPCDL5WmfN4_PkmJMMsSCdRTxG24OQuf_EmHQ"],"n":"EcM4iw7fElX'
                                b'Whad8V-za4Px7nBKjndxoh3XZRkohghKY","bt":"0","br":[],"ba":[],"a":'
                                b'[]}-AADAA_dL3NRU7Gfu8R7SnIbabHmVoGtq9eMZNSp43WrxLNh4lp_39Af8j7p1'
                                b'oWTGr273NI4FbwvRpUk353b9dlW5iBwABeS2N22R4DqBHWbKoZCr0SdkY0d6oTj0'
                                b'ynXBmrfBDNWFIw8t_JicpJ-3rJ6a9akdS6uY-JgYoep2bjtMnYoEvBAACySVqIHL'
                                b'b3_oZIvI0vjCvF85m_m-qCmmnmP1kF-gvvgE7dld6olU2Ja1PvtxICphrwK6Jiuj'
                                b'DzKrMi3BCM03NCw')

        # apply msg to Wes's Kevery
        parsing.Parser().parse(ims=bytearray(msg), kvy=wesKvy)
        # wesKvy.process(ims=bytearray(msg))  # process local copy of msg
        assert wesK.serder.diger.qb64 == wesSrdr.dig  # key state updated so event was validated

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
                                  dig=wesK.serder.diger.qb64,
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

        assert msg == bytearray(b'{"v":"KERI10JSON000231_","t":"rot","d":"Er19kT320yZeT1-iRlPMagZd'
                                b'PDuvKNMCbhuF6dCJ_MBE","i":"EZgXYINAQWXFpxAmWI9AwOwjVOYXzjyEE_-Dd'
                                b'TfkEk8s","s":"4","p":"E0wXUK4nwf_03SoRfEbpo-KC4aKLSbx8ZgFfoIeF-T'
                                b'3c","kt":[["1/2","1/2","1/2"],["1/1","1/1"]],"k":["DToUWoemnetqJ'
                                b'oLFIqDI7lxIJEfF0W7xG5ZlqAseVUQc","Drz-IZjko61q-sPMDIW6n-0NGFubbX'
                                b'iZhzWZrO_BZ0Wc","DiGwL3hjQqiUgQlFPeA6kRR1EBXX0vSLm9b6QhPS8IkQ","'
                                b'Dxj5pcStgZ6CbQ2YktNaj8KLE_g9YAOZF6AL9fyLcWQw","DE5zr5eH8EUVQXyAa'
                                b'xWfQUWkGCId-QDCvvxMT77ibj2Q"],"n":"E3in3Z14va0kk4Wqd3vcCAojKNtQq'
                                b'7ZTrQaavR8x0yu4","bt":"0","br":[],"ba":[],"a":[]}-AAFAAg4qwKqoVL'
                                b'yMySwooHfjF6GzgrM5N6UVywH-gRjhIwbwzCLG-Faia8TmUA-4tSicAuaMK0YLoI'
                                b'vRdAOoydoAzBAABFxyy28bZJNT3uRSaTwKKCHcnq36WpeEVFSyRVUQ1uusReww3u'
                                b'JI55mXYuTueYgLcXPUuI5ZTb7zA8SihtY3MBgAChOvtbYM0ppYJLVARn7dbEJHRs'
                                b'bGB6AvDEIndjOR5np1Y1ouEXz2VP_1dmZWA59q8ssGma5s2hN6jkrBfyDYrBgAD8'
                                b'L3lZeqJe2A14ultXT4Qwu9Eicv38dOEp4O_FPd4LeMBYbvE-bpbWmT2_e06UElbr'
                                b'Jp5hJdYfOMyq4rQufykDQAE8gy5lRiW-GnlqTB9Q3ryPPjD5JPHu_cl3keDBUUW2'
                                b'K5sEu1t4QrC3MeE9k8qV0g55DSSvIN5AFLN5sLmE4IOAA')

        # apply msg to Wes's Kevery
        parsing.Parser().parse(ims=bytearray(msg), kvy=wesKvy)
        # wesKvy.process(ims=bytearray(msg))  # process local copy of msg
        assert wesK.serder.diger.qb64 == wesSrdr.dig  # key state updated so event was validated

    assert not os.path.exists(wesKS.path)
    assert not os.path.exists(wesDB.path)

    """End Test"""


if __name__ == "__main__":
    test_weighted()

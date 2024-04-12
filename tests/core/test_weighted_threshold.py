# -*- encoding: utf-8 -*-
"""
tests delegation primaily from keri.core.eventing

"""
import os

import pytest

from keri import help

from keri import core
from keri.core import coring, eventing, parsing

from keri.db import basing
from keri.app import keeping


logger = help.ogler.getLogger()


def test_weighted():
    """
    Test multisig with weighted threshold

    """
    wesSalt = core.Salter(raw=b'0123456789abcdef').qb64  # init wes Salter

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
        verfers, digers = wesMgr.incept(icount=3, ncount=3, stem='wes', temp=True)

        wesSrdr = eventing.incept(keys=[verfer.qb64 for verfer in verfers],
                                  isith=sith,
                                  nsith=nxtsith,
                                  ndigs=[diger.qb64 for diger in digers],
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

        assert msg == (b'{"v":"KERI10JSON000207_","t":"icp","d":"EIL2dvwm6lYAsyKKtzxIEFm5'
                    b'1gSfwe3IIZSx8kI8ve7_","i":"EIL2dvwm6lYAsyKKtzxIEFm51gSfwe3IIZSx8'
                    b'kI8ve7_","s":"0","kt":["1/2","1/2","1/2"],"k":["DCuDiSPCTq-qBBFD'
                    b'Hkhf1_kmysrH8KSsFvoaOSgEbx-X","DNUWS4GJHtBpn2Zvgh_ALFuB6E1OJvtph'
                    b'YLvJG8KfI0F","DAVcM7pvoz37lF1HBxFnaZQeGHKC9wVhlytEzKBfzXhV"],"nt'
                    b'":["1/2","1/2","1/2"],"n":["EFQZkN8MMEtZzaS-Tq1EEbH886vsf5SzwicS'
                    b'n_ywbzTy","ENOQnUj8GNr1ICJ1P4qmC3-aHTrpZqKVpZhvHCBVWE1p","EDFH1M'
                    b'fEJWlI9PpMbgBi_RGP7L4UivrLfozFucuEaWVH"],"bt":"0","b":[],"c":[],'
                    b'"a":[]}-AADAAC3xWTpnv14_khneBqDlrK7JHPUoHNJhWMIXzXbK80RVyEYV7iMs'
                    b'WaAXfepkRsyELBLd25atAtE3iLeDn1I-gUMABDr8iCcrun_otXsarVXpe6jgK2VG'
                    b'20RpgsVvFunUxHsrZRKm6gNjMAoKZkqzDVuY5tKD0XkTmonstex5Wj9dToBACAwN'
                    b'b8Lj-vxJYMi_vIH-ETGG0dVfqIk4ihrQvV1iL1_07eWfu4BwRYCPCZDo0F0Xbkz0'
                    b'DP4xXVfChR-lFd2npUG')

        # apply msg to Wes's Kevery
        parsing.Parser().parse(ims=bytearray(msg), kvy=wesKvy)
        # wesKvy.process(ims=bytearray(msg))  # process local copy of msg
        wesK = wesKvy.kevers[wesPre]  # kever created so event was validated
        assert wesK.prefixer.qb64 == wesPre
        assert wesK.serder.said == wesSrdr.said  # key state updated so event was validated

        # create interaction event for Wes
        wesSrdr = eventing.interact(pre=wesK.prefixer.qb64,
                                    dig=wesK.serder.said,
                                    sn=wesK.sn + 1,
                                    data=[])

        sigers = wesMgr.sign(ser=wesSrdr.raw, verfers=wesK.verfers)

        msg = bytearray(wesSrdr.raw)
        counter = coring.Counter(coring.CtrDex.ControllerIdxSigs,
                                 count=len(sigers))
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        assert msg == (b'{"v":"KERI10JSON0000cb_","t":"ixn","d":"EODgCVSGS9S8ZaOr89HKDP_Z'
                    b'll21C8zbUBjbBU1HjGEk","i":"EIL2dvwm6lYAsyKKtzxIEFm51gSfwe3IIZSx8'
                    b'kI8ve7_","s":"1","p":"EIL2dvwm6lYAsyKKtzxIEFm51gSfwe3IIZSx8kI8ve'
                    b'7_","a":[]}-AADAAAsZ-qmrZIreJgAd34xZEb_mHTc7tjgwMzMbd31sRyt8a1os'
                    b'duDv_uzeqWiicSauNyiehjfPjeJa1ZJfOGBgbEPABC3seofRQNJPKgqXy6Y2N_Vs'
                    b'ewM1QkG7Y1hfIOosAKW8EdB9nUvqofUhOdSuH2LUzV3S4uenFe-G8EP_VhQaLAHA'
                    b'CAwD7519eOtxzS_D8E0hXjVzVvrmUjOIBGk_gZrG-2pvkEKIpLZxffMUt6yQB9iV'
                    b'0kViHlHI7WkFVS5q8k1SfgI')

        # apply msg to wes's Kevery
        parsing.Parser().parse(ims=bytearray(msg), kvy=wesKvy)
        # wesKvy.process(ims=bytearray(msg))  # process local copy of msg
        assert wesK.serder.said == wesSrdr.said  # key state updated so event was validated

        # Create rotation event for Wes
        # get current keys as verfers and next digests as digers
        nxtsith = ["1/2", "1/2", "1/2"]  # 2 of 3 but with weighted threshold
        verfers, digers = wesMgr.rotate(pre=wesPre, ncount=3, temp=True)

        wesSrdr = eventing.rotate(pre=wesK.prefixer.qb64,
                                  keys=[verfer.qb64 for verfer in verfers],
                                  isith=sith,
                                  dig=wesK.serder.said,
                                  nsith=nxtsith,
                                  ndigs=[diger.qb64 for diger in digers],
                                  sn=wesK.sn + 1,
                                  data=[])

        sigers = wesMgr.sign(ser=wesSrdr.raw, verfers=verfers)

        msg = bytearray(wesSrdr.raw)
        counter = coring.Counter(coring.CtrDex.ControllerIdxSigs,
                                 count=len(sigers))
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        assert (b'{"v":"KERI10JSON00023c_","t":"rot","d":"ELKSLVpbV9eH3xk2xBqH3fSg'
                b'OmWTbUoBuE2JsLl0lu2L","i":"EIL2dvwm6lYAsyKKtzxIEFm51gSfwe3IIZSx8'
                b'kI8ve7_","s":"2","p":"EODgCVSGS9S8ZaOr89HKDP_Zll21C8zbUBjbBU1HjG'
                b'Ek","kt":["1/2","1/2","1/2"],"k":["DHqJ2DNmypwMKelWXLgl3V-9pDRcO'
                b'enM5Wf03O1xx1Ri","DEIISiMvtnaPTpMHkoGs4d0JdbwjreW53OUBfMedLUaF",'
                b'"DDQFJ_uXcZum_DY6NNTtI5UrTEQo6PRWEANpn6hVtfyQ"],"nt":["1/2","1/2'
                b'","1/2"],"n":["EJsp5uWsQOsioYA16kbCZW9HPMr0rEaU4NUvfm6QTYd2","EF'
                b'xT53mK2-1sAnh8VcLEL1HowQp0t84dfIWRaju5Ef61","EETqITKVCCpOS6aDPiZ'
                b'FJOSWll2i39xaFQkfAYsG18I_"],"bt":"0","br":[],"ba":[],"a":[]}-AAD'
                b'AADP60HsnBHLv8YAsR3987MVQ2A_KK0aBSUrek5YTsGKJF9F1DK7a5hqkTkgNvr3'
                b'68HoffgZpYHTcWO4IdcKuNALABA31PINHyZ0nsebwC23S7t-IJQP13wo6lgI8HJb'
                b'NuYz26ZgpISlTEbYHaHAkqdP0fzQ6kg4B_sIomdwKbjSIHcHACDbPDzDPIOck6Vr'
                b'DYC7gbgT8YtkGs_sKtZgyJjl2_FUzCzIqYoJmqq0x-mFCaWbZwt4erYsoJvwfQgc'
                b'dl5Rhu0K')


        # apply msg to Wes's Kevery
        parsing.Parser().parse(ims=bytearray(msg), kvy=wesKvy)
        # wesKvy.process(ims=bytearray(msg))  # process local copy of msg
        assert wesK.serder.said == wesSrdr.said  # key state updated so event was validated

        # Create rotation event for Wes
        # get current keys as verfers and next digests as digers
        sith = nxtsith  # rotate so nxtsith is now current sith and need new nextsith
        #  2 of first 3 and 1 of last 2
        nxtsith = [["1/2", "1/2", "1/2"], ["1", "1"]]
        verfers, digers = wesMgr.rotate(pre=wesPre, ncount=5, temp=True)

        wesSrdr = eventing.rotate(pre=wesK.prefixer.qb64,
                                  keys=[verfer.qb64 for verfer in verfers],
                                  isith=sith,
                                  dig=wesK.serder.said,
                                  nsith=nxtsith,
                                  ndigs=[diger.qb64 for diger in digers],
                                  sn=wesK.sn + 1,
                                  data=[])

        sigers = wesMgr.sign(ser=wesSrdr.raw, verfers=verfers)

        msg = bytearray(wesSrdr.raw)
        counter = coring.Counter(coring.CtrDex.ControllerIdxSigs,
                                 count=len(sigers))
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        assert msg == (b'{"v":"KERI10JSON0002a6_","t":"rot","d":"EJ4TG5D0URQ0InD_EIDXDoI9'
                    b'v1y3vIk-0LMJMjeZXryh","i":"EIL2dvwm6lYAsyKKtzxIEFm51gSfwe3IIZSx8'
                    b'kI8ve7_","s":"3","p":"ELKSLVpbV9eH3xk2xBqH3fSgOmWTbUoBuE2JsLl0lu'
                    b'2L","kt":["1/2","1/2","1/2"],"k":["DO1ligy1cGMWDCwIw3HiBLOusTzGO'
                    b'AH88fkUMNsdJkMy","DJoOgGofKsiig4kMjV04ju9UCcIs42XxjOtQQPrNAORe",'
                    b'"DEt34Sqbzwgy-VpnzePz5JiTDLEgnUU8RtuDkLn_xJh0"],"nt":[["1/2","1/'
                    b'2","1/2"],["1","1"]],"n":["ENzeDznmpi75oO8APbVzyW75xnmgLDJRo0rCH'
                    b'f4gsDPc","ELnNWeDypTMeaIZzbT8GoJJnbmm8ksJ8ic8b2-9KFZQK","ED2lFBw'
                    b'MbkNQy2vxFWLbbEg2V6OLChhLfTxmvuNGWz91","EHy3gn2wZog-q8V3r6RzduTN'
                    b'48nLEHgSYHaoNaWHrxrl","EHuCmMw5ksFOQxvDSXL9h-_94RMKERjqLj_KFSusu'
                    b'HQg"],"bt":"0","br":[],"ba":[],"a":[]}-AADAACxUM40kMP7aGrPIlwO1d'
                    b'6XAvk6jX22u2EwcB_IgsQSaxJlLbXEz4v2j9cUHQKkY7ek47TfFYir-rG5kyLWJa'
                    b'0MABCQ6AlObGVXjIslKCFZkZiBNvQSDLgUU_2sR4RQxghGCExNWG9jwsSAOFBGX5'
                    b'QcEb6Hqu4ZrdbnyV9GxRkR-jkDACC4Ydi6Jlqw9ROIqNvyHoXNoYcIZzI8iD8_YB'
                    b'1-U9J1xb55jG4z-1Ddyx8mLW6_O53boaFobaitvO13z3u5OswF')

        # apply msg to Wes's Kevery
        parsing.Parser().parse(ims=bytearray(msg), kvy=wesKvy)
        # wesKvy.process(ims=bytearray(msg))  # process local copy of msg
        assert wesK.serder.said == wesSrdr.said  # key state updated so event was validated

        # Create rotation event for Wes
        # get current keys as verfers and next digests as digers
        sith = nxtsith  # rotate so nxtsith is now current sith and need new nextsith
        #  2 of first 3 and 1 of last 2
        nxtsith = [["1/2", "1/2", "1/2"], ["1/1", "1/1"]]
        verfers, digers = wesMgr.rotate(pre=wesPre, ncount=5, temp=True)

        wesSrdr = eventing.rotate(pre=wesK.prefixer.qb64,
                                  keys=[verfer.qb64 for verfer in verfers],
                                  isith=sith,
                                  dig=wesK.serder.said,
                                  nsith=nxtsith,
                                  ndigs=[diger.qb64 for diger in digers],
                                  sn=wesK.sn + 1,
                                  data=[])

        sigers = wesMgr.sign(ser=wesSrdr.raw, verfers=verfers)

        msg = bytearray(wesSrdr.raw)
        counter = coring.Counter(coring.CtrDex.ControllerIdxSigs,
                                 count=len(sigers))
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        assert msg == (b'{"v":"KERI10JSON000310_","t":"rot","d":"EDDsDwylK-5wRXvhhFcR9A1w'
                    b'Wn5MDXhA-dJgTolQpRh3","i":"EIL2dvwm6lYAsyKKtzxIEFm51gSfwe3IIZSx8'
                    b'kI8ve7_","s":"4","p":"EJ4TG5D0URQ0InD_EIDXDoI9v1y3vIk-0LMJMjeZXr'
                    b'yh","kt":[["1/2","1/2","1/2"],["1","1"]],"k":["DE6FFqHpp3raiaCxS'
                    b'KgyO5cSCRHxdFu8RuWZagLHlVEH","DK8_iGY5KOtavrDzAyFup_tDRhbm214mYc'
                    b'1mazvwWdFn","DIhsC94Y0KolIEJRT3gOpEUdRAV19L0i5vW-kIT0vCJE","DMY-'
                    b'aXErYGegm0NmJLTWo_CixP4PWADmRegC_X8i3FkM","DBOc6-Xh_BFFUF8gGsVn0'
                    b'FFpBgiHfkAwr78TE--4m49k"],"nt":[["1/2","1/2","1/2"],["1","1"]],"'
                    b'n":["EIRcCDc9EN0cqc9itYLTC8AWdI8-W0Vx7Yt1RotQR4l0","EPU-29ZvOovk'
                    b'1YKYNExW_GYiyKDLEtPa-P8WpH1nO2aG","EDrDuTNHWoP9f8qLeLZT_hAYquRO5'
                    b'0E5k7L47adqA3z_","EP982h5HWP00GSFGAFOmQC5RtxnscLF2XDoz-duWGblx",'
                    b'"EMoJxeWkCePGAvhwa20i6kJsacO-54GNfTV5kRiSnnJy"],"bt":"0","br":[]'
                    b',"ba":[],"a":[]}-AAFAAA-wolFsUPPHR3oSv-h2o-9KcW35aMgbc3HseDbYVUw'
                    b'81cqQVIgQ1C4Wg6Ivde87nrtEibxUKgd-s63Tg6JkEYKABD-oMkTQSZqJ1uHNAnv'
                    b'xo5zKYQz9PkaxNjsrAc5EIwXmPvt5JR2wXZcglK_dHGloLR1Y7iM0ACvc5d-Idfn'
                    b'ikgMACDoWAZ5vKxMLvwZUtSsZOzPJiYGN3_r50B4_EF2q6onniYilDOBc67_Ckr9'
                    b'XYcjJEvKJLZAd4rGcziIl6PLEL0BADBSGdvXFRehhAjcH-uMyDA1YT_br4eBMyn4'
                    b'GitIfnl9Z1KyIpeFgOJgEMpXwNgnJiVDUjrZBAW9f_Lmr7_8_uULAEARPzSKqTVS'
                    b'kHDerR5KmWcto2AlPna4BZ8VOz28cKga-X_E4-JiP1LxAAlf3ysYNFrMlQGnBGr7'
                    b'l-pVBvUHEIIN')

        # apply msg to Wes's Kevery
        parsing.Parser().parse(ims=bytearray(msg), kvy=wesKvy)
        # wesKvy.process(ims=bytearray(msg))  # process local copy of msg
        assert wesK.serder.said == wesSrdr.said  # key state updated so event was validated

    assert not os.path.exists(wesKS.path)
    assert not os.path.exists(wesDB.path)

    """End Test"""


if __name__ == "__main__":
    test_weighted()

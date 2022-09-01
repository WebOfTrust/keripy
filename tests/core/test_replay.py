# -*- encoding: utf-8 -*-
"""
tests delegation primaily from keri.core.eventing

"""
import datetime
import os

from keri import help
from keri.app import habbing
from keri.core import coring, eventing, parsing
from keri.help import helping

logger = help.ogler.getLogger()


def test_replay():
    """
    Test disjoint and conjoint replay

    Deb creates series of events.
    Deb replays Deb's events to Cam and collects Cam's receipts
    Deb replays Deb's events with Cam's recepts to Bev and collects Bev's receipts
    Deb replays Deb's events with both Cam's and  Bev's receipts to Cam
    Compare replay of Deb's events with receipts by both Deb and Cam to confirm identical
    """
    artSalt = coring.Salter(raw=b'abcdef0123456789').qb64

    with (habbing.openHby(name="deb", base="test") as debHby,
         habbing.openHby(name="cam", base="test") as camHby,
         habbing.openHby(name="bev", base="test") as bevHby,
         habbing.openHby(name="art", base="test", salt=artSalt) as artHby):

        # setup Deb's habitat using default salt multisig already incepts
        sith = ["1/2", "1/2", "1/2"]  # weighted signing threshold
        debHab = debHby.makeHab(name="deb", isith=sith, icount=3)
        assert debHab.kever.prefixer.transferable

        # setup Cam's habitat using default salt multisig already incepts
        # Cam's receipts will be vrcs with 3 indexed sigantures attached
        sith = '2'  # hex str of threshold int
        camHab = camHby.makeHab(name="cam", isith=sith, icount=3)
        assert camHab.kever.prefixer.transferable

        # setup Bev's habitat using default salt nonstransferable already incepts
        # Bev's receipts will be rcts with a receipt couple attached
        sith = '1'  # hex str of threshold int
        bevHab = bevHby.makeHab(name="bev", isith=sith, icount=1, transferable=False)
        assert not bevHab.kever.prefixer.transferable

        # setup Art's habitat using custom salt nonstransferable so not match Bev
        # already incepts
        # Art's receipts will be rcts with a receipt couple attached
        sith = '1'  # hex str of threshold int
        artHab = artHby.makeHab(name="art", isith=sith, icount=1, transferable=False)
        assert not artHab.kever.prefixer.transferable

        # first setup disjoint replay then conjoint replay
        # Create series of event for Deb
        debMsgs = bytearray()
        debMsgs.extend(debHab.makeOwnInception())
        debMsgs.extend(debHab.interact())
        debMsgs.extend(debHab.rotate())
        debMsgs.extend(debHab.interact())
        debMsgs.extend(debHab.interact())
        debMsgs.extend(debHab.interact())
        debMsgs.extend(debHab.interact())

        assert debMsgs == (b'{"v":"KERI10JSON000207_","t":"icp","d":"EMBfbPte3yoP3DCK7Rwhb8ry'
                        b'6YOAfi8iosb2lfIEyLNu","i":"EMBfbPte3yoP3DCK7Rwhb8ry6YOAfi8iosb2l'
                        b'fIEyLNu","s":"0","kt":["1/2","1/2","1/2"],"k":["DEM46LIn08SNwsRX'
                        b'vCXHOytw4qAx6mBpVF2bFZoGwkgh","DD7qGJOSq1EJ7H8X3YEwEep3z6Lwr7uci'
                        b'ZTWTQYgRg-Y","DFh1Fq80-9u1iwIatHQI5WGhER4KKn_NDq1zDxt64ibT"],"nt'
                        b'":["1/2","1/2","1/2"],"n":["ENFGRrVTZOwd1Mg71cO2zh3zWg0Sn2EFhL_S'
                        b'BT1-IsOP","EGcW4Dcfvkl9JuiLWR4EWjgnJTbP5A2CPV1z0P4jC7Cv","EFnwzt'
                        b'tI3ltKXE3iozDczsE1UaVG122X2SWwu2VxPDmr"],"bt":"0","b":[],"c":[],'
                        b'"a":[]}-AADAADVZcpr3j_gUpg942sPGZbtqpGFQeZJViiVBK6UH_L3AF-tparBc'
                        b'kwsriQxW8dXbEtlbQOigexZgOgyXMInEzEHABB6IjiwTBkhh8dSQRqNFv-S2eSM5'
                        b'90-GfnerDBdrLMWPFKrb-l-R5UuOn_0CRLVfLzUheir7PSjYRSmrN0est0JACBsq'
                        b'zsTbgR99AagaVBsQ8UVHXOJx6AwHmHrVkXooJluzcthHmpsw3eHkfydymaNU7wPc'
                        b'zzSts7MxbH5bKcH030P{"v":"KERI10JSON0000cb_","t":"ixn","d":"EP3kC'
                        b'E8A78KWOzk13RW1Bmoq-ckJGcMWgvipBvWBwQLe","i":"EMBfbPte3yoP3DCK7R'
                        b'whb8ry6YOAfi8iosb2lfIEyLNu","s":"1","p":"EMBfbPte3yoP3DCK7Rwhb8r'
                        b'y6YOAfi8iosb2lfIEyLNu","a":[]}-AADAABy7xYYC3JKXiE-hZ1gv4JZEvVwlb'
                        b'eIwExgUnWyD3rZZqF3dJ6eCi7h_jyk57WrVnpFN0p4qVooTtkFrgOW4Z0PABDFE8'
                        b'oPayC1hHKGdSk5Xj2QEnSIP0tZVToe9uf0UJdn49nTI6QO4nbwcpyM5FVDxuBSgP'
                        b'ZK2QtulrPIuCk-mqkFACDLQphoY2No5AfOTU7UOKD2zjRh29Ciyqp5JFI6gJO5gL'
                        b'7dxPHH7EyIvPHgiINI5SAQdGIcE018-w3YLV6ipgoJ{"v":"KERI10JSON00023c'
                        b'_","t":"rot","d":"ELCAenmexV_eKeguvHqvHY_VnwZaUwg629hN3NJxmCVr",'
                        b'"i":"EMBfbPte3yoP3DCK7Rwhb8ry6YOAfi8iosb2lfIEyLNu","s":"2","p":"'
                        b'EP3kCE8A78KWOzk13RW1Bmoq-ckJGcMWgvipBvWBwQLe","kt":["1/2","1/2",'
                        b'"1/2"],"k":["DKPrBZiTjrWtyX51NPmapm6xvOsFMgoFmbXZVB9Q9hIS","DPoM'
                        b'lfIRi4brXKaHxa2Jx90jk8Fo1TU1O5kxwbGquiao","DOrKeNqYvHnUbVLgKb6oP'
                        b'-L7lbaKsNKHj2WrDuAvaeVB"],"nt":["1/2","1/2","1/2"],"n":["EGumHNT'
                        b'aXz4QAW0GNO7x3va_UfNZXm7vt_oGJO15J9I6","EBkEWkkgJw0LfRwf1eNCzAEw'
                        b'50e6iRcHjxwDMkUN-_6v","EL5wQxpoCRfTK96MSM6Edau-q4nU2ang6PJFMJ5NC'
                        b'uJw"],"bt":"0","br":[],"ba":[],"a":[]}-AADAAC2HvOfUjmWUNMk15FJhQ'
                        b'LrKPjIHFeDA93bux-QRbFxCSxkaMpW0XitvtExRjJIn3MombphqxU05t0pRkiZpI'
                        b'oLABB2aIUfhKlYKwzfTzQeJcEJbFsB1-ZAzGvUldvqW_lkMB32uZz0woK97vrQ1w'
                        b'fsGi8o8OAKF02-kbVG6cxWpBoFACD15Mn8Ng7J2Zc-KXXIckinAo4zJ-Se-TaAzt'
                        b'2Eehcm6LzOepW66Jz-k-wvkzx8cuXq0k96RYaFXkdXVeH8W-II{"v":"KERI10JS'
                        b'ON0000cb_","t":"ixn","d":"EBJAa0fb-Q-RvQiVcCPMXZQ968HiZ1wZSlfKry'
                        b'QbY24d","i":"EMBfbPte3yoP3DCK7Rwhb8ry6YOAfi8iosb2lfIEyLNu","s":"'
                        b'3","p":"ELCAenmexV_eKeguvHqvHY_VnwZaUwg629hN3NJxmCVr","a":[]}-AA'
                        b'DAADc5hsbsssi2pumvPph6kRWcK5CyUUpWgZnLaIyM_b0Jt5jQ8q6KJjIgyVCiCi'
                        b'LyTxl75Y03urrhpOhQXJRkNYJABDvXxzTxF1Bushr9AnHJGGR3GC4rxgMIdXXRoc'
                        b'B7tEARxULAsa2RP9lbhNB659TP3lj2oEhonWZwNLPY9rihqcPACCUX7ndEjqAmfe'
                        b'dNLlg-sEmp4L173JMpCPjSnnpz33yTOvu27ltltOOB9rXGYCmDJ8BIdwAN-mQSnz'
                        b'S1NczeXAO{"v":"KERI10JSON0000cb_","t":"ixn","d":"ECo0O7ksyNzUZne'
                        b'3j5-TfSRU_zQ7zKV9hPn1WCAeQOGD","i":"EMBfbPte3yoP3DCK7Rwhb8ry6YOA'
                        b'fi8iosb2lfIEyLNu","s":"4","p":"EBJAa0fb-Q-RvQiVcCPMXZQ968HiZ1wZS'
                        b'lfKryQbY24d","a":[]}-AADAAAPSnoZNjuYj4sn5-1dwGU86f2CGR_Bjykw6TW6'
                        b'7tiFIpmGO6kYWX9eDKuTWObPVUY6mhHkeQYK5WLXhhNtX-ELABA8doP8NcsUBUL8'
                        b'hgGO-r_XfvIXr5Og0yvP7q3PgTOIAe3w9paSOPTCTt13H0ECeKmfTg_lUtGXAkfl'
                        b'OXOyjZwAACBVQIYxGdTltLhiR3BlwqGPE6aR4yeoLcPLDwUuLQ4fF6oytiadlOox'
                        b'_k4Fs9T_OYTnId5i0spvrRVmpum0Iv8A{"v":"KERI10JSON0000cb_","t":"ix'
                        b'n","d":"EDBwmPl5YuWafCqQkjb4cfvQH9IMCP4EQnHUv_SqkU1w","i":"EMBfb'
                        b'Pte3yoP3DCK7Rwhb8ry6YOAfi8iosb2lfIEyLNu","s":"5","p":"ECo0O7ksyN'
                        b'zUZne3j5-TfSRU_zQ7zKV9hPn1WCAeQOGD","a":[]}-AADAACf5W2kkPiH9nKSd'
                        b'LHffjwx-0_C3t8eRa_o4sghEpQkzojkSc3wLCDhWdDQyS3YzOAohPBEuMvUvJTMX'
                        b'cWpWOQHABDSY1aCv0HPk-HMDilFkwdDoZ84T61LSaJ6d2WDAzPIt-jVwWh-yvw9J'
                        b'5_bb1-glJnp9BRt76k0512HF1eiCWsJACAEVYWLg91podscXXWl8n1vnnrOd3e7M'
                        b'2MscJ7P3sIG1TDND9uErYUbFvE6h8J2dJ9O7fZ12oYSb2SUAUpqs0YF{"v":"KER'
                        b'I10JSON0000cb_","t":"ixn","d":"EEWEBNSMFFAATJKSfQJpsgc9UNpeoJSFE'
                        b'DTQrxlKb5bu","i":"EMBfbPte3yoP3DCK7Rwhb8ry6YOAfi8iosb2lfIEyLNu",'
                        b'"s":"6","p":"EDBwmPl5YuWafCqQkjb4cfvQH9IMCP4EQnHUv_SqkU1w","a":['
                        b']}-AADAACfpuq77QP7-EP25QXp5foJq-oCrA05O13vJDqCnCq4jeBYSjudNCa9IP'
                        b'VnUOmr3MXMN2qaNNVp-j_bcyNNV7gBABBCYB0euAnYKijrE713HwC0tLSwQFtOcy'
                        b'RJhODilWsyPcRGBfLe-13VUm4yKFnuHBSeL2bs_zEJ_19H7tVh8U8GACCYlJC_uH'
                        b'lv4v59V8oW2ZrFGyz8tZ41d7o9CSzo4urkI5VCTnNrZu9RouQP_7sV8tZzsZGgVU'
                        b'O2mt0vCPHI0BYI')

        # Play debMsgs to Cam
        # create non-local kevery for Cam to process msgs from Deb
        camKevery = eventing.Kevery(db=camHab.db,
                                    lax=False,
                                    local=False)
        parsing.Parser().parse(ims=bytearray(debMsgs), kvy=camKevery)
        # camKevery.process(ims=bytearray(debMsgs))  # give copy to process
        assert debHab.pre in camKevery.kevers
        assert camKevery.kevers[debHab.pre].sn == debHab.kever.sn == 6
        assert len(camKevery.cues) == 7

        # get disjoints receipts (vrcs) from Cam of Deb's events by processing Cam's cues
        camMsgs = camHab.processCues(camKevery.cues)
        assert camMsgs == (b'{"v":"KERI10JSON0001e7_","t":"icp","d":"ENK59uYGyR9z6fatJ_FG9EUB'
                        b'FSHj88v4bab3lMAieOqG","i":"ENK59uYGyR9z6fatJ_FG9EUBFSHj88v4bab3l'
                        b'MAieOqG","s":"0","kt":"2","k":["DEB3RUo3OzfY-xNbhG9FkMl41xhVBvyJ'
                        b'PLp7kYZIlpXe","DKHNZLIidpl5SWUDnHboKBCJgC72R8d-YEZewhPWo-1H","DK'
                        b'aIgMbIGIf2LT0Rh_usypPcR4PJyjZ_OEOcdupUpcor"],"nt":"2","n":["EGvO'
                        b'7EkWkLVKt7_YJrBnEC9e0VabR5mCDUKHx0KuLahM","EOve2Q43QvXwNAcOgo8IH'
                        b'ykL8TCpmwi6Im9zCJCCSAG3","EEr6taIV3iqtZMjD828ciGP0csVwZ8Z06kH3UC'
                        b'6HZbiH"],"bt":"0","b":[],"c":[],"a":[]}-AADAAAOQjwQcPUjIyCVaBQQE'
                        b'FWLtjYa831Y1i0qQ2GZXuqCyX0v05zy2NZEBJ-aiVFQzPJMptayapYvXxvmxo5-X'
                        b'B0HABACyET8_yhR2b3u1peYjvIQiBPKDvP12Q2t4sYBMHZggjY84vif14qPlOrXj'
                        b'KflUD1oImkfbS-VMy0ap1GM4aoMACBlt-eMfJYFy2esixPcDfhj88vNBB77gTEED'
                        b'xoZ0-v6aWn8Fdn7Lj0B-aEuxjKKAJ7fwO6SY37tK89hij4oG-QF{"v":"KERI10J'
                        b'SON000091_","t":"rct","d":"EMBfbPte3yoP3DCK7Rwhb8ry6YOAfi8iosb2l'
                        b'fIEyLNu","i":"EMBfbPte3yoP3DCK7Rwhb8ry6YOAfi8iosb2lfIEyLNu","s":'
                        b'"0"}-FABENK59uYGyR9z6fatJ_FG9EUBFSHj88v4bab3lMAieOqG0AAAAAAAAAAA'
                        b'AAAAAAAAAAAAENK59uYGyR9z6fatJ_FG9EUBFSHj88v4bab3lMAieOqG-AADAAAt'
                        b'cnzgy6J0pkPtK0SrLsY8qov540EdLW1q77HM9jwMVm8-ahEyKZjF9QD5CxI_HbzO'
                        b'yWLRZrzG6bIdrwTxBNUJABBDlkpGma3TRAeAGHjo8S2LpsW1Cj9ceoOd6N57laRY'
                        b'RhEnTQbmPgnfcmqztFb6ZQohY1oKYtpli_eh73AofIoNACA8urCG0vTS7xCP_rPl'
                        b'yvubEoT_T8cNUZ-YSXcJg918X-5Ys-dIaGOtO6LZFojfBmu_6Oq-iCMjhq9aPRC9'
                        b'wpkB{"v":"KERI10JSON000091_","t":"rct","d":"EP3kCE8A78KWOzk13RW1'
                        b'Bmoq-ckJGcMWgvipBvWBwQLe","i":"EMBfbPte3yoP3DCK7Rwhb8ry6YOAfi8io'
                        b'sb2lfIEyLNu","s":"1"}-FABENK59uYGyR9z6fatJ_FG9EUBFSHj88v4bab3lMA'
                        b'ieOqG0AAAAAAAAAAAAAAAAAAAAAAAENK59uYGyR9z6fatJ_FG9EUBFSHj88v4bab'
                        b'3lMAieOqG-AADAACmhqNbbGx7hODsdqU0jOQHFlsuyeW_Bi2v_nkUgV1SHidsbNZ'
                        b'cKtbciU8RletzgiHHMutHy69zAZ8anC9WmH0PABCdbq0wZ1ivYcp678yT2YREWqZ'
                        b'4I3WJJ_8GXCzflBUAarrFQMG3wSyh1CvwANBY-nr-DQ0uJW1rH2YLILYwMgAMACB'
                        b'TMeSTNleimTiYEvOK3xHQA6tjBhnl6nxBamWaWUCx8l9apI5Ssf6619dvQjdMj_A'
                        b'oCFVc_XVF1st0sh9tv_UO{"v":"KERI10JSON000091_","t":"rct","d":"ELC'
                        b'AenmexV_eKeguvHqvHY_VnwZaUwg629hN3NJxmCVr","i":"EMBfbPte3yoP3DCK'
                        b'7Rwhb8ry6YOAfi8iosb2lfIEyLNu","s":"2"}-FABENK59uYGyR9z6fatJ_FG9E'
                        b'UBFSHj88v4bab3lMAieOqG0AAAAAAAAAAAAAAAAAAAAAAAENK59uYGyR9z6fatJ_'
                        b'FG9EUBFSHj88v4bab3lMAieOqG-AADAABtNLEVdIjgSBrkg6zN5O7QwujrclRfZN'
                        b'be5pDZLwEIskvHCoT8K_ul6IzB1eVVlyYd8X2M2dyuRcmHl13xs_QGABCMYL4UF4'
                        b'NSO5mAg47uC1OjOiV8sfnMl1USglhK3GxhX5VAEU209D_lCsC6HaxYz-6pSC932u'
                        b'G7b_4r0jNR30kNACB5RHBjRJd_kna1_QZbqUJAY61k1MkYj7BUMcGADPn9ZeLWII'
                        b'-gTmPK43Z1V_fGLvZGWiElps3vXqpzPLqzXdgM{"v":"KERI10JSON000091_","'
                        b't":"rct","d":"EBJAa0fb-Q-RvQiVcCPMXZQ968HiZ1wZSlfKryQbY24d","i":'
                        b'"EMBfbPte3yoP3DCK7Rwhb8ry6YOAfi8iosb2lfIEyLNu","s":"3"}-FABENK59'
                        b'uYGyR9z6fatJ_FG9EUBFSHj88v4bab3lMAieOqG0AAAAAAAAAAAAAAAAAAAAAAAE'
                        b'NK59uYGyR9z6fatJ_FG9EUBFSHj88v4bab3lMAieOqG-AADAAAbKgOGHuoZPTMZp'
                        b'-pIksMpCOBKJ31g_QkdkRQDXEPY1mV9gkp_RrSVdhkftSCrcayw5sVYiKf-HiWmT'
                        b'0o9C2IBABCA7au9_m5uXvNoYvEnOL_ujyNQ9OvPe8Y2VNsZugCdjoBI6hqg3sIyq'
                        b'QliBSebizfc-r0F8tu47P99OWYSm8MDACAvLx5cbznKmzzqC2DjqDyNd8rtWSOYV'
                        b'Aruybfo7eSnCUmEe2O-xEZL9m6AoZcVYRxxx-w-CB_o5ZVOPJsTGcoC{"v":"KER'
                        b'I10JSON000091_","t":"rct","d":"ECo0O7ksyNzUZne3j5-TfSRU_zQ7zKV9h'
                        b'Pn1WCAeQOGD","i":"EMBfbPte3yoP3DCK7Rwhb8ry6YOAfi8iosb2lfIEyLNu",'
                        b'"s":"4"}-FABENK59uYGyR9z6fatJ_FG9EUBFSHj88v4bab3lMAieOqG0AAAAAAA'
                        b'AAAAAAAAAAAAAAAAENK59uYGyR9z6fatJ_FG9EUBFSHj88v4bab3lMAieOqG-AAD'
                        b'AACWi_08H4mypzdEhbf_EaX3cW7knQyevyzTuNH_2szsknZq4A4rHEXmK96hvATa'
                        b'DL2u6RSeuYkpyQjik5v0X6AEABBUUFPuqgRu-TmtF0x9kLXoZIsx1ZGrg4YU88i-'
                        b'nzelKn__dvPCtP8Fl1nqxYziTOb05SuVh6xAXkmXsWLE8t8HACA_l7cx9MiWHyZK'
                        b'3imIPG1UYhNWdF6i8mnDXI48B8T8f212i6ftyFkSPYJKVnxaMJavdl3diiGhPWEp'
                        b'bSUAKKcM{"v":"KERI10JSON000091_","t":"rct","d":"EDBwmPl5YuWafCqQ'
                        b'kjb4cfvQH9IMCP4EQnHUv_SqkU1w","i":"EMBfbPte3yoP3DCK7Rwhb8ry6YOAf'
                        b'i8iosb2lfIEyLNu","s":"5"}-FABENK59uYGyR9z6fatJ_FG9EUBFSHj88v4bab'
                        b'3lMAieOqG0AAAAAAAAAAAAAAAAAAAAAAAENK59uYGyR9z6fatJ_FG9EUBFSHj88v'
                        b'4bab3lMAieOqG-AADAAD9ZVlw2V40M-S9OboZLK1_02bmEn_uxpe8OfvUFfg3zI8'
                        b'IR4vUdm4LNEPs3fZTLxDaHgR4VjuYlrM0Dzqq3yABABDmE8Zq867B5S_8a0H6MyS'
                        b'Sr6zlCfXYNSeWcPeV9bYWzIQ6p_3plddqymh8osbfNNoFHDTaXaHtae1p5Yb9a6w'
                        b'KACCIjeTqXm6EGhpH-v4uAQhZkqzPco8BjN8gekUv2ZwibddzbGswlorqS3t2xp2'
                        b'Pg8_u_l7OvaorNpohbovpRSQA{"v":"KERI10JSON000091_","t":"rct","d":'
                        b'"EEWEBNSMFFAATJKSfQJpsgc9UNpeoJSFEDTQrxlKb5bu","i":"EMBfbPte3yoP'
                        b'3DCK7Rwhb8ry6YOAfi8iosb2lfIEyLNu","s":"6"}-FABENK59uYGyR9z6fatJ_'
                        b'FG9EUBFSHj88v4bab3lMAieOqG0AAAAAAAAAAAAAAAAAAAAAAAENK59uYGyR9z6f'
                        b'atJ_FG9EUBFSHj88v4bab3lMAieOqG-AADAADeQDnZdLBEFRihbQGpIaMSieRVjL'
                        b'GVnPcOT7JPFvoP48cLGP8eOptISxQsX-TQvyB8e1la5ZMQpD4SIRayRwwFABAgGN'
                        b'XDNfUSNS-BpppP5t9uLTh77GKwErruP07-fVOj12upQzMdukvHo5QcwYsjxKJr4X'
                        b'wUvgmzYZQBcwfWhCICACA7-M8UwazuUbNHZ6RsJQQ3JPt9idipaSnOHYySxQ4NB-'
                        b'qGCpqDWDVOdAU1tg1NA0-ydK0hT1Ba1PsvQuNTlX0D')

        # Play camMsgs to Deb
        # create non-local kevery for Deb to process msgs from Cam
        debKevery = eventing.Kevery(db=debHab.db,
                                    lax=False,
                                    local=False)
        parsing.Parser().parse(ims=bytearray(camMsgs), kvy=debKevery)
        # debKevery.process(ims=bytearray(camMsgs))  # give copy to process
        assert camHab.pre in debKevery.kevers
        assert debKevery.kevers[camHab.pre].sn == camHab.kever.sn == 0
        assert len(debKevery.cues) == 1

        # get disjoints receipts (vrcs) from Deb of Cam's events by processing Deb's cues
        debCamVrcs = debHab.processCues(debKevery.cues)
        assert debCamVrcs == (b'{"v":"KERI10JSON000091_","t":"rct","d":"ENK59uYGyR9z6fatJ_FG9EUB'
                        b'FSHj88v4bab3lMAieOqG","i":"ENK59uYGyR9z6fatJ_FG9EUBFSHj88v4bab3l'
                        b'MAieOqG","s":"0"}-FABEMBfbPte3yoP3DCK7Rwhb8ry6YOAfi8iosb2lfIEyLN'
                        b'u0AAAAAAAAAAAAAAAAAAAAAACELCAenmexV_eKeguvHqvHY_VnwZaUwg629hN3NJ'
                        b'xmCVr-AADAABO5fobjegrnLwnSK98EHLGC_WuXvBMB6AGEClPz8a3WY7UGiIgsur'
                        b'kNcg4dZWfHg4L82KTEuh0DjPSNTM8BdAEABDvNxxFxGXha7y74AxXKxyU5OsajTQ'
                        b'Ip2QChaFbEsK8T8SEzELfYPbPIXM3t7pQ9BNjR-8yDpK27up4lQBtAVIOACDKXA9'
                        b'5dkpfXsXOVT0rhzm2YkanmwmRqQGh1_KlR1aCrL2REhPT02L_qUQRbYv_OYp1jU8'
                        b'vzxgHmNFFpyGBjtMA')

        # Play disjoints debCamVrcs to Cam
        parsing.Parser().parseOne(ims=bytearray(debCamVrcs), kvy=camKevery)
        # camKevery.processOne(ims=bytearray(debCamVrcs))  # give copy to process

        # Play debMsgs to Bev
        # create non-local kevery for Bev to process msgs from Deb
        bevKevery = eventing.Kevery(db=bevHab.db,
                                    lax=False,
                                    local=False)
        parsing.Parser().parse(ims=bytearray(debMsgs), kvy=bevKevery)
        # bevKevery.process(ims=bytearray(debMsgs))  # give copy to process
        assert debHab.pre in bevKevery.kevers
        assert bevKevery.kevers[debHab.pre].sn == debHab.kever.sn == 6
        assert len(bevKevery.cues) == 7

        # get disjoints receipts (rcts) from Bev of Deb's events by processing Bevs's cues
        bevMsgs = bevHab.processCues(bevKevery.cues)
        assert bevMsgs == (b'{"v":"KERI10JSON0000fd_","t":"icp","d":"EEgQobjRpE3PO4gk2Vc8JWrM'
                    b'25lKNRZW32ZGZUXRL4zA","i":"BCXYLq1jTwMSX5G6SzoFv-KnnMdE2zbri22PK'
                    b'dyBlSDL","s":"0","kt":"1","k":["BCXYLq1jTwMSX5G6SzoFv-KnnMdE2zbr'
                    b'i22PKdyBlSDL"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-AA'
                    b'BAABEPOqXuOAMMgmrp6onBYy2R6wNQMDf5_P6WPoyc3EL5AEVMj997HZ4hQft98H'
                    b'8xVESm_7DR_2W2YPu0bsvOqUB{"v":"KERI10JSON000091_","t":"rct","d":'
                    b'"EMBfbPte3yoP3DCK7Rwhb8ry6YOAfi8iosb2lfIEyLNu","i":"EMBfbPte3yoP'
                    b'3DCK7Rwhb8ry6YOAfi8iosb2lfIEyLNu","s":"0"}-CABBCXYLq1jTwMSX5G6Sz'
                    b'oFv-KnnMdE2zbri22PKdyBlSDL0BDV0wEZCyskhdoJISuC2bVtvdtH-fpe-NlUMR'
                    b'UDwQcCKdFnmIkkm7c7-krH-6BsznJPzDaTpjVA8V3MK_rdf-MB{"v":"KERI10JS'
                    b'ON000091_","t":"rct","d":"EP3kCE8A78KWOzk13RW1Bmoq-ckJGcMWgvipBv'
                    b'WBwQLe","i":"EMBfbPte3yoP3DCK7Rwhb8ry6YOAfi8iosb2lfIEyLNu","s":"'
                    b'1"}-CABBCXYLq1jTwMSX5G6SzoFv-KnnMdE2zbri22PKdyBlSDL0BAbrim_lK7FR'
                    b'cQFWVXDxlsuDwxy3JbK0X25b0vomU3lDmcpCyDx9U9r_IIrxK60zDpiuuKnPLJjr'
                    b'xkIP3C8crAM{"v":"KERI10JSON000091_","t":"rct","d":"ELCAenmexV_eK'
                    b'eguvHqvHY_VnwZaUwg629hN3NJxmCVr","i":"EMBfbPte3yoP3DCK7Rwhb8ry6Y'
                    b'OAfi8iosb2lfIEyLNu","s":"2"}-CABBCXYLq1jTwMSX5G6SzoFv-KnnMdE2zbr'
                    b'i22PKdyBlSDL0BAQgQA5sliwmgtaWBzx7pdVBUFkdl3P1EzKvSU0tzNhDk_9Xa-v'
                    b'VQFCvUVjTdNgag4v_VTDnvXTuPHsRiMx2KYE{"v":"KERI10JSON000091_","t"'
                    b':"rct","d":"EBJAa0fb-Q-RvQiVcCPMXZQ968HiZ1wZSlfKryQbY24d","i":"E'
                    b'MBfbPte3yoP3DCK7Rwhb8ry6YOAfi8iosb2lfIEyLNu","s":"3"}-CABBCXYLq1'
                    b'jTwMSX5G6SzoFv-KnnMdE2zbri22PKdyBlSDL0BA7sdFz4wUb7aMfK915xKXgXjq'
                    b'aRR6wdrVQYNIf3MZszSmPkI2JVcJ0dZpyXRao5VBrnYTCvNBD18R3CcpXQKoK{"v'
                    b'":"KERI10JSON000091_","t":"rct","d":"ECo0O7ksyNzUZne3j5-TfSRU_zQ'
                    b'7zKV9hPn1WCAeQOGD","i":"EMBfbPte3yoP3DCK7Rwhb8ry6YOAfi8iosb2lfIE'
                    b'yLNu","s":"4"}-CABBCXYLq1jTwMSX5G6SzoFv-KnnMdE2zbri22PKdyBlSDL0B'
                    b'Ctwg-_Md_G2o3C3Kgj1ADj85IDq6-Tnk8hN8fDRSyLwqtFKf4lwQ7ezEj-c4FymA'
                    b'FpkzY6bNphVahA7TIbvY8J{"v":"KERI10JSON000091_","t":"rct","d":"ED'
                    b'BwmPl5YuWafCqQkjb4cfvQH9IMCP4EQnHUv_SqkU1w","i":"EMBfbPte3yoP3DC'
                    b'K7Rwhb8ry6YOAfi8iosb2lfIEyLNu","s":"5"}-CABBCXYLq1jTwMSX5G6SzoFv'
                    b'-KnnMdE2zbri22PKdyBlSDL0BB-w6CD-j4D2Fls3Y0omcNgLfWx202MTXHTL8ijC'
                    b'Owj9kOVAPOiTrWeOvGpRPywQFPSVxhiL70It1lQkGo67FcI{"v":"KERI10JSON0'
                    b'00091_","t":"rct","d":"EEWEBNSMFFAATJKSfQJpsgc9UNpeoJSFEDTQrxlKb'
                    b'5bu","i":"EMBfbPte3yoP3DCK7Rwhb8ry6YOAfi8iosb2lfIEyLNu","s":"6"}'
                    b'-CABBCXYLq1jTwMSX5G6SzoFv-KnnMdE2zbri22PKdyBlSDL0BBQysWQ8gdoV6tt'
                    b'k-9KlSnAMXREva2dgbD1EYXcKim8aixOVNUHcM4ch6eXp1hMwJiyLYwwye_kavPg'
                    b'AST1-IAA')

        # Play bevMsgs to Deb
        parsing.Parser().parse(ims=bytearray(bevMsgs), kvy=debKevery)
        # debKevery.process(ims=bytearray(bevMsgs))  # give copy to process
        assert bevHab.pre in debKevery.kevers
        assert debKevery.kevers[bevHab.pre].sn == bevHab.kever.sn == 0
        assert len(debKevery.cues) == 1

        # get disjoints receipts (vrcs) from Deb of Bev's events by processing Deb's cues
        debBevVrcs = debHab.processCues(debKevery.cues)
        assert debBevVrcs == (b'{"v":"KERI10JSON000091_","t":"rct","d":"EEgQobjRpE3PO4gk2Vc8JWrM'
                        b'25lKNRZW32ZGZUXRL4zA","i":"BCXYLq1jTwMSX5G6SzoFv-KnnMdE2zbri22PK'
                        b'dyBlSDL","s":"0"}-FABEMBfbPte3yoP3DCK7Rwhb8ry6YOAfi8iosb2lfIEyLN'
                        b'u0AAAAAAAAAAAAAAAAAAAAAACELCAenmexV_eKeguvHqvHY_VnwZaUwg629hN3NJ'
                        b'xmCVr-AADAACWlGA7Hr2y_mmrl7cFMEboQj1OeY96-bUnCCC6hnVFbUzZ5Y9loZL'
                        b'L5CUktJSoCOylrtkHVg1BBYtGFl1-XLMIABB0WqjyM-CONBWDfROL0Y5K4KU-1wY'
                        b'zH37QCGuqkknJgpsfLsTo914_3ha60JpJSiOgMwA0k3SS40Qi47uZOA8EACB2adz'
                        b'kcq0w0RAgQN4upl5L8BqBn7jWPvAaegFTvTLcz3FavXdbzD41JMSWC-AW0e0EXvK'
                        b'4TU921pRZXV7TN54J')

        # Play disjoints debBevVrcs to Bev
        parsing.Parser().parseOne(ims=bytearray(debBevVrcs), kvy=bevKevery)
        # bevKevery.processOne(ims=bytearray(debBevVrcs))  # give copy to process

        # now setup conjoint replay

        # Replay Deb's First Seen Events with receipts (vrcs and rcts) from both Cam and Bev
        # datetime is different in each run in the fse attachment in clone replay
        # so we either have to force dts in db or we parse in pieces
        debFelMsgs = bytearray()
        fn = 0
        cloner = debHab.db.clonePreIter(pre=debHab.pre, fn=fn)  # create iterator
        msg = next(cloner)  # get zeroth event with attachments
        assert len(msg) == 1595
        debFelMsgs.extend(msg)

        # parse msg
        serder = coring.Serder(raw=msg)
        assert serder.raw == debHab.iserder.raw
        assert serder.sn == fn  # no recovery forks so sn == fn
        assert serder.ked["t"] == coring.Ilks.icp
        del msg[:len(serder.raw)]
        assert len(msg) == 1076

        counter = coring.Counter(qb64b=msg)  # attachment length quadlets counter
        assert counter.code == coring.CtrDex.AttachedMaterialQuadlets
        assert counter.count == (len(msg) - len(counter.qb64b)) // 4 == 268
        del msg[:len(counter.qb64b)]
        assert len(msg) == 1072 == 268 * 4

        counter = coring.Counter(qb64b=msg)  # indexed signatures counter
        assert counter.code == coring.CtrDex.ControllerIdxSigs
        assert counter.count == 3  # multisig deb
        del msg[:len(counter.qb64b)]
        assert len(msg) == 1068

        for i in range(counter.count):  # parse signatures
            siger = coring.Siger(qb64b=msg)
            del msg[:len(siger.qb64b)]
        assert len(msg) == 1068 - 3 * len(siger.qb64b) == 804

        counter = coring.Counter(qb64b=msg)  # trans receipt (vrc) counter
        assert counter.code == coring.CtrDex.TransReceiptQuadruples
        assert counter.count == 3  # multisig cam
        del msg[:len(counter.qb64b)]
        assert len(msg) == 800

        for i in range(counter.count):  # parse receipt quadruples
            prefixer, seqner, diger, siger = eventing.deTransReceiptQuadruple(msg, strip=True)
        assert len(msg) == 800 - 3 * (len(prefixer.qb64b) + len(seqner.qb64b) +
                                      len(diger.qb64b) + len(siger.qb64b)) == 200

        counter = coring.Counter(qb64b=msg)  # nontrans receipt (rct) counter
        assert counter.code == coring.CtrDex.NonTransReceiptCouples
        assert counter.count == 1  # single sig bev
        del msg[:len(counter.qb64b)]
        assert len(msg) == 196

        for i in range(counter.count):  # parse receipt couples
            prefixer, cigar = eventing.deReceiptCouple(msg, strip=True)
        assert len(msg) == 196 - 1 * (len(prefixer.qb64b) + len(cigar.qb64b)) == 64

        counter = coring.Counter(qb64b=msg)  # first seen replay couple counter
        assert counter.code == coring.CtrDex.FirstSeenReplayCouples
        assert counter.count == 1
        del msg[:len(counter.qb64b)]
        assert len(msg) == 60

        seqner = coring.Seqner(qb64b=msg)
        assert seqner.sn == fn == 0
        del msg[:len(seqner.qb64b)]
        assert len(msg) == 36  # 24 less

        dater = coring.Dater(qb64b=msg)
        assert (helping.fromIso8601(helping.nowIso8601()) -
                helping.fromIso8601(dater.dts)) > datetime.timedelta()
        del msg[:len(dater.qb64b)]
        assert len(msg) == 0  # 36 less

        cloner.close()  # must close or get lmdb error upon with exit
        """Exception ignored in: <generator object LMDBer.getAllOrdItemPreIter at 0x106fe1c10>
        Traceback (most recent call last):
        File "/Users/Load/Data/Code/public/keripy/src/keri/db/dbing.py", line 512, in getAllOrdItemPreIter
        yield (cn, bytes(val))  # (on, dig) of event
        lmdb.Error: Attempt to operate on closed/deleted/dropped object.
        """

        fn += 1
        cloner = debHab.db.clonePreIter(pre=debHab.pre, fn=fn)  # create iterator not at 0
        msg = next(cloner)  # next event with attachments
        assert len(msg) == 1279
        serder = coring.Serder(raw=msg)
        assert serder.sn == fn  # no recovery forks so sn == fn
        assert serder.ked["t"] == coring.Ilks.ixn
        debFelMsgs.extend(msg)

        fn += 1
        msg = next(cloner)  # get zeroth event with attachments
        serder = coring.Serder(raw=msg)
        assert serder.sn == fn  # no recovery forks so sn == fn
        assert serder.ked["t"] == coring.Ilks.rot
        assert len(msg) == 1648
        assert ([verfer.qb64 for verfer in serder.verfers] ==
                [verfer.qb64 for verfer in debHab.kever.verfers])
        debFelMsgs.extend(msg)

        fn += 1
        while (fn <= 6):
            msg = next(cloner)  # get zeroth event with attachments
            serder = coring.Serder(raw=msg)
            assert serder.sn == fn  # no recovery forks so sn == fn
            assert serder.ked["t"] == coring.Ilks.ixn
            assert len(msg) == 1279
            debFelMsgs.extend(msg)
            fn += 1

        assert len(debFelMsgs) == 9638
        cloner.close()  # must close or get lmdb error upon with exit

        msgs = debHab.replay()
        assert msgs == debFelMsgs

        # Play Cam's messages to Bev
        parsing.Parser().parse(ims=bytearray(camMsgs), kvy=bevKevery)
        # bevKevery.process(ims=bytearray(camMsgs))  # give copy to process
        assert camHab.pre in bevKevery.kevers
        assert bevKevery.kevers[camHab.pre].sn == camHab.kever.sn == 0
        assert len(bevKevery.cues) == 1

        # Play Bev's messages to Cam
        parsing.Parser().parse(ims=bytearray(bevMsgs), kvy=camKevery)
        # camKevery.process(ims=bytearray(bevMsgs))  # give copy to process
        assert bevHab.pre in camKevery.kevers
        assert camKevery.kevers[bevHab.pre].sn == bevHab.kever.sn == 0
        assert len(camKevery.cues) == 1

        camDebFelMsgs = camHab.replay(pre=debHab.pre)
        bevDebFelMsgs = bevHab.replay(pre=debHab.pre)

        assert len(bevDebFelMsgs) == len(camDebFelMsgs) == len(debFelMsgs) == 9638

        # create non-local kevery for Art to process conjoint replay msgs from Deb
        artKevery = eventing.Kevery(db=artHab.db,
                                    lax=False,
                                    local=False)
        # process Cam's inception so Art will proces Cam's vrcs without escrowing
        camIcpMsg = camHab.makeOwnInception()
        parsing.Parser().parse(ims=bytearray(camIcpMsg), kvy=artKevery)
        # artKevery.process(ims=bytearray(camIcpMsg))
        assert camHab.pre in artKevery.kevers
        assert len(artKevery.cues) == 1

        # process in cloned mode
        artKevery.cloned = True
        parsing.Parser().parse(ims=bytearray(debFelMsgs), kvy=artKevery)
        assert debHab.pre in artKevery.kevers
        assert artKevery.kevers[debHab.pre].sn == debHab.kever.sn == 6
        assert len(artKevery.cues) == 8
        artDebFelMsgs = artHab.replay(pre=debHab.pre)
        assert len(artDebFelMsgs) == 9638

    assert not os.path.exists(artHby.ks.path)
    assert not os.path.exists(artHby.db.path)
    assert not os.path.exists(bevHby.ks.path)
    assert not os.path.exists(bevHby.db.path)
    assert not os.path.exists(camHby.ks.path)
    assert not os.path.exists(camHby.db.path)
    assert not os.path.exists(debHby.ks.path)
    assert not os.path.exists(debHby.db.path)

    """End Test"""


def test_replay_all():
    """
    Test conjoint replay all

    Setup database with events from Deb, Cam, Bev, abd Art
    Replay all the events in database.

    """
    artSalt = coring.Salter(raw=b'abcdef0123456789').qb64


    with (habbing.openHby(name="deb", base="test") as debHby,
         habbing.openHby(name="cam", base="test") as camHby,
         habbing.openHby(name="bev", base="test") as bevHby,
         habbing.openHby(name="art", base="test", salt=artSalt) as artHby):

        # setup Deb's habitat using default salt multisig already incepts
        sith = ["1/2", "1/2", "1/2"]  # weighted signing threshold
        debHab = debHby.makeHab(name='test', isith=sith, icount=3)
        assert debHab.kever.prefixer.transferable

        # setup Cam's habitat using default salt multisig already incepts
        # Cam's receipts will be vrcs with 3 indexed sigantures attached
        sith = '2'  # hex str of threshold int
        camHab = camHby.makeHab(name='test', isith=sith, icount=3)
        assert camHab.kever.prefixer.transferable

        # setup Bev's habitat using default salt nonstransferable already incepts
        # Bev's receipts will be rcts with a receipt couple attached
        sith = '1'  # hex str of threshold int
        bevHab = bevHby.makeHab(name='test', isith=sith, icount=1, transferable=False)
        assert not bevHab.kever.prefixer.transferable

        # setup Art's habitat using custom salt nonstransferable so not match Bev
        # already incepts
        # Art's receipts will be rcts with a receipt couple attached
        sith = '1'  # hex str of threshold int
        artHab = artHby.makeHab(name='test', isith=sith, icount=1, transferable=False)
        assert not artHab.kever.prefixer.transferable

        # Create series of event for Deb
        debMsgs = bytearray()
        debMsgs.extend(debHab.makeOwnInception())
        debMsgs.extend(debHab.interact())
        debMsgs.extend(debHab.rotate())
        debMsgs.extend(debHab.interact())
        debMsgs.extend(debHab.interact())
        debMsgs.extend(debHab.interact())
        debMsgs.extend(debHab.interact())

        # Play debMsgs to Cam
        # create non-local kevery for Cam to process msgs from Deb
        camKevery = eventing.Kevery(db=camHab.db,
                                    lax=False,
                                    local=False)
        parsing.Parser().parse(ims=bytearray(debMsgs), kvy=camKevery)
        # camKevery.process(ims=bytearray(debMsgs))  # give copy to process
        assert debHab.pre in camKevery.kevers
        assert camKevery.kevers[debHab.pre].sn == debHab.kever.sn == 6
        assert len(camKevery.cues) == 7

        # get disjoints receipts (vrcs) from Cam of Deb's events by processing Cam's cues
        camMsgs = camHab.processCues(camKevery.cues)

        # Play camMsgs to Deb
        # create non-local kevery for Deb to process msgs from Cam
        debKevery = eventing.Kevery(db=debHab.db,
                                    lax=False,
                                    local=False)
        parsing.Parser().parse(ims=bytearray(camMsgs), kvy=debKevery)
        # debKevery.process(ims=bytearray(camMsgs))  # give copy to process
        assert camHab.pre in debKevery.kevers
        assert debKevery.kevers[camHab.pre].sn == camHab.kever.sn == 0
        assert len(debKevery.cues) == 1

        # get disjoints receipts (vrcs) from Deb of Cam's events by processing Deb's cues
        debCamVrcs = debHab.processCues(debKevery.cues)

        # Play disjoints debCamVrcs to Cam
        parsing.Parser().parseOne(ims=bytearray(debCamVrcs), kvy=camKevery)
        # camKevery.processOne(ims=bytearray(debCamVrcs))  # give copy to process

        # Play debMsgs to Bev
        # create non-local kevery for Bev to process msgs from Deb
        bevKevery = eventing.Kevery(db=bevHab.db,
                                    lax=False,
                                    local=False)
        parsing.Parser().parse(ims=bytearray(debMsgs), kvy=bevKevery)
        # bevKevery.process(ims=bytearray(debMsgs))  # give copy to process
        assert debHab.pre in bevKevery.kevers
        assert bevKevery.kevers[debHab.pre].sn == debHab.kever.sn == 6
        assert len(bevKevery.cues) == 7

        # get disjoints receipts (rcts) from Bev of Deb's events by processing Bevs's cues
        bevMsgs = bevHab.processCues(bevKevery.cues)

        # Play bevMsgs to Deb
        parsing.Parser().parse(ims=bytearray(bevMsgs), kvy=debKevery)
        # debKevery.process(ims=bytearray(bevMsgs))  # give copy to process
        assert bevHab.pre in debKevery.kevers
        assert debKevery.kevers[bevHab.pre].sn == bevHab.kever.sn == 0
        assert len(debKevery.cues) == 1

        # get disjoints receipts (vrcs) from Deb of Bev's events by processing Deb's cues
        debBevVrcs = debHab.processCues(debKevery.cues)

        # Play disjoints debBevVrcs to Bev
        parsing.Parser().parseOne(ims=bytearray(debBevVrcs), kvy=bevKevery)
        # bevKevery.processOne(ims=bytearray(debBevVrcs))  # give copy to process

        # now setup replay
        debAllFelMsgs = debHab.replayAll()
        assert len(debAllFelMsgs) == 12495

        # create non-local kevery for Art to process conjoint replay msgs from Deb
        artKevery = eventing.Kevery(db=artHab.db,
                                    lax=False,
                                    local=False)
        # process Cam's inception so Art will proces Cam's vrcs without escrowing
        camIcpMsg = camHab.makeOwnInception()
        parsing.Parser().parse(ims=bytearray(camIcpMsg), kvy=artKevery)
        assert camHab.pre in artKevery.kevers
        assert len(artKevery.cues) == 1
        # give copy to process in cloned mode
        artKevery.cloned = True
        parsing.Parser().parse(ims=bytearray(debAllFelMsgs), kvy=artKevery)
        assert debHab.pre in artKevery.kevers
        assert artKevery.kevers[debHab.pre].sn == debHab.kever.sn == 6
        assert len(artKevery.cues) == 10
        artAllFelMsgs = artHab.replayAll()
        assert len(artAllFelMsgs) == 12717 #12113

    assert not os.path.exists(artHby.ks.path)
    assert not os.path.exists(artHby.db.path)
    assert not os.path.exists(bevHby.ks.path)
    assert not os.path.exists(bevHby.db.path)
    assert not os.path.exists(camHby.ks.path)
    assert not os.path.exists(camHby.db.path)
    assert not os.path.exists(debHby.ks.path)
    assert not os.path.exists(debHby.db.path)

    """End Test"""


if __name__ == "__main__":
    test_replay_all()

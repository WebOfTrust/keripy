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

    with habbing.openHby(name="deb", base="test") as debHby, \
         habbing.openHby(name="cam", base="test") as camHby, \
         habbing.openHby(name="bev", base="test") as bevHby,  \
         habbing.openHby(name="art", base="test", salt=artSalt) as artHby:

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

        assert debMsgs == (b'{"v":"KERI10JSON000207_","t":"icp","d":"Eban8TbpEQ4HX5hwefKvH5-7'
                           b'eP5SOctXFdAkliMo-Rbk","i":"Eban8TbpEQ4HX5hwefKvH5-7eP5SOctXFdAkl'
                           b'iMo-Rbk","s":"0","kt":["1/2","1/2","1/2"],"k":["DRxCLERO9eSvG4fl'
                           b'uzOsK52GCWCtKOZClVwA38Oa--MA","DCxzT16ikP6LKVJfr6hv1jmhynm6I4-Ko'
                           b'GYkJtd9uBro","DsDl5xSHnIlcGo13u5jDRr1jJMkQ34nEc5R6NYsdPS2k"],"nt'
                           b'":["1/2","1/2","1/2"],"n":["E1jYwSdDo3A59-KuFE7ZDb8oJl3mCXkqR8gm'
                           b'4sUPFcFg","Eb0d6f-KcOc0Pti8w8kRWG6b7qlLv0LVe97Hn73Gx1Tw","EQkLya'
                           b'hIDBh-IYFo3UxTuScoZbz7DVx3z2WZcm9XBQwo"],"bt":"0","b":[],"c":[],'
                           b'"a":[]}-AADAAVrPSS8sfubmKKLLzvlHAVD8Zy7atX_CJk0YXq_YVV-oyroXaLVQ'
                           b'lpJwLPX0CyhzDSg7U6HBeA3xQejfzS3ALDQABSPMBXtxqaRLsv5qmxzSTgO-QcqM'
                           b'tw-GZKoKZxP4lS8AAODQHFNt8cppD6ZqI3QAbEJIy9QKtCrIdo3nUxdCwDgACpPY'
                           b'lToFb_RIs3878JshYs5gg_6OxkVyDluanpjedrJ0lxPANXUW2XvPb0VWE9X7nmGU'
                           b'tqFw0BHfeaEUNcrzfBQ{"v":"KERI10JSON0000cb_","t":"ixn","d":"E0EFb'
                           b'DrGf49mevhj9LjqdDF9Zv1e3xZrVV-o74knmodI","i":"Eban8TbpEQ4HX5hwef'
                           b'KvH5-7eP5SOctXFdAkliMo-Rbk","s":"1","p":"Eban8TbpEQ4HX5hwefKvH5-'
                           b'7eP5SOctXFdAkliMo-Rbk","a":[]}-AADAA-MLip3S7FemcusKfo6FA05i_Z45I'
                           b'WO1mMDpvjpwHnyXEhEvSQlVcQV_T7efrl7RmqAXwoyD3XNssCcR9igY9AgABl6FV'
                           b'b5wIrkHw9tzoauSQg3IM4-aFYP8u7Bw4-GL24yVFN47SfcOanNEhVNo-P9PM3zwj'
                           b'cUTJiFdkQ4zW-E8LDgAC7h1fDyGoOPyj5PYOtC_T5Cjm8rZLA8H7UGr7bBSQDP0W'
                           b'_ouYByk4-UF10YnjIiCExAcxmdK6Q8Sm9Q_UKAQ-AA{"v":"KERI10JSON00023c'
                           b'_","t":"rot","d":"EsZ2thB6qZ8l_eaxur-1YtY7D9PBxL7yhCdC93hYvX1M",'
                           b'"i":"Eban8TbpEQ4HX5hwefKvH5-7eP5SOctXFdAkliMo-Rbk","s":"2","p":"'
                           b'E0EFbDrGf49mevhj9LjqdDF9Zv1e3xZrVV-o74knmodI","kt":["1/2","1/2",'
                           b'"1/2"],"k":["Dj-DUwfCmOrE3ijqucR0I89_fYTFbyotaqeQyDfupkEU","DL-k'
                           b'_8BanjLYaAdm6WWKIpHcHwcbF834vnLPgpW1NL8k","DWG2ZFsWYUsbDI1Kmu8JH'
                           b'22iGaVDGvM7pnuT4y2oR3VI"],"nt":["1/2","1/2","1/2"],"n":["EhmOyqs'
                           b'UMujcjLHWJaam_AEdv9OXgnS6n2WHGtwdPVIM","EAKmM34UmvEqzao5s-wEGox1'
                           b'XWgf4o-vsX7ZUPnbtj2M","EZpn1keK-72sCwF23w_IQ1Q6kT5ROcUw5V0iprub4'
                           b'K4I"],"bt":"0","br":[],"ba":[],"a":[]}-AADAALL5ItV9rkzyErrEK427X'
                           b'py95OFPM_xLorhaoShNRiV_mTjun3b4lHJJ-oimf2sER9YnxSsw-NajY4P9hS6pK'
                           b'BAAB1r0tNgvrKm0czmjRxtoHLG54rTHEAFaNd9YqnGQ6R4PnLZvMShkp0wL_YcGS'
                           b'qxKRxVz0QDX7A2UPl2qJc0N9AgACEci2PEK6giZ82QP-qOqhCtMtdG5R0g5HTOzj'
                           b'307f-BcIZxXnhpMTYX6O-cai0fA-blHwby-bgwjvBNns80eNCg{"v":"KERI10JS'
                           b'ON0000cb_","t":"ixn","d":"EvnHJz9YFtaiMlCbyq4wMulC3TXAZ9JyH2pTyX'
                           b'kd93Lw","i":"Eban8TbpEQ4HX5hwefKvH5-7eP5SOctXFdAkliMo-Rbk","s":"'
                           b'3","p":"EsZ2thB6qZ8l_eaxur-1YtY7D9PBxL7yhCdC93hYvX1M","a":[]}-AA'
                           b'DAATSxYMGzBdshao1-RhVekwwEW4AWXHT21-bH_nkpatGdlzK1bz9ybZ9xvAt3R7'
                           b'Csf7V4H1pjRsgoB49jVSToJAAABZTay5Nz6q-Kj6yf0XF8fBT5bJ2Zf39mPr79h4'
                           b'RpohPoURI9tXJfBcmjNjJanNxwlEv2RGSljtHGgWuUUDuuaDQACXn0pu-vHMqd2j'
                           b'V54VpyFMwAOqSUXs4lftpwUktYko-V6QGphD9nyc0Qdra2nEuN5ET3sTtS1sh7Fw'
                           b'veoD3atCA{"v":"KERI10JSON0000cb_","t":"ixn","d":"EQigFoXAX3U0JLw'
                           b'8LSRtzqJENPEotsV6N_7Cl9X9GTK4","i":"Eban8TbpEQ4HX5hwefKvH5-7eP5S'
                           b'OctXFdAkliMo-Rbk","s":"4","p":"EvnHJz9YFtaiMlCbyq4wMulC3TXAZ9JyH'
                           b'2pTyXkd93Lw","a":[]}-AADAAZHpUM53Az9glxch1V76b1Id44j4YGuQMNLeSU9'
                           b'EhktXb1zNeEhjfioSYjdpAhlv2kq6smMfXX4axZyroxd8OCQABouL7UZzySw9q7g'
                           b'DbRwvlCCdR9LlkBo2aNrDjdMbo2YoGsT9wLxoMPL_Q3XO5HK0DmTHzmSfyfVjtE6'
                           b'maiFbFCQACVVERmP2XE5Z6h5hkGGeRquq31rJrvmy69ZG-Kma2TUnlnYpU6eAKhR'
                           b'nI9PciQLpFk6VjNI_nofnZzfp-6-aoAw{"v":"KERI10JSON0000cb_","t":"ix'
                           b'n","d":"EEoiyGRkxjb-bRZQUIiEfkijxg8c1_jzJYE6p0YeWZ-0","i":"Eban8'
                           b'TbpEQ4HX5hwefKvH5-7eP5SOctXFdAkliMo-Rbk","s":"5","p":"EQigFoXAX3'
                           b'U0JLw8LSRtzqJENPEotsV6N_7Cl9X9GTK4","a":[]}-AADAAvMdmu5ppGll9w5Z'
                           b'cc_V1Q6D66_lq4e6ACPSrSOwRqEHAXdG6ZRBXMhTuxZ9zUwstf9THEfLEvo-FCxM'
                           b'ka3-yBQAB_02jO4KLKlaHmYrV3a99-uTlwRlkZ6OOhWaOgMQihYzSSj7dus1rR0l'
                           b'TgszUOjOT6k7liOWR7aWtBhgDNqOgCQACQchXgBhmk51GnZW6ThdhB4xPsOmn73p'
                           b'A9ADrBk2vCgmmJAof5_8sRWUvvZFgcwJlqQ65ZrD6bg7yaQTSQQwnCQ{"v":"KER'
                           b'I10JSON0000cb_","t":"ixn","d":"ECwRGikXaPuVHZplHFnVWv6cYG-ovQpso'
                           b'sZXEX93uLgU","i":"Eban8TbpEQ4HX5hwefKvH5-7eP5SOctXFdAkliMo-Rbk",'
                           b'"s":"6","p":"EEoiyGRkxjb-bRZQUIiEfkijxg8c1_jzJYE6p0YeWZ-0","a":['
                           b']}-AADAAo2CED43TfZBRKdUUjIWhMf2IdFgXhgIPn4AZ7PBS7LtZP3v6Hm6UPKYL'
                           b'BBeIriMcnPc1FkK0vGwu6cexsqEkAgAB7ztsDrbLfkJ7hOsfiPgfC5E7adjLmddE'
                           b'TKFkXrSFGq13680q_5D6RJV7sgqvSoLLVDG10_jXPRDQUUB34dZ2AgACA2BbjvAS'
                           b'mEfCbXPWuBij8WYjHQMJgQnj5AA0TVqMVuOv48N4DMkGpLOjgs2WRravAHlMB0hR'
                           b'J2XaoSekBCMjCQ')

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
        assert camMsgs == (b'{"v":"KERI10JSON0001e7_","t":"icp","d":"EGifcQT5E5KKdvND2j7dLTWh'
                           b'7YH1GaEVuq8UHe4YlmPk","i":"EGifcQT5E5KKdvND2j7dLTWh7YH1GaEVuq8UH'
                           b'e4YlmPk","s":"0","kt":"2","k":["DJBtEHHnzNtE-zxH1xeX4wxs9rEfUQ8d'
                           b'1ancgJJ1BLKk","DMu6yPITjrOBoTPfsY-r1Rc0ead8GKmoCxA_BugKehgY","Df'
                           b'hpvbNyYu1fxTBTXy8eCgghMcOYnxkgoGPBr0ZBZPQA"],"nt":"2","n":["Eq-s'
                           b'_yaBaeq3BavwLMc7Q4TM1N1cxK0JFIiJEKNU18tA","EwGXfFpxspo-1acgIRGvY'
                           b'h6Vn76V3XpLKSXURpl35bO0","EzX47juZp1pl0qMZU8yUCNNhLx5Lte9GtYRV50'
                           b'xS3EKg"],"bt":"0","b":[],"c":[],"a":[]}-AADAArIlwP9SZ7tQYTH90KUI'
                           b'7P8dlwvf24JW0LjF01Udc3Rns3T3LvvScQ9rZTEMdgfFXiEEXe8ZjG_VZqNHb66m'
                           b'3BQABuHWYMgm_tZ3hzIJARVCJYia9f4UpWPH7KTor0X-KxPbh5hHi6wYCksaf73o'
                           b'0xZH9V1OQrxdbaL4t3CupspQ4CwAC5ynsGiCew_9rZue8_DAzZohQIOWutyVY4nD'
                           b'0989WSjBkAXVxmoTSn306htquWndjPPtqoI465YoFb5mNpdEuBw{"v":"KERI10J'
                           b'SON000091_","t":"rct","d":"Eban8TbpEQ4HX5hwefKvH5-7eP5SOctXFdAkl'
                           b'iMo-Rbk","i":"Eban8TbpEQ4HX5hwefKvH5-7eP5SOctXFdAkliMo-Rbk","s":'
                           b'"0"}-FABEGifcQT5E5KKdvND2j7dLTWh7YH1GaEVuq8UHe4YlmPk0AAAAAAAAAAA'
                           b'AAAAAAAAAAAAEGifcQT5E5KKdvND2j7dLTWh7YH1GaEVuq8UHe4YlmPk-AADAAUp'
                           b'_cOQDlxQ1UIFLlj3TFujVJiaWdR1vA-Xtfzrreo2edQqnOSdm-E3NJSLDyJYD_zm'
                           b'dfmI3LYxVtR92mXOmuBgABLv94hqxM8bbdfZf6WwSZl64By-Ej4dwN9mSyddjL5G'
                           b'g5B8atYP6Oa8IZxX1HqJ330BotXcgjaGIjAoNfboEqAwACZdxxR4o4UXvRfqqjc0'
                           b'C9SEXlFlfuNG6UEZUTAj8OtffsZR2gJaNNf_Mz14GUz4xAzV-XnK3mVeIBi4laNC'
                           b'FXAA{"v":"KERI10JSON000091_","t":"rct","d":"E0EFbDrGf49mevhj9Ljq'
                           b'dDF9Zv1e3xZrVV-o74knmodI","i":"Eban8TbpEQ4HX5hwefKvH5-7eP5SOctXF'
                           b'dAkliMo-Rbk","s":"1"}-FABEGifcQT5E5KKdvND2j7dLTWh7YH1GaEVuq8UHe4'
                           b'YlmPk0AAAAAAAAAAAAAAAAAAAAAAAEGifcQT5E5KKdvND2j7dLTWh7YH1GaEVuq8'
                           b'UHe4YlmPk-AADAAM209g6h3ILA1zvNU1o7Zg416UHVZTGu671pUjC_BOVGa7QAqb'
                           b'RBRMQ3WlzeK6hshaPx15L71-8xLG2UteHXiCAAB3uz7fveuGtlpjgd8mkfw_DxA7'
                           b'BkpgEp_-72aYRNoQxuVFX-SrPKU-Uiz9oOHA1F639d4siDCnKv9hm32trwSAAACe'
                           b'XGbEJ21PyNUbLgRCDz4fkbu8YWGJ9H76MpojO4LHtjLTsbvibYpJupDsmAoaiNhm'
                           b'-UfB4owHgAeFEKYqiCPAA{"v":"KERI10JSON000091_","t":"rct","d":"EsZ'
                           b'2thB6qZ8l_eaxur-1YtY7D9PBxL7yhCdC93hYvX1M","i":"Eban8TbpEQ4HX5hw'
                           b'efKvH5-7eP5SOctXFdAkliMo-Rbk","s":"2"}-FABEGifcQT5E5KKdvND2j7dLT'
                           b'Wh7YH1GaEVuq8UHe4YlmPk0AAAAAAAAAAAAAAAAAAAAAAAEGifcQT5E5KKdvND2j'
                           b'7dLTWh7YH1GaEVuq8UHe4YlmPk-AADAA5mDJQRG9bdXCOplYYUzwpFvpcLMrH09J'
                           b'sbGe9qsHNjaTv44UZc-BwiDgthviCjNPSTTwkqR6IP_osSIIkBcPBAABOadA5-ZL'
                           b'r57TGIj3ZN3dICmfe94OxzMXkmv6FnZbctQ64uQtcFrVHNG_DOEpzNmFMT0MqY1h'
                           b'T3v_rSOXqStrCQACg89jpowxSZaDXgzqwtBsddK-aSD-9IRuByZ2fzESMePvyBIK'
                           b'VeQBkgp4cfQAtWFNry_gP3OyB1Nhxtg2wM-QDg{"v":"KERI10JSON000091_","'
                           b't":"rct","d":"EvnHJz9YFtaiMlCbyq4wMulC3TXAZ9JyH2pTyXkd93Lw","i":'
                           b'"Eban8TbpEQ4HX5hwefKvH5-7eP5SOctXFdAkliMo-Rbk","s":"3"}-FABEGifc'
                           b'QT5E5KKdvND2j7dLTWh7YH1GaEVuq8UHe4YlmPk0AAAAAAAAAAAAAAAAAAAAAAAE'
                           b'GifcQT5E5KKdvND2j7dLTWh7YH1GaEVuq8UHe4YlmPk-AADAAHkKSxBrCTAp3S3i'
                           b'p12D0_64Bl37fETH3LFGGvoF0a7uMnKZ_YgsHw8Pt4NMKbNHEgDsIm5Vl5fU8Ls-'
                           b'qNguJCQAB3fTvkA2jLXwI4tgL7OhOWlTCVoSwRTe9Y0jInmuP3pBKRUKGqcNIvwY'
                           b'ma3kf33gUSNs8d4jUA3FZbRydmQV7CgAC0lDZfsM6AWa9XNwyaD5JJBA-dWjsb4p'
                           b'RBkshcthhzbeXfVa7q9-C6j0RjI7bYZOxScz3oOLvWe0UFtVjGiwlBA{"v":"KER'
                           b'I10JSON000091_","t":"rct","d":"EQigFoXAX3U0JLw8LSRtzqJENPEotsV6N'
                           b'_7Cl9X9GTK4","i":"Eban8TbpEQ4HX5hwefKvH5-7eP5SOctXFdAkliMo-Rbk",'
                           b'"s":"4"}-FABEGifcQT5E5KKdvND2j7dLTWh7YH1GaEVuq8UHe4YlmPk0AAAAAAA'
                           b'AAAAAAAAAAAAAAAAEGifcQT5E5KKdvND2j7dLTWh7YH1GaEVuq8UHe4YlmPk-AAD'
                           b'AAeqzcOLqnBpH8JtJt86Zr0w3kakOp7UHg_HNxEb-K63dvoFTBwWk_GT9zKYwWPu'
                           b'z4YpS8drx4nBF8kkazE1mBBgABsYKOB3bQR6T0Q3Rw4F0WxOfWjoGcAwCL7rYC0l'
                           b'e7b3W8FhzUFKVbcMHasegXltXEod0bNi-vXPbWNqh2teXPDgACs8a-QfePlA8mcC'
                           b'JzHJ3A3OKaasuGV3rc36ep0mBJx2B53AW22VZ_Y1v8_fL6HtE8iAo8XM9Wjc3R35'
                           b'TG7F3JBA{"v":"KERI10JSON000091_","t":"rct","d":"EEoiyGRkxjb-bRZQ'
                           b'UIiEfkijxg8c1_jzJYE6p0YeWZ-0","i":"Eban8TbpEQ4HX5hwefKvH5-7eP5SO'
                           b'ctXFdAkliMo-Rbk","s":"5"}-FABEGifcQT5E5KKdvND2j7dLTWh7YH1GaEVuq8'
                           b'UHe4YlmPk0AAAAAAAAAAAAAAAAAAAAAAAEGifcQT5E5KKdvND2j7dLTWh7YH1GaE'
                           b'Vuq8UHe4YlmPk-AADAAIncXU_AogkuFeiIe5REZJnDQTiaje3MFpoePRUUOaj1xW'
                           b'On3LgmwUO75eF-S5oWr4floZDd20JCdz_qDZOO3AAABuoTcnV1TL7Vli6Ffyh6Si'
                           b'PIjjOwEars3FFhGP3D_WeklRwPELLmAxftNCPdPiko4dYMK3Gp8Bq3AUB1L4hpSB'
                           b'QACliE514Ps-MfOJnK7HuZshd6HETvXm4550yaeOTNdNPus0q5JL8wtoZ2XERBs0'
                           b'h8BiR8cNCFVGNocnfxV64lGBA{"v":"KERI10JSON000091_","t":"rct","d":'
                           b'"ECwRGikXaPuVHZplHFnVWv6cYG-ovQpsosZXEX93uLgU","i":"Eban8TbpEQ4H'
                           b'X5hwefKvH5-7eP5SOctXFdAkliMo-Rbk","s":"6"}-FABEGifcQT5E5KKdvND2j'
                           b'7dLTWh7YH1GaEVuq8UHe4YlmPk0AAAAAAAAAAAAAAAAAAAAAAAEGifcQT5E5KKdv'
                           b'ND2j7dLTWh7YH1GaEVuq8UHe4YlmPk-AADAAP0rhZlAaxWG5ZD3Iy5oMJhp-qapt'
                           b'Rsb9x3GWcwgPqKr99aR_mIceVk3NkTb-Vc0NjKLYsv6cHoBHZpLvgj8FCwAB_Dlj'
                           b'947F5wJr8etCsQjLWzeKyX9OMgZFKeLGofA9aH0kqfKkZdUw6JpoJlCfYlbe_61g'
                           b'jyw8SbTD3mQAQ8E2AwACyZf2HploOJN7iQYmIMj_tJ6RPDwwMpFMnDrl1FLPF1Qd'
                           b'CWZoZfikZvGWPeLjCEob0eZ185eHN7V25WWcjc_GDg')

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
        assert debCamVrcs == (b'{"v":"KERI10JSON000091_","t":"rct","d":"EGifcQT5E5KKdvND2j7dLTWh'
                              b'7YH1GaEVuq8UHe4YlmPk","i":"EGifcQT5E5KKdvND2j7dLTWh7YH1GaEVuq8UH'
                              b'e4YlmPk","s":"0"}-FABEban8TbpEQ4HX5hwefKvH5-7eP5SOctXFdAkliMo-Rb'
                              b'k0AAAAAAAAAAAAAAAAAAAAAAgEsZ2thB6qZ8l_eaxur-1YtY7D9PBxL7yhCdC93h'
                              b'YvX1M-AADAAFgIYCUZpSPL3YkJmPJvkVv2ObazNX9Aiy_8EiqViACWuRdOCBo5iq'
                              b'62y1GiMarTUBp2sqS_ZpCz3hRBTVWFyCgABe22VhixbyQmBPBHU4mG3txPTw_0Iu'
                              b'u-QNesBMI4Xqn3YEpS0VeYl4WN8pCnL6tFk7ZqOqR7zA7dCyFHc8666AQACvGsH6'
                              b'RtNPoF4ZdhJecQFTohQn-MzbanFlMqLQfPQhFidNNuqoGBNKS7tDOnqgQjrbj1t8'
                              b'8Fkrkv9peEHd_w7AQ')

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
        assert bevMsgs == (b'{"v":"KERI10JSON0000fd_","t":"icp","d":"ENE38noQTiyoAneEYmNSKNIu'
                           b'v6lTMp20wSWanPkcA_L4","i":"BCqmHiYBZx_uaQiCTVeum-vt1ZPti8chqb-Gp'
                           b'QBPaurA","s":"0","kt":"1","k":["BCqmHiYBZx_uaQiCTVeum-vt1ZPti8ch'
                           b'qb-GpQBPaurA"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-AA'
                           b'BAAozuDFSORYWsy7Jl9asA7bicvf5xLaneMbo7Yl2lvkAT0HSjvhI8QUh9agW9e4'
                           b'APcy_xphMdRzlDPNRfixqlWCg{"v":"KERI10JSON000091_","t":"rct","d":'
                           b'"Eban8TbpEQ4HX5hwefKvH5-7eP5SOctXFdAkliMo-Rbk","i":"Eban8TbpEQ4H'
                           b'X5hwefKvH5-7eP5SOctXFdAkliMo-Rbk","s":"0"}-CABBCqmHiYBZx_uaQiCTV'
                           b'eum-vt1ZPti8chqb-GpQBPaurA0B4DXMxgfIL54GtKxHFwmblsGpT3SHcAWz49kn'
                           b'MuSfPcV41Yd0NFi1BgK5YrB9f2HGVtkr5cIGtETpz-L8k4JZBg{"v":"KERI10JS'
                           b'ON000091_","t":"rct","d":"E0EFbDrGf49mevhj9LjqdDF9Zv1e3xZrVV-o74'
                           b'knmodI","i":"Eban8TbpEQ4HX5hwefKvH5-7eP5SOctXFdAkliMo-Rbk","s":"'
                           b'1"}-CABBCqmHiYBZx_uaQiCTVeum-vt1ZPti8chqb-GpQBPaurA0BzsAJ_ozo7HX'
                           b'Kdbbx_FU1YIZfOGn2f-qhh3pP4hfDSxt9m6QBdWRy6bAkAhXmg5g4qRkZyEu-XqJ'
                           b'DEBCGMe3dCw{"v":"KERI10JSON000091_","t":"rct","d":"EsZ2thB6qZ8l_'
                           b'eaxur-1YtY7D9PBxL7yhCdC93hYvX1M","i":"Eban8TbpEQ4HX5hwefKvH5-7eP'
                           b'5SOctXFdAkliMo-Rbk","s":"2"}-CABBCqmHiYBZx_uaQiCTVeum-vt1ZPti8ch'
                           b'qb-GpQBPaurA0B2feSG3gWubwMdbhB4FAx9EKJUCEkhmahECvFYx784dp-atqnpJ'
                           b'fW0ngmYM8hFKqx-Ahbxg1t00lK2gbWL1I4CQ{"v":"KERI10JSON000091_","t"'
                           b':"rct","d":"EvnHJz9YFtaiMlCbyq4wMulC3TXAZ9JyH2pTyXkd93Lw","i":"E'
                           b'ban8TbpEQ4HX5hwefKvH5-7eP5SOctXFdAkliMo-Rbk","s":"3"}-CABBCqmHiY'
                           b'BZx_uaQiCTVeum-vt1ZPti8chqb-GpQBPaurA0Bzb-G2a56g6vhAVGvlCpcKBAWS'
                           b'wC1NTzxj5YVteYsFWEMHhhgdn49Hy82CT8Deiqs64DydxlQLTuCdA5aN09lBg{"v'
                           b'":"KERI10JSON000091_","t":"rct","d":"EQigFoXAX3U0JLw8LSRtzqJENPE'
                           b'otsV6N_7Cl9X9GTK4","i":"Eban8TbpEQ4HX5hwefKvH5-7eP5SOctXFdAkliMo'
                           b'-Rbk","s":"4"}-CABBCqmHiYBZx_uaQiCTVeum-vt1ZPti8chqb-GpQBPaurA0B'
                           b'OMJ_BkHWf1IYQXP4mf2flEokBYU9FakIMJFO4lLtYg8WLVnVyc9k_wIoUMJTWM9R'
                           b'llnTMEqODSVayvXjWwMmAA{"v":"KERI10JSON000091_","t":"rct","d":"EE'
                           b'oiyGRkxjb-bRZQUIiEfkijxg8c1_jzJYE6p0YeWZ-0","i":"Eban8TbpEQ4HX5h'
                           b'wefKvH5-7eP5SOctXFdAkliMo-Rbk","s":"5"}-CABBCqmHiYBZx_uaQiCTVeum'
                           b'-vt1ZPti8chqb-GpQBPaurA0BTYb-mi5zkMhOBDmlwNBUlWCDFlm1OaWDkj6GgwL'
                           b'OTOfkClUxo16TDIl8jdfA_mdfXn7ipKFg_osGkBUI5IRHAg{"v":"KERI10JSON0'
                           b'00091_","t":"rct","d":"ECwRGikXaPuVHZplHFnVWv6cYG-ovQpsosZXEX93u'
                           b'LgU","i":"Eban8TbpEQ4HX5hwefKvH5-7eP5SOctXFdAkliMo-Rbk","s":"6"}'
                           b'-CABBCqmHiYBZx_uaQiCTVeum-vt1ZPti8chqb-GpQBPaurA0BVqibBPSzBELmCw'
                           b'VX-rivkcfRUEHPbaHo4031l6al0bsoBc3Jp7l-9UCul9prLPTJijkPY1irJvtqyz'
                           b'fq8rn7Dg')

        # Play bevMsgs to Deb
        parsing.Parser().parse(ims=bytearray(bevMsgs), kvy=debKevery)
        # debKevery.process(ims=bytearray(bevMsgs))  # give copy to process
        assert bevHab.pre in debKevery.kevers
        assert debKevery.kevers[bevHab.pre].sn == bevHab.kever.sn == 0
        assert len(debKevery.cues) == 1

        # get disjoints receipts (vrcs) from Deb of Bev's events by processing Deb's cues
        debBevVrcs = debHab.processCues(debKevery.cues)
        assert debBevVrcs == (b'{"v":"KERI10JSON000091_","t":"rct","d":"ENE38noQTiyoAneEYmNSKNIu'
                              b'v6lTMp20wSWanPkcA_L4","i":"BCqmHiYBZx_uaQiCTVeum-vt1ZPti8chqb-Gp'
                              b'QBPaurA","s":"0"}-FABEban8TbpEQ4HX5hwefKvH5-7eP5SOctXFdAkliMo-Rb'
                              b'k0AAAAAAAAAAAAAAAAAAAAAAgEsZ2thB6qZ8l_eaxur-1YtY7D9PBxL7yhCdC93h'
                              b'YvX1M-AADAA6zpBCPrz6-mmX3JSjgBZYWde2FZbZp1UfDmJWg1K6b6AUs-yEdboQ'
                              b'ZxNpao_zFftmJomy3D3yT8PKnqfmmxbAAABZTWv3ic3Ppf7s0jWhqiA6453XBoxM'
                              b'P4Q9mCfHCL1MGHH8BA5ncj7fmRYSi7nL23scwG-DJAwNBZq193ma4NcDgACPMTbW'
                              b'D67Wv3864TercRAX3NOdUrBrtqsky2uLub95yf_ojgG49JfGJ7ACe1Rr0WxDCes5'
                              b'o8GorLlyvGFuv3NBw')

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


    with habbing.openHby(name="deb", base="test") as debHby, \
         habbing.openHby(name="cam", base="test") as camHby, \
         habbing.openHby(name="bev", base="test") as bevHby,  \
         habbing.openHby(name="art", base="test", salt=artSalt) as artHby:

        # setup Deb's habitat using default salt multisig already incepts
        sith = ["1/2", "1/2", "1/2"]  # weighted signing threshold
        #debHab = habbing.Habitat(ks=debKS, db=debDB, isith=sith, icount=3,
                                 #temp=True)
        debHab = debHby.makeHab(name='test', isith=sith, icount=3)
        #assert debHab.ks == debKS
        #assert debHab.db == debDB
        assert debHab.kever.prefixer.transferable

        # setup Cam's habitat using default salt multisig already incepts
        # Cam's receipts will be vrcs with 3 indexed sigantures attached
        sith = '2'  # hex str of threshold int
        #camHab = habbing.Habitat(ks=camKS, db=camDB, isith=sith, icount=3,
                                 #temp=True)
        camHab = camHby.makeHab(name='test', isith=sith, icount=3)
        #assert camHab.ks == camKS
        #assert camHab.db == camDB
        assert camHab.kever.prefixer.transferable

        # setup Bev's habitat using default salt nonstransferable already incepts
        # Bev's receipts will be rcts with a receipt couple attached
        sith = '1'  # hex str of threshold int
        #bevHab = habbing.Habitat(ks=bevKS, db=bevDB, isith=sith, icount=1,
                                 #transferable=False, temp=True)
        bevHab = bevHby.makeHab(name='test', isith=sith, icount=1, transferable=False)
        #assert bevHab.ks == bevKS
        #assert bevHab.db == bevDB
        assert not bevHab.kever.prefixer.transferable

        # setup Art's habitat using custom salt nonstransferable so not match Bev
        # already incepts
        # Art's receipts will be rcts with a receipt couple attached
        salt = coring.Salter(raw=b'abcdef0123456789').qb64
        sith = '1'  # hex str of threshold int
        #artHab = habbing.Habitat(ks=artKS, db=artDB, isith=sith, icount=1,
                                 #salt=salt, transferable=False, temp=True)
        artHab = artHby.makeHab(name='test', isith=sith, icount=1, transferable=False)
        #assert artHab.ks == artKS
        #assert artHab.db == artDB
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
        assert len(artAllFelMsgs) == 12113

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
    test_replay()

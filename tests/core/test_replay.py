# -*- encoding: utf-8 -*-
"""
tests delegation primaily from keri.core.eventing

"""
import os
import datetime

import pytest

from keri import help
from keri.help import helping
from keri.db import dbing
from keri.base import keeping, directing
from keri.core import coring, eventing


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

    with dbing.openDB(name="deb") as debDB, keeping.openKS(name="deb") as debKS, \
         dbing.openDB(name="cam") as camDB, keeping.openKS(name="cam") as camKS, \
         dbing.openDB(name="bev") as bevDB, keeping.openKS(name="bev") as bevKS:

        # setup Deb's habitat using default salt multisig already incepts
        sith = ["1/2", "1/2", "1/2"]  # weighted signing threshold
        debHab = directing.Habitat(ks=debKS, db=debDB, sith=sith, count=3,
                                   temp=True)
        assert debHab.ks == debKS
        assert debHab.db == debDB
        assert debHab.kever.prefixer.transferable

        # setup Cam's habitat using default salt multisig already incepts
        # Cam's receipts will be vrcs with 3 indexed sigantures attached
        sith = '2'  # hex str of threshold int
        camHab = directing.Habitat(ks=camKS, db=camDB, sith=sith, count=3,
                                   temp=True)
        assert camHab.ks == camKS
        assert camHab.db == camDB
        assert camHab.kever.prefixer.transferable

        # setup Bev's habitat using default salt nonstransferable already incepts
        # Bev's receipts will be rcts with a receipt couple attached
        sith = '1'  # hex str of threshold int
        bevHab = directing.Habitat(ks=bevKS, db=bevDB, sith=sith, count=1,
                                   transferable=False, temp=True)
        assert bevHab.ks == bevKS
        assert bevHab.db == bevDB
        assert not bevHab.kever.prefixer.transferable

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

        assert debMsgs == bytearray(b'{"v":"KERI10JSON000154_","i":"E4ReNhXtuh4DAKe4_qcX__uF70MnOvW5Wa'
                                    b'pj3LcQ8CT4","s":"0","t":"icp","kt":["1/2","1/2","1/2"],"k":["DaY'
                                    b'h8uaASuDjMUd8_BoNyQs3GwupzmJL8_RBsuNtZHQg","Duzj-Z2lR2DqB0cI0421'
                                    b'oSMUVWOrN5axojx8g9fSx3PM","DRXPAmNVVqafWvQiN5qQmWUDvVupF2w8xFNGg'
                                    b'1Gays9Y"],"n":"EO5f_IQjtBoeN_-OyzfVJx1_WqBFUL-Ely4x-xmUtOW8","wt'
                                    b'":"0","w":[],"c":[]}-AADAA6Z50BRlXby_uSdkqbybLXds-5OMwQil4miux1s'
                                    b'RxJkiD3kRS4HuCpv5m-wwsPHWwn_Ku5xB2P--NJ1pl7KXjAQABDjMdRtemkn9oyk'
                                    b'LFo9MBwZsS85hGd1yaMMdFb_P1FY8_PZcHBVTc2iF5Bd6T2rGorwS-ChRa24bxUr'
                                    b'kemWD1DAACpxUYq2zrFAlMdWuxdaYTqvh12pgk4Ba-vllsaZP5ct5HcOtJw47B6c'
                                    b'VLcEePwEHk6jHlSoDGgH2YiyOwPbgSBQ{"v":"KERI10JSON000098_","i":"E4'
                                    b'ReNhXtuh4DAKe4_qcX__uF70MnOvW5Wapj3LcQ8CT4","s":"1","t":"ixn","p'
                                    b'":"Egd_fi2QDtfjjdB5p9tT6QCHuBsSWUwQP6AbarcjLgw0","a":[]}-AADAAPL'
                                    b'MNHELcDDuPT1gyI9_TEBM6FRji2xmc0iBfNBwoKJttbJfeQhH41y-ayubtyhyMzH'
                                    b'aqrq-WXaNQkpnzTTOPBAABUawpt1Nd7GR9rTwPD4ucT-M7Vy1xuxGlgRf9pgkOcX'
                                    b'BBbhomjjEpz3aid9PP2vWeJ_rvw7W5rgrTJ38Q2v8bDwACoHNjlZ-IZ1K9opgeu3'
                                    b'3TNIFBd3rNW_gKO_bFa-t2GYwOzlWoDlzF7kSRQnVKlXMeVrLBe3uwO6PjYjeZdU'
                                    b'SlDg{"v":"KERI10JSON000190_","i":"E4ReNhXtuh4DAKe4_qcX__uF70MnOv'
                                    b'W5Wapj3LcQ8CT4","s":"2","t":"rot","p":"E8MU3qwR6gzbMUqEXh0CgG4k3'
                                    b'k4WKkk9hM0iaVeCmG7E","kt":["1/2","1/2","1/2"],"k":["DIsi8qYso1KM'
                                    b'mpLOGYty3NC2BAojZmUCfzR5_5oQRiso","DkdClpaWCAoCPBYgUmqP9gwAtsGq8'
                                    b'1yyPhGQKQ6-W_F0","DKDyq4QQYKnx9ircxeCvEcraI4HUSr_ytWPelDHAM98w"]'
                                    b',"n":"E1oOvJmwenmC4uHjX7qB40LGVbeZY5rYQeZ6IK5zmdmM","wt":"0","wr'
                                    b'":[],"wa":[],"a":[]}-AADAAr5HeTAGJ_WfIMO82lbEnpAMkuqZ0iJO0yYhjwv'
                                    b'LElPYltF_jSOApKPWxepare2O7XMMOvtgxjXj9pvvqpW8WDgABKHoueBd4JgakpV'
                                    b'ydJYADwh5wMSNyHNMKXwhYMGrgApl_EvsTmEt8uS94PmrfCtRjLRbZdzLRZVkX7Y'
                                    b'x4jlNNCgACjKJlODGhL_a0S3-oDRJhOUG0sul4SCJd21Qp-KSFSfGavACAwQdEYQ'
                                    b'L43jko9lFDuhwKDt1BD8kAoy3T-tdoAw{"v":"KERI10JSON000098_","i":"E4'
                                    b'ReNhXtuh4DAKe4_qcX__uF70MnOvW5Wapj3LcQ8CT4","s":"3","t":"ixn","p'
                                    b'":"EO2hh7xg29y3i7uywQ_n0g7vk0W1oGiErUY9QpGjSUhc","a":[]}-AADAA5I'
                                    b'ox67c4HL78UrYqpSNH-UkHZRpR7X0fPQ0GEYJG8OGqCHBvPJica_yohOQP8GNOFQ'
                                    b'9UsmBa0TDji6EAaXivBwAB6BgG2CQ-Ukw8CchtCHf9L5kVsmg1Tu2OuLkcy9Sb9u'
                                    b'Vm23yLx-8I4pc6KHmZke8KCvpXjcdV65gOOE-VUIMOBwACXtTZoFqJHFhoMZABun'
                                    b'XETksrK1nNiP9xzXx13gl4uqoVZkqfwqUTL3C7q0RcxYwaz5sYSNQA8zblA8YxVy'
                                    b'FuCQ{"v":"KERI10JSON000098_","i":"E4ReNhXtuh4DAKe4_qcX__uF70MnOv'
                                    b'W5Wapj3LcQ8CT4","s":"4","t":"ixn","p":"EQI0EXdK6WvQae17PBWDUkMOd'
                                    b'OiTPpx48oMSYTUYsCl0","a":[]}-AADAAbnPY1i0cpo6q0cmvQr2bZOcipzl7LY'
                                    b'Y2h-3ixndlzB3f-4VFLzSnIUtB_qwp1H2NI_DNGqXWGACywJoxkFccAQABHDicUl'
                                    b'iz3Bl6y1T7-sQteMKxoDYZ4A8hVx3p3EjztyO8UnA6PkaV2b7AFwAfk4UbBWKMGj'
                                    b'TtpZ88S7P9EsXLBAACNFFh6nDIWNG1ZbEsqqlCG2aKLgnpHmR6cJr1dq1F4pylAF'
                                    b'1e3-on2aasDMYk3c2fj-AWErRqbsf8ejnJE3YvDg{"v":"KERI10JSON000098_"'
                                    b',"i":"E4ReNhXtuh4DAKe4_qcX__uF70MnOvW5Wapj3LcQ8CT4","s":"5","t":'
                                    b'"ixn","p":"EvrAC5XVQyu01ZuKfq1wiR0kXF2j8TjrCg4QyA0LVjKk","a":[]}'
                                    b'-AADAA1OJn3UHjLcI333fduqTj6nAJY27VtkQqW_lHalnJKtgmb0tk1tV5xUCVzp'
                                    b'al14xWDuyCdImhFzTk0sRgW4MYDQABOR8ay9qQYR3ieant4ujM_FX0Nm_mUHcVVo'
                                    b'4pCqDy8jLaM3EBNmkOKUIfxgZC-8k6OpYcy33gC-qgUpc6C2_PDwACSoZSibaYci'
                                    b'n32vY4ANzflFpJh_EF7mcGbTWSFrNLnwFrrOfhXL3i1Pf39Sk079ApSI87Nt-CvH'
                                    b'pRRdows3TABQ{"v":"KERI10JSON000098_","i":"E4ReNhXtuh4DAKe4_qcX__'
                                    b'uF70MnOvW5Wapj3LcQ8CT4","s":"6","t":"ixn","p":"EwmQtlcszNoEIDfqD'
                                    b'-Zih3N6o5B3humRKvBBln2juTEM","a":[]}-AADAAvYMCRmJgjFM7EG7rWng7Q3'
                                    b'WRfwcd908UdKL-7ZfGw4igpF9DcA-yxwliba59D4pkmhIcrW_Ax76iuaD6yD03Bw'
                                    b'AB9Wp-awBUfw2jnDRjvEU3xpFlLDHwiFLRKpom8Wnx7qDD4aEv6ERZh-H8yP3eL4'
                                    b'sNEFjP5HcRrb5MpFwOp0VyAwACdedbq9E2Exs1NobGwSNQpNxKlgDPiNDE8nOeOq'
                                    b'gXt1rAj8SAh8gX2pOgEFj3g3UB69dNGw2M-bEZ557-p9G-Aw')


        # Play debMsgs to Cam
        # create non-local kevery for Cam to process msgs from Deb
        camKevery = eventing.Kevery(kevers=camHab.kevers,
                                    db=camHab.db,
                                    framed=True,
                                    pre=camHab.pre,
                                    local=False)
        camKevery.process(ims=bytearray(debMsgs))  # give copy to process
        assert debHab.pre in camKevery.kevers
        assert camKevery.kevers[debHab.pre].sn == debHab.kever.sn == 6
        assert len(camKevery.cues) == 7

        # get disjoints receipts (vrcs) from Cam of Deb's events by processing Cam's cues
        camMsgs = camHab.processCues(camKevery.cues)
        assert camMsgs == bytearray(b'{"v":"KERI10JSON000144_","i":"E_T2_p83_gRSuAYvGhqV3S0JzYEF2dIa-O'
                                    b'CPLbIhBO7Y","s":"0","t":"icp","kt":"2","k":["DaYh8uaASuDjMUd8_Bo'
                                    b'NyQs3GwupzmJL8_RBsuNtZHQg","Duzj-Z2lR2DqB0cI0421oSMUVWOrN5axojx8'
                                    b'g9fSx3PM","DRXPAmNVVqafWvQiN5qQmWUDvVupF2w8xFNGg1Gays9Y"],"n":"E'
                                    b'OySO3Oa400n3Ss9JftGYmgS5M4jgPInNnMntC_l-PEQ","wt":"0","w":[],"c"'
                                    b':[]}-AADAA5267UlFg1jHee4Dauht77SzGl8WUC_0oimYG5If3SdIOSzWM8Qs9SF'
                                    b'ajAilQcozXJVnbkY5stG_K4NbKdNB4AQABBgeqntZW3Gu4HL0h3odYz6LaZ_SMfm'
                                    b'ITL-Btoq_7OZFe3L16jmOe49Ur108wH7mnBaq2E_0U0N0c5vgrJtDpAQACTD7NDX'
                                    b'93ZGTkZBBuSeSGsAQ7u0hngpNTZTK_Um7rUZGnLRNJvo5oOnnC1J2iBQHuxoq8Py'
                                    b'jdT3BHS2LiPrs2Cg{"v":"KERI10JSON000105_","i":"E4ReNhXtuh4DAKe4_q'
                                    b'cX__uF70MnOvW5Wapj3LcQ8CT4","s":"0","t":"vrc","d":"Egd_fi2QDtfjj'
                                    b'dB5p9tT6QCHuBsSWUwQP6AbarcjLgw0","a":{"i":"E_T2_p83_gRSuAYvGhqV3'
                                    b'S0JzYEF2dIa-OCPLbIhBO7Y","s":"0","d":"EFSbLZkTmOMfRCyEYLgz53ARZo'
                                    b'ugmEu_edeW-0j2DVRY"}}-AADAA6Z50BRlXby_uSdkqbybLXds-5OMwQil4miux1'
                                    b'sRxJkiD3kRS4HuCpv5m-wwsPHWwn_Ku5xB2P--NJ1pl7KXjAQABDjMdRtemkn9oy'
                                    b'kLFo9MBwZsS85hGd1yaMMdFb_P1FY8_PZcHBVTc2iF5Bd6T2rGorwS-ChRa24bxU'
                                    b'rkemWD1DAACpxUYq2zrFAlMdWuxdaYTqvh12pgk4Ba-vllsaZP5ct5HcOtJw47B6'
                                    b'cVLcEePwEHk6jHlSoDGgH2YiyOwPbgSBQ{"v":"KERI10JSON000105_","i":"E'
                                    b'4ReNhXtuh4DAKe4_qcX__uF70MnOvW5Wapj3LcQ8CT4","s":"1","t":"vrc","'
                                    b'd":"E8MU3qwR6gzbMUqEXh0CgG4k3k4WKkk9hM0iaVeCmG7E","a":{"i":"E_T2'
                                    b'_p83_gRSuAYvGhqV3S0JzYEF2dIa-OCPLbIhBO7Y","s":"0","d":"EFSbLZkTm'
                                    b'OMfRCyEYLgz53ARZougmEu_edeW-0j2DVRY"}}-AADAAPLMNHELcDDuPT1gyI9_T'
                                    b'EBM6FRji2xmc0iBfNBwoKJttbJfeQhH41y-ayubtyhyMzHaqrq-WXaNQkpnzTTOP'
                                    b'BAABUawpt1Nd7GR9rTwPD4ucT-M7Vy1xuxGlgRf9pgkOcXBBbhomjjEpz3aid9PP'
                                    b'2vWeJ_rvw7W5rgrTJ38Q2v8bDwACoHNjlZ-IZ1K9opgeu33TNIFBd3rNW_gKO_bF'
                                    b'a-t2GYwOzlWoDlzF7kSRQnVKlXMeVrLBe3uwO6PjYjeZdUSlDg{"v":"KERI10JS'
                                    b'ON000105_","i":"E4ReNhXtuh4DAKe4_qcX__uF70MnOvW5Wapj3LcQ8CT4","s'
                                    b'":"2","t":"vrc","d":"EO2hh7xg29y3i7uywQ_n0g7vk0W1oGiErUY9QpGjSUh'
                                    b'c","a":{"i":"E_T2_p83_gRSuAYvGhqV3S0JzYEF2dIa-OCPLbIhBO7Y","s":"'
                                    b'0","d":"EFSbLZkTmOMfRCyEYLgz53ARZougmEu_edeW-0j2DVRY"}}-AADAA7JJ'
                                    b'AxJL3nhVur7YboCK2zPSmx_AaYDYeN7UsvoKcZKrYbuScUje_qfx_e9z1SM4tm8b'
                                    b'UbYJnLXTz8dOta9ZiDwABi7dsjnldn7E-L56Rlz4ZWp8XC5y8v7h4XRoZp2sO69H'
                                    b'84dhyRM27UE9_egCWQZJ_MHJKVA5g2s0hXmXvjSKrAQACo0JcZmUhiNBfb_3bBwg'
                                    b'X7KfN52vmazAzEFgJlr8wNfXSvF6rA5lED4J1EWuEnhA00vUHQqPrjk78nnRBBZl'
                                    b'VAA{"v":"KERI10JSON000105_","i":"E4ReNhXtuh4DAKe4_qcX__uF70MnOvW'
                                    b'5Wapj3LcQ8CT4","s":"3","t":"vrc","d":"EQI0EXdK6WvQae17PBWDUkMOdO'
                                    b'iTPpx48oMSYTUYsCl0","a":{"i":"E_T2_p83_gRSuAYvGhqV3S0JzYEF2dIa-O'
                                    b'CPLbIhBO7Y","s":"0","d":"EFSbLZkTmOMfRCyEYLgz53ARZougmEu_edeW-0j'
                                    b'2DVRY"}}-AADAAG1L04T2jREp2pizW-jQ0tglZ8I4CDNoKx4bN2K0ztuf_0ywQ29'
                                    b'p2kFkBVZaRPwljOZlUzJqlPU6P2R-IVORJBQAB2ss-isfVr2WpdCWwNxO_9N75eJ'
                                    b'K-2CZp1J-DicWd8FqziZIc-kAmxNBD9TjxfuYn7pQmXnaWF7g4RhCLJGBuDAACrx'
                                    b'gx3QlrBs-g369i807ntd8rGWGC4WGrrdy60cPy9hjrP10qjDtSTwa2UZPNVEUZol'
                                    b'M-lHsFqoNhjeaHmg_mDA{"v":"KERI10JSON000105_","i":"E4ReNhXtuh4DAK'
                                    b'e4_qcX__uF70MnOvW5Wapj3LcQ8CT4","s":"4","t":"vrc","d":"EvrAC5XVQ'
                                    b'yu01ZuKfq1wiR0kXF2j8TjrCg4QyA0LVjKk","a":{"i":"E_T2_p83_gRSuAYvG'
                                    b'hqV3S0JzYEF2dIa-OCPLbIhBO7Y","s":"0","d":"EFSbLZkTmOMfRCyEYLgz53'
                                    b'ARZougmEu_edeW-0j2DVRY"}}-AADAAh0E0mltmkUz1_TXMirWFa67IGAaK7fThh'
                                    b'rJ8TQyuhY7usunzf8VtWfaaLBQSpofhgppsMlf3zZxDS1g6t-7PCgABECiScuPby'
                                    b'_LbGw5s6qNTJQm2m6Dqbsig7sRdk841XWU6hV3MlD-k_SriiPEJWMAWDmY74lM-U'
                                    b'iNDvnmN4OAJCAACSc48sfSvNtYByMlUQsMPdEsDw5Z6oDX4jlZ9F5eCMcRvYWWAp'
                                    b'AD-OOi85JTIiW3y3nSdbfyt4vS6YvroA68MAQ{"v":"KERI10JSON000105_","i'
                                    b'":"E4ReNhXtuh4DAKe4_qcX__uF70MnOvW5Wapj3LcQ8CT4","s":"5","t":"vr'
                                    b'c","d":"EwmQtlcszNoEIDfqD-Zih3N6o5B3humRKvBBln2juTEM","a":{"i":"'
                                    b'E_T2_p83_gRSuAYvGhqV3S0JzYEF2dIa-OCPLbIhBO7Y","s":"0","d":"EFSbL'
                                    b'ZkTmOMfRCyEYLgz53ARZougmEu_edeW-0j2DVRY"}}-AADAAgXtG2I3AxvU5yHKz'
                                    b'fucOKOvxeKWwChKQvEQJtJnz9iIpsXqyyrgRfOyoyjhk73D-E3FbDg_3k1XK_3i-'
                                    b'yDWeAQAByUVjq4Y_sMWi9iqqWXTo2ES5pBMlBgJbAY3h61aJElQdCIxr2ldx_BSq'
                                    b'4vA-FlELEBUkSbeHnHGXeFfVi6AjCwAC6GmjxPFclVsY7smEcpmptQnZgET9LUO6'
                                    b'06SzhkCaGCe1jR2KZ3vNsgitA_7OQ_VDipLwoWGv_Kz2YnUkjKFsCw{"v":"KERI'
                                    b'10JSON000105_","i":"E4ReNhXtuh4DAKe4_qcX__uF70MnOvW5Wapj3LcQ8CT4'
                                    b'","s":"6","t":"vrc","d":"EvFMG33kYq7JGOY1fWl1_VqfAe0MfPO3IhasTID'
                                    b'kayaY","a":{"i":"E_T2_p83_gRSuAYvGhqV3S0JzYEF2dIa-OCPLbIhBO7Y","'
                                    b's":"0","d":"EFSbLZkTmOMfRCyEYLgz53ARZougmEu_edeW-0j2DVRY"}}-AADA'
                                    b'A9U_Kq0GNM1fFq1Vgp937kHkwxSBn4nT8UciTepjjOdOAR-hvsLCxQx2V2pbyQo3'
                                    b'fubs6mPd6TQ4ZUmXNrtxmBwABuFO678xi0JuYyQWnSOtOVXABknvRo6-0EWFCv7h'
                                    b'xucmqgE6Je2R4120G3nFsJ_ImTjkDibQU8m7CYBGcFh-hAQACBUqcpzMYX373ePK'
                                    b'sfKBjt9aXO2vkl9jAb5vBHFYc0h5r-pGL2TIgoyfMPMAf0zFrsKnDdmN0HmSaE1O'
                                    b'sP2hmDA')

        # Play camMsgs to Deb
        # create non-local kevery for Deb to process msgs from Cam
        debKevery = eventing.Kevery(kevers=debHab.kevers,
                                    db=debHab.db,
                                    framed=True,
                                    pre=debHab.pre,
                                    local=False)
        debKevery.process(ims=bytearray(camMsgs))  # give copy to process
        assert camHab.pre in debKevery.kevers
        assert debKevery.kevers[camHab.pre].sn == camHab.kever.sn == 0
        assert len(debKevery.cues) == 1

        # get disjoints receipts (vrcs) from Deb of Cam's events by processing Deb's cues
        debCamVrcs = debHab.processCues(debKevery.cues)
        assert debCamVrcs == bytearray(b'{"v":"KERI10JSON000105_","i":"E_T2_p83_gRSuAYvGhqV3S0JzYEF2dIa-O'
                                    b'CPLbIhBO7Y","s":"0","t":"vrc","d":"EFSbLZkTmOMfRCyEYLgz53ARZougm'
                                    b'Eu_edeW-0j2DVRY","a":{"i":"E4ReNhXtuh4DAKe4_qcX__uF70MnOvW5Wapj3'
                                    b'LcQ8CT4","s":"2","d":"EO2hh7xg29y3i7uywQ_n0g7vk0W1oGiErUY9QpGjSU'
                                    b'hc"}}-AADAAmZij1Eyp2LOvVf0EevWsIIUiE9OEbhV5MvWvGHWzlvmzoaJ71KxSL'
                                    b'dMkqWG6yPyBLJjVNds_SQVVFnbpoPKwAAABNLo-_rnW2tfAu9GaP6XS2lyHTLUkG'
                                    b'TGKwjBA6hepC-E8XEiFMQekheKx-ir6xWxRPF9vBZuWwZKIqtwR2EwcDwACeHbCs'
                                    b'HbSgD7m9bWGB2ZCN8jxAfrbCMRGWersAEXqtdtkYT0Xxg33W61o5IffZjWxsHY_i'
                                    b'JQOPDVF3tA4DniWBg')

        # Play disjoints debCamVrcs to Cam
        camKevery.processOne(ims=bytearray(debCamVrcs))  # give copy to process

        # Play debMsgs to Bev
        # create non-local kevery for Bev to process msgs from Deb
        bevKevery = eventing.Kevery(kevers=bevHab.kevers,
                                    db=bevHab.db,
                                    framed=True,
                                    pre=bevHab.pre,
                                    local=False)
        bevKevery.process(ims=bytearray(debMsgs))  # give copy to process
        assert debHab.pre in bevKevery.kevers
        assert bevKevery.kevers[debHab.pre].sn == debHab.kever.sn == 6
        assert len(bevKevery.cues) == 7

        # get disjoints receipts (rcts) from Bev of Deb's events by processing Bevs's cues
        bevMsgs = bevHab.processCues(bevKevery.cues)
        assert bevMsgs == bytearray(b'{"v":"KERI10JSON0000ba_","i":"BaYh8uaASuDjMUd8_BoNyQs3GwupzmJL8_'
                                    b'RBsuNtZHQg","s":"0","t":"icp","kt":"1","k":["BaYh8uaASuDjMUd8_Bo'
                                    b'NyQs3GwupzmJL8_RBsuNtZHQg"],"n":"","wt":"0","w":[],"c":[]}-AABAA'
                                    b'dRmfIn6JHxhpyooEf22kqZxsa4OTpl9DVL6GDWNWlyk-MGQeo2pU5mI288Jl8SwP'
                                    b'PbTGbdeKdWUfG15bjil8AA{"v":"KERI10JSON000091_","i":"E4ReNhXtuh4D'
                                    b'AKe4_qcX__uF70MnOvW5Wapj3LcQ8CT4","s":"0","t":"rct","d":"Egd_fi2'
                                    b'QDtfjjdB5p9tT6QCHuBsSWUwQP6AbarcjLgw0"}-CABBaYh8uaASuDjMUd8_BoNy'
                                    b'Qs3GwupzmJL8_RBsuNtZHQg0B6Z50BRlXby_uSdkqbybLXds-5OMwQil4miux1sR'
                                    b'xJkiD3kRS4HuCpv5m-wwsPHWwn_Ku5xB2P--NJ1pl7KXjAQ{"v":"KERI10JSON0'
                                    b'00091_","i":"E4ReNhXtuh4DAKe4_qcX__uF70MnOvW5Wapj3LcQ8CT4","s":"'
                                    b'1","t":"rct","d":"E8MU3qwR6gzbMUqEXh0CgG4k3k4WKkk9hM0iaVeCmG7E"}'
                                    b'-CABBaYh8uaASuDjMUd8_BoNyQs3GwupzmJL8_RBsuNtZHQg0BPLMNHELcDDuPT1'
                                    b'gyI9_TEBM6FRji2xmc0iBfNBwoKJttbJfeQhH41y-ayubtyhyMzHaqrq-WXaNQkp'
                                    b'nzTTOPBA{"v":"KERI10JSON000091_","i":"E4ReNhXtuh4DAKe4_qcX__uF70'
                                    b'MnOvW5Wapj3LcQ8CT4","s":"2","t":"rct","d":"EO2hh7xg29y3i7uywQ_n0'
                                    b'g7vk0W1oGiErUY9QpGjSUhc"}-CABBaYh8uaASuDjMUd8_BoNyQs3GwupzmJL8_R'
                                    b'BsuNtZHQg0B7JJAxJL3nhVur7YboCK2zPSmx_AaYDYeN7UsvoKcZKrYbuScUje_q'
                                    b'fx_e9z1SM4tm8bUbYJnLXTz8dOta9ZiDw{"v":"KERI10JSON000091_","i":"E'
                                    b'4ReNhXtuh4DAKe4_qcX__uF70MnOvW5Wapj3LcQ8CT4","s":"3","t":"rct","'
                                    b'd":"EQI0EXdK6WvQae17PBWDUkMOdOiTPpx48oMSYTUYsCl0"}-CABBaYh8uaASu'
                                    b'DjMUd8_BoNyQs3GwupzmJL8_RBsuNtZHQg0BG1L04T2jREp2pizW-jQ0tglZ8I4C'
                                    b'DNoKx4bN2K0ztuf_0ywQ29p2kFkBVZaRPwljOZlUzJqlPU6P2R-IVORJBQ{"v":"'
                                    b'KERI10JSON000091_","i":"E4ReNhXtuh4DAKe4_qcX__uF70MnOvW5Wapj3LcQ'
                                    b'8CT4","s":"4","t":"rct","d":"EvrAC5XVQyu01ZuKfq1wiR0kXF2j8TjrCg4'
                                    b'QyA0LVjKk"}-CABBaYh8uaASuDjMUd8_BoNyQs3GwupzmJL8_RBsuNtZHQg0Bh0E'
                                    b'0mltmkUz1_TXMirWFa67IGAaK7fThhrJ8TQyuhY7usunzf8VtWfaaLBQSpofhgpp'
                                    b'sMlf3zZxDS1g6t-7PCg{"v":"KERI10JSON000091_","i":"E4ReNhXtuh4DAKe'
                                    b'4_qcX__uF70MnOvW5Wapj3LcQ8CT4","s":"5","t":"rct","d":"EwmQtlcszN'
                                    b'oEIDfqD-Zih3N6o5B3humRKvBBln2juTEM"}-CABBaYh8uaASuDjMUd8_BoNyQs3'
                                    b'GwupzmJL8_RBsuNtZHQg0BgXtG2I3AxvU5yHKzfucOKOvxeKWwChKQvEQJtJnz9i'
                                    b'IpsXqyyrgRfOyoyjhk73D-E3FbDg_3k1XK_3i-yDWeAQ{"v":"KERI10JSON0000'
                                    b'91_","i":"E4ReNhXtuh4DAKe4_qcX__uF70MnOvW5Wapj3LcQ8CT4","s":"6",'
                                    b'"t":"rct","d":"EvFMG33kYq7JGOY1fWl1_VqfAe0MfPO3IhasTIDkayaY"}-CA'
                                    b'BBaYh8uaASuDjMUd8_BoNyQs3GwupzmJL8_RBsuNtZHQg0B9U_Kq0GNM1fFq1Vgp'
                                    b'937kHkwxSBn4nT8UciTepjjOdOAR-hvsLCxQx2V2pbyQo3fubs6mPd6TQ4ZUmXNr'
                                    b'txmBw')

        # Play bevMsgs to Deb
        debKevery.process(ims=bytearray(bevMsgs))  # give copy to process
        assert bevHab.pre in debKevery.kevers
        assert debKevery.kevers[bevHab.pre].sn == bevHab.kever.sn == 0
        assert len(debKevery.cues) == 1

        # get disjoints receipts (vrcs) from Deb of Bev's events by processing Deb's cues
        debBevVrcs = debHab.processCues(debKevery.cues)
        assert debBevVrcs == bytearray(b'{"v":"KERI10JSON000105_","i":"BaYh8uaASuDjMUd8_BoNyQs3GwupzmJL8_'
                                        b'RBsuNtZHQg","s":"0","t":"vrc","d":"EtTEz3ofbRmq4qeoKSc5uYWUhxeZa'
                                        b'8OjmCkZnesb0gws","a":{"i":"E4ReNhXtuh4DAKe4_qcX__uF70MnOvW5Wapj3'
                                        b'LcQ8CT4","s":"2","d":"EO2hh7xg29y3i7uywQ_n0g7vk0W1oGiErUY9QpGjSU'
                                        b'hc"}}-AADAAk0o2XsjZ8tfbaCKZZcSvmYdUxmqWMVMH1PLD6081VC04_c_nIXHfy'
                                        b'G5gRVXDsoncZk7euiZ9Q60E7rGi-FOLBQAB6xngS-To8PAVjMSz0bv4oqju1vmke'
                                        b'Hwq7EQOWMvM5WeKzLOwpgnCxCyZkYCzXU6Yyym9_TJOxL144wRVS92sAQACSG9_s'
                                        b'dTl_1t_bFi-fnkBwX7QLvB53NDNQShHwUjdvxupDMUJkx6QLwsUH_SwybCFO0rX5'
                                        b'K5TQKbTKbQ9F9TcAg')


        # Play disjoints debBevVrcs to Bev
        bevKevery.processOne(ims=bytearray(debBevVrcs))  # give copy to process

        # now setup conjoint replay

        # Replay Deb's First Seen Events with receipts (vrcs and rcts) from both Cam and Bev
        # datetime is different in each run in the fse attachment in clone replay
        # so we either have to force dts in db or we parse in pieces
        debFelMsgs = bytearray()
        fn = 0
        cloner = debHab.db.cloneIter(pre=debHab.pre, fn=fn)  # create iterator
        msg = next(cloner)  # get zeroth event with attachments
        assert len(msg) == 1416
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
        assert counter.count == (len(msg) - len(counter.qb64b)) // 4 ==  268
        del msg[:len(counter.qb64b)]
        assert len(msg) == 1072 == 268 *  4

        counter = coring.Counter(qb64b=msg)  # indexed signatures counter
        assert counter.code == coring.CtrDex.ControllerIdxSigs
        assert counter.count == 3  #  multisig deb
        del msg[:len(counter.qb64b)]
        assert len(msg) == 1068

        for i in range(counter.count):  # parse signatures
            siger = coring.Siger(qb64b=msg)
            del msg[:len(siger.qb64b)]
        assert len(msg) == 1068 - 3 * len(siger.qb64b) == 804

        counter = coring.Counter(qb64b=msg)  # trans receipt (vrc) counter
        assert counter.code == coring.CtrDex.TransReceiptQuadruples
        assert counter.count == 3  #  multisig cam
        del msg[:len(counter.qb64b)]
        assert len(msg) == 800

        for i in range(counter.count):  # parse receipt quadruples
            prefixer, seqner, diger, siger = eventing.dequadruple(msg, deletive=True)
        assert len(msg) == 800 - 3 * (len(prefixer.qb64b) + len(seqner.qb64b) +
                                len(diger.qb64b) + len(siger.qb64b)) == 200

        counter = coring.Counter(qb64b=msg)  # nontrans receipt (rct) counter
        assert counter.code == coring.CtrDex.NonTransReceiptCouples
        assert counter.count == 1  #  single sig bev
        del msg[:len(counter.qb64b)]
        assert len(msg) == 196

        for i in range(counter.count):  # parse receipt couples
            prefixer, cigar = eventing.decouple(msg, deletive=True)
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


        fn += 1
        cloner = debHab.db.cloneIter(pre=debHab.pre, fn=fn)  # create iterator not at 0
        msg = next(cloner)  # next event with attachments
        assert len(msg) == 1228
        serder = coring.Serder(raw=msg)
        assert serder.sn == fn  # no recovery forks so sn == fn
        assert serder.ked["t"] == coring.Ilks.ixn
        debFelMsgs.extend(msg)

        fn += 1
        msg = next(cloner)  # get zeroth event with attachments
        serder = coring.Serder(raw=msg)
        assert serder.sn == fn  # no recovery forks so sn == fn
        assert serder.ked["t"] == coring.Ilks.rot
        assert len(msg) == 1476
        assert ([verfer.qb64 for verfer in serder.verfers] ==
                [verfer.qb64 for verfer in debHab.kever.verfers])
        debFelMsgs.extend(msg)

        fn += 1
        while (fn <= 6 ):
            msg = next(cloner)  # get zeroth event with attachments
            serder = coring.Serder(raw=msg)
            assert serder.sn == fn  # no recovery forks so sn == fn
            assert serder.ked["t"] == coring.Ilks.ixn
            assert len(msg) == 1228
            debFelMsgs.extend(msg)
            fn += 1

        assert len(debFelMsgs) == 9032

        msgs = debHab.replay()
        assert msgs == debFelMsgs

        # Play Cam's messages to Bev
        bevKevery.process(ims=bytearray(camMsgs))  # give copy to process
        assert camHab.pre in bevKevery.kevers
        assert bevKevery.kevers[camHab.pre].sn == camHab.kever.sn == 0
        assert len(bevKevery.cues) == 1

        # Play Bev's messages to Cam
        camKevery.process(ims=bytearray(bevMsgs))  # give copy to process
        assert bevHab.pre in camKevery.kevers
        assert camKevery.kevers[bevHab.pre].sn == bevHab.kever.sn == 0
        assert len(camKevery.cues) == 1

        camDebFelMsgs = camHab.replay(pre=debHab.pre)
        bevDebFelMsgs = bevHab.replay(pre=debHab.pre)

        assert len(bevDebFelMsgs) == len(camDebFelMsgs) == len(debFelMsgs) == 9032

    assert not os.path.exists(bevKS.path)
    assert not os.path.exists(bevDB.path)
    assert not os.path.exists(camKS.path)
    assert not os.path.exists(camDB.path)
    assert not os.path.exists(debKS.path)
    assert not os.path.exists(debDB.path)

    """End Test"""


if __name__ == "__main__":
    test_replay()

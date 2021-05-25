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
         dbing.openDB(name="bev") as bevDB, keeping.openKS(name="bev") as bevKS, \
         dbing.openDB(name="art") as artDB, keeping.openKS(name="art") as artKS:

        # setup Deb's habitat using default salt multisig already incepts
        sith = ["1/2", "1/2", "1/2"]  # weighted signing threshold
        debHab = directing.Habitat(ks=debKS, db=debDB, isith=sith, icount=3,
                                   temp=True)
        assert debHab.ks == debKS
        assert debHab.db == debDB
        assert debHab.kever.prefixer.transferable

        # setup Cam's habitat using default salt multisig already incepts
        # Cam's receipts will be vrcs with 3 indexed sigantures attached
        sith = '2'  # hex str of threshold int
        camHab = directing.Habitat(ks=camKS, db=camDB, isith=sith, icount=3,
                                   temp=True)
        assert camHab.ks == camKS
        assert camHab.db == camDB
        assert camHab.kever.prefixer.transferable

        # setup Bev's habitat using default salt nonstransferable already incepts
        # Bev's receipts will be rcts with a receipt couple attached
        sith = '1'  # hex str of threshold int
        bevHab = directing.Habitat(ks=bevKS, db=bevDB, isith=sith, icount=1,
                                   transferable=False, temp=True)
        assert bevHab.ks == bevKS
        assert bevHab.db == bevDB
        assert not bevHab.kever.prefixer.transferable

        # setup Art's habitat using custom salt nonstransferable so not match Bev
        # already incepts
        # Art's receipts will be rcts with a receipt couple attached
        salt = coring.Salter(raw=b'abcdef0123456789').qb64
        sith = '1'  # hex str of threshold int
        artHab = directing.Habitat(ks=artKS, db=artDB, isith=sith, icount=1,
                                   salt=salt, transferable=False, temp=True)
        assert artHab.ks == artKS
        assert artHab.db == artDB
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

        assert debMsgs == (b'{"v":"KERI10JSON00015b_","i":"EBfdpo5wnI3XTcdUIgJRf1-xLhy8Ud8lry'
                            b'kGGHz2vlMw","s":"0","t":"icp","kt":["1/2","1/2","1/2"],"k":["DaY'
                            b'h8uaASuDjMUd8_BoNyQs3GwupzmJL8_RBsuNtZHQg","Duzj-Z2lR2DqB0cI0421'
                            b'oSMUVWOrN5axojx8g9fSx3PM","DRXPAmNVVqafWvQiN5qQmWUDvVupF2w8xFNGg'
                            b'1Gays9Y"],"n":"EO5f_IQjtBoeN_-OyzfVJx1_WqBFUL-Ely4x-xmUtOW8","bt'
                            b'":"0","b":[],"c":[],"a":[]}-AADAA1G77zOmX-GYRN5yk5X704dneyog8BHJ'
                            b'ItCZdLmXl4Tlfd-bE3K8WpbApL_-n1o18Ato90tRhAIZjuBIlxF9vAgAByElIwoU'
                            b'aqbuJzHevggmdBySCIropnrylNFmSETWjOwLT2ifZgCJ1lm27IbknR_33LPPIyN3'
                            b'U6dbIAG3kko7IDgACdOTaaqRtwquJiBZJfWYKtH48gZTezMLzXviMUeo2Z1cJ-_M'
                            b'xQvDNh85FjXAOEQ-3hPEiqmY1SpjElZIXGs13DA{"v":"KERI10JSON000098_",'
                            b'"i":"EBfdpo5wnI3XTcdUIgJRf1-xLhy8Ud8lrykGGHz2vlMw","s":"1","t":"'
                            b'ixn","p":"E5OQH-DOSjcX8JlBtznPaaawhP0iuZhjf9cxWVAXNTX0","a":[]}-'
                            b'AADAAO7JjY0oHH5z68S4ZlYUAOAFnMfRu6OZB9hMGgu6teSzvL_3kzAiiPig6vch'
                            b'lnXDxmKFWMDLXAZsCBN3T0chVCwAB_I3BVOYI2K_VSeLDcq32czYe-kTyPZ1E0wd'
                            b'-F78Ixsz99mQwwylJsbRBb2l1Q2-1UnbQ4NZzj0w2xo5fEBv4BAACHO5PyuMrekU'
                            b'FWbirPNt7etpA3cUVAR94XFlJDUYYSE4tq1gD6Pab-L2PP3ifFlluO-aoVpf3G8h'
                            b'Sl75t2k7rCg{"v":"KERI10JSON000190_","i":"EBfdpo5wnI3XTcdUIgJRf1-'
                            b'xLhy8Ud8lrykGGHz2vlMw","s":"2","t":"rot","p":"EjevD0KmiBZQHqVNND'
                            b'mpTfrp0lqZI5eicRRNf3OqLW9o","kt":["1/2","1/2","1/2"],"k":["DIsi8'
                            b'qYso1KMmpLOGYty3NC2BAojZmUCfzR5_5oQRiso","DkdClpaWCAoCPBYgUmqP9g'
                            b'wAtsGq81yyPhGQKQ6-W_F0","DKDyq4QQYKnx9ircxeCvEcraI4HUSr_ytWPelDH'
                            b'AM98w"],"n":"E1oOvJmwenmC4uHjX7qB40LGVbeZY5rYQeZ6IK5zmdmM","bt":'
                            b'"0","br":[],"ba":[],"a":[]}-AADAAfELYptGBeOzZ1ex7MIxYAUN_f4mr0gZ'
                            b'gUZAQTZQbZKsTykDGqTcsbuLurhFviHttWylHBBjDwfCRF8eFCpLkDgABRLbYyJQ'
                            b'W8plPZ3PcdBLHgl4NWnB5NeTOI9tjW53DL4le2N-nVPVXr_fAvWcksevbGNRZxCU'
                            b'ePoDlThcBShDdBwACSPQd27SozRqfeW7YWWQS87JXdgy-ZGTrhrT1bUTTQKAngwE'
                            b'1hwWgIYw8LUgz3YH6SZC5zAWUN_Fv3OzSb_BXBg{"v":"KERI10JSON000098_",'
                            b'"i":"EBfdpo5wnI3XTcdUIgJRf1-xLhy8Ud8lrykGGHz2vlMw","s":"3","t":"'
                            b'ixn","p":"Ew3t8tlmqfRSwyyRF1nsKLjNOySvj-KTd-SmDu_AjzuA","a":[]}-'
                            b'AADAAJ4MM4lGyFUsszt7fXksb13wqyiBTd3AirhQaTO3udtTilMfviCutx-ipkgT'
                            b'u56huDbWLiA47LqUzqP63rKv3DQAB9hmDtEawFFGHMeS92RBuuMMQroBM5fodzeo'
                            b'leSrV0IyETDSpjaRhcsDf25EqNTJUcnv-_jSzRPEtM8GEv3AJCgACxWtyOC4ks1F'
                            b'8-YdHSM32VLysW0ypRBpfYDOHyfmtktb1XQjdAAJpkSDe9wvrttvE2xJ5GzyfpVv'
                            b'Ps4zK54pCDA{"v":"KERI10JSON000098_","i":"EBfdpo5wnI3XTcdUIgJRf1-'
                            b'xLhy8Ud8lrykGGHz2vlMw","s":"4","t":"ixn","p":"EY_w2vUVqsE6jdgdxJ'
                            b'VvMW3434NG1w_asCW7ohG1nmMY","a":[]}-AADAANw16XHQyB4Edm0MF4b0m8Ez'
                            b'8jOZSYr_bYn7ilsFTNBypC_tSIcLnOUarG1xuhFU21WjXiSHWt2t2BSIHulgtDgA'
                            b'Bm1DN8JigUofEC8mXb7YgklycIqDt7F7p8s6x8VHlAqLsCiMsXGQlRCwUwF7DFeu'
                            b'6Fw_43Io6evqKpzaTR31SCwACJE0jOjykDr4SU59Mpd-EBTwKc8hUUWeIQTF3qU4'
                            b'H56jqKozmgsyzzViob_DZ828OGBLRG_WoIQxTvstXql3QDw{"v":"KERI10JSON0'
                            b'00098_","i":"EBfdpo5wnI3XTcdUIgJRf1-xLhy8Ud8lrykGGHz2vlMw","s":"'
                            b'5","t":"ixn","p":"EwJ79SUIE69dA0my9ai9hK3yH8cqqyD9CS62lyRTDn-o",'
                            b'"a":[]}-AADAAhAypLrhzTbvSPdErva4IzRRSq6EZCC_dCe3pkLGpPcVHdi3Mu2B'
                            b'-c0oW1My7HFFa1-JNTbjnNtgK-Or297PmAgABM1DYwa0Khbr79SbRaC6l8rAwsxs'
                            b'Vopeid8KfS-7pt60y9drfLpXIUFzt5rk24KUuZROO33KiHmfKNbviW6GVCgACQRj'
                            b'qwHlELgvpFJwQx-6yBVuAgbsT7AK1mbxfsUo2XfzkAUTbn9H1vxOQX1Rg_3cLYZv'
                            b'ryKcP4MdjZFfFYaNmBQ{"v":"KERI10JSON000098_","i":"EBfdpo5wnI3XTcd'
                            b'UIgJRf1-xLhy8Ud8lrykGGHz2vlMw","s":"6","t":"ixn","p":"EBjW8_7rqn'
                            b'AXV0Il5BJ4XWZcIb355Ltj-9F9JRZLn75c","a":[]}-AADAAbbH94e474Pflg_Y'
                            b'dlivHMQQL_7rUlr1DEut8SSbEs6cmUixWHW8SuZG2UlpKoqsAL-STNALsRCmDw_2'
                            b'wWsmWAAABnedMdYxUbNgwJpG5AcNsxMIZCjuu486-wuiUm3BO_1h40_qvoMicneV'
                            b'edtBOLxD5zKtdZhBHZqtd3-qQDmIVDgACqms_mYs0LAwAi2zGN6lpKmdqs2twyJz'
                            b'9xiyPeERHG7D2FiTZqow19UieVYobmhGeHuoS5WxNPgcponbhHeFnDA')


        # Play debMsgs to Cam
        # create non-local kevery for Cam to process msgs from Deb
        camKevery = eventing.Kevery(kevers=camHab.kevers,
                                    db=camHab.db,
                                    opre=camHab.pre,
                                    local=False)
        eventing.Parser().process(ims=bytearray(debMsgs), kvy=camKevery)
        # camKevery.process(ims=bytearray(debMsgs))  # give copy to process
        assert debHab.pre in camKevery.kevers
        assert camKevery.kevers[debHab.pre].sn == debHab.kever.sn == 6
        assert len(camKevery.cues) == 7

        # get disjoints receipts (vrcs) from Cam of Deb's events by processing Cam's cues
        camMsgs = camHab.processCues(camKevery.cues)
        assert camMsgs == (b'{"v":"KERI10JSON00014b_","i":"EiRjCnZfca8gUZqecerjGpjkiY8dIkGudP'
                        b'6GfapWi5MU","s":"0","t":"icp","kt":"2","k":["DaYh8uaASuDjMUd8_Bo'
                        b'NyQs3GwupzmJL8_RBsuNtZHQg","Duzj-Z2lR2DqB0cI0421oSMUVWOrN5axojx8'
                        b'g9fSx3PM","DRXPAmNVVqafWvQiN5qQmWUDvVupF2w8xFNGg1Gays9Y"],"n":"E'
                        b'OySO3Oa400n3Ss9JftGYmgS5M4jgPInNnMntC_l-PEQ","bt":"0","b":[],"c"'
                        b':[],"a":[]}-AADAATacW---OhatYudCOUeNdVpYq8Vk_LIKMQML86xz4b1ZQG9r'
                        b'ahEGEHMtDacANGyKFSkJBq4F3x8h30lWfrth2BQABnyZMjYDQs2IgFuVcRKCLi9F'
                        b'DFOw7uPqIvwossbC4H2Eu4_cIntaKeEmH7LBEzDbfQaQxWdgZ2YTnfFkoznL3AgA'
                        b'Ckf4d23ErgdwPZWJf_0jVtzVwoKsh_6W0V6BclmrbnL1NWM8ox2m3ff7LzZeSjF5'
                        b'9AvO-QmqCD325H3igOF0HCg{"v":"KERI10JSON000091_","i":"EBfdpo5wnI3'
                        b'XTcdUIgJRf1-xLhy8Ud8lrykGGHz2vlMw","s":"0","t":"rct","d":"E5OQH-'
                        b'DOSjcX8JlBtznPaaawhP0iuZhjf9cxWVAXNTX0"}-FABEiRjCnZfca8gUZqecerj'
                        b'GpjkiY8dIkGudP6GfapWi5MU0AAAAAAAAAAAAAAAAAAAAAAAE1tSV5RBIG7dGPN2'
                        b'Oof5DmZCqgGgpF7P9BbfOTnOEEpM-AADAA1G77zOmX-GYRN5yk5X704dneyog8BH'
                        b'JItCZdLmXl4Tlfd-bE3K8WpbApL_-n1o18Ato90tRhAIZjuBIlxF9vAgAByElIwo'
                        b'UaqbuJzHevggmdBySCIropnrylNFmSETWjOwLT2ifZgCJ1lm27IbknR_33LPPIyN'
                        b'3U6dbIAG3kko7IDgACdOTaaqRtwquJiBZJfWYKtH48gZTezMLzXviMUeo2Z1cJ-_'
                        b'MxQvDNh85FjXAOEQ-3hPEiqmY1SpjElZIXGs13DA{"v":"KERI10JSON000091_"'
                        b',"i":"EBfdpo5wnI3XTcdUIgJRf1-xLhy8Ud8lrykGGHz2vlMw","s":"1","t":'
                        b'"rct","d":"EjevD0KmiBZQHqVNNDmpTfrp0lqZI5eicRRNf3OqLW9o"}-FABEiR'
                        b'jCnZfca8gUZqecerjGpjkiY8dIkGudP6GfapWi5MU0AAAAAAAAAAAAAAAAAAAAAA'
                        b'AE1tSV5RBIG7dGPN2Oof5DmZCqgGgpF7P9BbfOTnOEEpM-AADAAO7JjY0oHH5z68'
                        b'S4ZlYUAOAFnMfRu6OZB9hMGgu6teSzvL_3kzAiiPig6vchlnXDxmKFWMDLXAZsCB'
                        b'N3T0chVCwAB_I3BVOYI2K_VSeLDcq32czYe-kTyPZ1E0wd-F78Ixsz99mQwwylJs'
                        b'bRBb2l1Q2-1UnbQ4NZzj0w2xo5fEBv4BAACHO5PyuMrekUFWbirPNt7etpA3cUVA'
                        b'R94XFlJDUYYSE4tq1gD6Pab-L2PP3ifFlluO-aoVpf3G8hSl75t2k7rCg{"v":"K'
                        b'ERI10JSON000091_","i":"EBfdpo5wnI3XTcdUIgJRf1-xLhy8Ud8lrykGGHz2v'
                        b'lMw","s":"2","t":"rct","d":"Ew3t8tlmqfRSwyyRF1nsKLjNOySvj-KTd-Sm'
                        b'Du_AjzuA"}-FABEiRjCnZfca8gUZqecerjGpjkiY8dIkGudP6GfapWi5MU0AAAAA'
                        b'AAAAAAAAAAAAAAAAAAE1tSV5RBIG7dGPN2Oof5DmZCqgGgpF7P9BbfOTnOEEpM-A'
                        b'ADAABkB5LzkcturaQSzTGH_KrWsEJR-x_CH8UPl9FQ1Dc461z5-Fdn3TLJ7DpUw-'
                        b'6VrbKGGjuDy2Nkg0xJdzh4F8CQABPgHmWCG4uUicqcBiHOJcygFsSqFMU2jkOgU7'
                        b'3eG-Jony_ZwctQl_1BCQ8eVTli44Uou4YMdgvRMfmiRGTuxeAwAC386oYzhQFZCk'
                        b'S6TM9vIFahT8vf0cQ7t2v5MqKhyJxBgA6CHJeQ8mxS8P7trjcEOGl79jwb6L-jyt'
                        b'qAnNPDJFCA{"v":"KERI10JSON000091_","i":"EBfdpo5wnI3XTcdUIgJRf1-x'
                        b'Lhy8Ud8lrykGGHz2vlMw","s":"3","t":"rct","d":"EY_w2vUVqsE6jdgdxJV'
                        b'vMW3434NG1w_asCW7ohG1nmMY"}-FABEiRjCnZfca8gUZqecerjGpjkiY8dIkGud'
                        b'P6GfapWi5MU0AAAAAAAAAAAAAAAAAAAAAAAE1tSV5RBIG7dGPN2Oof5DmZCqgGgp'
                        b'F7P9BbfOTnOEEpM-AADAAraP5JCHU-ZQwsDAWuLu_fvvYmkpVEu071l5P7fwHzqL'
                        b'bJ7kkvpSsXcGs2HpW_Bw_fjp07LfnN4de5zn7-owxAgABQUHJIy3inow-7ctn-jO'
                        b'F6r2IvOsC-Pl2jAueDZfH9p2pS_L9OhgHBr9ToilY4H_1bbIZK2kERtt47Qd0VVq'
                        b'qDAAC_0A73HjuuB42XhAqgPMWt1Fm-FwO55oT0z7TJR9PQ4ppaEuip5FUp-miRS9'
                        b'Rnoq0ZYPWskncUmLgcqxsOksvBw{"v":"KERI10JSON000091_","i":"EBfdpo5'
                        b'wnI3XTcdUIgJRf1-xLhy8Ud8lrykGGHz2vlMw","s":"4","t":"rct","d":"Ew'
                        b'J79SUIE69dA0my9ai9hK3yH8cqqyD9CS62lyRTDn-o"}-FABEiRjCnZfca8gUZqe'
                        b'cerjGpjkiY8dIkGudP6GfapWi5MU0AAAAAAAAAAAAAAAAAAAAAAAE1tSV5RBIG7d'
                        b'GPN2Oof5DmZCqgGgpF7P9BbfOTnOEEpM-AADAApIX866iuD6j14MFQbVdiJHMeTM'
                        b'Svd2EoibE7PPfwU7f6HcDCwmLmMCNpRVwM-Kf1kKIor7TETSX80jrliA_XBgAB1h'
                        b'phj5XH3E0oTANv6GVwJ5s0ZnLIPSYoBuvXaPOzWgW3nynVPwWnqCNuP7rdh-1NVB'
                        b'QUc9QHqrDWVnJaoVo5CQAC9PBjGWWN9J6jQXcLmQOfQxrWL3NFm93r7-nDiSbG-T'
                        b'KDvbcXcnoLfCitTt_B96JlvIpe6cI8DJZw3_SERLsaCg{"v":"KERI10JSON0000'
                        b'91_","i":"EBfdpo5wnI3XTcdUIgJRf1-xLhy8Ud8lrykGGHz2vlMw","s":"5",'
                        b'"t":"rct","d":"EBjW8_7rqnAXV0Il5BJ4XWZcIb355Ltj-9F9JRZLn75c"}-FA'
                        b'BEiRjCnZfca8gUZqecerjGpjkiY8dIkGudP6GfapWi5MU0AAAAAAAAAAAAAAAAAA'
                        b'AAAAAE1tSV5RBIG7dGPN2Oof5DmZCqgGgpF7P9BbfOTnOEEpM-AADAApBHqjI7V9'
                        b'yrCqUP1ZsnSHov3nNF90QNZEwPGZToAf6l3KeXPh4UQMZU70-5Cbbs2mswX8_Tg4'
                        b'5orHQz_mQkMCgABF3FoOib-wh0KQ26kdzfEBtnenPVN12GiP7NpIy2j3wW-enfJc'
                        b'gRTEE3XWVekl3IkU3o70Cnk4K1PONYCrO6hAwACWMhg7tNGae9I4mLtv5rVpb9Rr'
                        b'G70zGIwBDxN4QahABHlAvRdDpaSE5BpJ7nlOkShOZIva-qdcWS5TiRX8I43DQ{"v'
                        b'":"KERI10JSON000091_","i":"EBfdpo5wnI3XTcdUIgJRf1-xLhy8Ud8lrykGG'
                        b'Hz2vlMw","s":"6","t":"rct","d":"E8BEZ7sVSL-vamQnB8Oc72ov-gpiXJzL'
                        b'GXeiAW9_Vht8"}-FABEiRjCnZfca8gUZqecerjGpjkiY8dIkGudP6GfapWi5MU0A'
                        b'AAAAAAAAAAAAAAAAAAAAAAE1tSV5RBIG7dGPN2Oof5DmZCqgGgpF7P9BbfOTnOEE'
                        b'pM-AADAAlQ8kt9KwijVTzAS8-LUziqMPwvLDhoU9sVHN0a9wkICnezEmzrb4skeO'
                        b'wdNVbpek3Wn6xcRxa5wCuF9ub3T-CAAByaYGW-0ZX6oDmjk70BOpkRl8JvgVCm9w'
                        b'skxESXXFcMs_FWssXcUH1oDRzA2q7BMW80DpEtKtcY8phmbH8TTBBwACQd7bqYf-'
                        b'hcHe2B_FESYMXH2SloJ1o7XOry4KyBxZ9oJwtoa0iR4JPScb4_ix1p8p9n3HGMXT'
                        b'_Lou1q1l6AGAAQ')

        # Play camMsgs to Deb
        # create non-local kevery for Deb to process msgs from Cam
        debKevery = eventing.Kevery(kevers=debHab.kevers,
                                    db=debHab.db,
                                    opre=debHab.pre,
                                    local=False)
        eventing.Parser().process(ims=bytearray(camMsgs), kvy=debKevery)
        # debKevery.process(ims=bytearray(camMsgs))  # give copy to process
        assert camHab.pre in debKevery.kevers
        assert debKevery.kevers[camHab.pre].sn == camHab.kever.sn == 0
        assert len(debKevery.cues) == 1

        # get disjoints receipts (vrcs) from Deb of Cam's events by processing Deb's cues
        debCamVrcs = debHab.processCues(debKevery.cues)
        assert debCamVrcs == (b'{"v":"KERI10JSON000091_","i":"EiRjCnZfca8gUZqecerjGpjkiY8dIkGudP'
                              b'6GfapWi5MU","s":"0","t":"rct","d":"E1tSV5RBIG7dGPN2Oof5DmZCqgGgp'
                              b'F7P9BbfOTnOEEpM"}-FABEBfdpo5wnI3XTcdUIgJRf1-xLhy8Ud8lrykGGHz2vlM'
                              b'w0AAAAAAAAAAAAAAAAAAAAAAgEw3t8tlmqfRSwyyRF1nsKLjNOySvj-KTd-SmDu_'
                              b'AjzuA-AADAAII8AatcRUlekxpknQfnpZJ2KBrATxmFRLxb_zpdPOaG3pCQg6vqP0'
                              b'G96WmJO0hFwaGL-xheGy-SvX_5Q8b0gDQABRgVbtBmb3lR7UjuBjHmny7QkJ6waR'
                              b'MTwz2B_1ANJu9yDa5qsgJiMQ7aTc7lCpLJgZNyKUJaUmW8YJL6JrzteDwAC1zKj3'
                              b'HCcHwhw7OtEVXrgIobJO27d6389xdPXpkdVENb6XbsQLDEPNtv3g2POvWx1vESlp'
                              b'pIfOxaY8VATudBBBg')

        # Play disjoints debCamVrcs to Cam
        eventing.Parser().processOne(ims=bytearray(debCamVrcs), kvy=camKevery)
        # camKevery.processOne(ims=bytearray(debCamVrcs))  # give copy to process

        # Play debMsgs to Bev
        # create non-local kevery for Bev to process msgs from Deb
        bevKevery = eventing.Kevery(kevers=bevHab.kevers,
                                    db=bevHab.db,
                                    opre=bevHab.pre,
                                    local=False)
        eventing.Parser().process(ims=bytearray(debMsgs), kvy=bevKevery)
        # bevKevery.process(ims=bytearray(debMsgs))  # give copy to process
        assert debHab.pre in bevKevery.kevers
        assert bevKevery.kevers[debHab.pre].sn == debHab.kever.sn == 6
        assert len(bevKevery.cues) == 7

        # get disjoints receipts (rcts) from Bev of Deb's events by processing Bevs's cues
        bevMsgs = bevHab.processCues(bevKevery.cues)
        assert bevMsgs == (b'{"v":"KERI10JSON0000c1_","i":"BaYh8uaASuDjMUd8_BoNyQs3GwupzmJL8_'
                        b'RBsuNtZHQg","s":"0","t":"icp","kt":"1","k":["BaYh8uaASuDjMUd8_Bo'
                        b'NyQs3GwupzmJL8_RBsuNtZHQg"],"n":"","bt":"0","b":[],"c":[],"a":[]'
                        b'}-AABAA8dCt6i3swKOHoV10pEEOT7LOHxDWCfPWJm0Qvf6CXNaxTEOthHVgLihIz'
                        b'1ZwQYc_nvunt0Hkh5TnnG4OmnulCQ{"v":"KERI10JSON000091_","i":"EBfdp'
                        b'o5wnI3XTcdUIgJRf1-xLhy8Ud8lrykGGHz2vlMw","s":"0","t":"rct","d":"'
                        b'E5OQH-DOSjcX8JlBtznPaaawhP0iuZhjf9cxWVAXNTX0"}-CABBaYh8uaASuDjMU'
                        b'd8_BoNyQs3GwupzmJL8_RBsuNtZHQg0B1G77zOmX-GYRN5yk5X704dneyog8BHJI'
                        b'tCZdLmXl4Tlfd-bE3K8WpbApL_-n1o18Ato90tRhAIZjuBIlxF9vAg{"v":"KERI'
                        b'10JSON000091_","i":"EBfdpo5wnI3XTcdUIgJRf1-xLhy8Ud8lrykGGHz2vlMw'
                        b'","s":"1","t":"rct","d":"EjevD0KmiBZQHqVNNDmpTfrp0lqZI5eicRRNf3O'
                        b'qLW9o"}-CABBaYh8uaASuDjMUd8_BoNyQs3GwupzmJL8_RBsuNtZHQg0BO7JjY0o'
                        b'HH5z68S4ZlYUAOAFnMfRu6OZB9hMGgu6teSzvL_3kzAiiPig6vchlnXDxmKFWMDL'
                        b'XAZsCBN3T0chVCw{"v":"KERI10JSON000091_","i":"EBfdpo5wnI3XTcdUIgJ'
                        b'Rf1-xLhy8Ud8lrykGGHz2vlMw","s":"2","t":"rct","d":"Ew3t8tlmqfRSwy'
                        b'yRF1nsKLjNOySvj-KTd-SmDu_AjzuA"}-CABBaYh8uaASuDjMUd8_BoNyQs3Gwup'
                        b'zmJL8_RBsuNtZHQg0BBkB5LzkcturaQSzTGH_KrWsEJR-x_CH8UPl9FQ1Dc461z5'
                        b'-Fdn3TLJ7DpUw-6VrbKGGjuDy2Nkg0xJdzh4F8CQ{"v":"KERI10JSON000091_"'
                        b',"i":"EBfdpo5wnI3XTcdUIgJRf1-xLhy8Ud8lrykGGHz2vlMw","s":"3","t":'
                        b'"rct","d":"EY_w2vUVqsE6jdgdxJVvMW3434NG1w_asCW7ohG1nmMY"}-CABBaY'
                        b'h8uaASuDjMUd8_BoNyQs3GwupzmJL8_RBsuNtZHQg0BraP5JCHU-ZQwsDAWuLu_f'
                        b'vvYmkpVEu071l5P7fwHzqLbJ7kkvpSsXcGs2HpW_Bw_fjp07LfnN4de5zn7-owxA'
                        b'g{"v":"KERI10JSON000091_","i":"EBfdpo5wnI3XTcdUIgJRf1-xLhy8Ud8lr'
                        b'ykGGHz2vlMw","s":"4","t":"rct","d":"EwJ79SUIE69dA0my9ai9hK3yH8cq'
                        b'qyD9CS62lyRTDn-o"}-CABBaYh8uaASuDjMUd8_BoNyQs3GwupzmJL8_RBsuNtZH'
                        b'Qg0BpIX866iuD6j14MFQbVdiJHMeTMSvd2EoibE7PPfwU7f6HcDCwmLmMCNpRVwM'
                        b'-Kf1kKIor7TETSX80jrliA_XBg{"v":"KERI10JSON000091_","i":"EBfdpo5w'
                        b'nI3XTcdUIgJRf1-xLhy8Ud8lrykGGHz2vlMw","s":"5","t":"rct","d":"EBj'
                        b'W8_7rqnAXV0Il5BJ4XWZcIb355Ltj-9F9JRZLn75c"}-CABBaYh8uaASuDjMUd8_'
                        b'BoNyQs3GwupzmJL8_RBsuNtZHQg0BpBHqjI7V9yrCqUP1ZsnSHov3nNF90QNZEwP'
                        b'GZToAf6l3KeXPh4UQMZU70-5Cbbs2mswX8_Tg45orHQz_mQkMCg{"v":"KERI10J'
                        b'SON000091_","i":"EBfdpo5wnI3XTcdUIgJRf1-xLhy8Ud8lrykGGHz2vlMw","'
                        b's":"6","t":"rct","d":"E8BEZ7sVSL-vamQnB8Oc72ov-gpiXJzLGXeiAW9_Vh'
                        b't8"}-CABBaYh8uaASuDjMUd8_BoNyQs3GwupzmJL8_RBsuNtZHQg0BlQ8kt9Kwij'
                        b'VTzAS8-LUziqMPwvLDhoU9sVHN0a9wkICnezEmzrb4skeOwdNVbpek3Wn6xcRxa5'
                        b'wCuF9ub3T-CA')

        # Play bevMsgs to Deb
        eventing.Parser().process(ims=bytearray(bevMsgs), kvy=debKevery)
        # debKevery.process(ims=bytearray(bevMsgs))  # give copy to process
        assert bevHab.pre in debKevery.kevers
        assert debKevery.kevers[bevHab.pre].sn == bevHab.kever.sn == 0
        assert len(debKevery.cues) == 1

        # get disjoints receipts (vrcs) from Deb of Bev's events by processing Deb's cues
        debBevVrcs = debHab.processCues(debKevery.cues)
        assert debBevVrcs == (b'{"v":"KERI10JSON000091_","i":"BaYh8uaASuDjMUd8_BoNyQs3GwupzmJL8_'
                              b'RBsuNtZHQg","s":"0","t":"rct","d":"EW4yC5ZUXv8xhM3gXDvKwOCZkltCh'
                              b'RZe-hTb2mi1Zf04"}-FABEBfdpo5wnI3XTcdUIgJRf1-xLhy8Ud8lrykGGHz2vlM'
                              b'w0AAAAAAAAAAAAAAAAAAAAAAgEw3t8tlmqfRSwyyRF1nsKLjNOySvj-KTd-SmDu_'
                              b'AjzuA-AADAAmQ-kOahYYNCaatYN5YHfuruD93tOhJNQCt7Wy6LUCCkITxSj7Ogux'
                              b'aDrBo15FN7wk-BTgEV8ufOIsxhqVfmVBgAB5DhNTiOesOQxfxSn-0D7Ec9_S80xO'
                              b'9ck6Q6FKROXz2Evd4_TwfzMbgJKjSPXqkA16zju5GN6aDWeGWCJOTceDwACrkW_1'
                              b'_sKmtEWtlcON3IGzRygPc0tF-f5qTRJewOEIRIhCB81WnDi8PBa7F43YzSoJiSGV'
                              b'_PgAcg6zh6q8wxVDQ')



        # Play disjoints debBevVrcs to Bev
        eventing.Parser().processOne(ims=bytearray(debBevVrcs), kvy=bevKevery)
        # bevKevery.processOne(ims=bytearray(debBevVrcs))  # give copy to process

        # now setup conjoint replay

        # Replay Deb's First Seen Events with receipts (vrcs and rcts) from both Cam and Bev
        # datetime is different in each run in the fse attachment in clone replay
        # so we either have to force dts in db or we parse in pieces
        debFelMsgs = bytearray()
        fn = 0
        cloner = debHab.db.clonePreIter(pre=debHab.pre, fn=fn)  # create iterator
        msg = next(cloner)  # get zeroth event with attachments
        assert len(msg) == 1423
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
            prefixer, seqner, diger, siger = eventing.deTransReceiptQuadruple(msg, strip=True)
        assert len(msg) == 800 - 3 * (len(prefixer.qb64b) + len(seqner.qb64b) +
                                len(diger.qb64b) + len(siger.qb64b)) == 200

        counter = coring.Counter(qb64b=msg)  # nontrans receipt (rct) counter
        assert counter.code == coring.CtrDex.NonTransReceiptCouples
        assert counter.count == 1  #  single sig bev
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

        assert len(debFelMsgs) == 9039
        cloner.close()  # must close or get lmdb error upon with exit

        msgs = debHab.replay()
        assert msgs == debFelMsgs

        # Play Cam's messages to Bev
        eventing.Parser().process(ims=bytearray(camMsgs), kvy=bevKevery)
        # bevKevery.process(ims=bytearray(camMsgs))  # give copy to process
        assert camHab.pre in bevKevery.kevers
        assert bevKevery.kevers[camHab.pre].sn == camHab.kever.sn == 0
        assert len(bevKevery.cues) == 1

        # Play Bev's messages to Cam
        eventing.Parser().process(ims=bytearray(bevMsgs), kvy=camKevery)
        # camKevery.process(ims=bytearray(bevMsgs))  # give copy to process
        assert bevHab.pre in camKevery.kevers
        assert camKevery.kevers[bevHab.pre].sn == bevHab.kever.sn == 0
        assert len(camKevery.cues) == 1

        camDebFelMsgs = camHab.replay(pre=debHab.pre)
        bevDebFelMsgs = bevHab.replay(pre=debHab.pre)

        assert len(bevDebFelMsgs) == len(camDebFelMsgs) == len(debFelMsgs) == 9039

        # create non-local kevery for Art to process conjoint replay msgs from Deb
        artKevery = eventing.Kevery(kevers=artHab.kevers,
                                        db=artHab.db,
                                        opre=artHab.pre,
                                        local=False)
        # process Cam's inception so Art will proces Cam's vrcs without escrowing
        camIcpMsg = camHab.makeOwnInception()
        eventing.Parser().process(ims=bytearray(camIcpMsg), kvy=artKevery)
        # artKevery.process(ims=bytearray(camIcpMsg))
        assert camHab.pre in artKevery.kevers
        assert len(artKevery.cues) == 1

        eventing.Parser().process(ims=bytearray(debFelMsgs), kvy=artKevery, cloned=True)
        # artKevery.process(ims=bytearray(debFelMsgs), cloned=True)  # give copy to process
        assert debHab.pre in artKevery.kevers
        assert artKevery.kevers[debHab.pre].sn == debHab.kever.sn == 6
        assert len(artKevery.cues) == 8
        artDebFelMsgs = artHab.replay(pre=debHab.pre)
        assert len(artDebFelMsgs) == 9039


    assert not os.path.exists(artKS.path)
    assert not os.path.exists(artDB.path)
    assert not os.path.exists(bevKS.path)
    assert not os.path.exists(bevDB.path)
    assert not os.path.exists(camKS.path)
    assert not os.path.exists(camDB.path)
    assert not os.path.exists(debKS.path)
    assert not os.path.exists(debDB.path)

    """End Test"""


def test_replay_all():
    """
    Test conjoint replay all

    Setup database with events from Deb, Cam, Bev, abd Art
    Replay all the events in database.

    """

    with dbing.openDB(name="deb") as debDB, keeping.openKS(name="deb") as debKS, \
         dbing.openDB(name="cam") as camDB, keeping.openKS(name="cam") as camKS, \
         dbing.openDB(name="bev") as bevDB, keeping.openKS(name="bev") as bevKS, \
         dbing.openDB(name="art") as artDB, keeping.openKS(name="art") as artKS:

        # setup Deb's habitat using default salt multisig already incepts
        sith = ["1/2", "1/2", "1/2"]  # weighted signing threshold
        debHab = directing.Habitat(ks=debKS, db=debDB, isith=sith, icount=3,
                                   temp=True)
        assert debHab.ks == debKS
        assert debHab.db == debDB
        assert debHab.kever.prefixer.transferable

        # setup Cam's habitat using default salt multisig already incepts
        # Cam's receipts will be vrcs with 3 indexed sigantures attached
        sith = '2'  # hex str of threshold int
        camHab = directing.Habitat(ks=camKS, db=camDB, isith=sith, icount=3,
                                   temp=True)
        assert camHab.ks == camKS
        assert camHab.db == camDB
        assert camHab.kever.prefixer.transferable

        # setup Bev's habitat using default salt nonstransferable already incepts
        # Bev's receipts will be rcts with a receipt couple attached
        sith = '1'  # hex str of threshold int
        bevHab = directing.Habitat(ks=bevKS, db=bevDB, isith=sith, icount=1,
                                   transferable=False, temp=True)
        assert bevHab.ks == bevKS
        assert bevHab.db == bevDB
        assert not bevHab.kever.prefixer.transferable

        # setup Art's habitat using custom salt nonstransferable so not match Bev
        # already incepts
        # Art's receipts will be rcts with a receipt couple attached
        salt = coring.Salter(raw=b'abcdef0123456789').qb64
        sith = '1'  # hex str of threshold int
        artHab = directing.Habitat(ks=artKS, db=artDB, isith=sith, icount=1,
                                   salt=salt, transferable=False, temp=True)
        assert artHab.ks == artKS
        assert artHab.db == artDB
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
        camKevery = eventing.Kevery(kevers=camHab.kevers,
                                    db=camHab.db,
                                    opre=camHab.pre,
                                    local=False)
        eventing.Parser().process(ims=bytearray(debMsgs), kvy=camKevery)
        # camKevery.process(ims=bytearray(debMsgs))  # give copy to process
        assert debHab.pre in camKevery.kevers
        assert camKevery.kevers[debHab.pre].sn == debHab.kever.sn == 6
        assert len(camKevery.cues) == 7

        # get disjoints receipts (vrcs) from Cam of Deb's events by processing Cam's cues
        camMsgs = camHab.processCues(camKevery.cues)

        # Play camMsgs to Deb
        # create non-local kevery for Deb to process msgs from Cam
        debKevery = eventing.Kevery(kevers=debHab.kevers,
                                    db=debHab.db,
                                    opre=debHab.pre,
                                    local=False)
        eventing.Parser().process(ims=bytearray(camMsgs), kvy=debKevery)
        # debKevery.process(ims=bytearray(camMsgs))  # give copy to process
        assert camHab.pre in debKevery.kevers
        assert debKevery.kevers[camHab.pre].sn == camHab.kever.sn == 0
        assert len(debKevery.cues) == 1

        # get disjoints receipts (vrcs) from Deb of Cam's events by processing Deb's cues
        debCamVrcs = debHab.processCues(debKevery.cues)

        # Play disjoints debCamVrcs to Cam
        eventing.Parser().processOne(ims=bytearray(debCamVrcs), kvy=camKevery)
        # camKevery.processOne(ims=bytearray(debCamVrcs))  # give copy to process

        # Play debMsgs to Bev
        # create non-local kevery for Bev to process msgs from Deb
        bevKevery = eventing.Kevery(kevers=bevHab.kevers,
                                    db=bevHab.db,
                                    opre=bevHab.pre,
                                    local=False)
        eventing.Parser().process(ims=bytearray(debMsgs), kvy=bevKevery)
        # bevKevery.process(ims=bytearray(debMsgs))  # give copy to process
        assert debHab.pre in bevKevery.kevers
        assert bevKevery.kevers[debHab.pre].sn == debHab.kever.sn == 6
        assert len(bevKevery.cues) == 7

        # get disjoints receipts (rcts) from Bev of Deb's events by processing Bevs's cues
        bevMsgs = bevHab.processCues(bevKevery.cues)

        # Play bevMsgs to Deb
        eventing.Parser().process(ims=bytearray(bevMsgs), kvy=debKevery)
        # debKevery.process(ims=bytearray(bevMsgs))  # give copy to process
        assert bevHab.pre in debKevery.kevers
        assert debKevery.kevers[bevHab.pre].sn == bevHab.kever.sn == 0
        assert len(debKevery.cues) == 1

        # get disjoints receipts (vrcs) from Deb of Bev's events by processing Deb's cues
        debBevVrcs = debHab.processCues(debKevery.cues)

        # Play disjoints debBevVrcs to Bev
        eventing.Parser().processOne(ims=bytearray(debBevVrcs), kvy=bevKevery)
        # bevKevery.processOne(ims=bytearray(debBevVrcs))  # give copy to process

        # now setup replay
        debAllFelMsgs = debHab.replayAll()
        assert len(debAllFelMsgs) == 11267

        # create non-local kevery for Art to process conjoint replay msgs from Deb
        artKevery = eventing.Kevery(kevers=artHab.kevers,
                                        db=artHab.db,
                                        opre=artHab.pre,
                                        local=False)
        # process Cam's inception so Art will proces Cam's vrcs without escrowing
        camIcpMsg = camHab.makeOwnInception()
        eventing.Parser().process(ims=bytearray(camIcpMsg), kvy=artKevery)
        assert camHab.pre in artKevery.kevers
        assert len(artKevery.cues) == 1
        # give copy to process
        eventing.Parser().process(ims=bytearray(debAllFelMsgs), kvy=artKevery, cloned=True)
        # artKevery.process(ims=bytearray(debFelMsgs), cloned=True)
        assert debHab.pre in artKevery.kevers
        assert artKevery.kevers[debHab.pre].sn == debHab.kever.sn == 6
        assert len(artKevery.cues) == 9
        artAllFelMsgs = artHab.replayAll()
        assert len(artAllFelMsgs) == 11016


    assert not os.path.exists(artKS.path)
    assert not os.path.exists(artDB.path)
    assert not os.path.exists(bevKS.path)
    assert not os.path.exists(bevDB.path)
    assert not os.path.exists(camKS.path)
    assert not os.path.exists(camDB.path)
    assert not os.path.exists(debKS.path)
    assert not os.path.exists(debDB.path)

    """End Test"""


if __name__ == "__main__":
    test_replay_all()

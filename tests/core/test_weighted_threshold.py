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
                                  nsith=nxtsith,
                                  nkeys=[diger.qb64 for diger in digers],
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

        assert msg == bytearray(b'{"v":"KERI10JSON000207_","t":"icp","d":"EOsgPPbBijCbpu3R9N-TMdUR'
                                b'gcoFqrjUf3rQiIaJ5L7M","i":"EOsgPPbBijCbpu3R9N-TMdURgcoFqrjUf3rQi'
                                b'IaJ5L7M","s":"0","kt":["1/2","1/2","1/2"],"k":["DK4OJI8JOr6oEEUM'
                                b'eSF_X-SbKysfwpKwW-ho5KARvH5c","D1RZLgYke0GmfZm-CH8AsW4HoTU4m-2mF'
                                b'gu8kbwp8jQU","DBVwzum-jPfuUXUcHEWdplB4YcoL3BWGXK0TMoF_NeFU"],"nt'
                                b'":["1/2","1/2","1/2"],"n":["E9tzF91cgL0Xu4UkCqlCbDxXK-HnxmmTIwTi'
                                b'_ySgjGLc","Ez53UFJ6euROznsDhnPr4auhJGgzeM5ln5i-Tlp8V3L4","EPF1ap'
                                b'CK5AUL7k4AlFG4pSEgQX0h-kosQ_tfUtPJ_Ti0"],"bt":"0","b":[],"c":[],'
                                b'"a":[]}-AADAAjCyfd63fzueQfpOHGgSl4YvEXsc3IYpdlvXDKfpbicV8pGj2v-T'
                                b'WBDyFqkzIdB7hMhG1iR3IeS7vy3a3catGDgABhGYRTHmUMPIj2LV5iJLe6BtaO_o'
                                b'hLAVyP9mW0U4DdYT0Uiqh293sGFJ6e47uCkOqoLu9B6dF7wl-llurp3o5BAACJz5'
                                b'biC59pvOpb3aUadlNr_BZb-laG1zgX7FtO5Q0M_HPJObtlhVtUghTBythEb8FpoL'
                                b'ze8WnEWUayJnpLsYjAA')

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

        assert msg == bytearray(b'{"v":"KERI10JSON0000cb_","t":"ixn","d":"ErcMMcfO4fdplItWB_42GwyY'
                                b'21u0pJkQEVDvMmrLVgFc","i":"EOsgPPbBijCbpu3R9N-TMdURgcoFqrjUf3rQi'
                                b'IaJ5L7M","s":"1","p":"EOsgPPbBijCbpu3R9N-TMdURgcoFqrjUf3rQiIaJ5L'
                                b'7M","a":[]}-AADAAye1jlp6iz6h5raVAavZEEahPQ7mUVHxegfjgZCjaWA-UcSQ'
                                b'i5ic59-PKQ0tlEHlNHaeKIPts0lvONpW71dgOAgABHu-KLKX52wTZCwE4u_MEWrv'
                                b'PQ8kC_XSgzQ7Mqmrhv4imCCTaoiCCH2JbebIvfOHXlmwVwntz9B89qbf7SLT8BgA'
                                b'C5W2JKWRhhp6ZS8UQ0k_2-1-W0ZwgQAPDGDumFQ4CBTOH4srb4PVb5GCNx8Ygmpx'
                                b'OLplnVjVkkiQjKgLrHVvOBg')

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
                                  nsith=nxtsith,
                                  nkeys=[diger.qb64 for diger in digers],
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
                                  nsith=nxtsith,
                                  nkeys=[diger.qb64 for diger in digers],
                                  sn=wesK.sn + 1,
                                  data=[])

        sigers = wesMgr.sign(ser=wesSrdr.raw, verfers=verfers)

        msg = bytearray(wesSrdr.raw)
        counter = coring.Counter(coring.CtrDex.ControllerIdxSigs,
                                 count=len(sigers))
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        assert msg == bytearray(b'{"v":"KERI10JSON0002aa_","t":"rot","d":"EpaAOKbdwjjI7CAikCJDCr6r'
                                b'zmN14frB_cwif4MBnsTk","i":"EOsgPPbBijCbpu3R9N-TMdURgcoFqrjUf3rQi'
                                b'IaJ5L7M","s":"3","p":"EXlVGTrAuFlYjj1o1389Vfr1SecFYKJq4J9HkjlPyV'
                                b'qY","kt":["1/2","1/2","1/2"],"k":["D7WWKDLVwYxYMLAjDceIEs66xPMY4'
                                b'Afzx-RQw2x0mQzI","Dmg6Aah8qyKKDiQyNXTiO71QJwizjZfGM61BA-s0A5F4",'
                                b'"DS3fhKpvPCDL5WmfN4_PkmJMMsSCdRTxG24OQuf_EmHQ"],"nt":[["1/2","1/'
                                b'2","1/2"],["1/1","1/1"]],"n":["Ehru1umWyy696CK10v2ROEOv8csx-S4Kt'
                                b'YZHF4RbV3gc","EdsEn6HJLVLrhle11lqgImN0s7BQV03CfqxYpxs0qcrg","ED2'
                                b'DjOJWZyGUxGr_CFKA45dsmV72LvIvJWcB1xpuVGvM","EMwx5v3RMAjQ0GHdg5VR'
                                b'7XG2-2Cg4Kgslmn2lMCJ-oYs","EHN09tKWiJl83SPiBB_KDN1TKDutErXADGnl3'
                                b'TSx7ZLk"],"bt":"0","br":[],"ba":[],"a":[]}-AADAAHjkEbbFN_QkGinYu'
                                b'rCnQphjMOgfDdfuIyVNgn9krq-vYuJSlwhilVWquumLiJL7oCOJmF6aFDWcKKScN'
                                b'KiPHDgABQsjiEna5VZ7vE5ayRPswdjW2z19xRUyg4pktVGGw3yv9OvP6XUDRbvxU'
                                b's36hndwWE6y894bVbx5XUWWe5jDnCgACMMQCX8qjNcbHik2ukkv9mV45p3wgcxhu'
                                b'k_LMpXwt8KUT0eRwBHtnYuhFvXHYIDvaLTao4RxBg8AJhx8L-OdsDg')

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
                                  nsith=nxtsith,
                                  nkeys=[diger.qb64 for diger in digers],
                                  sn=wesK.sn + 1,
                                  data=[])

        sigers = wesMgr.sign(ser=wesSrdr.raw, verfers=verfers)

        msg = bytearray(wesSrdr.raw)
        counter = coring.Counter(coring.CtrDex.ControllerIdxSigs,
                                 count=len(sigers))
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        assert msg == bytearray(b'{"v":"KERI10JSON000318_","t":"rot","d":"EL9yfne-tGwzQvcwIBAEfLUb'
                                b'Vys6JF9ejzbd1mZmfKHc","i":"EOsgPPbBijCbpu3R9N-TMdURgcoFqrjUf3rQi'
                                b'IaJ5L7M","s":"4","p":"EpaAOKbdwjjI7CAikCJDCr6rzmN14frB_cwif4MBns'
                                b'Tk","kt":[["1/2","1/2","1/2"],["1/1","1/1"]],"k":["DToUWoemnetqJ'
                                b'oLFIqDI7lxIJEfF0W7xG5ZlqAseVUQc","Drz-IZjko61q-sPMDIW6n-0NGFubbX'
                                b'iZhzWZrO_BZ0Wc","DiGwL3hjQqiUgQlFPeA6kRR1EBXX0vSLm9b6QhPS8IkQ","'
                                b'Dxj5pcStgZ6CbQ2YktNaj8KLE_g9YAOZF6AL9fyLcWQw","DE5zr5eH8EUVQXyAa'
                                b'xWfQUWkGCId-QDCvvxMT77ibj2Q"],"nt":[["1/2","1/2","1/2"],["1/1","'
                                b'1/1"]],"n":["E3oSx8M1W9oMIqORgzoxTMtq4loSjOLs_IBYT7-IykMk","E1HU'
                                b'bg5n7JAOr8eSimUkgKNLZGuOoPFzuif3p8uSyxyc","E4uh2oW3SCRE09y8lkOXq'
                                b'T_bNwYyTxqi8azw2OP-USmc","ElNsZ_J-kqXAEfEqsQ_3nWXTg2v8oLHMzGbNFQ'
                                b'yq1bM4","EAu4l6xy-_8a_jaDhftZCN8jjus7h17BJVPc8L9naTHE"],"bt":"0"'
                                b',"br":[],"ba":[],"a":[]}-AAFAArIHrHuHj5D4H6y3lLMsFh3puF3r7iq5Loy'
                                b'at_UBNVrlxvdsawSfw2aaUGPewlIacEU4qmXE_jfnkkYuu9ILyAAABXdCyY-Lzp_'
                                b'erM6e75ucr69f543Z1B14siUu2VvNhmXDtg5oB7Huzk5R-pq51QwiokdEEKVnqfw'
                                b'UkDAFS8UGeAQACQ7LP-P8pvxjNTn-WI6p4mfUVk-yw321gyzoI9L2MKHtyLBm_NL'
                                b'86wqjXrhPHw8efeHMr7hYPf_om7YZ3RTJPDQADefKpouU2FmtypJV9QgJw4Jl7te'
                                b'ujJU-dsXlGdfdSVTRNIjv2RmGWuL0_r3F3pU4A_5ZVuOx7WjpHqwuh7gA0CwAEeR'
                                b'KbC2k_f7Im0HR7fqbLsaUvKMpF2Y14CYVKI-dabphSRRiB24_17hjSENPKO7t_4r'
                                b'7UTdxAqoTWUjCb1babCA')

        # apply msg to Wes's Kevery
        parsing.Parser().parse(ims=bytearray(msg), kvy=wesKvy)
        # wesKvy.process(ims=bytearray(msg))  # process local copy of msg
        assert wesK.serder.saider.qb64 == wesSrdr.said  # key state updated so event was validated

    assert not os.path.exists(wesKS.path)
    assert not os.path.exists(wesDB.path)

    """End Test"""


if __name__ == "__main__":
    test_weighted()

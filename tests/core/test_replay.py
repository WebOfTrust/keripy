# -*- encoding: utf-8 -*-
"""
tests delegation primaily from keri.core.eventing

"""
import os

import pytest

from keri import help
from keri.db import dbing
from keri.base import keeping
from keri.core import coring
from keri.core import eventing

logger = help.ogler.getLogger()


def test_replay():
    """
    Test conjoint replay

    """

    with dbing.openDB(name="eve") as eveDB, keeping.openKS(name="eve") as eveKS, \
         dbing.openDB(name="bob") as bobDB, keeping.openKS(name="bob") as bobKS:


        sith = ["1/2", "1/2", "1/2"]
        # setup bob  habitat has default salt
        bobHab = directing.Habitat(ks=bobKS, db=bobDB, sith=sith, count=3, temp=True)
        assert bobHab.ks == bobKS
        assert bobHab.db == bobDB
        assert bobHab.iserder.dig == bobSerder.dig
        assert bobHab.pre == bob

        self.sendOwnInception()  # Inception Event
        tyme = (yield (self.tock))

        msg = self.hab.interact()  # Interaction Event
        self.client.tx(msg)  # send to connected remote
        logger.info("%s sent event:\n%s\n\n", self.hab.pre, bytes(msg))
        tyme = (yield (self.tock))

        msg = self.hab.rotate()  # Rotation Event
        self.client.tx(msg)  # send to connected remote
        logger.info("%s sent event:\n%s\n\n", self.hab.pre, bytes(msg))
        tyme = (yield (self.tock))


        # create inception event for Wes with 3 keys each in incept and next sets
        # defaults are algo salty and rooted
        verfers, digers = wesMgr.incept(icount=3, ncount=3, stem='wes', temp=True)
        sith = ["1/2", "1/2", "1/2"]  #  2 of 3 but with weighted threshold
        nxtsith = ["1/2", "1/2", "1/2"]

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

        assert msg == bytearray(b'{"v":"KERI10JSON000154_","i":"EM8ac0UPJZCaWOw2uRcvx6FaygyxFvGzA5'
                                b'MTob9WfbDQ","s":"0","t":"icp","kt":["1/2","1/2","1/2"],"k":["DK4'
                                b'OJI8JOr6oEEUMeSF_X-SbKysfwpKwW-ho5KARvH5c","D1RZLgYke0GmfZm-CH8A'
                                b'sW4HoTU4m-2mFgu8kbwp8jQU","DBVwzum-jPfuUXUcHEWdplB4YcoL3BWGXK0TM'
                                b'oF_NeFU"],"n":"EhJGhyJQTpSlZ9oWfQT-lHNl1woMazLC42O89fRHocTI","wt'
                                b'":"0","w":[],"c":[]}-AADAAc4jIKyjjpK7rJzywkX2AXXaNGgUGfcUgT6fm7P'
                                b'iqL8H8tDsxHb6dcnybE7Hc34jtUq47OWWwCV3K9oCTUUAHAwABlP9qpCcMow8Lq5'
                                b'bzE-DLHlItNuQYD9SqOQDNyJoTpk_BEW6Q8UIG012MJEM7GoFTMV5H9UUztQfSQp'
                                b'l9Jh9lBQACVn_l3CTPIrCyGZpvW9qxVfZll0su-vIv1gvx0GQfo1qAMNk4c_7t-x'
                                b'bXKTw3hwDPt46m5zGd38Y3qIEwQD3jCA')

        # apply msg to Wes's Kevery
        wesKvy.process(ims=bytearray(msg))  # process local copy of msg
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

        assert msg == bytearray(b'{"v":"KERI10JSON000098_","i":"EM8ac0UPJZCaWOw2uRcvx6FaygyxFvGzA5'
                                b'MTob9WfbDQ","s":"1","t":"ixn","p":"E3-lhMd85oc8Uwrd_7c6xUy5tvZhr'
                                b'b9ZHvcOO4HxHB1c","a":[]}-AADAAWmzu83wDFTn9Hc6_xskGe8Ed_PhiOpVQ2H'
                                b'kxAx28qgLP_Zz7pwCsvmRDM1x9sL8Ygg7hQman5qDaeJS4fJm1DQABlc4hfziecy'
                                b'_DXVN2a8AttmuBL_Oh0-Ro_Rz3Mf6KWOJTMLQIHaRJ62L01Q5vP6KmiSr2zwJUT_'
                                b'urfGLZoaRUBwACt4l7pTFqmzfzk6p6FKlT1KGXYJ2ea2SmU7I-7agz0i4lCDNQf-'
                                b'Y_NJWs6NTWEs5vsPOskNcGnr8nIpQ51N1qBQ')

        # apply msg to wes's Kevery
        wesKvy.process(ims=bytearray(msg))  # process local copy of msg
        assert wesK.serder.diger.qb64 == wesSrdr.dig  # key state updated so event was validated

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
        counter = coring.Counter(coring.CtrDex.ControllerIdxSigs,
                                    count=len(sigers))
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        assert msg == bytearray(b'{"v":"KERI10JSON000190_","i":"EM8ac0UPJZCaWOw2uRcvx6FaygyxFvGzA5'
                                b'MTob9WfbDQ","s":"2","t":"rot","p":"E6wjlP_oqJzmo65d56XuTL602ABcK'
                                b'X0ZBEy9M-k7E1Eg","kt":["1/2","1/2","1/2"],"k":["DeonYM2bKnAwp6VZ'
                                b'cuCXdX72kNFw56czlZ_Tc7XHHVGI","DQghKIy-2do9OkweSgazh3Ql1vCOt5bnc'
                                b'5QF8x50tRoU","DNAUn-5dxm6b8Njo01O0jlStMRCjo9FYQA2mfqFW1_JA"],"n"'
                                b':"EX5fxvjOg5VuDboWbqnTjTPpXa3nNIm99hlsB1EmhTo8","wt":"0","wr":[]'
                                b',"wa":[],"a":[]}-AADAApZ3U4zacSPm5embDTRD2IxB1e4FrdAToP-tsXB-VVp'
                                b'fX6Yk78iIdFyeNi9U_sgefzvhR3_mH5Bj_ZlfpEMCQDAABWURvCkE1HjbE_noEqj'
                                b'BWEpdG1hUfP3_Oye5Ys0zquigDrOSv2ApXzlq1-ALDTZeqMX4lbVlqubRjDu3Qog'
                                b'xrAgACtyNpfXHvly2emXyAdJ5sAVUVCnodONK2CG8WGipISYLGIlyfmNoTVeHw-f'
                                b'_3ZY2tAgbmLZika4kEL8REfr5VCA')

        # apply msg to Wes's Kevery
        wesKvy.process(ims=bytearray(msg))  # process local copy of msg
        assert wesK.serder.diger.qb64 == wesSrdr.dig  # key state updated so event was validated

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
        counter = coring.Counter(coring.CtrDex.ControllerIdxSigs,
                                    count=len(sigers))
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        assert msg == bytearray(b'{"v":"KERI10JSON000190_","i":"EM8ac0UPJZCaWOw2uRcvx6FaygyxFvGzA5'
                                b'MTob9WfbDQ","s":"3","t":"rot","p":"E9tuWqXCN31LqElTSdfGp3lWDetle'
                                b'T4Pa9tuSUi2V87k","kt":["1/2","1/2","1/2"],"k":["D7WWKDLVwYxYMLAj'
                                b'DceIEs66xPMY4Afzx-RQw2x0mQzI","Dmg6Aah8qyKKDiQyNXTiO71QJwizjZfGM'
                                b'61BA-s0A5F4","DS3fhKpvPCDL5WmfN4_PkmJMMsSCdRTxG24OQuf_EmHQ"],"n"'
                                b':"EcM4iw7fElXWhad8V-za4Px7nBKjndxoh3XZRkohghKY","wt":"0","wr":[]'
                                b',"wa":[],"a":[]}-AADAAO0Ma_uiLbrXrqkNsLccCNgWcfvopoo2NwZ5aJLKBa9'
                                b'7OMuZibsiVL6bDues9r65o2Tq1hzuuQQK6cHg_OH3xDAAB-cLMTqhogxrxyhMVoP'
                                b'RXJ-rtQaV5oEsXSqcU3phI0bxFJvtydfnySe30LXbOwnFS-_HhCRMOulhBdcAvFR'
                                b'dKAAACXhumJPsAS1UWSjlKiSby_TCC_W82jkTcvWBB4pwrcYmno8jRpQoB0ubPyG'
                                b'96I2RqNql0Q9p5LcMPsLtT_Zt4DA')


        # apply msg to Wes's Kevery
        wesKvy.process(ims=bytearray(msg))  # process local copy of msg
        assert wesK.serder.diger.qb64 == wesSrdr.dig  # key state updated so event was validated

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
        counter = coring.Counter(coring.CtrDex.ControllerIdxSigs,
                                    count=len(sigers))
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        assert msg == bytearray(b'{"v":"KERI10JSON0001fe_","i":"EM8ac0UPJZCaWOw2uRcvx6FaygyxFvGzA5'
                                b'MTob9WfbDQ","s":"4","t":"rot","p":"EkBxzyMDQGRCNmoMOWwh58wuNuERR'
                                b'cLoMH2_F0w99Dw4","kt":[["1/2","1/2","1/2"],["1/1","1/1"]],"k":["'
                                b'DToUWoemnetqJoLFIqDI7lxIJEfF0W7xG5ZlqAseVUQc","Drz-IZjko61q-sPMD'
                                b'IW6n-0NGFubbXiZhzWZrO_BZ0Wc","DiGwL3hjQqiUgQlFPeA6kRR1EBXX0vSLm9'
                                b'b6QhPS8IkQ","Dxj5pcStgZ6CbQ2YktNaj8KLE_g9YAOZF6AL9fyLcWQw","DE5z'
                                b'r5eH8EUVQXyAaxWfQUWkGCId-QDCvvxMT77ibj2Q"],"n":"E3in3Z14va0kk4Wq'
                                b'd3vcCAojKNtQq7ZTrQaavR8x0yu4","wt":"0","wr":[],"wa":[],"a":[]}-A'
                                b'AFAAEjpPTMtLre--y96OaTckIov-qfWT1lqOvwNBAcdTfmsfCLIJgZO4Y2ybJqGw'
                                b'l2Q6DqLdfNQWHiDwnyllo1zZBgABny8aZlKENxCnulxSzSWIbFsg1Kv7RrdgTt4r'
                                b'19taFq-bmBmMTLrkidNbeMHwgsNhhT8f3KJnPTaHEZ2Myd3BDQACaJ2sc2SpEcM0'
                                b'9qMbk-8maWuxjAdMCb8n5P1vJesnf7TW6p3Vu2Mart5HuXW44r79DQ91sAmyYB_0'
                                b'4q--ZyNYAQAD5trFl0S9G0GQmFF7FCgMYWzKNe7x16622OvT1-HjDP-eXxf9dani'
                                b'dlUIbVWqalLgXOdhhsCNUDasvOHLByjSBgAEs-ovUeu2--2wnCJLpfHzLZUbc5fL'
                                b'8bpOShEoPUwxEH4H1Wxsn3xPlvL3_pe5Mun3sq2jIhl1EOjcDaKOHofZCA')

        # apply msg to Wes's Kevery
        wesKvy.process(ims=bytearray(msg))  # process local copy of msg
        assert wesK.serder.diger.qb64 == wesSrdr.dig  # key state updated so event was validated


    assert not os.path.exists(wesKS.path)
    assert not os.path.exists(wesDB.path)

    """End Test"""


if __name__ == "__main__":
    test_weighted()

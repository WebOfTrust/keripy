# -*- encoding: utf-8 -*-
"""
tests.peer.test_exchanging module

"""

from hio.base import doing
from hio.help import decking

from keri.app import keeping, habbing
from keri.core import coring, parsing, eventing
from keri.db import basing
from keri.peer import exchanging


def test_exchanger():
    """
    XXX Some assumptions here need to be updated since Habery creates all
    the shared resource dependencies
    """
    sidSalt = coring.Salter(raw=b'0123456789abcdef').qb64

    #with basing.openDB(name="sid") as sidDB, \
            #keeping.openKS(name="sid") as sidKS, \
            #basing.openDB(name="red") as redDB, \
            #keeping.openKS(name="red") as redKS:


    with habbing.openHby(name="sid", base="test", salt=sidSalt) as sidHby, \
         habbing.openHby(name="red", base="test") as redHby:

        limit = 1.0
        tock = 0.03125
        doist = doing.Doist(limit=limit, tock=tock)

        # should instead create sidHab here so can use it later more aligned with
        # normal use case

        # Init key pair managers XXX this may now be wrong use sidHby.mgr instead
        sidMgr = keeping.Manager(ks=sidHby.ks, salt=sidSalt)

        # Init Keverys
        sidKvy = eventing.Kevery(db=sidHby.db)
        redHab = redHby.makeHab(name='red')
        # redHab = habbing.Habitat(ks=redKS, db=redDB, temp=True)
        redKvy = eventing.Kevery(db=redHby.db)

        # Setup sid by creating inception event
        verfers, digers, cst, nst = sidMgr.incept(stem='sid', temp=True)  # algo default salty and rooted
        sidSrdr = eventing.incept(keys=[verfer.qb64 for verfer in verfers],
                                  nxt=coring.Nexter(digs=[diger.qb64 for diger in digers]).qb64,
                                  code=coring.MtrDex.Blake3_256)

        sidPre = sidSrdr.ked["i"]

        sidMgr.move(old=verfers[0].qb64, new=sidPre)  # move key pair label to prefix

        sigers = sidMgr.sign(ser=sidSrdr.raw, verfers=verfers)

        excMsg = bytearray(sidSrdr.raw)
        counter = coring.Counter(code=coring.CtrDex.ControllerIdxSigs,
                                 count=len(sigers))
        excMsg.extend(counter.qb64b)
        for siger in sigers:
            excMsg.extend(siger.qb64b)

        sidIcpMsg = excMsg  # save for later

        parsing.Parser().parse(ims=bytearray(sidIcpMsg), kvy=redKvy)
        assert redKvy.kevers[sidPre].sn == 0  # accepted event

        echo = EchoDoer(tymth=doist.tymen())
        redExc = exchanging.Exchanger(hby=redHby, tymth=doist.tymen(), handlers=[echo])

        pl = dict(x="y")
        sidExcSrdr = exchanging.exchange(route="/test/message", payload=pl)

        # Create exn message, sign it and attach Signer Seal
        sigers = sidMgr.sign(ser=sidExcSrdr.raw, verfers=verfers)

        excMsg = bytearray(sidExcSrdr.raw)
        excMsg.extend(coring.Counter(coring.CtrDex.TransLastIdxSigGroups, count=1).qb64b)
        excMsg.extend(sidPre.encode("utf-8"))
        counter = coring.Counter(code=coring.CtrDex.ControllerIdxSigs,
                                 count=len(sigers))
        excMsg.extend(counter.qb64b)
        for siger in sigers:
            excMsg.extend(siger.qb64b)

        parsing.Parser().parse(ims=bytearray(excMsg), kvy=redKvy, exc=redExc)

        doist.do(doers=[redExc])
        assert doist.tyme == limit

        resp = echo.cues.popleft()
        respSer = coring.Serder(raw=resp['rep'].raw)
        assert respSer.ked['t'] == coring.Ilks.exn
        assert respSer.ked['r'] == "/test/messageResp"
        assert respSer.ked['a'] == dict(req=pl)


class EchoDoer(doing.Doer):

    resource = "/test/message"

    def __init__(self, **kwa):

        self.msgs = decking.Deck()
        self.cues = decking.Deck()

        super(EchoDoer, self).__init__(**kwa)

    def do(self, tymth, tock=0.0, **opts):
        while True:
            while self.msgs:
                msg = self.msgs.popleft()
                payload = msg["payload"]
                pre = msg["pre"]
                verfers = msg["verfers"]
                sigers = msg["sigers"]

                assert payload == dict(x="y")
                assert pre.qb64 == "EtjehgJ3LiIcPUKIQy28zge56_B2lzdGGLwLpuRBkZ8w"
                assert len(verfers) == 1
                assert verfers[0].qb64 == "Djy1swBRlUIR5m16EUkc-Aj_WFCzAEbs0YpOh5IWt7kM"
                assert len(sigers) == 1

                self.cues.append(dict(rep=exchanging.exchange(route="/test/messageResp", payload=dict(req=payload))))
                yield
            yield


if __name__ == "__main__":
    test_exchanger()

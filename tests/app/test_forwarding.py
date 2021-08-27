# -*- encoding: utf-8 -*-
"""
KERI
tests.app.forwarding module


"""

import time

from hio.base import doing, tyming

from keri.app import forwarding, habbing, indirecting, storing
from keri.core import coring, eventing, parsing
from keri.peer import exchanging


def test_postman(mockGetWitnessByPrefixOneWitness):
    with habbing.openHab(name="test", transferable=True, temp=True) as hab, \
            habbing.openHab(name="wes", transferable=False, temp=True) as wesHab, \
            habbing.openHab(name="repTest", transferable=True, temp=True, wits=[wesHab.pre]) as recpHab:

        recpIcp = recpHab.makeOwnEvent(sn=0)
        wesKvy = eventing.Kevery(db=wesHab.db, lax=False, local=False)
        parsing.Parser().parse(ims=bytearray(recpIcp), kvy=wesKvy)
        assert recpHab.pre in wesKvy.kevers

        serder = coring.Serder(raw=recpIcp)
        rct = wesHab.receipt(serder)

        kvy = eventing.Kevery(db=hab.db)
        parsing.Parser().parseOne(bytearray(recpIcp), kvy=kvy)
        parsing.Parser().parseOne(bytearray(rct), kvy=kvy)
        kvy.processEscrows()
        assert recpHab.pre in kvy.kevers

        mbx = storing.Mailboxer(name="wes", temp=True)
        wesDoers = indirecting.setupWitness(name="wes", hab=wesHab, mbx=mbx, temp=True, tcpPort=5634, httpPort=5644)
        pman = forwarding.Postman(hab=hab)

        exn = exchanging.exchange(route="/echo", payload=dict(msg="test"))
        msg = bytearray(exn.raw)
        msg.extend(hab.sanction(exn))
        pman.send(recipient=recpHab.pre, topic="echo", msg=msg)

        doers = wesDoers + [pman]
        limit = 1.0
        tock = 0.03125
        doist = doing.Doist(tock=tock, limit=limit, doers=doers)
        doist.enter()

        tymer = tyming.Tymer(tymth=doist.tymen(), duration=doist.limit)

        while not tymer.expired:
            doist.recur()
            time.sleep(doist.tock)

        assert doist.limit == limit

        doist.exit()

        msgs = []
        for _, topic, msg in mbx.cloneTopicIter(topic=recpHab.pre + "/echo", fn=0):
            msgs.append(msg)

        assert len(msgs) == 1
        serder = coring.Serder(raw=msgs[0])
        assert serder.ked["t"] == coring.Ilks.exn
        assert serder.ked["r"] == "/echo"
        assert serder.ked["d"] == dict(msg="test")


def test_forward():
    recp = "E55b5PtyJY2UWHnTx7ruRdi60i7WovIa7vocO9REpVZA"
    exn = exchanging.exchange(route="/echo", payload=dict(msg="test"))

    fwd = forwarding.forward(pre=recp, serder=exn)
    assert fwd.ked["t"] == coring.Ilks.fwd
    assert fwd.ked["r"] == recp

    ked = fwd.ked["a"]
    assert ked == exn.ked

    pre = "BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc"
    icp = eventing.incept(keys=[pre])
    fwd = forwarding.forward(pre=recp, serder=icp)
    assert fwd.ked["t"] == coring.Ilks.fwd
    assert fwd.ked["r"] == recp

    ked = fwd.ked["a"]
    assert ked == icp.ked


    with habbing.openHab(name="test", transferable=True, temp=True) as hab:
        icp = hab.makeOwnEvent(sn=0)
        serder = coring.Serder(raw=bytearray(icp))

        fwd = forwarding.forward(pre=recp, serder=serder)
        assert fwd.ked["t"] == coring.Ilks.fwd
        assert fwd.ked["r"] == recp

        ked = fwd.ked["a"]
        assert ked == serder.ked

        rot = hab.rotate()
        serder = coring.Serder(raw=bytearray(rot))

        fwd = forwarding.forward(pre=recp, serder=serder)
        assert fwd.ked["t"] == coring.Ilks.fwd
        assert fwd.ked["r"] == recp

        ked = fwd.ked["a"]
        assert ked == serder.ked

        ixn = hab.interact(data=dict(d=recp))
        serder = coring.Serder(raw=bytearray(ixn))

        fwd = forwarding.forward(pre=recp, serder=serder)
        assert fwd.ked["t"] == coring.Ilks.fwd
        assert fwd.ked["r"] == recp

        ked = fwd.ked["a"]
        assert ked == serder.ked








if __name__ == '__main__':
    test_postman()
    test_forward()


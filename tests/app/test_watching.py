# -*- encoding: utf-8 -*-
"""
tests.app.watching module

"""
from hio.base import doing
from keri.app import habbing, watching
from keri.core import eventing, parsing, coring
from keri.peer import exchanging


def test_watcher_rotate_handler():
    with habbing.openHab(name="watcher", transferable=False, temp=True) as wat, \
            habbing.openHab(name="ctrl", transferable=True, temp=True) as hab:

        watKvy = eventing.Kevery(db=wat.db)
        ctrlIcp = hab.makeOwnEvent(sn=0)
        parsing.Parser().parse(ims=bytearray(ctrlIcp), kvy=watKvy)
        assert wat.pre == "BZg042qyBYoNC4rII1qdn7sPJPSh5vp5y0xnVYbJPujw"


        rotateHandler = watching.RotateIdentifierHandler(hab=wat)
        exchanger = exchanging.Exchanger(hab=wat, controller=hab.pre, handlers=[rotateHandler])

        exn = exchanging.exchange("/cmd/watcher/rotate", payload=dict())

        sigers = hab.mgr.sign(ser=exn.raw, verfers=hab.kever.verfers)

        exchanger.processEvent(exn, hab.kever.prefixer, sigers)

        msgDo = doing.doify(rotateHandler.msgDo)
        doer = msgDo()
        while not rotateHandler.reps:
            try:
                next(doer)
            except StopIteration:
                break

        rep = rotateHandler.reps.popleft()
        dest = rep["dest"]
        msg = rep["msg"]

        cue = coring.Serder(raw=msg)
        assert cue.ked["t"] == "fwd"
        assert cue.ked['r'] == "EXVHM9bcTrQS0uOGCRPPQCHZGghFAs2tvUQbYt4_nnT4"

        exn = coring.Serder(ked=cue.ked["a"])
        assert dest == "EXVHM9bcTrQS0uOGCRPPQCHZGghFAs2tvUQbYt4_nnT4"
        assert exn.ked["t"] == "exn"
        assert exn.ked['r'] == "/cmd/watcher/rotate"

        data = exn.ked["d"]
        icp = data["icp"]

        ctrlKvy = eventing.Kevery(db=hab.db)
        parsing.Parser().parse(ims=bytearray(icp.encode("utf-8")), kvy=ctrlKvy)

        assert wat.pre in ctrlKvy.kevers

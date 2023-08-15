# -*- encoding: utf-8 -*-
"""
tests.app.messaging module

"""
import time

from hio.base import doing, tyming

from keri.app import habbing, messaging
from keri.core import parsing
from keri.core.coring import MtrDex
from keri.peer import exchanging
from keri.vdr import eventing


def test_messagenger():
    with habbing.openHab(name="test0", temp=True) as (hby, hab):

        msgr = messaging.Messager(name=hab.name, temp=True)
        recp = "EfrzbTSWjccrTdNRsFUUfwaJ2dpYxu9_5jI2PJ-TRri0"
        regser = eventing.incept(hab.pre,
                                 baks=[],
                                 toad=0,
                                 cnfg=[],
                                 code=MtrDex.Blake3_256)

        data = dict(
            vcp=hab.endorse(regser, pipelined=False)
        )
        exn, atc = messaging.instantMessageExn(hab=hab,
                                               recipient=recp,
                                               subject="Credential Registry Inception",
                                               body="Attached is the credential registry to create",
                                               labels=["multisig", "registry/incept"],
                                               attachments=data)

        print(exn.pretty())

        exc = exchanging.Exchanger(db=hby.db, handlers=[])
        messaging.loadHandlers(hby=hby, exc=exc, msgr=msgr)

        ims = bytearray(exn.raw)
        ims.extend(atc)
        parsing.Parser().parseOne(ims=ims, exc=exc)

        limit = 0.5
        tock = 0.03125
        doist = doing.Doist(tock=tock, limit=limit, doers=[exc])
        doist.enter()

        tymer = tyming.Tymer(tymth=doist.tymen(), duration=doist.limit)

        while not tymer.expired:
            doist.recur()
            time.sleep(doist.tock)

        assert doist.limit == limit
        doist.exit()

        assert msgr.mexns.get(keys=(exn.said,)) is not None





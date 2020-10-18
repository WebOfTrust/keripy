# -*- encoding: utf-8 -*-
"""
tests.db.dbing module

"""
import pytest

import os

from hio.base import doing
from hio.core.tcp import clienting, serving

from keri.demo import demoing, directmode
from keri.db import dbing
from keri.core import eventing

def test_directmode():
    """
    Test directmode demo
    """
    with dbing.openLogger(name="eve") as eveDB, \
         dbing.openLogger(name="bob") as bobDB:

        limit = 0.25
        tock = 0.03125
        doist = doing.Doist(limit=limit, tock=tock)

        server = serving.Server(tymist=doist, host="", port=5620)
        serverd = doing.ServerDoer(server=server)
        eveKvy = eventing.Kevery(logger=eveDB)
        eve = directmode.ServerDirector(name='eve', kevery=eveKvy, server=server)

        client = clienting.Client(tymist=doist, host='127.0.0.1', port=5620)
        clientd = doing.ClientDoer(client=client)
        bobKvy = eventing.Kevery(logger=bobDB)
        bob = directmode.ClientDirector(name='bob', kevery=bobKvy, client=client)

        msgTx = b"Hi Eve its Bob"
        bob.client.tx(msgTx)

        doers = [serverd, clientd, eve, bob]
        doist.do(doers=doers)
        assert doist.tyme == limit

        assert eve.server.opened == False
        assert bob.client.opened == False

        assert not bob.client.txes
        ca, ix = list(eve.server.ixes.items())[0]
        msgRx = bytes(ix.rxbs)
        assert msgRx == msgTx

    assert not os.path.exists(eveDB.path)
    assert not os.path.exists(bobDB.path)


    """End Test"""


if __name__ == "__main__":
    test_directmode()

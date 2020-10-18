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
        serDoer = doing.ServerDoer(server=server)
        eveKevers = dict()
        eveD = directmode.ServerDirector(kevers=eveKevers, db=eveDB, name='eve', server=server)
        assert eveD.kevery.kevers == eveKevers
        assert eveD.kevery.logger == eveDB
        eveR = directmode.ServerReactant(kevers=eveKevers, db=eveDB, name='eve', server=server)
        assert eveR.kevery.kevers == eveKevers
        assert eveR.kevery.logger == eveDB

        client = clienting.Client(tymist=doist, host='127.0.0.1', port=5620)
        cliDoer = doing.ClientDoer(client=client)
        bobKevers = dict()
        bobD = directmode.ClientDirector(kevers=bobKevers, db=bobDB, name='bob', client=client)
        assert bobD.kevery.kevers == bobKevers
        assert bobD.kevery.logger == bobDB
        bobR = directmode.ClientReactant(kevers=bobKevers, db=bobDB, name='bob', client=client)
        assert bobR.kevery.kevers == bobKevers
        assert bobR.kevery.logger == bobDB

        msgTx = b"Hi Eve its Bob"
        bobD.client.tx(msgTx)

        doers = [serDoer, cliDoer, eveR, bobR, eveD, bobD]
        doist.do(doers=doers)
        assert doist.tyme == limit

        assert eveD.server.opened == False
        assert bobD.client.opened == False

        assert not bobD.client.txes
        ca, ix = list(eveD.server.ixes.items())[0]
        msgRx = bytes(ix.rxbs)
        assert msgRx == msgTx

    assert not os.path.exists(eveDB.path)
    assert not os.path.exists(bobDB.path)


    """End Test"""


if __name__ == "__main__":
    test_directmode()

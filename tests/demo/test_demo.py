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
from keri.core import eventing, coring

def test_directmode():
    """
    Test directmode demo


    """


    # set of secrets  (seeds for private keys)
    bobSecrets = [
                'ArwXoACJgOleVZ2PY7kXn7rA0II0mHYDhc6WrBH8fDAc',
                'A6zz7M08-HQSFq92sJ8KJOT2cZ47x7pXFQLPB0pckB3Q',
                'AcwFTk-wgk3ZT2buPRIbK-zxgPx-TKbaegQvPEivN90Y',
                'Alntkt3u6dDgiQxTATr01dy8M72uuaZEf9eTdM-70Gk8',
                'A1-QxDkso9-MR1A8rZz_Naw6fgaAtayda8hrbkRVVu1E',
                'AKuYMe09COczwf2nIoD5AE119n7GLFOVFlNLxZcKuswc',
                'AxFfJTcSuEE11FINfXMqWttkZGnUZ8KaREhrnyAXTsjw',
                'ALq-w1UKkdrppwZzGTtz4PWYEeWm0-sDHzOv5sq96xJY'
                ]

    #  create bob signers
    bobSigners = [coring.Signer(qb64=secret) for secret in bobSecrets]
    assert [signer.qb64 for signer in bobSigners] == bobSecrets

    # bob inception transferable (nxt digest not empty)
    bobSerder = eventing.incept(keys=[bobSigners[0].verfer.qb64],
                                nxt=coring.Nexter(keys=[bobSigners[1].verfer.qb64]).qb64,
                                code=coring.CryOneDex.Blake3_256)

    bob = bobSerder.ked['pre']
    assert bob == 'ETT9n-TCGn8XfkGkcNeNmZgdZSwHPLyDsojFXotBXdSo'


    # set of secrets (seeds for private keys)
    eveSecrets = ['AgjD4nRlycmM5cPcAkfOATAp8wVldRsnc9f1tiwctXlw',
                  'AKUotEE0eAheKdDJh9QvNmSEmO_bjIav8V_GmctGpuCQ',
                  'AK-nVhMMJciMPvmF5VZE_9H-nhrgng9aJWf7_UHPtRNM',
                  'AT2cx-P5YUjIw_SLCHQ0pqoBWGk9s4N1brD-4pD_ANbs',
                  'Ap5waegfnuP6ezC18w7jQiPyQwYYsp9Yv9rYMlKAYL8k',
                  'Aqlc_FWWrxpxCo7R12uIz_Y2pHUH2prHx1kjghPa8jT8',
                  'AagumsL8FeGES7tYcnr_5oN6qcwJzZfLKxoniKUpG4qc',
                  'ADW3o9m3udwEf0aoOdZLLJdf1aylokP0lwwI_M2J9h0s']

    #  create eve signers
    eveSigners = [coring.Signer(qb64=secret) for secret in eveSecrets]
    assert [signer.qb64 for signer in eveSigners] == eveSecrets

    # eve inception transferable (nxt digest not empty)
    eveSerder = eventing.incept(keys=[eveSigners[0].verfer.qb64],
                                nxt=coring.Nexter(keys=[eveSigners[1].verfer.qb64]).qb64,
                                code=coring.CryOneDex.Blake3_256)

    eve = eveSerder.ked['pre']
    assert eve == 'EwBwUb2eZcA5GDcN7g-87wpreM0nNkLqzkwviBHTcV1A'



    with dbing.openLogger(name="eve") as eveDB, \
         dbing.openLogger(name="bob") as bobDB:

        limit = 0.25
        tock = 0.03125
        doist = doing.Doist(limit=limit, tock=tock)


        client = clienting.Client(tymist=doist, host='127.0.0.1', port=5620)
        cliDoer = doing.ClientDoer(client=client)
        bobKevers = dict()
        bobD = directmode.ClientDirector(pre=bob, kevers=bobKevers, db=bobDB, client=client)
        assert bobD.kevery.kevers == bobKevers
        assert bobD.kevery.logger == bobDB
        bobR = directmode.ClientReactant(pre=bob, kevers=bobKevers, db=bobDB, client=client)
        assert bobR.kevery.kevers == bobKevers
        assert bobR.kevery.logger == bobDB

        server = serving.Server(tymist=doist, host="", port=5620)
        serDoer = doing.ServerDoer(server=server)
        eveKevers = dict()
        eveD = directmode.ServerDirector(pre=eve, kevers=eveKevers, db=eveDB, server=server)
        eveR = directmode.ServerReactant(pre=eve, kevers=eveKevers, db=eveDB, server=server)



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

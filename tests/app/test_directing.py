# -*- encoding: utf-8 -*-
"""
tests.db.dbing module

"""

import logging
import os

from hio.base import doing
from hio.core.tcp import clienting, serving

from keri import help  # logger support
from keri.app import habbing, directing
from keri.core import eventing, coring
from keri.demo import demoing


def test_directing_basic():
    """
    Test directing
    """
    help.ogler.resetLevel(level=logging.INFO)

    # set of secrets  (seeds for private keys)
    bobSecrets = ['AAwXoACJgOleVZ2PY7kXn7rA0II0mHYDhc6WrBH8fDAc',
                'ABzz7M08-HQSFq92sJ8KJOT2cZ47x7pXFQLPB0pckB3Q',
                'ACwFTk-wgk3ZT2buPRIbK-zxgPx-TKbaegQvPEivN90Y',
                'ADntkt3u6dDgiQxTATr01dy8M72uuaZEf9eTdM-70Gk8',
                'AE-QxDkso9-MR1A8rZz_Naw6fgaAtayda8hrbkRVVu1E',
                'AFuYMe09COczwf2nIoD5AE119n7GLFOVFlNLxZcKuswc',
                'AGFfJTcSuEE11FINfXMqWttkZGnUZ8KaREhrnyAXTsjw',
                'AHq-w1UKkdrppwZzGTtz4PWYEeWm0-sDHzOv5sq96xJY']

    bobSecrecies = []
    for secret in bobSecrets:  # convert secrets to secrecies
        bobSecrecies.append([secret])

    #  create bob signers
    bobSigners = [coring.Signer(qb64=secret) for secret in bobSecrets]
    assert [signer.qb64 for signer in bobSigners] == bobSecrets

    # bob inception transferable (nxt digest not empty)
    bobSerder = eventing.incept(keys=[bobSigners[0].verfer.qb64],
                                nkeys=[coring.Diger(ser=bobSigners[1].verfer.qb64b).qb64],
                                code=coring.MtrDex.Blake3_256)

    bob = bobSerder.ked["i"]
    assert bob == 'EJ0494QCl_MPxeIbOEJpcChHkqzlS9J6Vufp2sbAptI_'

    # set of secrets (seeds for private keys)
    eveSecrets = ['AAjD4nRlycmM5cPcAkfOATAp8wVldRsnc9f1tiwctXlw',
                  'ABUotEE0eAheKdDJh9QvNmSEmO_bjIav8V_GmctGpuCQ',
                  'AC-nVhMMJciMPvmF5VZE_9H-nhrgng9aJWf7_UHPtRNM',
                  'AD2cx-P5YUjIw_SLCHQ0pqoBWGk9s4N1brD-4pD_ANbs',
                  'AE5waegfnuP6ezC18w7jQiPyQwYYsp9Yv9rYMlKAYL8k',
                  'AFlc_FWWrxpxCo7R12uIz_Y2pHUH2prHx1kjghPa8jT8',
                  'AGgumsL8FeGES7tYcnr_5oN6qcwJzZfLKxoniKUpG4qc',
                  'AHW3o9m3udwEf0aoOdZLLJdf1aylokP0lwwI_M2J9h0s']

    eveSecrecies = []
    for secret in eveSecrets:  # convert secrets to secrecies
        eveSecrecies.append([secret])

    #  create eve signers
    eveSigners = [coring.Signer(qb64=secret) for secret in eveSecrets]
    assert [signer.qb64 for signer in eveSigners] == eveSecrets

    # eve inception transferable (nxt digest not empty)
    eveSerder = eventing.incept(keys=[eveSigners[0].verfer.qb64],
                                nkeys=[coring.Diger(ser=eveSigners[1].verfer.qb64b).qb64],
                                code=coring.MtrDex.Blake3_256)

    eve = eveSerder.ked["i"]
    assert eve == 'EKVW3Gh4ZVYeLBaMmE6E_NhVr5iOTiwjKrkclkoR_Gya'

    with habbing.openHby(name="eve", base="test") as eveHby, \
            habbing.openHby(name="bob", base="test") as bobHby:

        limit = 1.0
        tock = 0.03125
        doist = doing.Doist(limit=limit, tock=tock)

        bobPort = 5620  # bob's TCP listening port for server
        evePort = 5621  # eve's TCP listneing port for server

        # setup bob
        bobHab = bobHby.makeHab(name="Bob", secrecies=bobSecrecies)
        assert bobHab.iserder.said == bobSerder.said
        assert bobHab.pre == bob

        bobClient = clienting.Client(tymth=doist.tymen(), host='127.0.0.1', port=evePort)
        bobClientDoer = clienting.ClientDoer(tymth=doist.tymen(), client=bobClient)

        bobDirector = directing.Director(hab=bobHab, client=bobClient)
        assert bobDirector.hab == bobHab
        assert bobDirector.client == bobClient
        assert id(bobDirector.hab.kvy.kevers) == id(bobHab.kevers)
        assert bobDirector.hab.kvy.db == bobHby.db

        bobReactor = directing.Reactor(hab=bobHab, client=bobClient)
        assert bobReactor.hab == bobHab
        assert bobReactor.client == bobClient
        assert id(bobReactor.hab.kvy.kevers) == id(bobHab.kevers)
        assert bobReactor.hab.kvy.db == bobHby.db
        assert id(bobReactor.parser.ims) == id(bobReactor.client.rxbs)
        assert id(bobReactor.client.rxbs) == id(bobDirector.client.rxbs)

        bobServer = serving.Server(host="", port=bobPort)
        bobServerDoer = serving.ServerDoer(server=bobServer)

        bobDirectant = directing.Directant(hab=bobHab, server=bobServer)
        assert bobDirectant.hab == bobHab
        assert bobDirectant.server == bobServer
        # Bob's Reactants created on demand

        # setup eve
        eveHab = eveHby.makeHab(name="Eve", secrecies=eveSecrecies)
        print(eveHab.iserder.pretty())
        print(eveSerder.pretty())
        assert eveHab.iserder.said == eveSerder.said
        assert eveHab.pre == eve

        eveClient = clienting.Client(tymth=doist.tymen(), host='127.0.0.1', port=bobPort)
        eveClientDoer = clienting.ClientDoer(tymth=doist.tymen(), client=eveClient)

        eveDirector = directing.Director(hab=eveHab, client=eveClient)
        assert eveDirector.hab == eveHab
        assert eveDirector.client == eveClient
        assert id(eveDirector.hab.kvy.kevers) == id(eveHab.kevers)
        assert eveDirector.hab.kvy.db == eveHby.db

        eveReactor = directing.Reactor(hab=eveHab, client=eveClient)
        assert eveReactor.hab == eveHab
        assert eveReactor.client == eveClient
        assert id(eveReactor.hab.kvy.kevers) == id(eveHab.kevers)
        assert eveReactor.hab.kvy.db == eveHby.db
        assert id(eveReactor.parser.ims) == id(eveReactor.client.rxbs)
        assert id(eveReactor.client.rxbs) == id(eveDirector.client.rxbs)

        eveServer = serving.Server(host="", port=evePort)
        eveServerDoer = serving.ServerDoer(server=eveServer)

        eveDirectant = directing.Directant(hab=eveHab, server=eveServer)
        assert eveDirectant.hab == eveHab
        assert eveDirectant.server == eveServer
        # Eve's Reactants created on demand

        bobMsgTx = b"Hi Eve I am  Bob"
        bobDirector.client.tx(bobMsgTx)

        eveMsgTx = b"Hi Bob its me Eve"
        eveDirector.client.tx(eveMsgTx)

        doers = [bobClientDoer, bobDirector, bobReactor, bobServerDoer, bobDirectant,
                 eveClientDoer, eveDirector, eveReactor, eveServerDoer, eveDirectant]
        doist.do(doers=doers)
        assert doist.tyme == limit

        assert bobClient.opened is False
        assert bobServer.opened is False
        assert eveClient.opened is False
        assert eveServer.opened is False

        assert not bobClient.txbs
        ca, ix = list(eveServer.ixes.items())[0]
        eveMsgRx = bytes(ix.rxbs)  # ColdStart Error flushes buffer
        assert eveMsgRx == b''
        # assert eveMsgRx == bobMsgTx

        assert not eveClient.txbs
        ca, ix = list(bobServer.ixes.items())[0]
        bobMsgRx = bytes(ix.rxbs)  # ColdStart Error flushes buffer
        assert bobMsgRx == b''
        # assert bobMsgRx == eveMsgTx

    assert not os.path.exists(eveHby.db.path)
    assert not os.path.exists(bobHby.db.path)

    help.ogler.resetLevel(level=help.ogler.level)
    """End Test"""


def test_runcontroller_demo():
    """
    Test demo runController function
    """
    help.ogler.resetLevel(level=logging.DEBUG)

    name = "bob"
    remote = 5621
    local = 5620
    expire = 1.0

    secrets = [
        'AAwXoACJgOleVZ2PY7kXn7rA0II0mHYDhc6WrBH8fDAc',
        'ABzz7M08-HQSFq92sJ8KJOT2cZ47x7pXFQLPB0pckB3Q',
        'ACwFTk-wgk3ZT2buPRIbK-zxgPx-TKbaegQvPEivN90Y',
        'ADntkt3u6dDgiQxTATr01dy8M72uuaZEf9eTdM-70Gk8',
        'AE-QxDkso9-MR1A8rZz_Naw6fgaAtayda8hrbkRVVu1E',
        'AFuYMe09COczwf2nIoD5AE119n7GLFOVFlNLxZcKuswc',
        'AGFfJTcSuEE11FINfXMqWttkZGnUZ8KaREhrnyAXTsjw',
        'AHq-w1UKkdrppwZzGTtz4PWYEeWm0-sDHzOv5sq96xJY'
    ]

    doers = demoing.setupDemoController(secrets=secrets,
                                        name=name,
                                        remotePort=remote,
                                        localPort=local)

    directing.runController(doers=doers, expire=expire)

    help.ogler.resetLevel(level=help.ogler.level)
    """End Test"""


if __name__ == "__main__":
    test_directing_basic()

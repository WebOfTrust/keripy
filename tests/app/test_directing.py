# -*- encoding: utf-8 -*-
"""
tests.db.dbing module

"""

import logging
import os

from hio.base import doing
from hio.core.tcp import clienting, serving

from keri import help  # logger support
from keri.app import habbing, keeping, directing
from keri.core import eventing, coring
from keri.db import dbing, basing
from keri.demo import demoing


def test_directing_basic():
    """
    Test directing
    """
    help.ogler.resetLevel(level=logging.INFO)

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

    bobSecrecies = []
    for secret in bobSecrets:  # convert secrets to secrecies
        bobSecrecies.append([secret])

    #  create bob signers
    bobSigners = [coring.Signer(qb64=secret) for secret in bobSecrets]
    assert [signer.qb64 for signer in bobSigners] == bobSecrets

    # bob inception transferable (nxt digest not empty)
    bobSerder = eventing.incept(keys=[bobSigners[0].verfer.qb64],
                                nxt=coring.Nexter(keys=[bobSigners[1].verfer.qb64]).qb64,
                                code=coring.MtrDex.Blake3_256)

    bob = bobSerder.ked["i"]
    assert bob == 'EsZuhYAPBDnexP3SOl9YsGvWBrYkjYcRjomUYmCcLAYY'

    # set of secrets (seeds for private keys)
    eveSecrets = ['AgjD4nRlycmM5cPcAkfOATAp8wVldRsnc9f1tiwctXlw',
                  'AKUotEE0eAheKdDJh9QvNmSEmO_bjIav8V_GmctGpuCQ',
                  'AK-nVhMMJciMPvmF5VZE_9H-nhrgng9aJWf7_UHPtRNM',
                  'AT2cx-P5YUjIw_SLCHQ0pqoBWGk9s4N1brD-4pD_ANbs',
                  'Ap5waegfnuP6ezC18w7jQiPyQwYYsp9Yv9rYMlKAYL8k',
                  'Aqlc_FWWrxpxCo7R12uIz_Y2pHUH2prHx1kjghPa8jT8',
                  'AagumsL8FeGES7tYcnr_5oN6qcwJzZfLKxoniKUpG4qc',
                  'ADW3o9m3udwEf0aoOdZLLJdf1aylokP0lwwI_M2J9h0s']

    eveSecrecies = []
    for secret in eveSecrets:  # convert secrets to secrecies
        eveSecrecies.append([secret])

    #  create eve signers
    eveSigners = [coring.Signer(qb64=secret) for secret in eveSecrets]
    assert [signer.qb64 for signer in eveSigners] == eveSecrets

    # eve inception transferable (nxt digest not empty)
    eveSerder = eventing.incept(keys=[eveSigners[0].verfer.qb64],
                                nxt=coring.Nexter(keys=[eveSigners[1].verfer.qb64]).qb64,
                                code=coring.MtrDex.Blake3_256)

    eve = eveSerder.ked["i"]
    assert eve == 'E7pB5IKuaYh3aIWKxtexyYFhpSjDNTEGSQuxeJbWiylg'

    with basing.openDB(name="eve") as eveDB, keeping.openKS(name="eve") as eveKS, \
            basing.openDB(name="bob") as bobDB, keeping.openKS(name="bob") as bobKS:

        limit = 0.125
        tock = 0.03125
        doist = doing.Doist(limit=limit, tock=tock)

        bobPort = 5620  # bob's TCP listening port for server
        evePort = 5621  # eve's TCP listneing port for server
        eveKevers = dict()

        # setup bob
        bobHab = habbing.Habitat(ks=bobKS, db=bobDB, secrecies=bobSecrecies,
                                 temp=True)
        assert bobHab.ks == bobKS
        assert bobHab.db == bobDB
        assert bobHab.iserder.said == bobSerder.said
        assert bobHab.pre == bob

        bobClient = clienting.Client(tymth=doist.tymen(), host='127.0.0.1', port=evePort)
        bobClientDoer = clienting.ClientDoer(tymth=doist.tymen(), client=bobClient)

        bobDirector = directing.Director(hab=bobHab, client=bobClient)
        assert bobDirector.hab == bobHab
        assert bobDirector.client == bobClient
        assert id(bobDirector.hab.kvy.kevers) == id(bobHab.kevers)
        assert bobDirector.hab.kvy.db == bobDB

        bobReactor = directing.Reactor(hab=bobHab, client=bobClient)
        assert bobReactor.hab == bobHab
        assert bobReactor.client == bobClient
        assert id(bobReactor.hab.kvy.kevers) == id(bobHab.kevers)
        assert bobReactor.hab.kvy.db == bobDB
        assert id(bobReactor.parser.ims) == id(bobReactor.client.rxbs)
        assert id(bobReactor.client.rxbs) == id(bobDirector.client.rxbs)

        bobServer = serving.Server(host="", port=bobPort)
        bobServerDoer = serving.ServerDoer(server=bobServer)

        bobDirectant = directing.Directant(hab=bobHab, server=bobServer)
        assert bobDirectant.hab == bobHab
        assert bobDirectant.server == bobServer
        # Bob's Reactants created on demand

        # setup eve
        eveHab = habbing.Habitat(ks=eveKS, db=eveDB, secrecies=eveSecrecies,
                                 temp=True)
        assert eveHab.ks == eveKS
        assert eveHab.db == eveDB
        assert eveHab.iserder.said == eveSerder.said
        assert eveHab.pre == eve

        eveClient = clienting.Client(tymth=doist.tymen(), host='127.0.0.1', port=bobPort)
        eveClientDoer = clienting.ClientDoer(tymth=doist.tymen(), client=eveClient)

        eveDirector = directing.Director(hab=eveHab, client=eveClient)
        assert eveDirector.hab == eveHab
        assert eveDirector.client == eveClient
        assert id(eveDirector.hab.kvy.kevers) == id(eveHab.kevers)
        assert eveDirector.hab.kvy.db == eveDB

        eveReactor = directing.Reactor(hab=eveHab, client=eveClient)
        assert eveReactor.hab == eveHab
        assert eveReactor.client == eveClient
        assert id(eveReactor.hab.kvy.kevers) == id(eveHab.kevers)
        assert eveReactor.hab.kvy.db == eveDB
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

        assert bobClient.opened == False
        assert bobServer.opened == False
        assert eveClient.opened == False
        assert eveServer.opened == False

        assert not bobClient.txbs
        ca, ix = list(eveServer.ixes.items())[0]
        eveMsgRx = bytes(ix.rxbs)  # ColdStart Error fluhes buffer
        assert eveMsgRx == b''
        # assert eveMsgRx == bobMsgTx

        assert not eveClient.txbs
        ca, ix = list(bobServer.ixes.items())[0]
        bobMsgRx = bytes(ix.rxbs)  # ColdStart Error fluhes buffer
        assert bobMsgRx == b''
        # assert bobMsgRx == eveMsgTx

    assert not os.path.exists(eveDB.path)
    assert not os.path.exists(bobDB.path)

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
        'ArwXoACJgOleVZ2PY7kXn7rA0II0mHYDhc6WrBH8fDAc',
        'A6zz7M08-HQSFq92sJ8KJOT2cZ47x7pXFQLPB0pckB3Q',
        'AcwFTk-wgk3ZT2buPRIbK-zxgPx-TKbaegQvPEivN90Y',
        'Alntkt3u6dDgiQxTATr01dy8M72uuaZEf9eTdM-70Gk8',
        'A1-QxDkso9-MR1A8rZz_Naw6fgaAtayda8hrbkRVVu1E',
        'AKuYMe09COczwf2nIoD5AE119n7GLFOVFlNLxZcKuswc',
        'AxFfJTcSuEE11FINfXMqWttkZGnUZ8KaREhrnyAXTsjw',
        'ALq-w1UKkdrppwZzGTtz4PWYEeWm0-sDHzOv5sq96xJY'
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

# -*- encoding: utf-8 -*-
"""
tests.db.dbing module

"""
import pytest

import os
import logging

from hio.help import ogling
from hio.base import doing
from hio.core.tcp import clienting, serving

from keri.base import directing, keeping
from keri.db import dbing
from keri.core import eventing, coring
from keri.demo import demoing

from keri import help  # logger support



def test_direct_mode_bob_eve_demo():
    """
    Test direct mode bob and eve
    """
    help.ogler.resetLevel(level=logging.DEBUG)

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
    assert bob == 'EH7Oq9oxCgYa-nnNLvwhp9sFZpALILlRYyB-6n4WDi7w'


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
    assert eve == 'EpDA1n-WiBA0A8YOqnKrB-wWQYYC49i5zY_qrIZIicQg'

    with dbing.openDB(name="eve") as eveDB, keeping.openKS(name="eve") as eveKS, \
         dbing.openDB(name="bob") as bobDB, keeping.openKS(name="bob") as bobKS:

        bobPort = 5620  # bob's TCP listening port for server
        evePort = 5621  # eve's TCP listneing port for server
        bobKevers = dict()
        eveKevers = dict()

        # setup bob
        bobHab = directing.Habitat(ks=bobKS, db=bobDB, kevers=bobKevers,
                                   secrecies=bobSecrecies, temp=True)
        assert bobHab.ks == bobKS
        assert bobHab.db == bobDB
        assert bobHab.iserder.dig == bobSerder.dig
        assert bobHab.pre == bob

        bobClient = clienting.Client(host='127.0.0.1', port=evePort)
        bobClientDoer = doing.ClientDoer(client=bobClient)

        bobDirector = demoing.BobDirector(hab=bobHab, client=bobClient, tock=0.125)
        assert bobDirector.hab == bobHab
        assert bobDirector.client == bobClient
        assert bobDirector.hab.kvy.kevers == bobKevers
        assert bobDirector.hab.kvy.baser == bobDB
        assert bobDirector.tock == 0.125

        bobReactor = directing.Reactor(hab=bobHab, client=bobClient)
        assert bobReactor.hab == bobHab
        assert bobReactor.client == bobClient
        assert bobReactor.hab.kvy.kevers == bobKevers
        assert bobReactor.hab.kvy.baser == bobDB
        assert bobReactor.hab.kvy.ims == bobReactor.client.rxbs

        bobServer = serving.Server(host="", port=bobPort)
        bobServerDoer = doing.ServerDoer(server=bobServer)

        bobDirectant = directing.Directant(hab=bobHab, server=bobServer)
        assert bobDirectant.hab == bobHab
        assert bobDirectant.server == bobServer
        # Bob's Reactants created on demand

        # setup eve
        eveHab = directing.Habitat(ks=eveKS,  db=eveDB, kevers=eveKevers,
                                   secrecies=eveSecrecies, temp=True)

        assert eveHab.ks == eveKS
        assert eveHab.db == eveDB
        assert eveHab.iserder.dig == eveSerder.dig
        assert eveHab.pre == eve

        eveClient = clienting.Client(host='127.0.0.1', port=bobPort)
        eveClientDoer = doing.ClientDoer(client=eveClient)

        eveDirector = demoing.EveDirector(hab=eveHab, client=eveClient, tock=0.125)
        assert eveDirector.hab == eveHab
        assert eveDirector.client == eveClient
        assert eveDirector.hab.kvy.kevers == eveKevers
        assert eveDirector.hab.kvy.baser == eveDB

        eveReactor = directing.Reactor(hab=eveHab, client=eveClient)
        assert eveReactor.hab == eveHab
        assert eveReactor.client == eveClient
        assert eveReactor.hab.kvy.kevers == eveKevers
        assert eveReactor.hab.kvy.baser == eveDB
        assert eveReactor.hab.kvy.ims == eveReactor.client.rxbs

        eveServer = serving.Server(host="", port=evePort)
        eveServerDoer = doing.ServerDoer(server=eveServer)

        eveDirectant = directing.Directant(hab=eveHab, server=eveServer)
        assert eveDirectant.hab == eveHab
        assert eveDirectant.server == eveServer
        # Eve's Reactants created on demand

        limit = 1.0
        tock = 0.03125
        doist = doing.Doist(limit=limit, tock=tock)


        doers = [bobClientDoer, bobDirector, bobReactor, bobServerDoer, bobDirectant,
                 eveClientDoer, eveDirector, eveReactor, eveServerDoer, eveDirectant]
        doist.do(doers=doers)
        assert doist.tyme == limit

        assert bobClient.opened == False
        assert bobServer.opened == False
        assert eveClient.opened == False
        assert eveServer.opened == False

        assert bobHab.pre in bobHab.kevers
        assert eveHab.pre in eveHab.kevers

        assert not bobClient.txbs

        assert bobHab.pre in eveHab.kevers

        #  verify final event states

    assert not os.path.exists(eveDB.path)
    assert not os.path.exists(bobDB.path)

    help.ogler.resetLevel(level=help.ogler.level)
    """End Test"""



def test_direct_mode_sam_eve_demo():
    """
    Test direct mode sam and eve
    """
    help.ogler.resetLevel(level=logging.DEBUG)

    # set of secrets  (seeds for private keys)
    samSecrets = [
                'ArwXoACJgOleVZ2PY7kXn7rA0II0mHYDhc6WrBH8fDAc',
                'A6zz7M08-HQSFq92sJ8KJOT2cZ47x7pXFQLPB0pckB3Q',
                'AcwFTk-wgk3ZT2buPRIbK-zxgPx-TKbaegQvPEivN90Y',
                'Alntkt3u6dDgiQxTATr01dy8M72uuaZEf9eTdM-70Gk8',
                'A1-QxDkso9-MR1A8rZz_Naw6fgaAtayda8hrbkRVVu1E',
                'AKuYMe09COczwf2nIoD5AE119n7GLFOVFlNLxZcKuswc',
                'AxFfJTcSuEE11FINfXMqWttkZGnUZ8KaREhrnyAXTsjw',
                'ALq-w1UKkdrppwZzGTtz4PWYEeWm0-sDHzOv5sq96xJY'
                ]

    samSecrecies = []
    for secret in samSecrets:  # convert secrets to secrecies
        samSecrecies.append([secret])

    #  create bob signers
    samSigners = [coring.Signer(qb64=secret) for secret in samSecrets]
    assert [signer.qb64 for signer in samSigners] == samSecrets

    # bob inception transferable (nxt digest not empty)
    samSerder = eventing.incept(keys=[samSigners[0].verfer.qb64],
                                nxt=coring.Nexter(keys=[samSigners[1].verfer.qb64]).qb64,
                                code=coring.MtrDex.Blake3_256)

    sam = samSerder.ked["i"]
    assert sam == 'EH7Oq9oxCgYa-nnNLvwhp9sFZpALILlRYyB-6n4WDi7w'


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
    assert eve == 'EpDA1n-WiBA0A8YOqnKrB-wWQYYC49i5zY_qrIZIicQg'



    with dbing.openDB(name="eve") as eveDB, keeping.openKS(name="eve") as eveKS, \
         dbing.openDB(name="sam") as samDB, keeping.openKS(name="sam") as samKS:

        samPort = 5620  # bob's TCP listening port for server
        evePort = 5621  # eve's TCP listneing port for server
        samKevers = dict()
        eveKevers = dict()

        # setup bob
        samHab = directing.Habitat(ks=samKS,  db=samDB, kevers=samKevers,
                                   secrecies=samSecrecies, temp=True)

        assert samHab.ks == samKS
        assert samHab.db == samDB
        assert samHab.iserder.dig == samSerder.dig
        assert samHab.pre == sam

        samClient = clienting.Client(host='127.0.0.1', port=evePort)
        samClientDoer = doing.ClientDoer(client=samClient)

        samDirector = demoing.SamDirector(hab=samHab, client=samClient, tock=0.125)
        assert samDirector.hab == samHab
        assert samDirector.client == samClient
        assert samDirector.hab.kvy.kevers == samKevers
        assert samDirector.hab.kvy.baser == samDB
        assert samDirector.tock == 0.125

        samReactor = directing.Reactor(hab=samHab, client=samClient)
        assert samReactor.hab == samHab
        assert samReactor.client == samClient
        assert samReactor.hab.kvy.kevers == samKevers
        assert samReactor.hab.kvy.baser == samDB
        assert samReactor.hab.kvy.ims == samReactor.client.rxbs

        samServer = serving.Server(host="", port=samPort)
        samServerDoer = doing.ServerDoer(server=samServer)

        samDirectant = directing.Directant(hab=samHab, server=samServer)
        assert samDirectant.hab == samHab
        assert samDirectant.server == samServer
        # Bob's Reactants created on demand

        # setup eve
        eveHab = directing.Habitat(ks=eveKS,  db=eveDB, kevers=eveKevers,
                                   secrecies=eveSecrecies, temp=True)
        assert eveHab.ks == eveKS
        assert eveHab.db == eveDB
        assert eveHab.iserder.dig == eveSerder.dig
        assert eveHab.pre == eve

        eveClient = clienting.Client(host='127.0.0.1', port=samPort)
        eveClientDoer = doing.ClientDoer(client=eveClient)

        eveDirector = demoing.EveDirector(hab=eveHab, client=eveClient, tock=0.125)
        assert eveDirector.hab == eveHab
        assert eveDirector.client == eveClient
        assert eveDirector.hab.kvy.kevers == eveKevers
        assert eveDirector.hab.kvy.baser == eveDB

        eveReactor = directing.Reactor(hab=eveHab, client=eveClient)
        assert eveReactor.hab == eveHab
        assert eveReactor.client == eveClient
        assert eveReactor.hab.kvy.kevers == eveKevers
        assert eveReactor.hab.kvy.baser == eveDB
        assert eveReactor.hab.kvy.ims == eveReactor.client.rxbs

        eveServer = serving.Server(host="", port=evePort)
        eveServerDoer = doing.ServerDoer(server=eveServer)

        eveDirectant = directing.Directant(hab=eveHab, server=eveServer)
        assert eveDirectant.hab == eveHab
        assert eveDirectant.server == eveServer
        # Eve's Reactants created on demand

        limit = 1.0
        tock = 0.03125
        doist = doing.Doist(limit=limit, tock=tock)

        doers = [samClientDoer, samDirector, samReactor, samServerDoer, samDirectant,
                 eveClientDoer, eveDirector, eveReactor, eveServerDoer, eveDirectant]
        doist.do(doers=doers)
        assert doist.tyme == limit

        assert samClient.opened == False
        assert samServer.opened == False
        assert eveClient.opened == False
        assert eveServer.opened == False

        assert samHab.pre in samHab.kevers
        assert eveHab.pre in eveHab.kevers

        assert not samClient.txbs

        assert samHab.pre in eveHab.kevers

        #  verify final event states


    assert not os.path.exists(eveDB.path)
    assert not os.path.exists(samDB.path)

    help.ogler.resetLevel(level=help.ogler.level)
    """End Test"""



def test_run_bob_eve_demo():
    """
    Test demo setupController and run with DoDoers and Doist
    """
    help.ogler.resetLevel(level=logging.DEBUG)

    name = "bob"
    remote = 5621
    local = 5620


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

    # bobs is list of Doers
    bobs = demoing.setupDemoController(secrets=secrets,
                                     name=name,
                                     remotePort=remote,
                                     localPort=local)

    name = "eve"
    remote = 5620
    local = 5621


    # set of secrets (seeds for private keys)
    secrets = ['AgjD4nRlycmM5cPcAkfOATAp8wVldRsnc9f1tiwctXlw',
                'AKUotEE0eAheKdDJh9QvNmSEmO_bjIav8V_GmctGpuCQ',
                'AK-nVhMMJciMPvmF5VZE_9H-nhrgng9aJWf7_UHPtRNM',
                'AT2cx-P5YUjIw_SLCHQ0pqoBWGk9s4N1brD-4pD_ANbs',
                'Ap5waegfnuP6ezC18w7jQiPyQwYYsp9Yv9rYMlKAYL8k',
                'Aqlc_FWWrxpxCo7R12uIz_Y2pHUH2prHx1kjghPa8jT8',
                'AagumsL8FeGES7tYcnr_5oN6qcwJzZfLKxoniKUpG4qc',
                'ADW3o9m3udwEf0aoOdZLLJdf1aylokP0lwwI_M2J9h0s']

    eves = demoing.setupDemoController(secrets=secrets,
                                     name=name,
                                     remotePort=remote,
                                     localPort=local)

    bobDoer = doing.DoDoer(doers=bobs)
    eveDoer = doing.DoDoer(doers=eves)

    # run components
    tock = 0.03125
    expire =  1.0
    doist = doing.Doist(limit=expire, tock=tock, real=True, doers=[eveDoer, bobDoer])
    doist.do()

    help.ogler.resetLevel(level=help.ogler.level)
    """End Test"""


def test_run_sam_eve_demo():
    """
    Test demo setupController and run with DoDoers and Doist
    """
    help.ogler.resetLevel(level=logging.DEBUG)

    name = "sam"
    remote = 5621
    local = 5620


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

    # sams is list of Doers
    sams = demoing.setupDemoController(secrets=secrets,
                                     name=name,
                                     remotePort=remote,
                                     localPort=local)

    name = "eve"
    remote = 5620
    local = 5621


    # set of secrets (seeds for private keys)
    secrets = ['AgjD4nRlycmM5cPcAkfOATAp8wVldRsnc9f1tiwctXlw',
                'AKUotEE0eAheKdDJh9QvNmSEmO_bjIav8V_GmctGpuCQ',
                'AK-nVhMMJciMPvmF5VZE_9H-nhrgng9aJWf7_UHPtRNM',
                'AT2cx-P5YUjIw_SLCHQ0pqoBWGk9s4N1brD-4pD_ANbs',
                'Ap5waegfnuP6ezC18w7jQiPyQwYYsp9Yv9rYMlKAYL8k',
                'Aqlc_FWWrxpxCo7R12uIz_Y2pHUH2prHx1kjghPa8jT8',
                'AagumsL8FeGES7tYcnr_5oN6qcwJzZfLKxoniKUpG4qc',
                'ADW3o9m3udwEf0aoOdZLLJdf1aylokP0lwwI_M2J9h0s']

    eves = demoing.setupDemoController(secrets=secrets,
                                     name=name,
                                     remotePort=remote,
                                     localPort=local)

    samDoer = doing.DoDoer(doers=sams)
    eveDoer = doing.DoDoer(doers=eves)

    # run components
    tock = 0.03125
    expire =  1.0
    doist = doing.Doist(limit=expire, tock=tock, real=True, doers=[eveDoer, samDoer])
    doist.do()

    help.ogler.resetLevel(level=help.ogler.level)
    """End Test"""


if __name__ == "__main__":
    test_direct_mode_sam_eve_demo()

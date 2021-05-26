# -*- encoding: utf-8 -*-
"""
tests.db.dbing module

"""
import os
import logging

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
    assert bob == 'EQf1hzB6s5saaQPdDAsEzSMEFoQx_WLsq93bjPu5wuqA'


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
    assert eve == 'ED9EB3sA5u2vCPOEmX3d7bEyHiSh7Xi8fjew2KMl3FQM'

    with dbing.openDB(name="eve") as eveDB, keeping.openKS(name="eve") as eveKS, \
         dbing.openDB(name="bob") as bobDB, keeping.openKS(name="bob") as bobKS:

        limit = 1.0
        tock = 0.03125
        doist = doing.Doist(limit=limit, tock=tock)

        bobPort = 5620  # bob's TCP listening port for server
        evePort = 5621  # eve's TCP listneing port for server
        bobKevers = dict()
        eveKevers = dict()

        # setup bob
        bobHab = directing.Habitat(name='Bob', ks=bobKS, db=bobDB, kevers=bobKevers,
                                   secrecies=bobSecrecies, temp=True)
        assert bobHab.ks == bobKS
        assert bobHab.db == bobDB
        assert bobHab.iserder.dig == bobSerder.dig
        assert bobHab.pre == bob

        bobClient = clienting.Client(tymth=doist.tymen(), host='127.0.0.1', port=evePort)
        bobClientDoer = doing.ClientDoer(client=bobClient)

        bobDirector = demoing.BobDirector(hab=bobHab, client=bobClient, tock=0.125)
        assert bobDirector.hab == bobHab
        assert bobDirector.client == bobClient
        assert bobDirector.hab.kvy.kevers == bobKevers
        assert bobDirector.hab.kvy.db == bobDB
        assert bobDirector.tock == 0.125

        bobReactor = directing.Reactor(hab=bobHab, client=bobClient)
        assert bobReactor.hab == bobHab
        assert bobReactor.client == bobClient
        assert bobReactor.hab.kvy.kevers == bobKevers
        assert bobReactor.hab.kvy.db == bobDB
        assert bobReactor.hab.psr.ims == bobReactor.client.rxbs

        bobServer = serving.Server(host="", port=bobPort)
        bobServerDoer = doing.ServerDoer(server=bobServer)

        bobDirectant = directing.Directant(hab=bobHab, server=bobServer)
        assert bobDirectant.hab == bobHab
        assert bobDirectant.server == bobServer
        # Bob's Reactants created on demand

        # setup eve
        eveHab = directing.Habitat(name='Eve', ks=eveKS,  db=eveDB, kevers=eveKevers,
                                   secrecies=eveSecrecies, temp=True)

        assert eveHab.ks == eveKS
        assert eveHab.db == eveDB
        assert eveHab.iserder.dig == eveSerder.dig
        assert eveHab.pre == eve

        eveClient = clienting.Client(tymth=doist.tymen(), host='127.0.0.1', port=bobPort)
        eveClientDoer = doing.ClientDoer(client=eveClient)

        eveDirector = demoing.EveDirector(hab=eveHab, client=eveClient, tock=0.125)
        assert eveDirector.hab == eveHab
        assert eveDirector.client == eveClient
        assert eveDirector.hab.kvy.kevers == eveKevers
        assert eveDirector.hab.kvy.db == eveDB

        eveReactor = directing.Reactor(hab=eveHab, client=eveClient)
        assert eveReactor.hab == eveHab
        assert eveReactor.client == eveClient
        assert eveReactor.hab.kvy.kevers == eveKevers
        assert eveReactor.hab.kvy.db == eveDB
        assert eveReactor.hab.psr.ims == eveReactor.client.rxbs

        eveServer = serving.Server(host="", port=evePort)
        eveServerDoer = doing.ServerDoer(server=eveServer)

        eveDirectant = directing.Directant(hab=eveHab, server=eveServer)
        assert eveDirectant.hab == eveHab
        assert eveDirectant.server == eveServer
        # Eve's Reactants created on demand

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

    # create Sam signers
    samSigners = [coring.Signer(qb64=secret) for secret in samSecrets]
    assert [signer.qb64 for signer in samSigners] == samSecrets

    # Sam inception transferable (nxt digest not empty)
    samSerder = eventing.incept(keys=[samSigners[0].verfer.qb64],
                                nxt=coring.Nexter(keys=[samSigners[1].verfer.qb64]).qb64,
                                code=coring.MtrDex.Blake3_256)

    sam = samSerder.ked["i"]
    assert sam == 'EQf1hzB6s5saaQPdDAsEzSMEFoQx_WLsq93bjPu5wuqA'


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

    # create Eve signers
    eveSigners = [coring.Signer(qb64=secret) for secret in eveSecrets]
    assert [signer.qb64 for signer in eveSigners] == eveSecrets

    # eve inception transferable (nxt digest not empty)
    eveSerder = eventing.incept(keys=[eveSigners[0].verfer.qb64],
                                nxt=coring.Nexter(keys=[eveSigners[1].verfer.qb64]).qb64,
                                code=coring.MtrDex.Blake3_256)

    eve = eveSerder.ked["i"]
    assert eve == 'ED9EB3sA5u2vCPOEmX3d7bEyHiSh7Xi8fjew2KMl3FQM'



    with dbing.openDB(name="eve") as eveDB, keeping.openKS(name="eve") as eveKS, \
         dbing.openDB(name="sam") as samDB, keeping.openKS(name="sam") as samKS:

        limit = 1.0
        tock = 0.03125
        doist = doing.Doist(limit=limit, tock=tock)

        samPort = 5620  # bob's TCP listening port for server
        evePort = 5621  # eve's TCP listneing port for server
        samKevers = dict()
        eveKevers = dict()

        # setup Sam
        samHab = directing.Habitat(name='Sam', ks=samKS,  db=samDB, kevers=samKevers,
                                   secrecies=samSecrecies, temp=True)

        assert samHab.ks == samKS
        assert samHab.db == samDB
        assert samHab.iserder.dig == samSerder.dig
        assert samHab.pre == sam

        samClient = clienting.Client(tymth=doist.tymen(), host='127.0.0.1', port=evePort)
        samClientDoer = doing.ClientDoer(client=samClient)

        samDirector = demoing.SamDirector(hab=samHab, client=samClient, tock=0.125)
        assert samDirector.hab == samHab
        assert samDirector.client == samClient
        assert samDirector.hab.kvy.kevers == samKevers
        assert samDirector.hab.kvy.db == samDB
        assert samDirector.tock == 0.125

        samReactor = directing.Reactor(hab=samHab, client=samClient)
        assert samReactor.hab == samHab
        assert samReactor.client == samClient
        assert samReactor.hab.kvy.kevers == samKevers
        assert samReactor.hab.kvy.db == samDB
        assert samReactor.hab.psr.ims == samReactor.client.rxbs

        samServer = serving.Server(host="", port=samPort)
        samServerDoer = doing.ServerDoer(server=samServer)

        samDirectant = directing.Directant(hab=samHab, server=samServer)
        assert samDirectant.hab == samHab
        assert samDirectant.server == samServer
        # Sam's Reactants created on demand

        # setup eve
        eveHab = directing.Habitat(name='Eve', ks=eveKS,  db=eveDB, kevers=eveKevers,
                                   secrecies=eveSecrecies, temp=True)
        assert eveHab.ks == eveKS
        assert eveHab.db == eveDB
        assert eveHab.iserder.dig == eveSerder.dig
        assert eveHab.pre == eve

        eveClient = clienting.Client(tymth=doist.tymen(), host='127.0.0.1', port=samPort)
        eveClientDoer = doing.ClientDoer(client=eveClient)

        eveDirector = demoing.EveDirector(hab=eveHab, client=eveClient, tock=0.125)
        assert eveDirector.hab == eveHab
        assert eveDirector.client == eveClient
        assert eveDirector.hab.kvy.kevers == eveKevers
        assert eveDirector.hab.kvy.db == eveDB

        eveReactor = directing.Reactor(hab=eveHab, client=eveClient)
        assert eveReactor.hab == eveHab
        assert eveReactor.client == eveClient
        assert eveReactor.hab.kvy.kevers == eveKevers
        assert eveReactor.hab.kvy.db == eveDB
        assert eveReactor.hab.psr.ims == eveReactor.client.rxbs

        eveServer = serving.Server(host="", port=evePort)
        eveServerDoer = doing.ServerDoer(server=eveServer)

        eveDirectant = directing.Directant(hab=eveHab, server=eveServer)
        assert eveDirectant.hab == eveHab
        assert eveDirectant.server == eveServer
        # Eve's Reactants created on demand

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

    tock = 0.03125
    expire =  2.5
    doist = doing.Doist(limit=expire, tock=tock, real=True)

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
    # doist = doing.Doist(limit=expire, tock=tock, real=True, doers=[eveDoer, bobDoer])
    doist.do(doers=[eveDoer, bobDoer])

    help.ogler.resetLevel(level=help.ogler.level)
    """End Test"""


def test_run_sam_eve_demo():
    """
    Test demo setupController and run with DoDoers and Doist
    """
    help.ogler.resetLevel(level=logging.DEBUG)

    tock = 0.03125
    expire =  2.0
    doist = doing.Doist(limit=expire, tock=tock, real=True)

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
    # doist = doing.Doist(limit=expire, tock=tock, real=True, doers=[eveDoer, samDoer])
    doist.do(doers=[eveDoer, samDoer])

    help.ogler.resetLevel(level=help.ogler.level)
    """End Test"""


def test_indirect_mode_sam_cam_wit_demo():
    """ Test indirect mode, bob and eve with witness """

    help.ogler.resetLevel(level=logging.DEBUG)
    # set of secrets (seeds for private keys)
    camSecrets = ['AgjD4nRlycmM5cPcAkfOATAp8wVldRsnc9f1tiwctXlw',
                  'AKUotEE0eAheKdDJh9QvNmSEmO_bjIav8V_GmctGpuCQ',
                  'AK-nVhMMJciMPvmF5VZE_9H-nhrgng9aJWf7_UHPtRNM',
                  'AT2cx-P5YUjIw_SLCHQ0pqoBWGk9s4N1brD-4pD_ANbs',
                  'Ap5waegfnuP6ezC18w7jQiPyQwYYsp9Yv9rYMlKAYL8k',
                  'Aqlc_FWWrxpxCo7R12uIz_Y2pHUH2prHx1kjghPa8jT8',
                  'AagumsL8FeGES7tYcnr_5oN6qcwJzZfLKxoniKUpG4qc',
                  'ADW3o9m3udwEf0aoOdZLLJdf1aylokP0lwwI_M2J9h0s']

    camSecrecies = []
    for secret in camSecrets:  # convert secrets to secrecies
        camSecrecies.append([secret])

    #  create cam signers
    camSigners = [coring.Signer(qb64=secret) for secret in camSecrets]
    assert [signer.qb64 for signer in camSigners] == camSecrets

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

    #  create sam signers
    samSigners = [coring.Signer(qb64=secret) for secret in samSecrets]
    assert [signer.qb64 for signer in samSigners] == samSecrets

    with dbing.openDB(name="cam") as camDB, keeping.openKS(name="cam") as camKS, \
         dbing.openDB(name="sam") as samDB, keeping.openKS(name="sam") as samKS, \
         dbing.openDB(name="wit") as witDB, keeping.openKS(name="wit") as witKS:

        limit = 1.0
        tock = 0.03125
        samDoist = doing.Doist(limit=limit, tock=tock)
        camDoist = doing.Doist(limit=limit, tock=tock)

        samPort = 5620  # sam's TCP listening port for server
        witPort = 5621  # wit' TCP listneing port for server
        samKevers = dict()
        camKevers = dict()
        witKevers = dict()

        # setup the witness
        witHab = directing.Habitat(name='Wit', ks=witKS, db=witDB, kevers=witKevers, isith=1, icount=1,
                                   temp=True, transferable=False)
        wit = witHab.pre
        assert witHab.ks == witKS
        assert witHab.db == witDB
        witServer = serving.Server(host="", port=witPort)
        witServerDoer = doing.ServerDoer(server=witServer)
        witDirectant = directing.Directant(hab=witHab, server=witServer)



        # setup cam
        # cam inception transferable (nxt digest not empty)
        camSerder = eventing.incept(keys=[camSigners[0].verfer.qb64],
                                    nxt=coring.Nexter(keys=[camSigners[1].verfer.qb64]).qb64,
                                    code=coring.MtrDex.Blake3_256)

        cam = camSerder.ked["i"]
        assert cam == 'ED9EB3sA5u2vCPOEmX3d7bEyHiSh7Xi8fjew2KMl3FQM'

        # sam inception transferable (nxt digest not empty)
        samSerder = eventing.incept(keys=[samSigners[0].verfer.qb64], wits=[wit],
                                    nxt=coring.Nexter(keys=[samSigners[1].verfer.qb64]).qb64,
                                    code=coring.MtrDex.Blake3_256)

        sam = samSerder.ked["i"]
        print(sam)
        assert sam == 'EhnaYUqhHoo8kZaXJuTDCZ-h5ZDx3st4NemgqSITWp48'


        samHab = directing.Habitat(name='Sam', ks=samKS, db=samDB, kevers=samKevers, wits=[wit],
                                   secrecies=samSecrecies, temp=True)
        assert samHab.ks == samKS
        assert samHab.db == samDB
        assert samHab.iserder.dig == samSerder.dig
        assert samHab.pre == sam

        samClient = clienting.Client(tymth=samDoist.tymen(), host='127.0.0.1', port=witPort)
        samClientDoer = doing.ClientDoer(client=samClient)

        samDirector = demoing.SamDirector(hab=samHab, client=samClient, tock=0.125)
        assert samDirector.hab == samHab
        assert samDirector.client == samClient
        assert samDirector.hab.kvy.kevers == samKevers
        assert samDirector.hab.kvy.db == samDB
        assert samDirector.tock == 0.125

        samReactor = directing.Reactor(hab=samHab, client=samClient)
        assert samReactor.hab == samHab
        assert samReactor.client == samClient
        assert samReactor.hab.kvy.kevers == samKevers
        assert samReactor.hab.kvy.db == samDB
        assert samReactor.hab.psr.ims == samReactor.client.rxbs

        samServer = serving.Server(host="", port=samPort)
        samServerDoer = doing.ServerDoer(server=samServer)

        samDirectant = directing.Directant(hab=samHab, server=samServer)
        assert samDirectant.hab == samHab
        assert samDirectant.server == samServer
        # Sam's Reactants created on demand

        # setup cam
        camHab = directing.Habitat(name='Cam', ks=camKS,  db=camDB, kevers=camKevers,
                                   secrecies=camSecrecies, temp=True)

        assert camHab.ks == camKS
        assert camHab.db == camDB
        assert camHab.iserder.dig == camSerder.dig
        assert camHab.pre == cam

        camClient = clienting.Client(tymth=camDoist.tymen(), host='127.0.0.1', port=witPort)
        camClientDoer = doing.ClientDoer(client=camClient)

        camDirector = demoing.CamDirector(hab=camHab, remotePre=sam, client=camClient, tock=0.125)
        assert camDirector.hab == camHab
        assert camDirector.client == camClient
        assert camDirector.hab.kvy.kevers == camKevers
        assert camDirector.hab.kvy.db == camDB
        assert camDirector.tock == 0.125

        camReactor = directing.Reactor(hab=camHab, client=camClient, indirect=True)
        assert camReactor.hab == camHab
        assert camReactor.client == camClient
        assert camReactor.hab.kvy.kevers == camKevers
        assert camReactor.hab.kvy.db == camDB
        assert camReactor.hab.psr.ims == camReactor.client.rxbs

        samDoers = [samClientDoer, samDirector, samReactor, samServerDoer, samDirectant,
                    witServerDoer, witDirectant]
        samDoist.do(doers=samDoers)
        assert samDoist.tyme == limit

        # camDoers = [camClientDoer, camDirector, camReactor, witServerDoer, witDirectant]
        # camDoist.do(doers=camDoers)
        # assert camDoist.tyme == limit
        #
        #
        assert samClient.opened is False
        assert samServer.opened is False
        assert camClient.opened is False

        assert samHab.pre in samHab.kevers
        assert camHab.pre in camHab.kevers

        assert not samClient.txbs

        # TODO: fix this when I figure out how to delay Cam until after Sam is finished.
        # assert samHab.pre in camHab.kevers

        #  verify final event states

    assert not os.path.exists(camDB.path)
    assert not os.path.exists(samDB.path)

    help.ogler.resetLevel(level=help.ogler.level)
    """End Test"""


if __name__ == "__main__":
    test_indirect_mode_sam_cam_wit_demo()

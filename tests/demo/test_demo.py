# -*- encoding: utf-8 -*-
"""
tests.db.dbing module

"""
import logging
import os

import time
from hio.base import doing
from hio.core.tcp import clienting, serving

from keri import help  # logger support

from keri import core
from keri.core import eventing, coring

from keri.app import habbing, directing

from keri.demo import demoing


def test_direct_mode_bob_eve_demo():
    """
    Test direct mode bob and eve
    """
    help.ogler.resetLevel(level=logging.DEBUG)

    raw = b"raw salt to test"

    #  create bob signers and secrecies
    bobSigners = core.Salter(raw=raw).signers(count=8, path="bob", temp=True)
    bobSecrecies = [[signer.qb64] for signer in bobSigners]

    # bob inception transferable (nxt digest not empty)
    bobSerder = eventing.incept(keys=[bobSigners[0].verfer.qb64],
                                ndigs=[coring.Diger(ser=bobSigners[1].verfer.qb64b).qb64],
                                code=coring.MtrDex.Blake3_256)

    bob = bobSerder.ked["i"]
    assert bob == 'EFa1wAk_coghxxGCID6jEN79Kmvyj0Y1wWN_ndUv3LjW'

    #  create eve signers and secrecies
    eveSigners = core.Salter(raw=raw).signers(count=8, path="eve", temp=True)
    eveSecrecies = [[signer.qb64] for signer in eveSigners]

    # eve inception transferable (nxt digest not empty)
    eveSerder = eventing.incept(keys=[eveSigners[0].verfer.qb64],
                                ndigs=[coring.Diger(ser=eveSigners[1].verfer.qb64b).qb64],
                                code=coring.MtrDex.Blake3_256)

    eve = eveSerder.ked["i"]
    assert eve == 'EFhg5my9DuMU6gw1CVk6QgkmZKBttWSXDzVzWVmxh0_K'

    with (habbing.openHby(name="eve", base="test") as eveHby,
          habbing.openHby(name="bob", base="test") as bobHby):

        limit = 1.0
        tock = 0.03125
        doist = doing.Doist(limit=limit, tock=tock)

        bobPort = 5620  # bob's TCP listening port for server
        evePort = 5621  # eve's TCP listneing port for server

        # setup bob
        bobHab = bobHby.makeHab(name="Bob", secrecies=bobSecrecies)
        print(bobHab.iserder.pretty())
        print(bobSerder.pretty())

        assert bobHab.iserder.said == bobSerder.said
        assert bobHab.pre == bob

        bobClient = clienting.Client(tymth=doist.tymen(), host='127.0.0.1', port=evePort)
        bobClientDoer = clienting.ClientDoer(client=bobClient)

        bobDirector = demoing.BobDirector(hab=bobHab, client=bobClient, tock=0.125)
        assert bobDirector.hab == bobHab
        assert bobDirector.client == bobClient
        assert id(bobDirector.hab.kvy.kevers) == id(bobHab.kevers)
        assert bobDirector.hab.kvy.db == bobHby.db # bobDB
        assert bobDirector.tock == 0.125

        bobReactor = directing.Reactor(hab=bobHab, client=bobClient)
        assert bobReactor.hab == bobHab
        assert bobReactor.client == bobClient
        assert id(bobReactor.hab.kvy.kevers) == id(bobHab.kevers)
        assert bobReactor.hab.kvy.db == bobHby.db  # bobDB
        assert bobReactor.hab.psr.ims == bobReactor.client.rxbs

        bobServer = serving.Server(host="", port=bobPort)
        bobServerDoer = serving.ServerDoer(server=bobServer)

        bobDirectant = directing.Directant(hab=bobHab, server=bobServer)
        assert bobDirectant.hab == bobHab
        assert bobDirectant.server == bobServer
        # Bob's Reactants created on demand

        # setup eve
        eveHab = eveHby.makeHab(name="Eve", secrecies=eveSecrecies)
        assert eveHab.iserder.said == eveSerder.said
        assert eveHab.pre == eve

        eveClient = clienting.Client(tymth=doist.tymen(), host='127.0.0.1', port=bobPort)
        eveClientDoer = clienting.ClientDoer(client=eveClient)

        eveDirector = demoing.EveDirector(hab=eveHab, client=eveClient, tock=0.125)
        assert eveDirector.hab == eveHab
        assert eveDirector.client == eveClient
        assert id(eveDirector.hab.kvy.kevers) == id(eveHab.kevers)
        assert eveDirector.hab.kvy.db == eveHby.db  # eveDB

        eveReactor = directing.Reactor(hab=eveHab, client=eveClient)
        assert eveReactor.hab == eveHab
        assert eveReactor.client == eveClient
        assert id(eveReactor.hab.kvy.kevers) == id(eveHab.kevers)
        assert eveReactor.hab.kvy.db == eveHby.db # eveDB
        assert eveReactor.hab.psr.ims == eveReactor.client.rxbs

        eveServer = serving.Server(host="", port=evePort)
        eveServerDoer = serving.ServerDoer(server=eveServer)

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

    assert not os.path.exists(eveHby.db.path)
    assert not os.path.exists(bobHby.db.path)

    help.ogler.resetLevel(level=help.ogler.level)
    """End Test"""



def test_direct_mode_sam_eve_demo():
    """
    Test direct mode sam and eve
    """
    help.ogler.resetLevel(level=logging.DEBUG)

    raw = b"raw salt to test"

    #  create sam signers and secrecies
    samSigners = core.Salter(raw=raw).signers(count=8, path="sam", temp=True)
    samSecrecies = [[signer.qb64] for signer in samSigners]

    # sam inception transferable (nxt digest not empty)
    samSerder = eventing.incept(keys=[samSigners[0].verfer.qb64],
                                ndigs=[coring.Diger(ser=samSigners[1].verfer.qb64b).qb64],
                                code=coring.MtrDex.Blake3_256)

    sam = samSerder.ked["i"]
    assert sam == 'EDkU2U_TPKca14VElEItpj7twohQL60GIaUPvSHAghga'

    #  create eve signers and secrecies
    eveSigners = core.Salter(raw=raw).signers(count=8, path="eve", temp=True)
    eveSecrecies = [[signer.qb64] for signer in eveSigners]

    # eve inception transferable (nxt digest not empty)
    eveSerder = eventing.incept(keys=[eveSigners[0].verfer.qb64],
                                ndigs=[coring.Diger(ser=eveSigners[1].verfer.qb64b).qb64],
                                code=coring.MtrDex.Blake3_256)

    eve = eveSerder.ked["i"]
    assert eve == 'EFhg5my9DuMU6gw1CVk6QgkmZKBttWSXDzVzWVmxh0_K'


    with habbing.openHby(name="eve", base="test") as eveHby, \
         habbing.openHby(name="sam", base="test") as samHby:

        limit = 1.0
        tock = 0.03125
        doist = doing.Doist(limit=limit, tock=tock)

        samPort = 5620  # bob's TCP listening port for server
        evePort = 5621  # eve's TCP listneing port for server

        # setup Sam
        samHab = samHby.makeHab(name="Sam", secrecies=samSecrecies)
        #samHab = habbing.Habitat(name='Sam',
                                 #ks=samKS,
                                 #db=samDB,
                                 #secrecies=samSecrecies,
                                 #temp=True)

        #assert samHab.ks == samKS
        #assert samHab.db == samDB
        assert samHab.iserder.said == samSerder.said
        assert samHab.pre == sam

        samClient = clienting.Client(tymth=doist.tymen(), host='127.0.0.1', port=evePort)
        samClientDoer = clienting.ClientDoer(client=samClient)

        samDirector = demoing.SamDirector(hab=samHab, client=samClient, tock=0.125)
        assert samDirector.hab == samHab
        assert samDirector.client == samClient
        assert id(samDirector.hab.kvy.kevers) == id(samHab.kevers)
        assert samDirector.hab.kvy.db == samHby.db
        assert samDirector.tock == 0.125

        samReactor = directing.Reactor(hab=samHab, client=samClient)
        assert samReactor.hab == samHab
        assert samReactor.client == samClient
        assert id(samReactor.hab.kvy.kevers) == id(samHab.kevers)
        assert samReactor.hab.kvy.db == samHby.db
        assert samReactor.hab.psr.ims == samReactor.client.rxbs

        samServer = serving.Server(host="", port=samPort)
        samServerDoer = serving.ServerDoer(server=samServer)

        samDirectant = directing.Directant(hab=samHab, server=samServer)
        assert samDirectant.hab == samHab
        assert samDirectant.server == samServer
        # Sam's Reactants created on demand

        # setup eve
        eveHab = eveHby.makeHab(name="Eve", secrecies=eveSecrecies)
        #eveHab = habbing.Habitat(name='Eve',
                                 #ks=eveKS,
                                 #db=eveDB,
                                 #secrecies=eveSecrecies, temp=True)
        #assert eveHab.ks == eveKS
        #assert eveHab.db == eveDB
        assert eveHab.iserder.said == eveSerder.said
        assert eveHab.pre == eve

        eveClient = clienting.Client(tymth=doist.tymen(), host='127.0.0.1', port=samPort)
        eveClientDoer = clienting.ClientDoer(client=eveClient)

        eveDirector = demoing.EveDirector(hab=eveHab, client=eveClient, tock=0.125)
        assert eveDirector.hab == eveHab
        assert eveDirector.client == eveClient
        assert id(eveDirector.hab.kvy.kevers) == id(eveHab.kevers)
        assert eveDirector.hab.kvy.db == eveHby.db

        eveReactor = directing.Reactor(hab=eveHab, client=eveClient)
        assert eveReactor.hab == eveHab
        assert eveReactor.client == eveClient
        assert id(eveReactor.hab.kvy.kevers) == id(eveHab.kevers)
        assert eveReactor.hab.kvy.db == eveHby.db
        assert eveReactor.hab.psr.ims == eveReactor.client.rxbs

        eveServer = serving.Server(host="", port=evePort)
        eveServerDoer = serving.ServerDoer(server=eveServer)

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


    assert not os.path.exists(eveHby.db.path)
    assert not os.path.exists(samHby.db.path)

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

    raw = b"raw salt to test"

    name = "bob"
    remote = 5621
    local = 5620

    #  create bob secrecies
    secrecies = [[signer.qb64] for signer in
                    core.Salter(raw=raw).signers(count=8,
                                                   path="bob",
                                                   temp=True)]

    # bobs is list of Doers
    bobs = demoing.setupDemoController(secrecies=secrecies,
                                       name=name,
                                       remotePort=remote,
                                       localPort=local)

    name = "eve"
    remote = 5620
    local = 5621

    #  create eve secrecies
    secrecies = [[signer.qb64] for signer in
                       core.Salter(raw=raw).signers(count=8,
                                                      path="eve",
                                                      temp=True)]

    eves = demoing.setupDemoController(secrecies=secrecies,
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

    raw = b"raw salt to test"

    name = "sam"
    remote = 5621
    local = 5620

    #  create sam secrecies
    secrecies = [[signer.qb64] for signer in
                    core.Salter(raw=raw).signers(count=8,
                                                   path="sam",
                                                   temp=True)]

    # sams is list of Doers
    sams = demoing.setupDemoController(secrecies=secrecies,
                                       name=name,
                                       remotePort=remote,
                                       localPort=local)


    name = "eve"
    remote = 5620
    local = 5621

     #  create eve secrecies
    secrecies = [[signer.qb64] for signer in
                       core.Salter(raw=raw).signers(count=8,
                                                      path="eve",
                                                      temp=True)]

    # eves is list of Doers
    eves = demoing.setupDemoController(secrecies=secrecies,
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
    """ Test indirect mode, sam and cam with witness """

    help.ogler.resetLevel(level=logging.DEBUG)

    raw = b"raw salt to test"

    #  create sam signers and secrecies
    samSigners = core.Salter(raw=raw).signers(count=8, path="sam", temp=True)
    samSecrecies = [[signer.qb64] for signer in samSigners]

    #  create cam signers and secrecies
    camSigners = core.Salter(raw=raw).signers(count=8, path="cam", temp=True)
    camSecrecies = [[signer.qb64] for signer in camSigners]

    with (habbing.openHby(name="cam", base="test", salt=core.Salter(raw=b'0123456789abcdef').qb64) as camHby,
          habbing.openHby(name="sam", base="test", salt=core.Salter(raw=b'0123456789abcdef').qb64) as samHby,
          habbing.openHby(name="wit", base="test", salt=core.Salter(raw=b'0123456789abcdef').qb64) as witHby):

        samPort = 5620  # sam's TCP listening port for server
        witPort = 5621  # wit' TCP listening port for server

        # setup the witness
        witHab = witHby.makeHab(name="Wit",
                                 isith='1',
                                 icount=1,
                                 transferable=False)

        wit = witHab.pre
        witServer = serving.Server(host="", port=witPort)
        witServerDoer = serving.ServerDoer(server=witServer)
        witDirectant = directing.Directant(hab=witHab, server=witServer)
        witDoers = [witServerDoer, witDirectant]

        # setup sam with witness
        sam = 'EIlGc6ZMlYj_v4Tr0j2LMonB-b6akMjIw6ThJLT2-cJe'
        samHab = samHby.makeHab(name="Sam", wits=[wit], secrecies=samSecrecies)
        assert samHab.pre == sam

        # confirm that makeHab works the same as manual setup
        # sam inception transferable (nxt digest not empty)
        serder = eventing.incept(keys=[samSigners[0].verfer.qb64], wits=[wit],
                                     ndigs=[coring.Diger(ser=samSigners[1].verfer.qb64b).qb64],
                                            code=coring.MtrDex.Blake3_256)

        assert samHab.iserder.said == serder.said  # same setup
        assert serder.ked["i"] == sam

        samClient = clienting.Client(host='127.0.0.1', port=witPort)
        samClientDoer = clienting.ClientDoer(client=samClient)

        samDirector = demoing.SamDirector(hab=samHab, client=samClient, tock=0.125)
        assert samDirector.hab == samHab
        assert samDirector.client == samClient
        assert id(samDirector.hab.kvy.kevers) == id(samHab.kevers)
        assert samDirector.hab.kvy.db == samHby.db
        assert samDirector.tock == 0.125

        samReactor = directing.Reactor(hab=samHab, client=samClient)
        assert samReactor.hab == samHab
        assert samReactor.client == samClient
        assert id(samReactor.hab.kvy.kevers) == id(samHab.kevers)
        assert samReactor.hab.kvy.db == samHby.db
        assert samReactor.hab.psr.ims == samReactor.client.rxbs

        samServer = serving.Server(host="", port=samPort)
        samServerDoer = serving.ServerDoer(server=samServer)

        samDirectant = directing.Directant(hab=samHab, server=samServer)
        assert samDirectant.hab == samHab
        assert samDirectant.server == samServer
        # Sam's Reactants created on demand

        samDoers = [samClientDoer, samDirector, samReactor, samServerDoer, samDirectant]

        # setup cam no witness
        camHab = camHby.makeHab(name="Cam", secrecies=camSecrecies)
        cam = camHab.pre

        # confirm that makeHab works same as manual setup
        # cam inception transferable (nxt digest not empty)
        serder = eventing.incept(keys=[camSigners[0].verfer.qb64],
                                        ndigs=[coring.Diger(ser=camSigners[1].verfer.qb64b).qb64],
                                        code=coring.MtrDex.Blake3_256)

        assert camHab.iserder.said == serder.said  # same setup
        assert cam == serder.ked["i"] == 'EB1f36VmoizOIpBIBv3X4ZiWJQWjtKJ7TMmsZltT0B32'

        camClient = clienting.Client(host='127.0.0.1', port=witPort)
        camClientDoer = clienting.ClientDoer(client=camClient)

        camDirector = demoing.CamDirector(hab=camHab, remotePre=sam, client=camClient, tock=0.125)
        assert camDirector.hab == camHab
        assert camDirector.client == camClient
        assert id(camDirector.hab.kvy.kevers) == id(camHab.kevers)
        assert camDirector.hab.kvy.db == camHby.db
        assert camDirector.tock == 0.125

        camReactor = directing.Reactor(hab=camHab, client=camClient, indirect=True)
        assert camReactor.hab == camHab
        assert camReactor.client == camClient
        assert id(camReactor.hab.kvy.kevers) == id(camHab.kevers)
        assert camReactor.hab.kvy.db == camHby.db
        assert camReactor.hab.psr.ims == camReactor.client.rxbs

        camDoers = [camClientDoer, camDirector, camReactor]

        # Manually stage SamDoers and wit doers and then camDoers

        tock = 0.03125
        doist = doing.Doist(doers=samDoers + witDoers, tock=tock)

        # manually prep doers
        doist.done = False
        doist.enter()  # injects doist.tymth() dependency to all doers
        assert len(doist.deeds) == len(samDoers + witDoers)
        while doist.tyme < doist.tock *  16:
            doist.recur()  # iterate 16 times
            time.sleep(doist.tock)

        assert len(doist.deeds) == len(samDoers + witDoers)
        assert not doist.done
        assert samHab.pre in samHab.kevers

        # now start up cam doers
        doist.extend(camDoers)
        assert len(doist.deeds) == len(samDoers + witDoers + camDoers)

        while doist.tyme < doist.tock * 32:
            doist.recur()  # iterate 16 times
            time.sleep(doist.tock)

        assert len(doist.deeds) == len(samDoers + witDoers + camDoers) - 1
        # camDirector completes
        assert camDirector.done
        assert not doist.done
        assert camHab.pre in camHab.kevers
        assert samHab.pre in camHab.kevers

        #  verify final event states
        doist.exit()
        assert samClient.opened is False
        assert samServer.opened is False
        assert camClient.opened is False



    assert not os.path.exists(camHby.db.path)
    assert not os.path.exists(samHby.db.path)
    assert not os.path.exists(witHby.db.path)

    help.ogler.resetLevel(level=help.ogler.level)
    """End Test"""


if __name__ == "__main__":
    test_direct_mode_bob_eve_demo()
    test_direct_mode_sam_eve_demo()
    test_run_bob_eve_demo()
    test_run_sam_eve_demo()
    test_indirect_mode_sam_cam_wit_demo()


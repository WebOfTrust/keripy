# -*- encoding: utf-8 -*-
"""
tests.db.dbing module

"""

import logging
import os
import socket

import pytest

from hio.base import doing
from hio.core.tcp import clienting, serving

from keri import help  # logger support
from keri import core, kering
from keri.core import eventing, coring, serdering

from keri.app import habbing, directing

from keri.demo import demoing
from tests.app import recurUntil


@pytest.fixture()
def direct_habs():
    """Provide temporary sender and receiver habitats for direct-mode tests."""
    with habbing.openHab(name="alice-directing", temp=True) as (_, alice), \
            habbing.openHab(name="bob-directing", temp=True) as (_, bob):
        yield alice, bob


def make_remoter(ims=b"", *, cutoff=False, cs=None, tymeout=None):
    """Create a synthetic Remoter without binding its diagnostic addresses."""
    remoter = serving.Remoter(
        ha=("127.0.0.1", 5632),
        ca=("127.0.0.1", 5633),
        cs=cs,
        tymeout=tymeout,
    )
    remoter.rxbs.extend(ims)
    remoter.cutoff = cutoff
    return remoter


def drain_socket(sock):
    """Return all currently readable bytes without blocking."""
    sock.setblocking(False)
    received = bytearray()
    while True:
        try:
            data = sock.recv(4096)
        except (BlockingIOError, OSError):
            break
        if not data:
            break
        received.extend(data)
    return bytes(received)


def test_directing_basic():
    """
    Test directing
    """
    help.ogler.resetLevel(level=logging.INFO)

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


def test_reactant_drains_complete_messages_after_cutoff(direct_habs):
    alice, bob = direct_habs

    first = alice.makeOwnEvent(sn=0)  # get the icp event
    alice.interact()
    second = alice.makeOwnEvent(sn=1)  # get the ixn event

    # buffer two complete CESR messages before EOF
    remoter = make_remoter(first + second, cutoff=True)
    reactant = directing.Reactant(hab=bob, remoter=remoter)
    assert not reactant.msgInProgress

    dog = reactant.msgDo(tymth=lambda: 0.0, tock=0.0)
    assert next(dog) == 0.0  # primes reactant msgDo generator fn

    # one recurrence completes one message so its successor prevents drain
    assert next(dog) == 0.0  # runs reactant msgDo generator fn
    assert not reactant.msgInProgress
    assert not reactant.rxDrained
    assert reactant.kevery.kevers[alice.pre].sn == 0

    # next recurrence completes the successor and reaches drain
    assert next(dog) == 0.0
    assert not reactant.msgInProgress
    assert reactant.rxDrained
    assert not reactant.rxFailed
    assert reactant.kevery.kevers[alice.pre].sn == 1
    dog.close()


def test_reactant_rejects_incomplete_message_at_cutoff(direct_habs):
    alice, bob = direct_habs

    message = alice.makeOwnEvent(sn=0)
    bodySize = serdering.SerderKERI(raw=message).size

    # exercise shortage in the body, at its boundary, and in attachments
    for cut in (10, bodySize, len(message) - 1):
        remoter = make_remoter(message[:cut], cutoff=True)
        reactant = directing.Reactant(hab=bob, remoter=remoter)
        assert not reactant.msgInProgress

        dog = reactant.msgDo(tymth=lambda: 0.0, tock=0.0)
        assert next(dog) == 0.0  # primes reactant msgDo generator fn
        assert next(dog) == 0.0  # runs reactant msgDo generator fn

        # EOF turns the incomplete final message into deterministic failure
        assert not reactant.msgInProgress
        assert not reactant.rxDrained
        assert reactant.rxFailed
        assert isinstance(reactant.rxError, kering.ShortageError)
        assert not remoter.rxbs
        dog.close()


def test_reactant_finishes_message_split_before_cutoff(direct_habs):
    alice, bob = direct_habs
    message = alice.makeOwnEvent(sn=0)
    split = len(message) // 2

    # feed only the first half while the connection remains open
    remoter = make_remoter(message[:split])
    reactant = directing.Reactant(hab=bob, remoter=remoter)
    dog = reactant.msgDo(tymth=lambda: 0.0, tock=0.0)

    assert next(dog) == 0.0  # primes reactant msgDo generator fn
    assert next(dog) == 0.0  # runs reactant msgDo generator fn
    # parser remains in progress while waiting for the remaining bytes
    assert reactant.msgInProgress
    assert not reactant.rxDrained
    assert not reactant.rxFailed

    # receiving of final bytes plus EOF let the active message reach its boundary
    remoter.rxbs.extend(message[split:])
    remoter.cutoff = True
    assert next(dog) == 0.0
    # complete boundary is drained instead of failed
    assert not reactant.msgInProgress
    assert reactant.rxDrained
    assert not reactant.rxFailed
    assert alice.pre in reactant.kevery.kevers
    dog.close()


def test_reactant_close_resets_message_in_progress(direct_habs):
    alice, bob = direct_habs
    message = alice.makeOwnEvent(sn=0)

    remoter = make_remoter(message[:len(message) // 2])
    reactant = directing.Reactant(hab=bob, remoter=remoter)
    dog = reactant.msgDo(tymth=lambda: 0.0, tock=0.0)

    # start parsing an incomplete message
    assert next(dog) == 0.0
    assert next(dog) == 0.0
    assert reactant.msgInProgress

    # forced parser teardown clears progress in finally
    dog.close()
    assert not reactant.msgInProgress


def test_directant_retains_buffered_input_after_cutoff(direct_habs):
    alice, bob = direct_habs

    remoterSocket, peerSocket = socket.socketpair()
    remoter = make_remoter(alice.makeOwnEvent(sn=0), cutoff=True,
                           cs=remoterSocket)
    ca = remoter.ca

    server = serving.Server()
    server.ixes[ca] = remoter
    directant = directing.Directant(hab=bob, server=server)
    doist = doing.Doist(tock=0.03125, limit=1.0,
                        doers=[directant])
    doist.enter()

    try:
        # cutoff with buffered input creates and retains a Reactant
        doist.recur()
        assert ca in server.ixes
        assert ca in directant.rants
        rant = directant.rants[ca]
        assert not rant.rxDrained

        # recur until parser drain allows connection teardown
        recurUntil(
            doist,
            condition=lambda: (ca not in server.ixes and
                               ca not in directant.rants),
            message="cutoff connection did not drain",
        )

        # teardown occurs only after successful message processing
        assert ca not in directant.rants
        assert rant.rxDrained
        assert not rant.rxFailed
        assert alice.pre in rant.kevery.kevers
    finally:
        doist.exit()
        server.close()
        peerSocket.close()


def test_directant_closes_cutoff_without_buffered_input(direct_habs):
    _, bob = direct_habs

    remoter = make_remoter(cutoff=True)
    ca = remoter.ca

    server = serving.Server()
    server.ixes[ca] = remoter
    directant = directing.Directant(hab=bob, server=server)
    directant.wind(lambda: 0.0)
    dog = directant.serviceDo(tymth=lambda: 0.0, tock=0.0)

    # cutoff without buffered input needs no Reactant
    next(dog)  # first generator run just goes to primed first yield
    next(dog)  # second runs Reactant, removes Remoter since no bytes in buffer
    # service closes both the remoter and lifecycle entry immediately
    assert ca not in server.ixes
    assert ca not in directant.rants

    dog.close()
    server.close()


def test_directant_timeout_delivers_receipt_for_buffered_input(direct_habs):
    alice, bob = direct_habs

    # keep the peer open so the close request comes from local timeout
    remoterSocket, peerSocket = socket.socketpair()
    remoter = make_remoter(alice.makeOwnEvent(sn=0),
                           cs=remoterSocket, tymeout=0.03125)
    ca = remoter.ca

    server = serving.Server()
    server.ixes[ca] = remoter
    directant = directing.Directant(hab=bob, server=server)
    doist = doing.Doist(tock=0.03125, limit=1.0, doers=[directant])
    doist.enter()
    received = bytearray()

    def closed():
        received.extend(drain_socket(peerSocket))
        return ca not in server.ixes and ca not in directant.rants

    try:
        # timeout retains the Reactant until its input and response both drain
        doist.recur()
        assert ca in directant.rants
        rant = directant.rants[ca]

        recurUntil(doist, condition=closed,
                   message="timed-out connection did not finish draining")
        received.extend(drain_socket(peerSocket))

        # parsing the final event produces a receipt before teardown
        assert alice.pre in rant.kevery.kevers
        assert rant.rxDrained
        assert rant.txDrained
        assert b'"t":"rct"' in received
    finally:
        doist.exit()
        server.close()
        peerSocket.close()


def test_directant_delivers_receipt_after_peer_half_close(
        direct_habs, unused_tcp_port):
    alice, bob = direct_habs

    # run the production Directant and ServerDoer against a real TCP peer
    server = serving.Server(host="127.0.0.1", port=unused_tcp_port)
    directant = directing.Directant(hab=bob, server=server)
    serverDoer = serving.ServerDoer(server=server)
    doist = doing.Doist(tock=0.03125, limit=2.0,
                        doers=[directant, serverDoer])
    doist.enter()

    peer = socket.create_connection(("127.0.0.1", unused_tcp_port))
    peer.sendall(alice.makeOwnEvent(sn=0))
    peer.shutdown(socket.SHUT_WR)
    received = bytearray()
    seen = []

    def closed():
        received.extend(drain_socket(peer))
        seen.extend(ca for ca in server.ixes if ca not in seen)
        return bool(seen) and not server.ixes and not directant.rants

    try:
        # receive EOF still leaves the TCP send side available for the receipt
        recurUntil(doist, condition=closed,
                   message="half-closed connection did not finish draining")
        received.extend(drain_socket(peer))

        assert alice.pre in bob.kevers
        assert b'"t":"rct"' in received
    finally:
        doist.exit()
        peer.close()


def test_directant_closes_after_terminal_send_failure(direct_habs):
    alice, bob = direct_habs

    remoterSocket, peerSocket = socket.socketpair()
    peerSocket.close()
    message = alice.makeOwnEvent(sn=0)
    remoter = make_remoter(message[:10], cutoff=True, cs=remoterSocket)
    remoter.tx(b"unsendable response")
    ca = remoter.ca

    server = serving.Server()
    server.ixes[ca] = remoter
    directant = directing.Directant(hab=bob, server=server)
    doist = doing.Doist(tock=0.03125, limit=1.0, doers=[directant])
    doist.enter()

    try:
        # a broken send side is terminal but does not bypass receiver cleanup
        doist.recur()
        assert ca in directant.txFailed
        rant = directant.rants[ca]

        recurUntil(
            doist,
            condition=lambda: (ca not in server.ixes and
                               ca not in directant.rants),
            message="terminal send failure did not close the connection",
        )

        assert rant.rxFailed
        assert remoter.txbs
    finally:
        doist.exit()
        server.close()


def test_runcontroller_demo():
    """
    Test demo runController function
    """
    help.ogler.resetLevel(level=logging.DEBUG)

    name = "bob"  # must be one of 'bob', 'sam', 'eve'
    remote = 5621
    local = 5620
    expire = 1.0

    raw = b"raw salt to test"

    #  create secrecies
    secrecies = [[signer.qb64] for signer in
                 core.Salter(raw=raw).signers(count=8,
                                                path=name,
                                                temp=True)]

    doers = demoing.setupDemoController(secrecies=secrecies,
                                        name=name,
                                        remotePort=remote,
                                        localPort=local)

    directing.runController(doers=doers, expire=expire)

    help.ogler.resetLevel(level=help.ogler.level)
    """End Test"""


if __name__ == "__main__":
    test_directing_basic()

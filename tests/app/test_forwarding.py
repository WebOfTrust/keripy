# -*- encoding: utf-8 -*-
"""
KERI
tests.app.forwarding module

"""
import time
import pytest

from hio.base import doing, tyming

from keri import core
from keri.core import coring, eventing, parsing, serdering

from keri.app import forwarding, habbing, indirecting, storing

from keri.db import dbing
from keri.peer import exchanging


@pytest.mark.parametrize("transferable", [False, True])
def test_introduce_receipt_from_target(transferable):
    """Only Bob's verified receipt of Alice's latest event skips introduction.

    Alice is the sender being introduced to destination Bob; Carol is an
    unrelated receiptor. Real receipts are signed, parsed, and checked in
    Alice's receipt store before testing the introduction decision. With no
    receipt, Alice sends the full introduction. Carol's receipt does not
    suppress it; Bob's receipt does. After Alice adds an interaction event,
    Bob's older receipt no longer suppresses introduction.

    Both transferable and nontransferable destination AIDs are exercised.
    """
    with habbing.openHab(name="alice", temp=True) as (_, alice), \
            habbing.openHab(name="bob", temp=True,
                            transferable=transferable) as (_, bob), \
            habbing.openHab(name="carol", temp=True,
                            transferable=transferable) as (_, carol):
        expected = alice.replay()
        expected.extend(alice.replyEndRole(cid=alice.pre))
        assert expected
        assert forwarding.introduce(alice, bob.pre) == expected

        parser = parsing.Parser()
        kvy = eventing.Kevery(db=alice.db, lax=False, local=False)
        for peer in (carol, bob):
            # Verify a real receipt after learning the receiptor's keys.
            parser.parse(ims=bytearray(peer.makeOwnInception()), kvy=kvy)
            peer.psr.parse(ims=bytearray(alice.makeOwnInception()))
            parser.parse(ims=bytearray(peer.receipt(alice.kever.serder)), kvy=kvy)
            dgkey = dbing.dgKey(alice.pre, alice.kever.serder.said)
            if transferable:
                receiptors = [eventing.deTransReceiptQuadruple(raw)[0].qb64
                              for raw in alice.db.getVrcsIter(dgkey)]
            else:
                receiptors = [eventing.deReceiptCouple(raw)[0].qb64
                              for raw in alice.db.getRctsIter(dgkey)]
            assert peer.pre in receiptors

            if peer is carol:
                # Another receiptor must not suppress introduction to Bob.
                assert forwarding.introduce(alice, bob.pre)

        assert forwarding.introduce(alice, bob.pre) == bytearray()

        # A receipt for the inception does not acknowledge a newer event.
        alice.interact()
        assert forwarding.introduce(alice, bob.pre)


def test_postman(seeder):
    with habbing.openHab(name="test", transferable=True, temp=True) as (hby, hab), \
            habbing.openHby(name="wes", salt=core.Salter(raw=b'wess-the-witness').qb64, temp=True) as wesHby, \
            habbing.openHby(name="repTest", temp=True) as recpHby:

        mbx = storing.Mailboxer(name="wes", temp=True)
        wesDoers = indirecting.setupWitness(alias="wes", hby=wesHby, mbx=mbx, tcpPort=5634, httpPort=5644)
        wesHab = wesHby.habByName("wes")
        seeder.seedWitEnds(hby.db, witHabs=[wesHab])
        seeder.seedWitEnds(wesHby.db, witHabs=[wesHab])
        seeder.seedWitEnds(recpHby.db, witHabs=[wesHab])

        recpHab = recpHby.makeHab(name="repTest", transferable=True, wits=[wesHab.pre])

        recpIcp = recpHab.makeOwnEvent(sn=0)
        wesKvy = eventing.Kevery(db=wesHab.db, lax=False, local=False)
        parsing.Parser().parse(ims=bytearray(recpIcp), kvy=wesKvy, local=True)
        assert recpHab.pre in wesKvy.kevers

        serder = serdering.SerderKERI(raw=recpIcp)
        rct = wesHab.receipt(serder)

        kvy = eventing.Kevery(db=hab.db)
        parsing.Parser().parseOne(bytearray(recpIcp), kvy=kvy, local=True)
        parsing.Parser().parseOne(bytearray(rct), kvy=kvy, local=True)
        kvy.processEscrows()
        assert recpHab.pre in kvy.kevers

        pman = forwarding.Poster(hby=hby)

        exn, _ = exchanging.exchange(route="/echo", payload=dict(msg="test"), sender=hab.pre)
        atc = hab.endorse(exn, last=False)
        del atc[:exn.size]
        pman.send(src=hab.pre, dest=recpHab.pre, topic="echo", serder=exn, attachment=atc)

        doers = wesDoers + [pman]
        limit = 1.0
        tock = 0.03125
        doist = doing.Doist(tock=tock, limit=limit, doers=doers)
        doist.enter()

        tymer = tyming.Tymer(tymth=doist.tymen(), duration=doist.limit)

        while not tymer.expired:
            doist.recur()
            time.sleep(doist.tock)

        assert doist.limit == limit

        doist.exit()

        msgs = []
        for _, topic, msg in mbx.cloneTopicIter(topic=recpHab.pre + "/echo"):
            msgs.append(msg)

        assert len(msgs) == 1
        serder = serdering.SerderKERI(raw=msgs[0])
        assert serder.ked["t"] == coring.Ilks.exn
        assert serder.ked["r"] == "/echo"
        assert serder.ked["a"] == dict(msg="test")


def test_forward_handler():
    with habbing.openHab(name="test", transferable=True, temp=True) as (hby, hab):
        mbx = storing.Mailboxer()
        forwarder = forwarding.ForwardHandler(hby=hby, mbx=mbx)
        # TODO: implement a real test here

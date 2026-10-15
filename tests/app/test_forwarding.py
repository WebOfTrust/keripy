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
def test_introduce_without_destination_receipt(transferable):
    """Alice must introduce herself to Bob until Bob receipts her latest event.

    Bob is the destination and never signs a receipt in this test. First,
    Alice has no receipts and must send her full introduction. Then Carol,
    an unrelated receiptor, signs Alice's inception. Parsing and confirming
    Carol's receipt in Alice's store must still leave introduction to Bob
    necessary. Exercise both transferable and nontransferable receipts.
    """
    with habbing.openHab(name="alice", temp=True) as (_, alice), \
            habbing.openHab(name="bob", temp=True,
                            transferable=transferable) as (_, bob), \
            habbing.openHab(name="carol", temp=True,
                            transferable=transferable) as (_, carol):
        # Build the full history and endpoint-reply payload Bob needs initially.
        expected = alice.replay()
        expected.extend(alice.replyEndRole(cid=alice.pre))
        assert expected  # Ensure the expected introduction contains bytes.
        # Without Bob's receipt, Alice must send the full introduction.
        assert forwarding.introduce(alice, bob.pre) == expected

        # Alice learns Carol's keys so she can verify Carol's receipt.
        parser = parsing.Parser()
        kvy = eventing.Kevery(db=alice.db, lax=False, local=False)
        parser.parse(ims=bytearray(carol.makeOwnInception()), kvy=kvy)
        # Carol accepts Alice's inception, then signs a receipt of that event.
        carol.psr.parse(ims=bytearray(alice.makeOwnInception()))
        msg = carol.receipt(alice.kever.serder)
        # Alice verifies the receipt and stores its signature under her event.
        parser.parse(ims=bytearray(msg), kvy=kvy)

        dgkey = dbing.dgKey(alice.pre, alice.kever.serder.said)
        if transferable:
            receipts = [eventing.deTransReceiptQuadruple(raw)
                        for raw in alice.db.getVrcsIter(dgkey)]
            receiptors = [
                receiptor_prefix.qb64
                for receiptor_prefix, _est_sn, _est_said, _signature in receipts
            ]
        else:
            receipts = [eventing.deReceiptCouple(raw)
                        for raw in alice.db.getRctsIter(dgkey)]
            receiptors = [receiptor_prefix.qb64
                          for receiptor_prefix, _signature in receipts]
        assert carol.pre in receiptors  # Carol's verified receipt was stored.
        assert bob.pre not in receiptors  # Bob has not acknowledged Alice's event.

        # Return introduction bytes: Carol's receipt cannot stand in for Bob's.
        assert forwarding.introduce(alice, bob.pre)


@pytest.mark.parametrize("transferable", [False, True])
def test_introduce_with_destination_receipt(transferable):
    """Bob's receipt suppresses introduction only for Alice's acknowledged event.

    Alice is the sender and Bob is the destination. Bob signs a real receipt
    of Alice's inception; Alice parses it and confirms Bob is in her receipt
    store. That receipt suppresses introduction. Alice then adds an interaction
    event, so Bob's older receipt no longer suffices and introduction resumes.
    Exercise both transferable and nontransferable receipts.
    """
    with habbing.openHab(name="alice", temp=True) as (_, alice), \
            habbing.openHab(name="bob", temp=True,
                            transferable=transferable) as (_, bob):
        # Alice learns Bob's keys so she can verify Bob's receipt.
        parser = parsing.Parser()
        kvy = eventing.Kevery(db=alice.db, lax=False, local=False)
        parser.parse(ims=bytearray(bob.makeOwnInception()), kvy=kvy)
        # Bob accepts Alice's inception, then signs a receipt of that event.
        bob.psr.parse(ims=bytearray(alice.makeOwnInception()))
        msg = bob.receipt(alice.kever.serder)
        # Alice verifies the receipt and stores its signature under her event.
        parser.parse(ims=bytearray(msg), kvy=kvy)

        dgkey = dbing.dgKey(alice.pre, alice.kever.serder.said)
        if transferable:
            receipts = [eventing.deTransReceiptQuadruple(raw)
                        for raw in alice.db.getVrcsIter(dgkey)]
            receiptors = [
                receiptor_prefix.qb64
                for receiptor_prefix, _est_sn, _est_said, _signature in receipts
            ]
        else:
            receipts = [eventing.deReceiptCouple(raw)
                        for raw in alice.db.getRctsIter(dgkey)]
            receiptors = [receiptor_prefix.qb64
                          for receiptor_prefix, _signature in receipts]
        assert bob.pre in receiptors  # Bob's verified receipt was stored.
        # Return no introduction bytes: Bob already acknowledged this event.
        assert forwarding.introduce(alice, bob.pre) == bytearray()

        # Advance Alice's KEL beyond the inception Bob acknowledged.
        alice.interact()
        # Return introduction bytes again: Bob has not receipted the new event.
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

# -*- encoding: utf-8 -*-
"""
KERI
tests.app.forwarding module

"""
import time
import falcon

from hio.base import doing, tyming
from hio.core import http

from keri import help
from keri.core import (Salter, Pather, Prefixer,
                       Bexter, Kevery, Parser, SerderKERI)
from keri.kering import Vrsn_1_0, Ilks, Roles, Schemes

from keri.app import (Mailboxer, ForwardHandler, Poster,
                      StreamPoster, HttpEnd,
                      openHab, openHby, setupWitness)

from keri.peer import exchanging
from keri.spac import payloading


def test_postman(seeder):
    with openHab(name="test", transferable=True, temp=True) as (hby, hab), \
            openHby(name="wes", salt=Salter(raw=b'wess-the-witness').qb64, temp=True) as wesHby, \
            openHby(name="repTest", temp=True) as recpHby:

        mbx = Mailboxer(name="wes", temp=True)
        wesDoers = setupWitness(alias="wes", hby=wesHby, mbx=mbx, tcpPort=5634, httpPort=5644)
        wesHab = wesHby.habByName("wes")
        seeder.seedWitEnds(hby.db, witHabs=[wesHab])
        seeder.seedWitEnds(wesHby.db, witHabs=[wesHab])
        seeder.seedWitEnds(recpHby.db, witHabs=[wesHab])

        recpHab = recpHby.makeHab(name="repTest", transferable=True, wits=[wesHab.pre])

        recpIcp = recpHab.makeOwnEvent(sn=0)
        wesKvy = Kevery(db=wesHab.db, lax=False, local=False)
        Parser(version=Vrsn_1_0).parse(ims=bytearray(recpIcp), kvy=wesKvy, local=True)
        assert recpHab.pre in wesKvy.kevers

        serder = SerderKERI(raw=recpIcp)
        rct = wesHab.receipt(serder)

        kvy = Kevery(db=hab.db)
        Parser(version=Vrsn_1_0).parseOne(bytearray(recpIcp), kvy=kvy, local=True)
        Parser(version=Vrsn_1_0).parseOne(bytearray(rct), kvy=kvy, local=True)
        kvy.processEscrows()
        assert recpHab.pre in kvy.kevers

        pman = Poster(hby=hby)

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
        serder = SerderKERI(raw=msgs[0])
        assert serder.ked["t"] == Ilks.exn
        assert serder.ked["r"] == "/echo"
        assert serder.ked["a"] == dict(msg="test")


def test_forward_handler():
    with openHab(name="sender", transferable=True, temp=True) as (hby, hab), \
         openHab(name="recp", transferable=True, temp=True) as (recpHby, recpHab), \
         openHab(name="recp2", transferable=True, temp=True) as (recp2Hby, recp2Hab):

        mbx = Mailboxer(temp=True)
        forwarder = ForwardHandler(hby=hby, mbx=mbx)

        # Happy path: single embed
        inner_exn, _ = exchanging.exchange(route="/echo", payload=dict(msg="hello"), sender=hab.pre)
        inner_atc = hab.endorse(inner_exn, last=False)
        del inner_atc[:inner_exn.size]

        evt = bytearray(inner_exn.raw)
        evt.extend(inner_atc)
        fwd, _ = exchanging.exchange(
            route='/fwd',
            modifiers=dict(pre=recpHab.pre, topic="echo"),
            payload={},
            embeds=dict(evt=evt),
            sender=hab.pre,
        )
        pather = Pather(path=["evt"])
        forwarder.handle(serder=fwd, attachments=[(pather, inner_atc)])

        msgs = list(mbx.cloneTopicIter(topic=f"{recpHab.pre}/echo"))
        assert len(msgs) == 1
        _, _, raw = msgs[0]

        # Field-level correctness
        stored = SerderKERI(raw=raw)
        assert stored.ked["t"] == Ilks.exn
        assert stored.ked["r"] == "/echo"
        assert stored.ked["a"] == dict(msg="hello")

        # Byte-level fidelity: stored blob must start with the exact serder bytes
        # and total length must equal serder + attachment
        assert raw[:inner_exn.size] == bytes(inner_exn.raw)
        assert len(raw) == len(inner_exn.raw) + len(inner_atc)

        # Topic/recipient routing isolation
        # Same recipient, different topic
        inner_exn2, _ = exchanging.exchange(route="/delegate", payload=dict(msg="delegate"), sender=hab.pre)
        inner_atc2 = hab.endorse(inner_exn2, last=False)
        del inner_atc2[:inner_exn2.size]

        evt2 = bytearray(inner_exn2.raw)
        evt2.extend(inner_atc2)
        fwd2, _ = exchanging.exchange(
            route='/fwd',
            modifiers=dict(pre=recpHab.pre, topic="delegate"),
            payload={},
            embeds=dict(evt=evt2),
            sender=hab.pre,
        )
        forwarder.handle(serder=fwd2, attachments=[(Pather(path=["evt"]), inner_atc2)])

        echo_msgs = list(mbx.cloneTopicIter(topic=f"{recpHab.pre}/echo"))
        delegate_msgs = list(mbx.cloneTopicIter(topic=f"{recpHab.pre}/delegate"))
        assert len(echo_msgs) == 1    # unchanged
        assert len(delegate_msgs) == 1

        # Different recipient, same topic
        inner_exn3, _ = exchanging.exchange(route="/echo", payload=dict(msg="other"), sender=hab.pre)
        inner_atc3 = hab.endorse(inner_exn3, last=False)
        del inner_atc3[:inner_exn3.size]

        evt3 = bytearray(inner_exn3.raw)
        evt3.extend(inner_atc3)
        fwd3, _ = exchanging.exchange(
            route='/fwd',
            modifiers=dict(pre=recp2Hab.pre, topic="echo"),
            payload={},
            embeds=dict(evt=evt3),
            sender=hab.pre,
        )
        forwarder.handle(serder=fwd3, attachments=[(Pather(path=["evt"]), inner_atc3)])

        recp1_echo = list(mbx.cloneTopicIter(topic=f"{recpHab.pre}/echo"))
        recp2_echo = list(mbx.cloneTopicIter(topic=f"{recp2Hab.pre}/echo"))
        assert len(recp1_echo) == 1   # unchanged
        assert len(recp2_echo) == 1

        # Multiple attachments in one call
        # Two embeds in a single /fwd: both must appear in the stored blob
        inner_exnA, _ = exchanging.exchange(route="/echo", payload=dict(msg="A"), sender=hab.pre)
        inner_atcA = hab.endorse(inner_exnA, last=False)
        del inner_atcA[:inner_exnA.size]

        inner_exnB, _ = exchanging.exchange(route="/echo", payload=dict(msg="B"), sender=hab.pre)
        inner_atcB = hab.endorse(inner_exnB, last=False)
        del inner_atcB[:inner_exnB.size]

        evtA = bytearray(inner_exnA.raw); evtA.extend(inner_atcA)
        evtB = bytearray(inner_exnB.raw); evtB.extend(inner_atcB)
        fwd_multi, _ = exchanging.exchange(
            route='/fwd',
            modifiers=dict(pre=recpHab.pre, topic="multi"),
            payload={},
            embeds=dict(evtA=evtA, evtB=evtB),
            sender=hab.pre,
        )
        patherA = Pather(path=["evtA"])
        patherB = Pather(path=["evtB"])
        forwarder.handle(serder=fwd_multi, attachments=[(patherA, inner_atcA), (patherB, inner_atcB)])

        multi_msgs = list(mbx.cloneTopicIter(topic=f"{recpHab.pre}/multi"))
        assert len(multi_msgs) == 1
        _, _, multi_raw = multi_msgs[0]
        # Both serder payloads must be present in the concatenated blob
        assert bytes(inner_exnA.raw) in multi_raw
        assert bytes(inner_exnB.raw) in multi_raw

        # Edge: empty attachments, pevt stays empty, nothing stored
        count_before = len(list(mbx.cloneTopicIter(topic=f"{recpHab.pre}/echo")))
        forwarder.handle(serder=fwd, attachments=[])
        count_after = len(list(mbx.cloneTopicIter(topic=f"{recpHab.pre}/echo")))
        assert count_after == count_before


def test_essr_stream(seeder):
    with openHab(name="test", transferable=True, temp=True) as (hby, hab), \
            openHab(name="test", transferable=True, temp=True) as (recpHby, recpHab):

        app = falcon.App()
        httpEnd = HttpEnd(rxbs=recpHab.psr.ims)
        app.add_route("/", httpEnd)
        server = http.Server(port=5555, app=app)
        httpServerDoer = http.ServerDoer(server=server)

        kvy = Kevery(db=hab.db)
        Parser(version=Vrsn_1_0).parseOne(bytearray(recpHab.makeOwnEvent(sn=0)), kvy=kvy, local=True)
        kvy.processEscrows()
        assert recpHab.pre in kvy.kevers

        recpKvy = Kevery(db=recpHab.db)
        icp = hab.makeOwnEvent(sn=0)
        Parser(version=Vrsn_1_0).parseOne(bytearray(icp), kvy=recpKvy, local=True)
        kvy.processEscrows()
        assert hab.pre in recpKvy.kevers

        msgs = bytearray()
        msgs.extend(recpHab.makeEndRole(eid=recpHab.pre,
                                        role=Roles.controller,
                                        stamp=help.nowIso8601()))

        msgs.extend(recpHab.makeLocScheme(url='http://127.0.0.1:5555',
                                          scheme=Schemes.http,
                                          stamp=help.nowIso8601()))
        hab.psr.parse(ims=msgs)

        postman = StreamPoster(hby=hby, hab=hab, recp=recpHab.pre, essr=True)

        # Test chunking
        saids = []
        for i in range(0, 40):
            exn, _ = exchanging.exchange(route="/echo", payload=dict(msg="test", i=i), sender=hab.pre)
            atc = hab.endorse(exn, last=False)
            del atc[:exn.size]

            postman.send(exn, atc)
            saids.append(exn.said)

        doers = [httpServerDoer, doing.DoDoer(doers=postman.deliver())]
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

        recpHby.psr.parse()  # ims already populated from http server

        iter = recpHby.db.exns.getTopItemIter()
        essrSaidA, essrSerderA = next(iter)
        assert essrSerderA.ked["r"] == "/essr/req"
        assert essrSerderA.ked["q"] == {'src': hab.pre, 'dest': recpHab.pre}

        essrSaidB, essrSerderB = next(iter)
        iter.close()
        assert essrSerderB.ked["r"] == "/essr/req"
        assert essrSerderB.ked["q"] == {'src': hab.pre, 'dest': recpHab.pre}

        texter = recpHby.db.essrs.get(essrSaidA)[0]
        ims = bytearray(recpHab.decrypt(texter.raw))

        tag = recpHby.psr.extract(ims, payloading.PayloadTyper)
        assert tag.type == payloading.PayloadTypes.SCS
        pre = recpHby.psr.extract(ims, Prefixer)
        assert pre.qb64 == hab.pre  # encrypt sender
        pad = recpHby.psr.extract(ims, Bexter)
        assert pad.bext == ""
        recpHby.psr.parse(ims=ims)

        texter = recpHby.db.essrs.get(essrSaidB)[0]
        ims = bytearray(recpHab.decrypt(texter.raw))

        _tag = recpHby.psr.extract(ims, payloading.PayloadTyper)
        _pre = recpHby.psr.extract(ims, Prefixer)
        _pad = recpHby.psr.extract(ims, Bexter)
        recpHby.psr.parse(ims=ims)

        # Both chunks present
        # Can come out of order, so need to parse both ESSR packets first for test to be reliable
        serder = recpHby.db.exns.get(saids[0])
        assert serder.ked["t"] == Ilks.exn
        assert serder.ked["r"] == "/echo"
        assert serder.ked["a"] == dict(msg="test", i=0)

        serder = recpHby.db.exns.get(saids[39])
        assert serder.ked["t"] == Ilks.exn
        assert serder.ked["r"] == "/echo"
        assert serder.ked["a"] == dict(msg="test", i=39)


def test_essr_mbx(seeder):
    with openHab(name="test", transferable=True, temp=True) as (hby, hab), \
            openHby(name="wes", salt=Salter(raw=b'wess-the-witness').qb64, temp=True) as wesHby, \
            openHby(name="repTest", temp=True) as recpHby:

        mbx = Mailboxer(name="wes", temp=True)
        wesDoers = setupWitness(alias="wes", hby=wesHby, mbx=mbx, tcpPort=5634, httpPort=5644)
        wesHab = wesHby.habByName("wes")
        seeder.seedWitEnds(hby.db, witHabs=[wesHab])
        seeder.seedWitEnds(wesHby.db, witHabs=[wesHab])
        seeder.seedWitEnds(recpHby.db, witHabs=[wesHab])

        recpHab = recpHby.makeHab(name="repTest", transferable=True, wits=[wesHab.pre])

        recpIcp = recpHab.makeOwnEvent(sn=0)
        wesKvy = Kevery(db=wesHab.db, lax=False, local=False)
        Parser(version=Vrsn_1_0).parse(ims=bytearray(recpIcp), kvy=wesKvy, local=True)
        assert recpHab.pre in wesKvy.kevers

        serder = SerderKERI(raw=recpIcp)
        rct = wesHab.receipt(serder)

        kvy = Kevery(db=hab.db)
        Parser(version=Vrsn_1_0).parseOne(bytearray(recpIcp), kvy=kvy, local=True)
        Parser(version=Vrsn_1_0).parseOne(bytearray(rct), kvy=kvy, local=True)
        kvy.processEscrows()
        assert recpHab.pre in kvy.kevers

        recpKvy = Kevery(db=recpHab.db)
        icp = hab.makeOwnEvent(sn=0)
        Parser(version=Vrsn_1_0).parseOne(bytearray(icp), kvy=recpKvy, local=True)
        kvy.processEscrows()
        assert hab.pre in recpKvy.kevers

        postman = StreamPoster(hby=hby, hab=hab, recp=recpHab.pre, topic="echo", essr=True)

        # Test chunking
        saids = []
        for i in range(0, 15):
            exn, _ = exchanging.exchange(route="/echo", payload=dict(msg="test", i=i), sender=hab.pre)
            atc = hab.endorse(exn, last=False)
            del atc[:exn.size]

            postman.send(exn, atc)
            saids.append(exn.said)

        doers = wesDoers + [doing.DoDoer(doers=postman.deliver())]
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

        iter = wesHby.db.exns.getTopItemIter()
        essrSaidA, essrSerderA = next(iter)
        assert essrSerderA.ked["r"] == "/essr/req"
        assert essrSerderA.ked["q"] == {'src': hab.pre, 'dest': wesHab.pre}

        essrSaidB, essrSerderB = next(iter)
        iter.close()
        assert essrSerderB.ked["r"] == "/essr/req"
        assert essrSerderB.ked["q"] == {'src': hab.pre, 'dest': wesHab.pre}

        texter = wesHby.db.essrs.get(essrSaidA)[0]
        ims = bytearray(wesHab.decrypt(texter.raw))

        tag = wesHby.psr.extract(ims, payloading.PayloadTyper)
        assert tag.type == payloading.PayloadTypes.SCS
        pre = wesHby.psr.extract(ims, Prefixer)
        assert pre.qb64 == hab.pre  # encrypt sender
        pad = wesHby.psr.extract(ims, Bexter)
        assert pad.bext == ""

        forwarder = ForwardHandler(hby=hby, mbx=mbx)
        exchanger = exchanging.Exchanger(hby=hby, handlers=[forwarder])
        parser = Parser(framed=True,
                                kvy=wesHby.kvy,
                                exc=exchanger,
                                version=Vrsn_1_0)
        parser.parse(ims=ims)

        texter = wesHby.db.essrs.get(essrSaidB)[0]
        ims = bytearray(wesHab.decrypt(texter.raw))

        _tag = wesHby.psr.extract(ims, payloading.PayloadTyper)
        _pre = wesHby.psr.extract(ims, Prefixer)
        _pad = wesHby.psr.extract(ims, Bexter)
        parser.parse(ims=ims)

        mbxSaids = []
        for _, topic, msg in mbx.cloneTopicIter(topic=recpHab.pre + "/echo"):
            serder = SerderKERI(raw=msg)
            assert serder.ked["t"] == Ilks.exn
            assert serder.ked["r"] == "/echo"
            mbxSaids.append(serder.said)

        assert len(mbxSaids) == 15

        # Chunks can come out of order, so check for difference of SAIDs
        assert set(saids) == set(mbxSaids)

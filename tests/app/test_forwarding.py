# -*- encoding: utf-8 -*-
"""
KERI
tests.app.forwarding module

"""
import time
from types import SimpleNamespace

import falcon
import pytest
from falcon import testing

from hio.base import doing, tyming
from hio.core import http

from keri import help
from keri.acdc import (RegBaser, Regery, Registrar, acdcmap,
                       grant as ipexGrant, loadHandlers)
from keri.core import (Salter, Pather, Prefixer, Diger,
                       Bexter, Kevery, Parser, SerderKERI, exchange, messagize, receipt)
from keri.kering import Vrsn_1_0, Vrsn_2_0, Ilks, Roles, Schemes, Kinds

from keri.app import (Mailboxer, ForwardHandler, Poster,
                      StreamPoster, HttpEnd,
                      openHab, openHby, setupWitness)

from keri.db import openLMDB
from keri.peer import specialExchange, Exchanger, serializeMessage, verify
from keri.peer.exchanging import loadParsedNestedSubstreams
from keri.spac import payloading



@pytest.mark.parametrize("role", [Roles.witness, Roles.mailbox])
@pytest.mark.parametrize("version, gvrsn", [(Vrsn_1_0, None), (Vrsn_2_0, None),
                                            (Vrsn_2_0, Vrsn_1_0), (Vrsn_2_0, Vrsn_2_0)])
def test_stream_poster_selects_forwarding_protocol_and_framing(monkeypatch, role, version, gvrsn):
    with openHby(name="sender", temp=True, version=Vrsn_2_0) as hby, \
            openHab(name="receiver", temp=True) as (_, recp):
        hab = hby.makeHab(name="sender", version=Vrsn_1_0, kind=Kinds.json)
        event = exchange(sender=hab.pre, route="/echo", attributes=dict(msg="test"),
                         version=Vrsn_1_0, kind=Kinds.json)
        incoming = gvrsn if gvrsn is not None else version
        message = hab.endorse(event, last=False, framed=False, gvrsn=incoming)
        original = Parser(version=incoming).parse(ims=bytearray(message), processive=False)[0]
        poster = StreamPoster(hby=hby, hab=hab, recp=recp.pre,
                              topic="echo", version=version if version == Vrsn_1_0 else None)
        monkeypatch.setattr(hab, "endsFor", lambda pre: {role: {recp.pre: {}}})
        kwa = dict(gvrsn=gvrsn) if gvrsn is not None else {}
        poster.send(serder=event, attachment=message[event.size:], **kwa)
        queued = poster.evts[0]
        parsed = Parser(version=version).parse(
            ims=bytearray(queued["serder"].raw + queued["attachment"]), processive=False)
        assert len(parsed) == 1
        assert parsed[0].serder.pvrsn == version
        if version == Vrsn_2_0:
            assert parsed[0].serder.gvrsn == Vrsn_2_0
            assert parsed[0].serder.ked["a"] == dict(evt=Diger(ser=event.raw).qb64)
            child = parsed[0].nests[0]
            assert child.serder.raw == event.raw
            assert child.serder.pvrsn == Vrsn_1_0
            assert len(child.tsgs) == len(original.tsgs) == 1
            assert [siger.qb64b for siger in child.tsgs[0][3]] == [
                siger.qb64b for siger in original.tsgs[0][3]]
        else:
            assert parsed[0].serder.ked["e"]["evt"] == event.ked
            assert len(parsed[0].ptds) == 1


@pytest.mark.parametrize("hab_version", [Vrsn_1_0, Vrsn_2_0])
@pytest.mark.parametrize("version", [None, Vrsn_1_0, Vrsn_2_0])
def test_essr_wrapper_preserves_explicit_and_default_attachment_version(hab_version, version):
    with openHab(name="sender", temp=True, version=hab_version) as (hby, hab), \
            openHab(name="receiver", temp=True, transferable=False) as (_, recp):
        poster = StreamPoster(hby=hby, hab=hab, recp=recp.pre, version=version)
        original = b"encrypted forwarding payload"
        stream = poster._essrWrapper(hab, original, recp.pre)
        parsed = Parser(version=version or hab_version).parse(ims=stream, processive=False)
        assert len(parsed) == 1
        assert parsed[0].serder.pvrsn == Vrsn_1_0
        assert len(parsed[0].essrs) == 1
        assert recp.decrypt(parsed[0].essrs[0].raw) == original


@pytest.mark.parametrize("kind", [Kinds.json, Kinds.cbor, Kinds.mgpk])
def test_stream_poster_forwards_native_grant_with_registry_proof(monkeypatch, kind):
    with openHab(name="issuer", temp=True, version=Vrsn_2_0) as (hby, hab), \
            openHab(name="holder", temp=True, version=Vrsn_2_0) as (rhby, recp), \
            openHab(name="witness", transferable=False, temp=True, version=Vrsn_2_0) as (whby, wit), \
            openLMDB(cls=RegBaser, name="issuer") as ibaser, \
            openLMDB(cls=RegBaser, name="holder") as rbaser, \
            openLMDB(cls=Mailboxer, name="witness") as mbx:
        irgy = Regery(hby=hby, baser=ibaser)
        rrgy = Regery(hby=rhby, baser=rbaser)
        registrar = Registrar(rgy=irgy)
        registry = registrar.makeRegistry(name="credential", prefix=hab.pre)
        rip = irgy.store.event(registry.regk)
        hab.interact(data=[dict(i=registry.regk, s=rip.sad["n"], d=rip.said)],
                     gvrsn=Vrsn_2_0)
        assert registry.anchorMsg(rip.said)

        acdc = acdcmap(israid=hab.pre, regid=registry.regk,
                       attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                       iseaid=recp.pre)
        blinder, issued = registrar.issue(registry, acdc=acdc, state="issued")
        hab.interact(data=[dict(i=registry.regk, s=issued.sad["n"], d=issued.said)],
                     gvrsn=Vrsn_2_0)
        assert registry.anchorMsg(issued.said)
        origin = messagize(acdc, bonds=[blinder.data], gvrsn=Vrsn_2_0)
        grant, atc = ipexGrant(hab, recp.pre, "Here is the credential", origin)

        # Supply the receiver's proof history separately from transport.
        rrgy.store.accept(registry.regk, 0, rip)
        rrgy.store.accept(registry.regk, 1, issued)
        notices = []
        exc = Exchanger(hby=rhby, handlers=[])
        loadHandlers(hby=rhby, exc=exc, rgy=rrgy,
                     notifier=SimpleNamespace(add=lambda attrs: notices.append(attrs)))
        receiver = Parser(kvy=rhby.kvy, exc=exc, framed=True, version=Vrsn_2_0)
        receiver.parse(ims=hab.replay(gvrsn=Vrsn_2_0), local=False)

        witness = Parser(kvy=whby.kvy, framed=True, version=Vrsn_2_0,
                         exc=Exchanger(hby=whby, handlers=[ForwardHandler(hby=whby, mbx=mbx)]))
        endpoint = HttpEnd(rxbs=witness.ims, mbx=mbx)
        monkeypatch.setattr(hab, "endsFor", lambda pre: {
            Roles.witness: {wit.pre: {Schemes.http: "http://127.0.0.1:9999"}}
        })
        postman = StreamPoster(hby=hby, hab=hab, recp=recp.pre,
                               topic="credential", kind=kind)
        postman.send(serder=grant, attachment=atc)
        assert postman.evts[0]["serder"].pvrsn == Vrsn_2_0
        assert postman.evts[0]["serder"].gvrsn == Vrsn_2_0
        messengers = postman.deliver()
        assert len(messengers) == 1
        requests = list(messengers[0].client.requests)
        assert len(requests) == 1
        request = requests[0]
        assert request["method"] == "PUT"
        req = falcon.Request(testing.create_environ(
            method="PUT", body=bytes(request["body"]),
            headers={key: str(value) for key, value in request["headers"].items()}))
        rep = falcon.Response()
        endpoint.on_put(req, rep)
        assert rep.status == falcon.HTTP_204
        witness.parse(local=False)
        assert not witness.ims
        assert hab.pre in whby.kevers

        rows = list(mbx.cloneTopicIter(topic=f"{recp.pre}/credential"))
        assert len(rows) == 1
        _, _, message = rows[0]
        carried = Parser(version=Vrsn_2_0).parse(
            ims=bytearray(message), processive=False)
        assert len(carried) == 1
        assert carried[0].serder.raw == grant.raw
        assert not list(mbx.cloneTopicIter(topic=f"{hab.pre}/credential"))
        receiver.parse(ims=bytearray(message), local=False)
        assert exc.complete(grant.said)
        assert verify(rhby, grant)
        assert notices == [dict(r="/exn/ipex/grant", d=grant.said,
                                m="Here is the credential")]
        nested = loadParsedNestedSubstreams(rhby, grant.said)
        assert len(nested) == 1
        assert nested[0].serder.said == acdc.said
        assert len(nested[0].bsqs) + len(nested[0].bsss) == 1
        restored = Parser(version=Vrsn_2_0).parse(
            ims=serializeMessage(rhby, grant.said), processive=False)[0]
        assert restored.serder.raw == grant.raw
        assert restored.nests[0].serder.raw == acdc.raw
        proofs = restored.nests[0].bsqs + restored.nests[0].bsss
        assert len(proofs) == 1
        assert b"".join(item.qb64b for item in proofs[0]) == blinder.qb64b


def test_postman(seeder, witnessPorter):
    with openHab(name="test", transferable=True, temp=True, version=Vrsn_1_0, kind=Kinds.json) as (hby, hab), \
            openHby(name="wes", salt=Salter(raw=b'wess-the-witness').qb64, temp=True, version=Vrsn_1_0) as wesHby, \
            openHby(name="repTest", temp=True, version=Vrsn_1_0) as recpHby:

        witnessPorts, witnessUrls = witnessPorter("wes")
        mbx = Mailboxer(name="wes", temp=True)
        wesDoers = setupWitness(alias="wes",
                                hby=wesHby,
                                mbx=mbx,
                                tcpPort=witnessPorts["wes"]["tcp"],
                                httpPort=witnessPorts["wes"]["http"],
                                version=Vrsn_1_0, kind=Kinds.json)
        wesHab = wesHby.habByName("wes")
        seeder.seedWitEnds(hby.db, witHabs=[wesHab], witnessUrls=witnessUrls, version=Vrsn_1_0, kind=Kinds.json)
        seeder.seedWitEnds(wesHby.db, witHabs=[wesHab], witnessUrls=witnessUrls, version=Vrsn_1_0, kind=Kinds.json)
        seeder.seedWitEnds(recpHby.db, witHabs=[wesHab], witnessUrls=witnessUrls, version=Vrsn_1_0, kind=Kinds.json)

        recpHab = recpHby.makeHab(name="repTest",
                                  transferable=True,
                                  wits=[wesHab.pre],
                                  version=Vrsn_1_0, kind=Kinds.json)

        recpIcp = recpHab.msgOwnEvent(sn=0, framed=True, gvrsn=Vrsn_1_0)
        wesKvy = Kevery(db=wesHab.db, lax=False, local=False)
        Parser(version=Vrsn_1_0).parse(ims=bytearray(recpIcp), kvy=wesKvy, local=True)
        assert recpHab.pre in wesKvy.kevers

        serder = SerderKERI(raw=recpIcp)
        rct = wesHab.receipt(serder, framed=True, gvrsn=Vrsn_1_0, version=Vrsn_1_0, kind=Kinds.json)

        kvy = Kevery(db=hab.db)
        Parser(version=Vrsn_1_0).parseOne(bytearray(recpIcp), kvy=kvy, local=True)
        Parser(version=Vrsn_1_0).parseOne(bytearray(rct), kvy=kvy, local=True)
        kvy.processEscrows()
        assert recpHab.pre in kvy.kevers

        pman = Poster(hby=hby)

        exn = exchange(route="/echo",
                                     attributes=dict(msg="test"),
                                     sender=hab.pre,
                                     version=Vrsn_1_0, kind=Kinds.json)
        atc = hab.endorse(exn, last=False, framed=False, gvrsn=Vrsn_1_0)
        del atc[:exn.size]
        pman.send(src=hab.pre,
                  dest=recpHab.pre,
                  topic="echo",
                  serder=exn,
                  attachment=atc)

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
        inner_exn = exchange(route="/echo",
                                           attributes=dict(msg="hello"),
                                           sender=hab.pre,
                                     version=Vrsn_1_0, kind=Kinds.json)
        inner_atc = hab.endorse(inner_exn, last=False, framed=False, gvrsn=Vrsn_1_0)
        del inner_atc[:inner_exn.size]

        evt = bytearray(inner_exn.raw)
        evt.extend(inner_atc)
        fwd, _ = specialExchange(sender=hab.pre,
                                            route='/fwd',
                                            modifiers=dict(pre=recpHab.pre,
                                                           topic="echo"),
                                            attributes={},
                                            embeds=dict(evt=evt),
                                            version=Vrsn_1_0, kind=Kinds.json)
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
        inner_exn2 = exchange(route="/delegate",
                                            attributes=dict(msg="delegate"),
                                            sender=hab.pre,
                                     version=Vrsn_1_0, kind=Kinds.json)
        inner_atc2 = hab.endorse(inner_exn2, last=False, framed=False, gvrsn=Vrsn_1_0)
        del inner_atc2[:inner_exn2.size]

        evt2 = bytearray(inner_exn2.raw)
        evt2.extend(inner_atc2)
        fwd2, _ = specialExchange(sender=hab.pre,
                                             route='/fwd',
                                             modifiers=dict(pre=recpHab.pre,
                                                            topic="delegate"),
                                             attributes={},
                                             embeds=dict(evt=evt2),
                                            version=Vrsn_1_0, kind=Kinds.json)

        forwarder.handle(serder=fwd2, attachments=[(Pather(path=["evt"]), inner_atc2)])

        echo_msgs = list(mbx.cloneTopicIter(topic=f"{recpHab.pre}/echo"))
        delegate_msgs = list(mbx.cloneTopicIter(topic=f"{recpHab.pre}/delegate"))
        assert len(echo_msgs) == 1    # unchanged
        assert len(delegate_msgs) == 1

        # Different recipient, same topic
        inner_exn3 = exchange(route="/echo",
                                            attributes=dict(msg="other"),
                                            sender=hab.pre,
                                     version=Vrsn_1_0, kind=Kinds.json)
        inner_atc3 = hab.endorse(inner_exn3, last=False, framed=False, gvrsn=Vrsn_1_0)
        del inner_atc3[:inner_exn3.size]

        evt3 = bytearray(inner_exn3.raw)
        evt3.extend(inner_atc3)
        fwd3, _ = specialExchange(sender=hab.pre,
                                             route='/fwd',
                                             modifiers=dict(pre=recp2Hab.pre,
                                                            topic="echo"),
                                             attributes={},
                                             embeds=dict(evt=evt3),
                                            version=Vrsn_1_0, kind=Kinds.json)
        forwarder.handle(serder=fwd3, attachments=[(Pather(path=["evt"]), inner_atc3)])

        recp1_echo = list(mbx.cloneTopicIter(topic=f"{recpHab.pre}/echo"))
        recp2_echo = list(mbx.cloneTopicIter(topic=f"{recp2Hab.pre}/echo"))
        assert len(recp1_echo) == 1   # unchanged
        assert len(recp2_echo) == 1

        # Multiple attachments in one call
        # Two embeds in a single /fwd: both must appear in the stored blob
        inner_exnA = exchange(route="/echo",
                                         attributes=dict(msg="A"),
                                        sender=hab.pre,
                                     version=Vrsn_1_0, kind=Kinds.json)
        inner_atcA = hab.endorse(inner_exnA, last=False, framed=False, gvrsn=Vrsn_1_0)
        del inner_atcA[:inner_exnA.size]

        inner_exnB = exchange(route="/echo",
                                         attributes=dict(msg="B"),
                                        sender=hab.pre,
                                     version=Vrsn_1_0, kind=Kinds.json)
        inner_atcB = hab.endorse(inner_exnB, last=False, framed=False, gvrsn=Vrsn_1_0)
        del inner_atcB[:inner_exnB.size]

        evtA = bytearray(inner_exnA.raw); evtA.extend(inner_atcA)
        evtB = bytearray(inner_exnB.raw); evtB.extend(inner_atcB)
        fwd_multi, _ = specialExchange(sender=hab.pre,
                                                  route='/fwd',
                                                  modifiers=dict(pre=recpHab.pre,
                                                                 topic="multi"),
                                                  attributes={},
                                                  embeds=dict(evtA=evtA,
                                                              evtB=evtB),
                                            version=Vrsn_1_0, kind=Kinds.json)
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

        # Native forwarding must bind exactly one child before persisting it.
        child = exchange(sender=hab.pre, route="/echo", attributes=dict(msg="native"),
                         kind=Kinds.json)
        nest = hab.endorse(child, nested=True)
        exc = Exchanger(hby=hby, handlers=[forwarder])
        parser = Parser(kvy=hby.kvy, exc=exc, version=Vrsn_2_0)
        for attributes, nests in (({}, [nest]),
                                   (dict(evt=inner_exn.said), [nest]),
                                   (dict(evt=Diger(ser=child.raw).qb64), []),
                                   (dict(evt=Diger(ser=child.raw).qb64), [nest, nest])):
            native = exchange(sender=hab.pre, route="/fwd",
                              modifiers=dict(pre=recpHab.pre, topic="native"),
                              attributes=attributes, kind=Kinds.json)
            parser.parse(ims=hab.endorse(native, nests=nests), local=False)
            assert not exc.complete(native.said)
            assert not list(mbx.cloneTopicIter(topic=f"{recpHab.pre}/native"))

        parser.parse(ims=hab.endorse(native, nests=[nest]), local=False)
        assert exc.complete(native.said)
        rows = list(mbx.cloneTopicIter(topic=f"{recpHab.pre}/native"))
        assert len(rows) == 1
        carried = Parser().parse(ims=bytearray(rows[0][2]), processive=False)
        assert carried[0].serder.raw == child.raw

        # A receipt's d identifies the receipted event, not the receipt body.
        original = receipt(pre=hab.pre, sn=0, said=hab.kever.serder.said, kind=Kinds.json)
        substituted = receipt(pre=hab.pre, sn=1, said=original.said, kind=Kinds.json)
        assert original.said == substituted.said
        native = exchange(sender=hab.pre, route="/fwd",
                          modifiers=dict(pre=recpHab.pre, topic="receipt"),
                          attributes=dict(evt=Diger(ser=original.raw).qb64), kind=Kinds.json)
        parser.parse(ims=hab.endorse(native, nests=[hab.endorse(substituted, nested=True)]),
                     local=False)
        assert not exc.complete(native.said)
        assert not list(mbx.cloneTopicIter(topic=f"{recpHab.pre}/receipt"))
        parser.parse(ims=hab.endorse(native, nests=[hab.endorse(original, nested=True)]),
                     local=False)
        assert exc.complete(native.said)
        rows = list(mbx.cloneTopicIter(topic=f"{recpHab.pre}/receipt"))
        assert len(rows) == 1
        carried = Parser().parse(ims=bytearray(rows[0][2]), processive=False)
        assert carried[0].serder.raw == original.raw

def test_essr_stream(seeder, unused_tcp_port):
    with openHab(name="test", transferable=True, temp=True, version=Vrsn_1_0, kind=Kinds.json) as (hby, hab), \
            openHab(name="recp", transferable=True, temp=True, version=Vrsn_1_0, kind=Kinds.json) as (recpHby, recpHab):

        httpPort = unused_tcp_port
        app = falcon.App()
        httpEnd = HttpEnd(rxbs=recpHab.psr.ims)
        app.add_route("/", httpEnd)
        server = http.Server(port=httpPort, app=app)
        httpServerDoer = http.ServerDoer(server=server)

        kvy = Kevery(db=hab.db)
        Parser(version=Vrsn_1_0).parseOne(recpHab.msgOwnEvent(sn=0, framed=True, gvrsn=Vrsn_1_0),
                                          kvy=kvy, local=True)
        kvy.processEscrows()
        assert recpHab.pre in kvy.kevers

        recpKvy = Kevery(db=recpHab.db)
        icp = hab.msgOwnEvent(sn=0, framed=True, gvrsn=Vrsn_1_0)
        Parser(version=Vrsn_1_0).parseOne(bytearray(icp), kvy=recpKvy, local=True)
        kvy.processEscrows()
        assert hab.pre in recpKvy.kevers

        msgs = bytearray()
        msgs.extend(recpHab.makeEndRole(eid=recpHab.pre,
                                        role=Roles.controller,
                                        stamp=help.nowIso8601(), version=Vrsn_1_0,
                                        kind=Kinds.json, gvrsn=Vrsn_1_0))

        msgs.extend(recpHab.makeLocScheme(url=f'http://127.0.0.1:{httpPort}',
                                          scheme=Schemes.http,
                                          stamp=help.nowIso8601(), version=Vrsn_1_0,
                                          kind=Kinds.json, gvrsn=Vrsn_1_0))
        hab.psr.parse(ims=msgs)

        postman = StreamPoster(hby=hby, hab=hab, recp=recpHab.pre, essr=True)

        # Test chunking
        saids = []
        for i in range(0, 40):
            exn = exchange(route="/echo",
                                         attributes=dict(msg="test", i=i),
                                         sender=hab.pre,
                                         version=Vrsn_1_0, kind=Kinds.json)
            atc = hab.endorse(exn, last=False, framed=False, gvrsn=Vrsn_1_0)
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

def test_essr_mbx(seeder, witnessPorter):
    with openHab(name="test", transferable=True, temp=True, version=Vrsn_1_0, kind=Kinds.json) as (hby, hab), \
            openHby(name="wes", salt=Salter(raw=b'wess-the-witness').qb64, temp=True, version=Vrsn_1_0) as wesHby, \
            openHby(name="repTest", temp=True, version=Vrsn_1_0) as recpHby:

        witnessPorts, witnessUrls = witnessPorter("wes")
        mbx = Mailboxer(name="wes", temp=True)
        wesDoers = setupWitness(alias="wes", hby=wesHby, mbx=mbx,
                                tcpPort=witnessPorts["wes"]["tcp"],
                                httpPort=witnessPorts["wes"]["http"], version=Vrsn_1_0, kind=Kinds.json)
        wesHab = wesHby.habByName("wes")
        seeder.seedWitEnds(hby.db, witHabs=[wesHab], witnessUrls=witnessUrls, version=Vrsn_1_0, kind=Kinds.json)
        seeder.seedWitEnds(wesHby.db, witHabs=[wesHab], witnessUrls=witnessUrls, version=Vrsn_1_0, kind=Kinds.json)
        seeder.seedWitEnds(recpHby.db, witHabs=[wesHab], witnessUrls=witnessUrls, version=Vrsn_1_0, kind=Kinds.json)

        recpHab = recpHby.makeHab(name="repTest", transferable=True, wits=[wesHab.pre], version=Vrsn_1_0, kind=Kinds.json)

        recpIcp = recpHab.msgOwnEvent(sn=0, framed=True, gvrsn=Vrsn_1_0)
        wesKvy = Kevery(db=wesHab.db, lax=False, local=False)
        Parser(version=Vrsn_1_0).parse(ims=bytearray(recpIcp), kvy=wesKvy, local=True)
        assert recpHab.pre in wesKvy.kevers

        serder = SerderKERI(raw=recpIcp)
        rct = wesHab.receipt(serder, framed=True, gvrsn=Vrsn_1_0, version=Vrsn_1_0, kind=Kinds.json)

        kvy = Kevery(db=hab.db)
        Parser(version=Vrsn_1_0).parseOne(bytearray(recpIcp), kvy=kvy, local=True)
        Parser(version=Vrsn_1_0).parseOne(bytearray(rct), kvy=kvy, local=True)
        kvy.processEscrows()
        assert recpHab.pre in kvy.kevers

        recpKvy = Kevery(db=recpHab.db)
        icp = hab.msgOwnEvent(sn=0, gvrsn=Vrsn_1_0)
        Parser(version=Vrsn_1_0).parseOne(bytearray(icp), kvy=recpKvy, local=True)
        kvy.processEscrows()
        assert hab.pre in recpKvy.kevers

        postman = StreamPoster(hby=hby, hab=hab, recp=recpHab.pre, topic="echo", essr=True)

        # Test chunking
        saids = []
        for i in range(0, 30):
            exn = exchange(route="/echo",
                                         attributes=dict(msg="test", i=i),
                                         sender=hab.pre,
                                         version=Vrsn_1_0, kind=Kinds.json)
            atc = hab.endorse(exn, last=False, framed=False, gvrsn=Vrsn_1_0)
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
        exchanger = Exchanger(hby=hby, handlers=[forwarder])
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

        assert len(mbxSaids) == 30

        # Chunks can come out of order, so check for difference of SAIDs
        assert set(saids) == set(mbxSaids)

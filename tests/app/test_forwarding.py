# -*- encoding: utf-8 -*-
"""
KERI
tests.app.forwarding module

"""
import time

from hio.base import doing, tyming

from keri import kering
from keri.app import forwarding, habbing, indirecting, storing
from keri.core import coring, eventing, parsing
from keri.help import helping
from keri.peer import exchanging


def test_postman(seeder):
    with habbing.openHab(name="test", transferable=True, temp=True) as (hby, hab), \
            habbing.openHby(name="wes", salt=coring.Salter(raw=b'wess-the-witness').qb64, temp=True) as wesHby, \
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
        parsing.Parser().parse(ims=bytearray(recpIcp), kvy=wesKvy)
        assert recpHab.pre in wesKvy.kevers

        serder = coring.Serder(raw=recpIcp)
        rct = wesHab.receipt(serder)

        kvy = eventing.Kevery(db=hab.db)
        parsing.Parser().parseOne(bytearray(recpIcp), kvy=kvy)
        parsing.Parser().parseOne(bytearray(rct), kvy=kvy)
        kvy.processEscrows()
        assert recpHab.pre in kvy.kevers

        pman = forwarding.Poster(hby=hby)

        exn = exchanging.exchange(route="/echo", payload=dict(msg="test"))
        atc = hab.endorse(exn)
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
        for _, topic, msg in mbx.cloneTopicIter(topic=recpHab.pre + "/echo", fn=0):
            msgs.append(msg)

        assert len(msgs) == 1
        serder = coring.Serder(raw=msgs[0])
        assert serder.ked["t"] == coring.Ilks.exn
        assert serder.ked["r"] == "/echo"
        assert serder.ked["a"] == dict(msg="test")


def test_forward_handler():
    with habbing.openHab(name="test", transferable=True, temp=True) as (hby, hab):
        mbx = storing.Mailboxer()
        forwarder = forwarding.ForwardHandler(hby=hby, mbx=mbx)

        limit = 1.0
        tock = 0.03125
        doist = doing.Doist(tock=tock, limit=limit, doers=[forwarder])
        doist.enter()

        tymer = tyming.Tymer(tymth=doist.tymen(), duration=doist.limit)

        while not tymer.expired:
            doist.recur()
            time.sleep(doist.tock)

        assert doist.limit == limit

        doist.exit()


def test_postman_endsfor():
    with habbing.openHby(name="test", temp=True) as hby, \
            habbing.openHby(name="wes", salt=coring.Salter(raw=b'wess-the-witness').qb64, temp=True) as wesHby, \
            habbing.openHab(name="agent", temp=True) as (agentHby, agentHab):

        print()

        wesHab = wesHby.makeHab(name='wes', isith="1", icount=1, transferable=False)
        assert not wesHab.kever.prefixer.transferable
        # create non-local kevery for Wes to process nonlocal msgs
        wesKvy = eventing.Kevery(db=wesHab.db, lax=False, local=False)

        wits = [wesHab.pre]
        hab = hby.makeHab(name='cam', isith="1", icount=1, toad=1, wits=wits, )
        assert hab.kever.prefixer.transferable
        assert len(hab.iserder.werfers) == len(wits)
        for werfer in hab.iserder.werfers:
            assert werfer.qb64 in wits
        assert hab.kever.wits == wits
        assert hab.kever.toader.num == 1
        assert hab.kever.sn == 0

        kvy = eventing.Kevery(db=hab.db, lax=False, local=False)
        icpMsg = hab.makeOwnInception()
        rctMsgs = []  # list of receipts from each witness
        parsing.Parser().parse(ims=bytearray(icpMsg), kvy=wesKvy)
        assert wesKvy.kevers[hab.pre].sn == 0  # accepted event
        assert len(wesKvy.cues) == 1  # queued receipt cue
        rctMsg = wesHab.processCues(wesKvy.cues)  # process cue returns rct msg
        assert len(rctMsg) == 626
        rctMsgs.append(rctMsg)

        for msg in rctMsgs:  # process rct msgs from all witnesses
            parsing.Parser().parse(ims=bytearray(msg), kvy=kvy)
        assert wesHab.pre in kvy.kevers

        agentIcpMsg = agentHab.makeOwnInception()
        parsing.Parser().parse(ims=bytearray(agentIcpMsg), kvy=kvy)
        assert agentHab.pre in kvy.kevers

        msgs = bytearray()
        msgs.extend(wesHab.makeEndRole(eid=wesHab.pre,
                                       role=kering.Roles.controller,
                                       stamp=helping.nowIso8601()))

        msgs.extend(wesHab.makeLocScheme(url='http://127.0.0.1:8888',
                                         scheme=kering.Schemes.http,
                                         stamp=helping.nowIso8601()))
        wesHab.psr.parse(ims=bytearray(msgs))

        # Set up
        msgs.extend(hab.makeEndRole(eid=hab.pre,
                                    role=kering.Roles.controller,
                                    stamp=helping.nowIso8601()))

        msgs.extend(hab.makeLocScheme(url='http://127.0.0.1:7777',
                                      scheme=kering.Schemes.http,
                                      stamp=helping.nowIso8601()))
        hab.psr.parse(ims=msgs)

        msgs = bytearray()
        msgs.extend(agentHab.makeEndRole(eid=agentHab.pre,
                                         role=kering.Roles.controller,
                                         stamp=helping.nowIso8601()))

        msgs.extend(agentHab.makeLocScheme(url='http://127.0.0.1:6666',
                                           scheme=kering.Schemes.http,
                                           stamp=helping.nowIso8601()))

        msgs.extend(hab.makeEndRole(eid=agentHab.pre,
                                    role=kering.Roles.agent,
                                    stamp=helping.nowIso8601()))

        msgs.extend(hab.makeEndRole(eid=agentHab.pre,
                                    role=kering.Roles.mailbox,
                                    stamp=helping.nowIso8601()))

        agentHab.psr.parse(ims=bytearray(msgs))
        hab.psr.parse(ims=bytearray(msgs))

        ends = forwarding.Poster.endsFor(hab, hab.pre)
        assert ends == {
            'agent': {
                'EBErgFZoM3PBQNTpTuK9bax_U8HLJq1Re2RM1cdifaTJ': {'http': 'http://127.0.0.1:6666'}},
            'controller': {
                'EGadHcyW9IfVIPrFUAa_I0z4dF8QzQAvUvfaUTJk8Jre': {'http': 'http://127.0.0.1:7777'}},
            'mailbox': {
                'EBErgFZoM3PBQNTpTuK9bax_U8HLJq1Re2RM1cdifaTJ': {'http': 'http://127.0.0.1:6666'}},
            'witness': {
                'BN8t3n1lxcV0SWGJIIF46fpSUqA7Mqre5KJNN3nbx3mr': {'http': 'http://127.0.0.1:8888'}}
        }

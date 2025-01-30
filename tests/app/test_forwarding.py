# -*- encoding: utf-8 -*-
"""
KERI
tests.app.forwarding module

"""
import time
import falcon

from hio.base import doing, tyming
from hio.core import http

from keri import core, kering, help
from keri.core import coring, eventing, parsing, serdering
from keri.kering import Vrsn_1_0, Vrsn_2_0

from keri.app import forwarding, habbing, indirecting, storing

from keri.peer import exchanging


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
        parsing.Parser(version=Vrsn_1_0).parse(ims=bytearray(recpIcp), kvy=wesKvy, local=True)
        assert recpHab.pre in wesKvy.kevers

        serder = serdering.SerderKERI(raw=recpIcp)
        rct = wesHab.receipt(serder)

        kvy = eventing.Kevery(db=hab.db)
        parsing.Parser(version=Vrsn_1_0).parseOne(bytearray(recpIcp), kvy=kvy, local=True)
        parsing.Parser(version=Vrsn_1_0).parseOne(bytearray(rct), kvy=kvy, local=True)
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

def test_essr_stream(seeder):
    with habbing.openHab(name="test", transferable=True, temp=True) as (hby, hab), \
            habbing.openHab(name="test", transferable=True, temp=True) as (recpHby, recpHab):

        app = falcon.App()
        httpEnd = indirecting.HttpEnd(rxbs=recpHab.psr.ims)
        app.add_route("/", httpEnd)
        server = http.Server(port=5555, app=app)
        httpServerDoer = http.ServerDoer(server=server)

        kvy = eventing.Kevery(db=hab.db)
        parsing.Parser().parseOne(bytearray(recpHab.makeOwnEvent(sn=0)), kvy=kvy, local=True)
        kvy.processEscrows()
        assert recpHab.pre in kvy.kevers

        recpKvy = eventing.Kevery(db=recpHab.db)
        icp = hab.makeOwnEvent(sn=0)
        parsing.Parser().parseOne(bytearray(icp), kvy=recpKvy, local=True)
        kvy.processEscrows()
        assert hab.pre in recpKvy.kevers

        msgs = bytearray()
        msgs.extend(recpHab.makeEndRole(eid=recpHab.pre,
                                        role=kering.Roles.controller,
                                        stamp=help.nowIso8601()))

        msgs.extend(recpHab.makeLocScheme(url='http://127.0.0.1:5555',
                                          scheme=kering.Schemes.http,
                                          stamp=help.nowIso8601()))
        hab.psr.parse(ims=msgs)

        postman = forwarding.StreamPoster(hby=hby, hab=hab, recp=recpHab.pre, essr=True)

        exn, _ = exchanging.exchange(route="/echo", payload=dict(msg="test"), sender=hab.pre)
        atc = hab.endorse(exn, last=False)
        del atc[:exn.size]

        postman.send(exn, atc)

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

        recpHby.psr.parseOne()  # ims already populated from http server
        exnSaid, exnSerder = next(recpHby.db.exns.getItemIter())
        assert exnSerder.ked["r"] == "/essr/req"
        assert exnSerder.ked["q"] == {'src': hab.pre, 'dest': recpHab.pre}

        texter = recpHby.db.essrs.get(exnSaid)[0]
        ims = bytearray(recpHab.decrypt(texter.raw))

        tag = parsing.Parser.extract(ims, coring.Tsper)
        assert tag.tsp == coring.Tsps.SCS
        pre = parsing.Parser.extract(ims, coring.Prefixer)
        assert pre.qb64 == hab.pre  # encrypt sender

        recpHby.psr.parseOne(ims=ims)
        serder = recpHby.db.exns.get(exn.said)
        assert serder.ked["t"] == coring.Ilks.exn
        assert serder.ked["r"] == "/echo"
        assert serder.ked["a"] == dict(msg="test")

# -*- encoding: utf-8 -*-
"""
tests.app.agenting module

"""
import time

from hio.base import doing, tyming

from keri import kering, core
from keri.app import habbing, indirecting, agenting, directing
from keri.db import dbing
from keri.help import nowIso8601


def test_withness_receiptor(seeder):
    with habbing.openHby(name="wan1", salt=core.Salter(raw=b'wann-the-witness').qb64) as wanHby, \
            habbing.openHby(name="wil1", salt=core.Salter(raw=b'will-the-witness').qb64) as wilHby, \
            habbing.openHby(name="wes1", salt=core.Salter(raw=b'wess-the-witness').qb64) as wesHby, \
            habbing.openHby(name="pal1", salt=core.Salter(raw=b'0123456789abcdef').qb64) as palHby:

        wanDoers = indirecting.setupWitness(alias="wan", hby=wanHby, tcpPort=5632, httpPort=5642)
        wilDoers = indirecting.setupWitness(alias="wil", hby=wilHby, tcpPort=5633, httpPort=5643)
        wesDoers = indirecting.setupWitness(alias="wes", hby=wesHby, tcpPort=5634, httpPort=5644)

        wanHab = wanHby.habByName(name="wan")
        wilHab = wilHby.habByName(name="wil")
        wesHab = wesHby.habByName(name="wes")
        seeder.seedWitEnds(palHby.db, witHabs=[wanHab, wilHab, wesHab], protocols=[kering.Schemes.tcp])

        rctDoer = ReceiptDoer(hby=palHby, wanHab=wanHab, wilHab=wilHab, wesHab=wesHab)

        limit = 5.0
        tock = 0.03125
        doers = wanDoers + wilDoers + wesDoers + [rctDoer]
        doist = doing.Doist(limit=limit, tock=tock, doers=doers)
        doist.enter()
        tymer = tyming.Tymer(tymth=doist.tymen(), duration=doist.limit)

        while not (rctDoer.done or tymer.expired):
            doist.recur()
            time.sleep(doist.tock)

        doist.exit()

        assert rctDoer.done is True


class ReceiptDoer(doing.DoDoer):
    """ Test scenario of witness receipts. """

    def __init__(self, hby, wanHab, wilHab, wesHab):
        self.hby = hby
        self.wanHab = wanHab
        self.wilHab = wilHab
        self.wesHab = wesHab

        super(ReceiptDoer, self).__init__(doers=[doing.doify(self.testDo)])

    def testDo(self, tymth, tock=0.0, **kwa):
        """ Execute a series of kli commands for this test scenario """
        # enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        palHab = self.hby.makeHab(name="pal", wits=[self.wanHab.pre, self.wilHab.pre], transferable=True)

        witDoer = agenting.WitnessReceiptor(hby=self.hby)
        witDoer.msgs.append(dict(pre=palHab.pre))
        self.extend([witDoer])

        kev = palHab.kever
        ser = kev.serder
        dgkey = dbing.dgKey(ser.preb, ser.saidb)

        while True:
            wilWigs = self.wilHab.db.getWigs(dgkey)
            wanWigs = self.wanHab.db.getWigs(dgkey)
            if len(wilWigs) == 2 and len(wanWigs) == 2:
                break
            yield self.tock

        # Controller should send endpoints between witnesses.  Check for Endpoints for each other:
        keys = (self.wanHab.pre, kering.Schemes.tcp)
        said = self.wilHab.db.lans.get(keys=keys)
        assert said is not None
        keys = (self.wilHab.pre, kering.Schemes.tcp)
        said = self.wanHab.db.lans.get(keys=keys)
        assert said is not None

        palHab.rotate(adds=[self.wesHab.pre])

        witDoer.msgs.append(dict(pre=palHab.pre, sn=1))

        kev = palHab.kever
        ser = kev.serder
        dgkey = dbing.dgKey(ser.preb, ser.saidb)

        while True:
            wilWigs = self.wilHab.db.getWigs(dgkey)
            wanWigs = self.wanHab.db.getWigs(dgkey)
            wesWigs = self.wesHab.db.getWigs(dgkey)
            if len(wilWigs) == 3 and len(wanWigs) == 3 and len(wesWigs) == 3:
                break
            yield self.tock

        self.remove([witDoer])
        return True


def test_witness_sender(seeder):
    with habbing.openHby(name="wan2", salt=core.Salter(raw=b'wann-the-witness').qb64) as wanHby, \
            habbing.openHby(name="wil2", salt=core.Salter(raw=b'will-the-witness').qb64) as wilHby, \
            habbing.openHby(name="wes2", salt=core.Salter(raw=b'wess-the-witness').qb64) as wesHby, \
            habbing.openHby(name="pal2", salt=core.Salter(raw=b'0123456789abcdef').qb64) as palHby:

        # looks like bad magic value in seeder is causing this to fail
        pdoer = PublishDoer(wanHby, wilHby, wesHby, palHby, seeder)
        directing.runController(doers=[pdoer], expire=15.0)
        assert pdoer.done is True


class PublishDoer(doing.DoDoer):

    def __init__(self, wanHby, wilHby, wesHby, palHby, seeder):
        wanDoers = indirecting.setupWitness(alias="wan", hby=wanHby, tcpPort=5632, httpPort=5642)
        wilDoers = indirecting.setupWitness(alias="wil", hby=wilHby, tcpPort=5633, httpPort=5643)
        wesDoers = indirecting.setupWitness(alias="wes", hby=wesHby, tcpPort=5634, httpPort=5644)

        self.wanHab = wanHby.habByName(name="wan")
        self.wilHab = wilHby.habByName(name="wil")
        self.wesHab = wesHby.habByName(name="wes")
        seeder.seedWitEnds(palHby.db, witHabs=[self.wanHab, self.wilHab, self.wesHab], protocols=[kering.Schemes.tcp])

        self.palHab = palHby.makeHab(name="pal", wits=[self.wanHab.pre, self.wilHab.pre, self.wesHab.pre], transferable=True)

        self.witDoer = agenting.WitnessPublisher(hby=palHby)
        doers = wanDoers + wilDoers + wesDoers + [self.witDoer]
        self.toRemove = list(doers)
        doers.extend([doing.doify(self.testDo)])

        super(PublishDoer, self).__init__(doers=doers)

    def testDo(self, tymth, tock=0.0, **kwa):
        """ Run the test and exit and remove all child doers when done """
        self.wind(tymth)
        self.tock = tock
        yield self.tock

        msg = self.palHab.makeOwnEvent(sn=0)
        self.witDoer.msgs.append(dict(pre=self.palHab.pre, msg=msg))

        for hab in [self.wanHab, self.wilHab, self.wesHab]:
            while True:
                if self.palHab.pre in hab.kevers:
                    break
                yield self.tock

        self.remove(self.toRemove)
        return True


def test_witness_inquisitor(mockHelpingNowUTC, seeder):
    with habbing.openHby(name="wan3", salt=core.Salter(raw=b'wann-the-witness').qb64) as wanHby, \
            habbing.openHby(name="wil3", salt=core.Salter(raw=b'will-the-witness').qb64) as wilHby, \
            habbing.openHby(name="wes3", salt=core.Salter(raw=b'wess-the-witness').qb64) as wesHby, \
            habbing.openHby(name="pal3", salt=core.Salter(raw=b'0123456789abcdef').qb64) as palHby, \
            habbing.openHby(name="qin3", salt=core.Salter(raw=b'abcdef0123456789').qb64) as qinHby:
        wanDoers = indirecting.setupWitness(alias="wan", hby=wanHby, tcpPort=5632, httpPort=5642)
        wilDoers = indirecting.setupWitness(alias="wil", hby=wilHby, tcpPort=5633, httpPort=5643)
        wesDoers = indirecting.setupWitness(alias="wes", hby=wesHby, tcpPort=5634, httpPort=5644)

        wanHab = wanHby.habByName(name="wan")
        wilHab = wilHby.habByName(name="wil")
        wesHab = wesHby.habByName(name="wes")
        seeder.seedWitEnds(palHby.db, witHabs=[wanHab, wilHab, wesHab], protocols=[kering.Schemes.tcp])
        seeder.seedWitEnds(qinHby.db, witHabs=[wanHab, wilHab, wesHab], protocols=[kering.Schemes.tcp])

        palHab = palHby.makeHab(name="pal", wits=[wanHab.pre, wilHab.pre, wesHab.pre], transferable=True)
        qinHab = qinHby.makeHab(name="qin", wits=[wanHab.pre, wilHab.pre, wesHab.pre], transferable=True)

        palWitDoer = agenting.WitnessReceiptor(hby=palHby)
        palWitDoer.msgs.append(dict(pre=palHab.pre))
        qinWitDoer = agenting.WitnessReceiptor(hby=qinHby)
        qinWitDoer.msgs.append(dict(pre=qinHab.pre))

        doers = wanDoers + wilDoers + wesDoers + [palWitDoer, qinWitDoer]
        doist = doing.Doist(doers=doers)
        doist.enter()
        doist.recur()

        while True:
            wigs = []
            for hab in [palHab, qinHab]:
                kev = hab.kever
                ser = kev.serder
                dgkey = dbing.dgKey(ser.preb, ser.saidb)
                wigs.extend(wanHab.db.getWigs(dgkey))
                wigs.extend(wilHab.db.getWigs(dgkey))
                wigs.extend(wesHab.db.getWigs(dgkey))

            if len(wigs) == 18:
                break

            doist.recur()

        kev = qinHab.kever
        ser = kev.serder
        dgkey = dbing.dgKey(ser.preb, ser.saidb)

        wigs = wanHab.db.getWigs(dgkey)
        assert len(wigs) == 3
        wigs = wilHab.db.getWigs(dgkey)
        assert len(wigs) == 3
        wigs = wesHab.db.getWigs(dgkey)
        assert len(wigs) == 3


        qinWitq = agenting.WitnessInquisitor(hby=qinHby)
        stamp = nowIso8601()
        qinWitq.query(src=qinHab.pre, pre=palHab.pre, stamp=stamp, wits=palHab.kever.wits)

        palWitq = agenting.WitnessInquisitor(hby=palHby)
        palWitq.query(src=palHab.pre, pre=qinHab.pre, stamp=stamp, wits=qinHab.kever.wits)

        doist.extend([qinWitq, palWitq])
        while True:
            if palHab.pre in qinHab.kevers and qinHab.pre in palHab.kevers:
                break
            doist.recur()

        assert palHab.pre in qinHab.kevers
        assert qinHab.pre in palHab.kevers

        doist.exit()

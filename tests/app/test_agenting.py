# -*- encoding: utf-8 -*-
"""
tests.app.agenting module

"""
import time
from types import SimpleNamespace

import pytest
from hio.base import doing, tyming

from keri.kering import Schemes, Vrsn_1_0, Vrsn_2_0, Kinds
from keri.core import Counter, Codens, Salter, SerderKERI, Siger
from keri.app import (Receiptor, WitnessReceiptor, WitnessPublisher, WitnessInquisitor,
                      runController, openHby, setupWitness)
from keri.app import agenting
from keri.help import nowIso8601

TEST_VERSION = Vrsn_1_0
KWA = dict(version=TEST_VERSION, kind=Kinds.json)
CUE_KWA = dict(**KWA, gvrsn=TEST_VERSION)


def test_receiptor_v2_propagates_witness_receipts(monkeypatch, seeder, witnessPorter):
    kwa = dict(version=Vrsn_2_0, kind=Kinds.json)
    propagated = []
    streamCESRRequests = agenting.streamCESRRequests

    def capturePropagation(client, ims, dest, path=None, headers=None):
        if path != "/receipts":
            propagated.append((dest, bytes(ims)))
        return streamCESRRequests(client=client, ims=ims, dest=dest,
                                  path=path, headers=headers)

    monkeypatch.setattr(agenting, "streamCESRRequests", capturePropagation)

    with openHby(name="wan-v2", salt=Salter(raw=b'wann-the-witness').qb64,
                 version=Vrsn_2_0) as wanHby, \
            openHby(name="wil-v2", salt=Salter(raw=b'will-the-witness').qb64,
                    version=Vrsn_2_0) as wilHby, \
            openHby(name="wes-v2", salt=Salter(raw=b'wess-the-witness').qb64,
                    version=Vrsn_2_0) as wesHby, \
            openHby(name="pal-v2", salt=Salter(raw=b'0123456789abcdef').qb64,
                    version=Vrsn_2_0) as palHby:
        witnessPorts, witnessUrls = witnessPorter("wan-v2", "wil-v2", "wes-v2")
        witnessDoers = []
        for alias, hby in (("wan-v2", wanHby), ("wil-v2", wilHby), ("wes-v2", wesHby)):
            witnessDoers.extend(setupWitness(alias=alias, hby=hby,
                                             tcpPort=witnessPorts[alias]["tcp"],
                                             httpPort=witnessPorts[alias]["http"],
                                             **kwa))

        witHabs = [wanHby.habByName("wan-v2"),
                   wilHby.habByName("wil-v2"),
                   wesHby.habByName("wes-v2")]
        seeder.seedWitEnds(palHby.db, witHabs=witHabs,
                           protocols=[Schemes.http], witnessUrls=witnessUrls,
                           **kwa)
        singleHab = palHby.makeHab(name="single-v2", wits=[witHabs[0].pre],
                                   transferable=True, **kwa)
        palHab = palHby.makeHab(name="pal-v2",
                                wits=[witHab.pre for witHab in witHabs],
                                transferable=True, **kwa)
        receiptor = Receiptor(hby=palHby)
        receiptor.msgs.append(dict(pre=singleHab.pre))

        doist = doing.Doist(limit=5.0, tock=0.03125,
                            doers=witnessDoers + [receiptor])
        doist.enter()
        tymer = tyming.Tymer(tymth=doist.tymen(), duration=doist.limit)
        while not (receiptor.cues or tymer.expired):
            doist.recur()
            time.sleep(doist.tock)

        assert receiptor.cues
        receiptor.cues.popleft()
        singleSerder = singleHab.kever.serder
        wigers = witHabs[0].db.wigs.get(keys=(singleSerder.preb, singleSerder.saidb))
        assert {wiger.index for wiger in wigers} == {0}
        assert propagated == []

        receiptor.msgs.append(dict(pre=palHab.pre))
        tymer = tyming.Tymer(tymth=doist.tymen(), duration=doist.limit)
        while not (receiptor.cues or tymer.expired):
            doist.recur()
            time.sleep(doist.tock)
        doist.exit()

        assert receiptor.cues
        serder = palHab.kever.serder
        assert serder.pvrsn == Vrsn_2_0
        assert serder.gvrsn == Vrsn_2_0

        expected = {0, 1, 2}
        for witHab in witHabs:
            wigers = witHab.db.wigs.get(keys=(serder.preb, serder.saidb))
            assert {wiger.index for wiger in wigers} == expected

        assert {dest for dest, _ in propagated} == {witHab.pre for witHab in witHabs}
        for _, stream in propagated:
            ims = bytearray(stream)
            receiptAttachments = []
            while ims:
                rserder = SerderKERI(raw=ims)
                del ims[:rserder.size]
                attachments = bytearray()
                while ims and ims[0] != ord("{"):
                    attachments.append(ims.pop(0))
                if rserder.ked["t"] == "rct":
                    receiptAttachments.append(attachments)

            assert len(receiptAttachments) == 1
            attachments = receiptAttachments[0]
            counter = Counter(qb64b=attachments, version=Vrsn_2_0)
            assert counter.name == Codens.WitnessIdxSigs
            assert counter.count == (len(attachments) - len(counter.qb64b)) // 4


@pytest.mark.parametrize("version", [Vrsn_1_0, Vrsn_2_0])
def test_receiptor_propagates_only_verified_receipts(monkeypatch, version):
    kwa = dict(version=version, kind=Kinds.json)
    propagated = {}

    class FakeClient:
        def __init__(self, body):
            self.responses = [SimpleNamespace(status=200, body=body)]

        def respond(self):
            return self.responses.pop(0)

    with openHby(name="wan-bad", salt=Salter(raw=b'wann-the-witness').qb64,
                 version=version) as wanHby, \
            openHby(name="wil-bad", salt=Salter(raw=b'will-the-witness').qb64,
                    version=version) as wilHby, \
            openHby(name="wes-bad", salt=Salter(raw=b'wess-the-witness').qb64,
                    version=version) as wesHby, \
            openHby(name="pal-bad", salt=Salter(raw=b'0123456789abcdef').qb64,
                    version=version) as palHby:
        witHabs = [wanHby.makeHab(name="wan-bad", transferable=False, **kwa),
                   wilHby.makeHab(name="wil-bad", transferable=False, **kwa),
                   wesHby.makeHab(name="wes-bad", transferable=False, **kwa)]
        palHab = palHby.makeHab(name="pal-bad",
                                wits=[witHab.pre for witHab in witHabs],
                                transferable=True, **kwa)
        serder = palHab.kever.serder
        receipts = [witHab.receipt(serder=serder, framed=True,
                                   gvrsn=version, **kwa)
                    for witHab in witHabs]
        receipts[2][-1] = ord("A") if receipts[2][-1] != ord("A") else ord("B")
        clients = {witHab.pre: FakeClient(receipt)
                   for witHab, receipt in zip(witHabs, receipts)}

        def fakeHttpClient(hab, wit):
            return clients[wit], doing.Doer()

        def capturePropagation(client, ims, dest, path=None, headers=None):
            if path != "/receipts":
                propagated[dest] = bytes(ims)
            return 0

        monkeypatch.setattr(agenting, "httpClient", fakeHttpClient)
        monkeypatch.setattr(agenting, "streamCESRRequests", capturePropagation)

        receiptor = Receiptor(hby=palHby)
        dog = receiptor.receipt(palHab.pre)
        with pytest.raises(StopIteration) as ex:
            while True:
                next(dog)

        assert list(ex.value.value) == [witHab.pre for witHab in witHabs]
        wigers = palHab.db.wigs.get(keys=(serder.preb, serder.saidb))
        assert {wiger.index for wiger in wigers} == {0, 1}

        expected = {
            witHabs[0].pre: {1},
            witHabs[1].pre: {0},
            witHabs[2].pre: {0, 1},
        }
        assert propagated.keys() == expected.keys()
        for wit, msg in propagated.items():
            ims = bytearray(msg)
            rserder = SerderKERI(raw=ims)
            del ims[:rserder.size]
            attachmentSize = len(ims)
            counter = Counter(qb64b=ims, strip=True, version=version)
            assert counter.name == Codens.WitnessIdxSigs
            if version == Vrsn_1_0:
                assert counter.count == len(expected[wit])
            else:
                assert counter.count == (attachmentSize - len(counter.qb64b)) // 4
            indices = set()
            while ims:
                indices.add(Siger(qb64b=ims, strip=True).index)
            assert indices == expected[wit]


def test_witness_receiptor(seeder, witnessPorter):
    with openHby(name="wan1", salt=Salter(raw=b'wann-the-witness').qb64, version=TEST_VERSION) as wanHby, \
            openHby(name="wil1", salt=Salter(raw=b'will-the-witness').qb64, version=TEST_VERSION) as wilHby, \
            openHby(name="wes1", salt=Salter(raw=b'wess-the-witness').qb64, version=TEST_VERSION) as wesHby, \
            openHby(name="pal1", salt=Salter(raw=b'0123456789abcdef').qb64, version=TEST_VERSION) as palHby:

        witnessPorts, witnessUrls = witnessPorter("wan", "wil", "wes")
        wanDoers = setupWitness(alias="wan", hby=wanHby,
                                tcpPort=witnessPorts["wan"]["tcp"],
                                httpPort=witnessPorts["wan"]["http"], **KWA)
        wilDoers = setupWitness(alias="wil", hby=wilHby,
                                tcpPort=witnessPorts["wil"]["tcp"],
                                httpPort=witnessPorts["wil"]["http"], **KWA)
        wesDoers = setupWitness(alias="wes", hby=wesHby,
                                tcpPort=witnessPorts["wes"]["tcp"],
                                httpPort=witnessPorts["wes"]["http"], **KWA)

        wanHab = wanHby.habByName(name="wan")
        wilHab = wilHby.habByName(name="wil")
        wesHab = wesHby.habByName(name="wes")
        seeder.seedWitEnds(palHby.db, witHabs=[wanHab, wilHab, wesHab],
                           protocols=[Schemes.tcp], witnessUrls=witnessUrls, **KWA)

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

        palHab = self.hby.makeHab(name="pal", wits=[self.wanHab.pre, self.wilHab.pre],
                                  transferable=True, **KWA)

        witDoer = WitnessReceiptor(hby=self.hby)
        witDoer.msgs.append(dict(pre=palHab.pre))
        self.extend([witDoer])

        kev = palHab.kever
        ser = kev.serder

        while True:
            wilWigs = self.wilHab.db.wigs.get(keys=(ser.preb, ser.saidb))
            wanWigs = self.wanHab.db.wigs.get(keys=(ser.preb, ser.saidb))
            if len(wilWigs) == 2 and len(wanWigs) == 2:
                break
            yield self.tock

        # Controller should send endpoints between witnesses.  Check for Endpoints for each other:
        keys = (self.wanHab.pre, Schemes.tcp)
        said = self.wilHab.db.lans.get(keys=keys)
        assert said is not None
        keys = (self.wilHab.pre, Schemes.tcp)
        said = self.wanHab.db.lans.get(keys=keys)
        assert said is not None

        palHab.rotate(adds=[self.wesHab.pre], framed=True, **CUE_KWA)

        witDoer.msgs.append(dict(pre=palHab.pre, sn=1))

        kev = palHab.kever
        ser = kev.serder

        while True:
            wilWigs = self.wilHab.db.wigs.get(keys=(ser.preb, ser.saidb))
            wanWigs = self.wanHab.db.wigs.get(keys=(ser.preb, ser.saidb))
            wesWigs = self.wesHab.db.wigs.get(keys=(ser.preb, ser.saidb))
            if len(wilWigs) == 3 and len(wanWigs) == 3 and len(wesWigs) == 3:
                break
            yield self.tock

        self.remove([witDoer])
        return True


def test_witness_sender(seeder, witnessPorter):
    with openHby(name="wan2", salt=Salter(raw=b'wann-the-witness').qb64, version=TEST_VERSION) as wanHby, \
            openHby(name="wil2", salt=Salter(raw=b'will-the-witness').qb64, version=TEST_VERSION) as wilHby, \
            openHby(name="wes2", salt=Salter(raw=b'wess-the-witness').qb64, version=TEST_VERSION) as wesHby, \
            openHby(name="pal2", salt=Salter(raw=b'0123456789abcdef').qb64, version=TEST_VERSION) as palHby:

        # looks like bad magic value in seeder is causing this to fail
        witnessPorts, witnessUrls = witnessPorter("wan", "wil", "wes")
        pdoer = PublishDoer(wanHby, wilHby, wesHby, palHby, seeder, witnessPorts, witnessUrls)
        runController(doers=[pdoer], expire=15.0)
        assert pdoer.done is True


class PublishDoer(doing.DoDoer):

    def __init__(self, wanHby, wilHby, wesHby, palHby, seeder, witnessPorts, witnessUrls):
        wanDoers = setupWitness(alias="wan", hby=wanHby,
                                tcpPort=witnessPorts["wan"]["tcp"],
                                httpPort=witnessPorts["wan"]["http"], **KWA)
        wilDoers = setupWitness(alias="wil", hby=wilHby,
                                tcpPort=witnessPorts["wil"]["tcp"],
                                httpPort=witnessPorts["wil"]["http"], **KWA)
        wesDoers = setupWitness(alias="wes", hby=wesHby,
                                tcpPort=witnessPorts["wes"]["tcp"],
                                httpPort=witnessPorts["wes"]["http"], **KWA)

        self.wanHab = wanHby.habByName(name="wan")
        self.wilHab = wilHby.habByName(name="wil")
        self.wesHab = wesHby.habByName(name="wes")
        seeder.seedWitEnds(palHby.db, witHabs=[self.wanHab, self.wilHab, self.wesHab],
                           protocols=[Schemes.tcp], witnessUrls=witnessUrls, **KWA)

        self.palHab = palHby.makeHab(name="pal", wits=[self.wanHab.pre, self.wilHab.pre, self.wesHab.pre],
                                     transferable=True, **KWA)

        self.witDoer = WitnessPublisher(hby=palHby)
        doers = wanDoers + wilDoers + wesDoers + [self.witDoer]
        self.toRemove = list(doers)
        doers.extend([doing.doify(self.testDo)])

        super(PublishDoer, self).__init__(doers=doers)

    def testDo(self, tymth, tock=0.0, **kwa):
        """ Run the test and exit and remove all child doers when done """
        self.wind(tymth)
        self.tock = tock
        yield self.tock

        serder, _, _ = self.palHab.getOwnEvent(sn=0)
        msg = self.palHab.msgOwnEvent(sn=0, framed=True, gvrsn=serder.pvrsn)
        self.witDoer.msgs.append(dict(pre=self.palHab.pre, msg=msg))

        for hab in [self.wanHab, self.wilHab, self.wesHab]:
            while True:
                if self.palHab.pre in hab.kevers:
                    break
                yield self.tock

        self.remove(self.toRemove)
        return True


def test_witness_inquisitor(mockHelpingNowUTC, seeder, witnessPorter):
    with openHby(name="wan3", salt=Salter(raw=b'wann-the-witness').qb64, version=TEST_VERSION) as wanHby, \
            openHby(name="wil3", salt=Salter(raw=b'will-the-witness').qb64, version=TEST_VERSION) as wilHby, \
            openHby(name="wes3", salt=Salter(raw=b'wess-the-witness').qb64, version=TEST_VERSION) as wesHby, \
            openHby(name="pal3", salt=Salter(raw=b'0123456789abcdef').qb64, version=TEST_VERSION) as palHby, \
            openHby(name="qin3", salt=Salter(raw=b'abcdef0123456789').qb64, version=TEST_VERSION) as qinHby:
        witnessPorts, witnessUrls = witnessPorter("wan", "wil", "wes")
        wanDoers = setupWitness(alias="wan", hby=wanHby,
                                tcpPort=witnessPorts["wan"]["tcp"],
                                httpPort=witnessPorts["wan"]["http"], **KWA)
        wilDoers = setupWitness(alias="wil", hby=wilHby,
                                tcpPort=witnessPorts["wil"]["tcp"],
                                httpPort=witnessPorts["wil"]["http"], **KWA)
        wesDoers = setupWitness(alias="wes", hby=wesHby,
                                tcpPort=witnessPorts["wes"]["tcp"],
                                httpPort=witnessPorts["wes"]["http"], **KWA)

        wanHab = wanHby.habByName(name="wan")
        wilHab = wilHby.habByName(name="wil")
        wesHab = wesHby.habByName(name="wes")
        seeder.seedWitEnds(palHby.db, witHabs=[wanHab, wilHab, wesHab],
                           protocols=[Schemes.tcp], witnessUrls=witnessUrls, **KWA)
        seeder.seedWitEnds(qinHby.db, witHabs=[wanHab, wilHab, wesHab],
                           protocols=[Schemes.tcp], witnessUrls=witnessUrls, **KWA)

        palHab = palHby.makeHab(name="pal", wits=[wanHab.pre, wilHab.pre, wesHab.pre], transferable=True, **KWA)
        qinHab = qinHby.makeHab(name="qin", wits=[wanHab.pre, wilHab.pre, wesHab.pre], transferable=True, **KWA)

        palWitDoer = WitnessReceiptor(hby=palHby)
        palWitDoer.msgs.append(dict(pre=palHab.pre))
        qinWitDoer = WitnessReceiptor(hby=qinHby)
        qinWitDoer.msgs.append(dict(pre=qinHab.pre))

        doers = wanDoers + wilDoers + wesDoers + [palWitDoer, qinWitDoer]
        doist = doing.Doist(doers=doers)
        doist.enter()
        doist.recur()

        while True:
            wigers = []
            for hab in [palHab, qinHab]:
                kev = hab.kever
                ser = kev.serder
                wigers.extend(wanHab.db.wigs.get(keys=(ser.preb, ser.saidb)))
                wigers.extend(wilHab.db.wigs.get(keys=(ser.preb, ser.saidb)))
                wigers.extend(wesHab.db.wigs.get(keys=(ser.preb, ser.saidb)))

            if len(wigers) == 18:
                break

            doist.recur()

        kev = qinHab.kever
        ser = kev.serder

        wigers = wanHab.db.wigs.get(keys=(ser.preb, ser.saidb))
        assert len(wigers) == 3
        wigers = wilHab.db.wigs.get(keys=(ser.preb, ser.saidb))
        assert len(wigers) == 3
        wigers = wesHab.db.wigs.get(keys=(ser.preb, ser.saidb))
        assert len(wigers) == 3

        qinWitq = WitnessInquisitor(hby=qinHby)
        stamp = nowIso8601()
        qinWitq.query(src=qinHab.pre, pre=palHab.pre, stamp=stamp, wits=palHab.kever.wits, **CUE_KWA)

        palWitq = WitnessInquisitor(hby=palHby)
        palWitq.query(src=palHab.pre, pre=qinHab.pre, stamp=stamp, wits=qinHab.kever.wits, **CUE_KWA)

        doist.extend([qinWitq, palWitq])
        while True:
            if palHab.pre in qinHab.kevers and qinHab.pre in palHab.kevers:
                break
            doist.recur()

        assert palHab.pre in qinHab.kevers
        assert qinHab.pre in palHab.kevers

        doist.exit()


@pytest.mark.skip(reason="need to wait for DB changes")
def test_witness_inquisitor_v2(mockHelpingNowUTC, seeder):

    KWA = dict(version=Vrsn_2_0, kind=Kinds.json)
    CUE_KWA = dict(**KWA, gvrsn=Vrsn_2_0)

    with openHby(name="wan3", salt=Salter(raw=b'wann-the-witness').qb64, version=Vrsn_2_0) as wanHby, \
            openHby(name="wil3", salt=Salter(raw=b'will-the-witness').qb64, version=Vrsn_2_0) as wilHby, \
            openHby(name="wes3", salt=Salter(raw=b'wess-the-witness').qb64, version=Vrsn_2_0) as wesHby, \
            openHby(name="pal3", salt=Salter(raw=b'0123456789abcdef').qb64, version=Vrsn_2_0) as palHby, \
            openHby(name="qin3", salt=Salter(raw=b'abcdef0123456789').qb64, version=Vrsn_2_0) as qinHby:
        cf = {
            "kram": {
                "enabled": True,
                "denials": [],
                "caches": {
                    "~": [1000, 5000, 60000, 300000, 5000, 60000, 300000]
                }
            }
        }

        for hby in (wanHby, wilHby, wesHby):
            hby.cf.put(cf)

        wanDoers = setupWitness(alias="wan", hby=wanHby, tcpPort=5632, httpPort=5642, **KWA)
        wilDoers = setupWitness(alias="wil", hby=wilHby, tcpPort=5633, httpPort=5643, **KWA)
        wesDoers = setupWitness(alias="wes", hby=wesHby, tcpPort=5634, httpPort=5644, **KWA)

        wanHab = wanHby.habByName(name="wan")
        wilHab = wilHby.habByName(name="wil")
        wesHab = wesHby.habByName(name="wes")

        seeder.seedWitEnds(palHby.db, witHabs=[wanHab, wilHab, wesHab], protocols=[Schemes.tcp], **KWA)
        seeder.seedWitEnds(qinHby.db, witHabs=[wanHab, wilHab, wesHab], protocols=[Schemes.tcp], **KWA)

        palHab = palHby.makeHab(name="pal", wits=[wanHab.pre, wilHab.pre, wesHab.pre], transferable=True, **KWA)
        qinHab = qinHby.makeHab(name="qin", wits=[wanHab.pre, wilHab.pre, wesHab.pre], transferable=True, **KWA)

        palWitDoer = WitnessReceiptor(hby=palHby)
        palWitDoer.msgs.append(dict(pre=palHab.pre))
        qinWitDoer = WitnessReceiptor(hby=qinHby)
        qinWitDoer.msgs.append(dict(pre=qinHab.pre))

        doers = wanDoers + wilDoers + wesDoers + [palWitDoer, qinWitDoer]
        doist = doing.Doist(limit=5.0, tock=0.03125, doers=doers)
        doist.enter()
        doist.recur()

        tymer = tyming.Tymer(tymth=doist.tymen(), duration=doist.limit)
        wigers = []
        while not tymer.expired:
            wigers = []
            for hab in [palHab, qinHab]:
                kev = hab.kever
                ser = kev.serder
                wigers.extend(wanHab.db.wigs.get(keys=(ser.preb, ser.saidb)))
                wigers.extend(wilHab.db.wigs.get(keys=(ser.preb, ser.saidb)))
                wigers.extend(wesHab.db.wigs.get(keys=(ser.preb, ser.saidb)))

            if len(wigers) == 18:
                break

            doist.recur()

        assert len(wigers) == 18

        kev = qinHab.kever
        ser = kev.serder

        wigers = wanHab.db.wigs.get(keys=(ser.preb, ser.saidb))
        assert len(wigers) == 3
        wigers = wilHab.db.wigs.get(keys=(ser.preb, ser.saidb))
        assert len(wigers) == 3
        wigers = wesHab.db.wigs.get(keys=(ser.preb, ser.saidb))
        assert len(wigers) == 3

        qinWitq = WitnessInquisitor(hby=qinHby)
        stamp = nowIso8601()
        qinWitq.query(src=qinHab.pre, pre=palHab.pre, stamp=stamp, wits=palHab.kever.wits, **CUE_KWA)

        palWitq = WitnessInquisitor(hby=palHby)
        palWitq.query(src=palHab.pre, pre=qinHab.pre, stamp=stamp, wits=qinHab.kever.wits, **CUE_KWA)

        doist.extend([qinWitq, palWitq])
        tymer = tyming.Tymer(tymth=doist.tymen(), duration=doist.limit)
        while not (palHab.pre in qinHab.kevers and qinHab.pre in palHab.kevers) and not tymer.expired:
            doist.recur()

        assert palHab.pre in qinHab.kevers
        assert qinHab.pre in palHab.kevers

        expected_senders = [palHab.pre, qinHab.pre]
        kram_entries = [(keys, cache)
                        for hby in (wanHby, wilHby, wesHby)
                        for keys, cache in hby.db.kramMSGC.getTopItemIter()
                        if keys[0] in expected_senders]

        senders = []
        for keys, cache in kram_entries:
            senders.append(keys[0])
            assert keys[0] in expected_senders
            assert cache.mdt == stamp
            assert cache.d == 1000

        assert len(senders) == len(expected_senders)
        assert palHab.pre in senders
        assert qinHab.pre in senders

        doist.exit()


def test_messenger_prefers_https():
    """Verify messengerFrom and streamMessengerFrom prefer HTTPS over HTTP.

    Regression test for https://github.com/WebOfTrust/keripy/issues/1008
    """
    from unittest.mock import MagicMock, patch
    from keri.app.agenting import messengerFrom, streamMessengerFrom

    hab = MagicMock()
    pre = "EtyPSuUjLyLdXAtGMrsTt0-ELyWeU8fJcymHiGOfuaSA"

    # Both HTTP and HTTPS available
    urls = {
        Schemes.http: "http://example.com:5632",
        Schemes.https: "https://example.com:5643",
    }

    with patch("keri.app.agenting.HTTPMessenger") as MockHTTP:
        messengerFrom(hab, pre, urls)
        MockHTTP.assert_called_once()
        call_url = MockHTTP.call_args[1]["url"]
        assert call_url == "https://example.com:5643", f"Expected HTTPS URL, got {call_url}"

    with patch("keri.app.agenting.HTTPStreamMessenger") as MockStream:
        streamMessengerFrom(hab, pre, urls, msg=b"test")
        MockStream.assert_called_once()
        call_url = MockStream.call_args[1]["url"]
        assert call_url == "https://example.com:5643", f"Expected HTTPS URL, got {call_url}"

    # Only HTTP available - should still work
    http_only = {Schemes.http: "http://example.com:5632"}

    with patch("keri.app.agenting.HTTPMessenger") as MockHTTP:
        messengerFrom(hab, pre, http_only)
        call_url = MockHTTP.call_args[1]["url"]
        assert call_url == "http://example.com:5632"

    # Only HTTPS available - should still work
    https_only = {Schemes.https: "https://example.com:5643"}

    with patch("keri.app.agenting.HTTPStreamMessenger") as MockStream:
        streamMessengerFrom(hab, pre, https_only, msg=b"test")
        call_url = MockStream.call_args[1]["url"]
        assert call_url == "https://example.com:5643"


def test_telquery_uses_pre_not_wits():
    """Test that WitnessInquisitor.telquery queues a message with `pre` parameter
    for endpoint resolution instead of `wits`, matching KERIA behavior.

    Regression test for issue #1160: kli admit fails when issuer has no witness
    because telquery was called with wits=[] (empty list) instead of pre=issr.
    When wits is an empty list, random.choice([]) raises IndexError.
    When pre is provided, WitnessInquisitor.msgDo resolves endpoints via
    hab.endsFor(pre=pre) which works for issuers with or without witnesses.
    """
    with openHby(name="test", temp=True, version=TEST_VERSION) as hby:
        hab = hby.makeHab(name="test", **KWA)
        witq = WitnessInquisitor(hby=hby)

        issr_pre = hab.pre  # use hab's own prefix as a stand-in issuer
        ri = "EAbcdefghijklmnopqrstuvwxyz012345678901234567"
        acdc_said = "EBcdefghijklmnopqrstuvwxyz0123456789012345678"

        # Call telquery with pre= (the fix) instead of wits=
        witq.telquery(src=hab.pre, pre=issr_pre, ri=ri, i=acdc_said)

        assert len(witq.msgs) == 1
        msg = witq.msgs[0]

        # Verify pre is set for endpoint resolution
        assert msg["pre"] == issr_pre
        # Verify wits is None (endpoint resolution path, not random witness path)
        assert msg["wits"] is None
        # Verify other fields
        assert msg["src"] == hab.pre
        assert msg["target"] == acdc_said
        assert msg["q"]["ri"] == ri
